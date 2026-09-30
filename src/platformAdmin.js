import { createHash, randomBytes } from 'node:crypto'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { pool, withTransaction } from './db.js'
import { deployment, originMatchesTenant, tenantUrls } from './deploymentConfig.js'
import { verifyPassword } from './password.js'
import { resolveSession } from './session.js'
import { ensureRedisConnected } from './redis.js'
import { requestIp, requestUserAgent } from './securityAudit.js'
import {
  cancelSoftwareQualificationQueue,
  forceQualificationCleanup,
  QUALIFICATION_TIMING_LIMITS,
  prioritiseSoftwareQualificationQueue,
  pushSoftwareQualificationToTop,
  qualificationRunnerContaminantsForAdmin,
  reconcileSoftwareQualificationQueue,
  retrySoftwareQualification,
  runSoftwareQualificationQueue,
  setQualificationRunnerDispatch,
  setSoftwareQualificationPriority,
} from './rmmSoftwareQualification.js'
import { ensureDefaultRoles } from './access.js'
import { sendTenantOwnerTransferApprovalEmail } from './mailer.js'
import { issueMspLicense } from './licenseAuthority.js'
import { wingetRepositorySearch } from './rmmWingetFallback.js'
import { syncSoftwareVendorSource } from './rmmSoftwareVendorIntel.js'

const COOKIE_NAME = 'hi5central_admin_session'
const SESSION_SECONDS = 60 * 60 * 12
const ADMIN_ROLES = new Set(['owner','admin','support','catalogue','billing','read_only'])
const WRITE_ROLES = new Set(['owner','admin'])
const BILLING_ROLES = new Set(['owner','admin','billing'])
const CATALOGUE_ROLES = new Set(['owner','admin','catalogue'])

function clean(value, max = 500) { return String(value ?? '').trim().slice(0, max) }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function normaliseEmail(value) { return clean(value, 254).toLowerCase() }
function hash(value) { return createHash('sha256').update(String(value || '')).digest('hex') }
function validEmail(value) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) }
function validSlug(value) { return /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/.test(value) && !value.includes('--') }
function htmlEscape(value = '') {
  return String(value)
    .replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')
    .replaceAll('"','&quot;').replaceAll("'",'&#039;')
}
function mdCell(value = '') {
  return String(value ?? '').replaceAll('|','\\|').replaceAll('\r',' ').replaceAll('\n',' ').trim()
}

function isoTime(value) {
  if (!value) return ''
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? '' : date.toISOString()
}
function plusSeconds(value, seconds) {
  const base = value instanceof Date ? value : new Date(value || '')
  if (Number.isNaN(base.getTime())) return ''
  return new Date(base.getTime() + Math.max(0, Number(seconds) || 0) * 1000).toISOString()
}
function qualificationTiming(row) {
  const evidence = object(row.evidence)
  const overallStartedAt = isoTime(row.started_at || row.install_claimed_at || row.install_created_at || evidence.dispatchedAt)
  const cleanupPhase = clean(evidence.cleanupPhase)
  let phase = clean(row.state)
  let phaseLabel = clean(row.state).replaceAll('_', ' ')
  let phaseStartedAt = overallStartedAt
  let deadlineAt = ''
  let deadlineLabel = ''
  let nextPhaseLabel = ''

  if (clean(row.state) === 'running') {
    phase = clean(row.install_job_status) === 'completed' ? 'verification_reconcile' : 'install'
    phaseLabel = phase === 'install' ? 'Install / verify' : 'Verified install — awaiting reconcile'
    phaseStartedAt = isoTime(row.install_claimed_at || row.install_created_at || row.started_at)
    if (phase === 'install') {
      deadlineAt = plusSeconds(phaseStartedAt, QUALIFICATION_TIMING_LIMITS.installRuntimeSeconds)
      deadlineLabel = 'Install timeout'
      nextPhaseLabel = 'Cleanup begins after verified install'
    } else {
      nextPhaseLabel = 'Cleanup due now'
    }
  } else if (clean(row.state) === 'cleanup_pending') {
    phase = 'cleanup_pending'
    phaseLabel = 'Waiting to dispatch cleanup'
    phaseStartedAt = isoTime(evidence.installCompletedAt || row.updated_at)
    deadlineAt = plusSeconds(phaseStartedAt, QUALIFICATION_TIMING_LIMITS.inventoryGraceSeconds)
    deadlineLabel = 'Inventory / cleanup deadline'
    nextPhaseLabel = 'Uninstall dispatch is due now'
  } else if (clean(row.state) === 'cleanup_running') {
    const cleanupStatus = clean(row.cleanup_job_status)
    const cleanupCompletedAt = isoTime(row.cleanup_completed_at)
    if (cleanupPhase === 'residue_cleanup') {
      phase = 'residue_cleanup'
      phaseLabel = 'Final residue cleanup'
      phaseStartedAt = isoTime(row.cleanup_claimed_at || row.cleanup_created_at || evidence.residueCleanupDispatchedAt)
      deadlineAt = plusSeconds(phaseStartedAt, QUALIFICATION_TIMING_LIMITS.residueCleanupSeconds)
      deadlineLabel = 'Residue cleanup timeout'
      nextPhaseLabel = 'Qualification completes after residue verification'
    } else if (cleanupStatus === 'completed') {
      phase = 'cleanup_inventory_wait'
      const preclean = cleanupPhase === 'preclean'
      phaseLabel = preclean
        ? 'Pre-clean complete — verifying clean inventory'
        : 'Uninstall complete — verifying removal'
      phaseStartedAt = cleanupCompletedAt || isoTime(evidence.uninstallCompletedAt || evidence.precleanUninstallCompletedAt || row.updated_at)
      deadlineAt = plusSeconds(phaseStartedAt, QUALIFICATION_TIMING_LIMITS.inventoryGraceSeconds)
      deadlineLabel = preclean ? 'Pre-clean verification deadline' : 'Removal verification deadline'
      nextPhaseLabel = preclean
        ? 'Install begins after clean inventory'
        : 'Residue cleanup follows confirmed removal'
    } else {
      phase = cleanupPhase === 'preclean' ? 'preclean_uninstall' : 'uninstall_cleanup'
      phaseLabel = cleanupPhase === 'preclean' ? 'Pre-clean uninstall' : 'Uninstall cleanup'
      phaseStartedAt = isoTime(row.cleanup_claimed_at || row.cleanup_created_at || evidence.cleanupDispatchedAt || evidence.precleanDispatchedAt)
      const cleanupRuntimeSeconds = clean(row.cleanup_job_type) === 'patch.software'
        ? QUALIFICATION_TIMING_LIMITS.installRuntimeSeconds
        : QUALIFICATION_TIMING_LIMITS.uninstallRuntimeSeconds
      deadlineAt = plusSeconds(phaseStartedAt, cleanupRuntimeSeconds)
      deadlineLabel = clean(row.cleanup_job_type) === 'patch.software'
        ? 'PatchHost cleanup timeout'
        : 'Uninstall timeout'
      nextPhaseLabel = cleanupPhase === 'preclean'
        ? 'Install begins after clean inventory'
        : 'Removal verification follows uninstall'
    }
  }

  return {
    overallStartedAt,
    phase,
    phaseLabel,
    phaseStartedAt,
    deadlineAt,
    deadlineLabel,
    nextPhaseLabel,
    limits: QUALIFICATION_TIMING_LIMITS,
  }
}

function originAllowed(c) {
  const origin = clean(c.req.header('origin')).toLowerCase()
  if (!origin || process.env.NODE_ENV !== 'production') return true
  return origin === String(deployment.adminUrl || `https://admin.${deployment.rootDomain}`).toLowerCase()
}
function cookieOptions(extra = {}) {
  return { secure: true, httpOnly: true, sameSite: 'Lax', path: '/api/platform', ...extra }
}

async function rateLimit(key, max, seconds) {
  const redis = await ensureRedisConnected()
  const count = await redis.incr(key)
  if (count === 1) await redis.expire(key, seconds)
  return count <= max
}

async function audit(c, session, action, targetType = '', targetId = '', metadata = {}, db = pool) {
  await db.query(
    `INSERT INTO platform_admin_audit_events
      (actor_user_id,session_id,action,target_type,target_id,ip_address,user_agent,metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
    [session?.user_id || null, session?.session_id || null, clean(action,160), clean(targetType,80),
      clean(targetId,160), requestIp(c), requestUserAgent(c), JSON.stringify(metadata || {})],
  )
}

async function resolveAdminSession(c) {
  const token = getCookie(c, COOKIE_NAME)
  if (!token) return null
  const result = await pool.query(
    `SELECT s.id AS session_id,s.user_id,s.expires_at,u.email,u.name,m.role,m.status
       FROM platform_admin_sessions s
       JOIN users u ON u.id=s.user_id
       JOIN platform_admin_members m ON m.user_id=s.user_id
      WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now()
      LIMIT 1`,
    [hash(token)],
  )
  const row = result.rows[0]
  if (!row || row.status !== 'active' || !ADMIN_ROLES.has(row.role)) return null
  pool.query('UPDATE platform_admin_sessions SET last_seen_at=now() WHERE id=$1', [row.session_id]).catch(() => {})
  return row
}

async function requireAdmin(c, roles = null) {
  const standardReleaseControl = deployment.deploymentMode === 'self_hosted'
    && deployment.selfHostEdition === 'standard'
    && deployment.runtimeEnvironment === 'live'
    && c.req.path.startsWith('/api/platform/v1/releases')

  if (standardReleaseControl) {
    const tenantSession = await resolveSession(c)
    if (!tenantSession) return { error: c.json({ error: 'Authentication required.' }, 401) }
    if (!originMatchesTenant(c.req.header('origin'), tenantSession.slug)) {
      return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
    }
    const role = tenantSession.tenant_role
    if (!['owner','admin'].includes(role)) {
      return { error: c.json({ error: 'Organisation administrator access is required.' }, 403) }
    }
    if (roles && !roles.has(role)) return { error: c.json({ error: 'This organisation role cannot perform that action.' }, 403) }
    return { session: { ...tenantSession, role, session_id: null } }
  }

  if (!originAllowed(c)) return { error: c.json({ error: 'Admin origin required.' }, 403) }
  const session = await resolveAdminSession(c)
  if (!session) return { error: c.json({ error: 'Platform administrator authentication required.' }, 401) }
  if (roles && !roles.has(session.role)) return { error: c.json({ error: 'This platform role cannot perform that action.' }, 403) }
  return { session }
}

function adminPayload(session) {
  return { authenticated: true, user: { id: session.user_id, name: session.name, email: session.email, role: session.role } }
}

function mspLicensePayload(row) {
  return {
    id: row.id,
    customerName: row.customer_name,
    status: row.status,
    keySuffix: row.display_key_suffix,
    products: row.products || [],
    features: row.features || {},
    limits: {
      tenants: row.tenant_limit == null ? null : Number(row.tenant_limit),
      users: row.user_limit == null ? null : Number(row.user_limit),
      devices: row.device_limit == null ? null : Number(row.device_limit),
    },
    startsAt: row.starts_at,
    expiresAt: row.expires_at,
    graceDays: Number(row.grace_days || 0),
    boundInstallationId: row.bound_installation_id,
    boundAt: row.bound_at,
    lastActivatedAt: row.last_activated_at,
    lastRefreshedAt: row.last_refreshed_at,
    notes: row.notes || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}


function releaseChangePayload(row, results = {}) {
  return {
    id: row.id,
    changeKey: row.change_key,
    title: row.title,
    description: row.description || '',
    component: row.component,
    featureKey: row.feature_key || '',
    sourceRef: row.source_ref || '',
    version: row.version || '',
    risk: row.risk,
    state: row.state,
    testResult: results.test || null,
    uatResult: results.uat || null,
    promotedAt: row.promoted_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}


function tenantReleasePreferencePayload(row) {
  return {
    tenantId: row.tenant_id,
    slug: row.slug,
    companyName: row.company_name,
    updateMode: row.update_mode || 'admin_controlled',
    managedByHi5Central: row.update_mode === 'hi5_managed',
    testAutoSync: row.test_auto_sync == null ? true : Boolean(row.test_auto_sync),
    uatAutoStage: Boolean(row.uat_auto_stage),
    liveAutoPromote: Boolean(row.live_auto_promote),
    liveDelayHours: Number(row.live_delay_hours ?? 24),
    allowEmergencySecurityUpdates: row.allow_emergency_security_updates == null ? true : Boolean(row.allow_emergency_security_updates),
    maintenanceWindow: object(row.maintenance_window),
    updatedAt: row.release_updated_at || row.updated_at || null,
  }
}

function environmentStatePayload(row) {
  return {
    environment: row.environment,
    featureMode: row.feature_mode,
    disposable: Boolean(row.disposable),
    activeReleaseRef: row.active_release_ref || '',
    lastResetAt: row.last_reset_at,
    lastDeployedAt: row.last_deployed_at,
    updatedAt: row.updated_at,
  }
}

const RELEASE_COMPONENTS = new Set([
  'platform','control-server','itsm','rmm','admin','agent','viewer','app-portal',
  'docs','deploy','integration','other',
])
const RELEASE_RISKS = new Set(['low','medium','high'])
const RELEASE_EDITABLE_STATES = new Set([
  'draft','ready_for_test','testing','ready_for_uat','uat_testing','uat_passed','uat_failed','withdrawn',
])

async function releaseOverview(tenantId = null) {
  const [environments, features, flags, tenantFlags, tenants, changes, latestResults, promotions, actions] = await Promise.all([
    pool.query('SELECT * FROM platform_environment_state ORDER BY CASE environment WHEN \'dev\' THEN 1 WHEN \'test\' THEN 2 WHEN \'uat\' THEN 3 ELSE 4 END'),
    pool.query('SELECT * FROM platform_feature_definitions ORDER BY component,title'),
    pool.query('SELECT * FROM platform_environment_feature_flags ORDER BY environment,feature_key'),
    tenantId
      ? pool.query('SELECT * FROM tenant_environment_feature_overrides WHERE tenant_id=$1 ORDER BY environment,feature_key', [tenantId])
      : Promise.resolve({ rows: [] }),
    pool.query(`SELECT t.id AS tenant_id,t.slug,t.company_name,t.updated_at,
      p.update_mode,p.test_auto_sync,p.uat_auto_stage,p.live_auto_promote,p.live_delay_hours,
      p.allow_emergency_security_updates,p.maintenance_window,p.updated_at AS release_updated_at
      FROM tenants t
      LEFT JOIN tenant_release_preferences p ON p.tenant_id=t.id
      ORDER BY t.company_name,t.slug`),
    pool.query('SELECT * FROM platform_release_changes ORDER BY created_at DESC LIMIT 300'),
    pool.query(`SELECT DISTINCT ON (change_id,environment)
      change_id,environment,result,notes,evidence,tested_by,created_at
      FROM platform_release_test_results
      ORDER BY change_id,environment,created_at DESC`),
    pool.query(`SELECT p.*,
      COALESCE(array_agg(i.change_id) FILTER (WHERE i.change_id IS NOT NULL),'{}') AS change_ids
      FROM platform_release_promotions p
      LEFT JOIN platform_release_promotion_items i ON i.promotion_id=p.id
      GROUP BY p.id ORDER BY p.requested_at DESC LIMIT 50`),
    pool.query('SELECT * FROM platform_environment_actions ORDER BY requested_at DESC LIMIT 50'),
  ])
  const resultMap = new Map()
  for (const row of latestResults.rows) {
    if (!resultMap.has(row.change_id)) resultMap.set(row.change_id, {})
    resultMap.get(row.change_id)[row.environment] = {
      result: row.result,
      notes: row.notes || '',
      evidence: object(row.evidence),
      testedBy: row.tested_by,
      createdAt: row.created_at,
    }
  }
  const featureFlags = {}
  for (const row of flags.rows) {
    if (!featureFlags[row.environment]) featureFlags[row.environment] = {}
    featureFlags[row.environment][row.feature_key] = Boolean(row.enabled)
  }
  const tenantFeatureFlags = {}
  for (const row of tenantFlags.rows) {
    if (!tenantFeatureFlags[row.environment]) tenantFeatureFlags[row.environment] = {}
    tenantFeatureFlags[row.environment][row.feature_key] = Boolean(row.enabled)
  }
  return {
    currentEnvironment: deployment.runtimeEnvironment,
    currentFeatureMode: deployment.featureMode,
    selectedTenantId: tenantId,
    tenants: tenants.rows.map(tenantReleasePreferencePayload),
    environments: environments.rows.map(environmentStatePayload),
    features: features.rows.map((row) => ({
      key: row.feature_key,
      title: row.title,
      description: row.description || '',
      component: row.component,
      defaultEnabled: Boolean(row.default_enabled),
      status: row.status,
      flags: Object.fromEntries(['dev','test','uat','live'].map((environment) => [
        environment,
        environment === 'dev' || environment === 'test'
          ? true
          : Boolean(tenantFeatureFlags[environment]?.[row.feature_key] ?? featureFlags[environment]?.[row.feature_key] ?? row.default_enabled),
      ])),
    })),
    changes: changes.rows.map((row) => releaseChangePayload(row, resultMap.get(row.id) || {})),
    promotions: promotions.rows.map((row) => ({
      id: row.id,
      fromEnvironment: row.from_environment,
      toEnvironment: row.to_environment,
      status: row.status,
      releaseRef: row.release_ref || '',
      changeIds: row.change_ids || [],
      requestedAt: row.requested_at,
      startedAt: row.started_at,
      completedAt: row.completed_at,
      errorMessage: row.error_message || '',
    })),
    actions: actions.rows.map((row) => ({
      id: row.id,
      environment: row.environment,
      action: row.action,
      status: row.status,
      payload: object(row.payload),
      requestedAt: row.requested_at,
      startedAt: row.started_at,
      completedAt: row.completed_at,
      errorMessage: row.error_message || '',
    })),
  }
}

function nullablePositiveInteger(value) {
  if (value === null || value === undefined || value === '') return null
  const number = Math.floor(Number(value))
  return Number.isFinite(number) && number >= 1 ? number : null
}

export function registerPlatformAdminRoutes(app) {
  app.post('/api/platform/v1/auth/login', async (c) => {
    if (!originAllowed(c)) return c.json({ error: 'Admin origin required.' }, 403)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const email = normaliseEmail(body?.email)
    const password = String(body?.password || '')
    if (!validEmail(email) || !password) return c.json({ error: 'Enter a valid email address and password.' }, 400)
    if (!await rateLimit(`platform-admin-login:${requestIp(c)}:${email}`, 8, 900)) {
      return c.json({ error: 'Too many sign-in attempts. Try again later.' }, 429)
    }
    const result = await pool.query(
      `SELECT u.id AS user_id,u.email,u.name,u.password_hash,m.role,m.status
         FROM users u JOIN platform_admin_members m ON m.user_id=u.id
        WHERE u.email=$1 LIMIT 1`,
      [email],
    )
    const account = result.rows[0]
    if (!account || account.status !== 'active' || !await verifyPassword(password, account.password_hash)) {
      return c.json({ error: 'Email address or password is incorrect.' }, 401)
    }
    const token = randomBytes(32).toString('base64url')
    const created = await pool.query(
      `INSERT INTO platform_admin_sessions (user_id,token_hash,expires_at)
       VALUES ($1,$2,now()+make_interval(secs=>$3::int)) RETURNING id`,
      [account.user_id, hash(token), SESSION_SECONDS],
    )
    const session = { ...account, session_id: created.rows[0].id }
    setCookie(c, COOKIE_NAME, token, cookieOptions({ maxAge: SESSION_SECONDS }))
    await audit(c, session, 'platform.auth.login')
    return c.json(adminPayload(session))
  })

  app.get('/api/platform/v1/auth/session', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    return c.json(adminPayload(auth.session))
  })

  app.post('/api/platform/v1/auth/logout', async (c) => {
    const session = await resolveAdminSession(c)
    const token = getCookie(c, COOKIE_NAME)
    if (token) await pool.query(
      'UPDATE platform_admin_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE token_hash=$1',
      [hash(token)],
    )
    if (session) await audit(c, session, 'platform.auth.logout')
    deleteCookie(c, COOKIE_NAME, cookieOptions())
    return c.json({ ok: true })
  })

  app.get('/api/platform/v1/overview', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    const [tenants, devices, catalogue, qualification, runners] = await Promise.all([
      pool.query(`SELECT count(*)::int total,count(*) FILTER (WHERE status='active')::int active FROM tenants`),
      pool.query(`SELECT count(*)::int total,count(*) FILTER (WHERE websocket_status='Connected')::int online FROM rmm_agent_devices`),
      pool.query(`SELECT count(*) FILTER (WHERE tenant_id IS NULL AND status='active')::int total,
                         count(*) FILTER (WHERE tenant_id IS NULL AND status='active' AND qualification_state='qualified')::int qualified,
                         count(*) FILTER (WHERE tenant_id IS NULL AND status='active' AND qualification_state='deployment_candidate')::int candidates
                    FROM rmm_software_catalogue`),
      pool.query(`SELECT count(*) FILTER (WHERE state IN ('queued','running','cleanup_pending','cleanup_running'))::int active,
                         count(*) FILTER (WHERE state='review_required')::int review
                    FROM rmm_software_qualification_queue`),
      pool.query(`SELECT count(*)::int total,count(*) FILTER (WHERE enabled)::int enabled
                    FROM rmm_software_vendor_qualification_runners`),
    ])
    return c.json({
      tenants: tenants.rows[0],
      devices: devices.rows[0],
      catalogue: catalogue.rows[0],
      qualification: qualification.rows[0],
      runners: runners.rows[0],
    })
  })


  app.get('/api/platform/v1/releases/overview', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    const tenantId = auth.session.tenant_id || clean(c.req.query('tenantId'), 80) || null
    return c.json(await releaseOverview(tenantId))
  })

  app.post('/api/platform/v1/releases/features', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const featureKey = clean(body?.featureKey, 120).toLowerCase()
    const title = clean(body?.title, 180)
    const component = clean(body?.component, 80) || 'platform'
    if (!/^[a-z0-9][a-z0-9._-]{1,119}$/.test(featureKey)) return c.json({ error: 'featureKey is invalid.' }, 400)
    if (title.length < 2) return c.json({ error: 'Feature title is required.' }, 400)
    const result = await pool.query(
      `INSERT INTO platform_feature_definitions
        (feature_key,title,description,component,default_enabled)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (feature_key) DO UPDATE
       SET title=EXCLUDED.title,description=EXCLUDED.description,component=EXCLUDED.component,
           default_enabled=EXCLUDED.default_enabled,status='active',updated_at=now()
       RETURNING *`,
      [featureKey,title,clean(body?.description,4000),component,Boolean(body?.defaultEnabled)],
    )
    await audit(c, auth.session, 'release.feature.saved', 'feature', featureKey, { component })
    return c.json({ feature: result.rows[0] }, 201)
  })

  app.patch('/api/platform/v1/releases/features/:featureKey/:environment', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const featureKey = clean(c.req.param('featureKey'), 120).toLowerCase()
    const environment = clean(c.req.param('environment'), 20).toLowerCase()
    if (!['uat','live'].includes(environment)) {
      return c.json({ error: 'Only UAT and Live use controlled feature switches. Dev and Test always enable all features.' }, 409)
    }
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    if (typeof body?.enabled !== 'boolean') return c.json({ error: 'enabled must be true or false.' }, 400)
    const feature = await pool.query('SELECT 1 FROM platform_feature_definitions WHERE feature_key=$1 AND status=\'active\'', [featureKey])
    if (!feature.rowCount) return c.json({ error: 'Feature not found.' }, 404)
    const tenantId = auth.session.tenant_id || clean(body?.tenantId, 80) || null
    if (tenantId) {
      const tenant = await pool.query('SELECT 1 FROM tenants WHERE id=$1', [tenantId])
      if (!tenant.rowCount) return c.json({ error: 'Tenant not found.' }, 404)
      await pool.query(
        `INSERT INTO tenant_environment_feature_overrides (tenant_id,environment,feature_key,enabled,updated_by)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (tenant_id,environment,feature_key) DO UPDATE
         SET enabled=EXCLUDED.enabled,updated_by=EXCLUDED.updated_by,updated_at=now()`,
        [tenantId,environment,featureKey,body.enabled,auth.session.user_id],
      )
    } else {
      await pool.query(
        `INSERT INTO platform_environment_feature_flags (environment,feature_key,enabled,updated_by)
         VALUES ($1,$2,$3,$4)
         ON CONFLICT (environment,feature_key) DO UPDATE
         SET enabled=EXCLUDED.enabled,updated_by=EXCLUDED.updated_by,updated_at=now()`,
        [environment,featureKey,body.enabled,auth.session.user_id],
      )
    }
    await audit(c, auth.session, 'release.feature.toggle', 'feature', featureKey, { environment, tenantId, enabled: body.enabled })
    return c.json({ ok: true, environment, featureKey, tenantId, enabled: body.enabled })
  })


  app.patch('/api/platform/v1/releases/tenants/:tenantId/preferences', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const tenantId = auth.session.tenant_id || clean(c.req.param('tenantId'), 80)
    if (!tenantId) return c.json({ error: 'Tenant is required.' }, 400)

    const tenant = await pool.query('SELECT id,slug,company_name FROM tenants WHERE id=$1', [tenantId])
    if (!tenant.rowCount) return c.json({ error: 'Tenant not found.' }, 404)

    let body
    try { body = await c.req.json() } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const updateMode = clean(body?.updateMode, 40).toLowerCase()
    if (!['admin_controlled','hi5_managed'].includes(updateMode)) {
      return c.json({ error: 'updateMode must be admin_controlled or hi5_managed.' }, 400)
    }
    const delay = body?.liveDelayHours == null ? 24 : Math.floor(Number(body.liveDelayHours))
    if (!Number.isFinite(delay) || delay < 0 || delay > 720) {
      return c.json({ error: 'liveDelayHours must be between 0 and 720.' }, 400)
    }
    const managed = updateMode === 'hi5_managed'

    const result = await pool.query(
      `INSERT INTO tenant_release_preferences
        (tenant_id,update_mode,test_auto_sync,uat_auto_stage,live_auto_promote,
         live_delay_hours,allow_emergency_security_updates,maintenance_window,updated_by)
       VALUES ($1,$2,true,$3,$3,$4,$5,$6::jsonb,$7)
       ON CONFLICT (tenant_id) DO UPDATE SET
         update_mode=EXCLUDED.update_mode,
         test_auto_sync=true,
         uat_auto_stage=EXCLUDED.uat_auto_stage,
         live_auto_promote=EXCLUDED.live_auto_promote,
         live_delay_hours=EXCLUDED.live_delay_hours,
         allow_emergency_security_updates=EXCLUDED.allow_emergency_security_updates,
         maintenance_window=CASE
           WHEN EXCLUDED.maintenance_window='{}'::jsonb THEN tenant_release_preferences.maintenance_window
           ELSE EXCLUDED.maintenance_window
         END,
         updated_by=EXCLUDED.updated_by,
         updated_at=now()
       RETURNING *`,
      [
        tenantId,
        updateMode,
        managed,
        delay,
        body?.allowEmergencySecurityUpdates !== false,
        JSON.stringify(object(body?.maintenanceWindow)),
        auth.session.user_id,
      ],
    )

    await audit(c, auth.session, 'release.tenant_preferences.updated', 'tenant', tenantId, {
      updateMode,
      liveDelayHours: delay,
      allowEmergencySecurityUpdates: body?.allowEmergencySecurityUpdates !== false,
    })

    return c.json({
      preference: tenantReleasePreferencePayload({
        ...result.rows[0],
        slug: tenant.rows[0].slug,
        company_name: tenant.rows[0].company_name,
        release_updated_at: result.rows[0].updated_at,
      }),
    })
  })

  app.post('/api/platform/v1/releases/changes', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const title = clean(body?.title, 220)
    const component = clean(body?.component, 80) || 'platform'
    const risk = clean(body?.risk, 20) || 'medium'
    const state = clean(body?.state, 30) || 'ready_for_test'
    const featureKey = clean(body?.featureKey, 120).toLowerCase() || null
    if (title.length < 3) return c.json({ error: 'Change title is required.' }, 400)
    if (!RELEASE_COMPONENTS.has(component)) return c.json({ error: 'component is invalid.' }, 400)
    if (!RELEASE_RISKS.has(risk)) return c.json({ error: 'risk must be low, medium or high.' }, 400)
    if (!['draft','ready_for_test'].includes(state)) return c.json({ error: 'New changes must start as draft or ready_for_test.' }, 400)
    if (featureKey) {
      const feature = await pool.query('SELECT 1 FROM platform_feature_definitions WHERE feature_key=$1 AND status=\'active\'', [featureKey])
      if (!feature.rowCount) return c.json({ error: 'Feature key is not registered.' }, 400)
    }
    const changeKey = clean(body?.changeKey, 80).toUpperCase()
      || `H5C-${Date.now().toString(36).toUpperCase()}-${randomBytes(2).toString('hex').toUpperCase()}`
    try {
      const result = await pool.query(
        `INSERT INTO platform_release_changes
          (change_key,title,description,component,feature_key,source_ref,version,risk,state,created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         RETURNING *`,
        [
          changeKey,title,clean(body?.description,8000),component,featureKey,
          clean(body?.sourceRef,300),clean(body?.version,120),risk,state,auth.session.user_id,
        ],
      )
      await audit(c, auth.session, 'release.change.created', 'release_change', result.rows[0].id, { changeKey, component, sourceRef: clean(body?.sourceRef,300) })
      return c.json({ change: releaseChangePayload(result.rows[0]) }, 201)
    } catch (error) {
      if (error?.code === '23505') return c.json({ error: 'That change key already exists.' }, 409)
      throw error
    }
  })

  app.patch('/api/platform/v1/releases/changes/:id', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const id = clean(c.req.param('id'), 80)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const currentResult = await pool.query('SELECT * FROM platform_release_changes WHERE id=$1', [id])
    if (!currentResult.rowCount) return c.json({ error: 'Release change not found.' }, 404)
    const current = currentResult.rows[0]
    const component = Object.hasOwn(body,'component') ? clean(body.component,80) : current.component
    const risk = Object.hasOwn(body,'risk') ? clean(body.risk,20) : current.risk
    const state = Object.hasOwn(body,'state') ? clean(body.state,30) : current.state
    if (!RELEASE_COMPONENTS.has(component)) return c.json({ error: 'component is invalid.' }, 400)
    if (!RELEASE_RISKS.has(risk)) return c.json({ error: 'risk is invalid.' }, 400)
    if (!RELEASE_EDITABLE_STATES.has(state)) return c.json({ error: 'Use the approval/promotion actions for selected or promoted states.' }, 409)
    const result = await pool.query(
      `UPDATE platform_release_changes SET
        title=$2,description=$3,component=$4,source_ref=$5,version=$6,risk=$7,state=$8,updated_at=now()
       WHERE id=$1 RETURNING *`,
      [
        id,
        Object.hasOwn(body,'title') ? clean(body.title,220) : current.title,
        Object.hasOwn(body,'description') ? clean(body.description,8000) : current.description,
        component,
        Object.hasOwn(body,'sourceRef') ? clean(body.sourceRef,300) : current.source_ref,
        Object.hasOwn(body,'version') ? clean(body.version,120) : current.version,
        risk,state,
      ],
    )
    await audit(c, auth.session, 'release.change.updated', 'release_change', id, { fields: Object.keys(body || {}) })
    return c.json({ change: releaseChangePayload(result.rows[0]) })
  })

  app.post('/api/platform/v1/releases/changes/:id/test-results', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const id = clean(c.req.param('id'), 80)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const environment = clean(body?.environment,20).toLowerCase()
    const resultValue = clean(body?.result,20).toLowerCase()
    if (!['test','uat'].includes(environment)) return c.json({ error: 'environment must be test or uat.' }, 400)
    if (!['passed','failed','blocked'].includes(resultValue)) return c.json({ error: 'result must be passed, failed or blocked.' }, 400)
    const change = await pool.query('SELECT * FROM platform_release_changes WHERE id=$1', [id])
    if (!change.rowCount) return c.json({ error: 'Release change not found.' }, 404)
    if (['promoted','withdrawn'].includes(change.rows[0].state)) return c.json({ error: 'This change is no longer testable.' }, 409)
    if (environment === 'uat') {
      const latestTest = await pool.query(
        `SELECT result FROM platform_release_test_results
         WHERE change_id=$1 AND environment='test' ORDER BY created_at DESC LIMIT 1`,
        [id],
      )
      if (latestTest.rows[0]?.result !== 'passed') return c.json({ error: 'Test must pass before a UAT result can be recorded.' }, 409)
    }
    const nextState = environment === 'test'
      ? (resultValue === 'passed' ? 'ready_for_uat' : 'testing')
      : (resultValue === 'passed' ? 'uat_passed' : 'uat_failed')
    await withTransaction(async (db) => {
      await db.query(
        `INSERT INTO platform_release_test_results
          (change_id,environment,result,notes,evidence,tested_by)
         VALUES ($1,$2,$3,$4,$5::jsonb,$6)`,
        [id,environment,resultValue,clean(body?.notes,8000),JSON.stringify(object(body?.evidence)),auth.session.user_id],
      )
      await db.query('UPDATE platform_release_changes SET state=$2,updated_at=now() WHERE id=$1', [id,nextState])
    })
    await audit(c, auth.session, 'release.test.recorded', 'release_change', id, { environment, result: resultValue })
    return c.json({ ok: true, state: nextState })
  })

  app.post('/api/platform/v1/releases/changes/:id/select-live', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const id = clean(c.req.param('id'), 80)
    const result = await pool.query(
      `SELECT c.id,c.state,c.feature_key,
        (SELECT r.result FROM platform_release_test_results r
         WHERE r.change_id=c.id AND r.environment='uat'
         ORDER BY r.created_at DESC LIMIT 1) AS uat_result
       FROM platform_release_changes c WHERE c.id=$1`,
      [id],
    )
    if (!result.rowCount) return c.json({ error: 'Release change not found.' }, 404)
    if (result.rows[0].uat_result !== 'passed' || result.rows[0].state !== 'uat_passed') {
      return c.json({ error: 'Only a change with a latest Passed UAT result can be selected for Live.' }, 409)
    }
    if (!result.rows[0].feature_key) {
      return c.json({ error: 'Selective Live promotion requires a registered feature flag so unselected candidate code remains disabled.' }, 409)
    }
    await pool.query("UPDATE platform_release_changes SET state='selected_for_live',updated_at=now() WHERE id=$1", [id])
    await audit(c, auth.session, 'release.change.selected_live', 'release_change', id)
    return c.json({ ok: true, state: 'selected_for_live' })
  })

  app.post('/api/platform/v1/releases/changes/:id/unselect-live', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const id = clean(c.req.param('id'), 80)
    const result = await pool.query(
      "UPDATE platform_release_changes SET state='uat_passed',updated_at=now() WHERE id=$1 AND state='selected_for_live' RETURNING id",
      [id],
    )
    if (!result.rowCount) return c.json({ error: 'Change is not selected for Live.' }, 409)
    await audit(c, auth.session, 'release.change.unselected_live', 'release_change', id)
    return c.json({ ok: true, state: 'uat_passed' })
  })

  app.post('/api/platform/v1/releases/promotions', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const toEnvironment = clean(body?.toEnvironment,20).toLowerCase()
    if (!['uat','live'].includes(toEnvironment)) return c.json({ error: 'toEnvironment must be uat or live.' }, 400)
    const fromEnvironment = toEnvironment === 'uat' ? 'test' : 'uat'
    const ids = Array.isArray(body?.changeIds) ? [...new Set(body.changeIds.map((value) => clean(value,80)).filter(Boolean))] : []
    if (!ids.length) return c.json({ error: 'Select at least one change.' }, 400)
    const rows = await pool.query(
      `SELECT c.id,c.state,
        (SELECT r.result FROM platform_release_test_results r
         WHERE r.change_id=c.id AND r.environment=$2 ORDER BY r.created_at DESC LIMIT 1) AS latest_result
       FROM platform_release_changes c WHERE c.id = ANY($1::uuid[])`,
      [ids,fromEnvironment],
    )
    if (rows.rowCount !== ids.length) return c.json({ error: 'One or more selected changes do not exist.' }, 400)
    for (const row of rows.rows) {
      if (row.latest_result !== 'passed') return c.json({ error: `Every selected change must have a latest Passed ${fromEnvironment.toUpperCase()} result.` }, 409)
      if (toEnvironment === 'live' && row.state !== 'selected_for_live') {
        return c.json({ error: 'Every Live promotion item must be explicitly selected for Live.' }, 409)
      }
    }
    const releaseRef = clean(body?.releaseRef,300)
    const promotion = await withTransaction(async (db) => {
      const created = await db.query(
        `INSERT INTO platform_release_promotions
          (from_environment,to_environment,release_ref,requested_by)
         VALUES ($1,$2,$3,$4) RETURNING *`,
        [fromEnvironment,toEnvironment,releaseRef,auth.session.user_id],
      )
      for (const id of ids) {
        await db.query('INSERT INTO platform_release_promotion_items (promotion_id,change_id) VALUES ($1,$2)', [created.rows[0].id,id])
      }
      await db.query(
        `INSERT INTO platform_environment_actions
          (environment,action,payload,requested_by)
         VALUES ($1,'promote',$2::jsonb,$3)`,
        [toEnvironment,JSON.stringify({ promotionId: created.rows[0].id, changeIds: ids, releaseRef }),auth.session.user_id],
      )
      if (toEnvironment === 'uat') {
        await db.query("UPDATE platform_release_changes SET state='uat_testing',updated_at=now() WHERE id=ANY($1::uuid[])", [ids])
      }
      return created.rows[0]
    })
    await audit(c, auth.session, 'release.promotion.requested', 'release_promotion', promotion.id, { fromEnvironment,toEnvironment,changeIds:ids,releaseRef })
    return c.json({ promotion: { id: promotion.id, fromEnvironment,toEnvironment,status:promotion.status,releaseRef,changeIds:ids } }, 201)
  })

  app.post('/api/platform/v1/releases/environments/test/reset', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const state = await pool.query("SELECT * FROM platform_environment_state WHERE environment='test' AND disposable=true")
    if (!state.rowCount) return c.json({ error: 'Test is not configured as a disposable environment.' }, 409)
    const pending = await pool.query(
      "SELECT id FROM platform_environment_actions WHERE environment='test' AND action='reset' AND status IN ('requested','running') LIMIT 1",
    )
    if (pending.rowCount) return c.json({ error: 'A Test reset is already queued or running.', actionId: pending.rows[0].id }, 409)
    const result = await pool.query(
      `INSERT INTO platform_environment_actions (environment,action,payload,requested_by)
       VALUES ('test','reset',$1::jsonb,$2) RETURNING *`,
      [JSON.stringify({ resetTo: 'default', requestedFromEnvironment: deployment.runtimeEnvironment }),auth.session.user_id],
    )
    await audit(c, auth.session, 'release.environment.reset_requested', 'environment', 'test', { actionId: result.rows[0].id })
    return c.json({ action: result.rows[0] }, 202)
  })

  app.get('/api/platform/v1/licenses', async (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    const auth = await requireAdmin(c, BILLING_ROLES)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT id,customer_name,status,display_key_suffix,products,features,
              tenant_limit,user_limit,device_limit,starts_at,expires_at,grace_days,
              bound_installation_id,bound_at,last_activated_at,last_refreshed_at,
              notes,created_at,updated_at
         FROM msp_licenses
        ORDER BY created_at DESC`,
    )
    return c.json({ items: result.rows.map(mspLicensePayload) })
  })

  app.post('/api/platform/v1/licenses', async (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    const auth = await requireAdmin(c, BILLING_ROLES)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    try {
      const issued = await issueMspLicense(body || {})
      await audit(c, auth.session, 'msp_license.created', 'msp_license', issued.license.id, {
        customerName: issued.license.customer_name,
        expiresAt: issued.license.expires_at,
      })
      return c.json({
        licenseKey: issued.licenseKey,
        license: mspLicensePayload(issued.license),
        notice: 'The licence key is returned once. Store and send it securely.',
      }, 201)
    } catch (error) {
      return c.json({ error: error?.message || 'Unable to issue MSP licence.' }, Number(error?.status) || 400)
    }
  })

  app.patch('/api/platform/v1/licenses/:id', async (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    const auth = await requireAdmin(c, BILLING_ROLES)
    if (auth.error) return auth.error
    const id = clean(c.req.param('id'), 80)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

    const existing = await pool.query('SELECT * FROM msp_licenses WHERE id=$1 LIMIT 1', [id])
    if (!existing.rowCount) return c.json({ error: 'MSP licence not found.' }, 404)
    const current = existing.rows[0]

    const status = Object.hasOwn(body, 'status') ? clean(body.status, 20) : current.status
    if (!['active','suspended','cancelled'].includes(status)) {
      return c.json({ error: 'status must be active, suspended or cancelled.' }, 400)
    }

    let expiresAt = current.expires_at
    if (Object.hasOwn(body, 'expiresAt')) {
      expiresAt = body.expiresAt ? new Date(body.expiresAt) : null
      if (expiresAt && Number.isNaN(expiresAt.getTime())) return c.json({ error: 'expiresAt is invalid.' }, 400)
    }
    const graceDays = Object.hasOwn(body, 'graceDays')
      ? Math.max(0, Math.min(90, Math.floor(Number(body.graceDays) || 0)))
      : Number(current.grace_days || 0)
    const features = Object.hasOwn(body, 'features')
      ? { ...object(current.features), ...object(body.features) }
      : object(current.features)

    const readLimit = (key, currentValue) => {
      if (!Object.hasOwn(body, key)) return currentValue
      if (body[key] === null || body[key] === '') return null
      return nullablePositiveInteger(body[key])
    }
    const tenantLimit = readLimit('tenantLimit', current.tenant_limit)
    const userLimit = readLimit('userLimit', current.user_limit)
    const deviceLimit = readLimit('deviceLimit', current.device_limit)
    for (const [key, value] of [['tenantLimit',tenantLimit],['userLimit',userLimit],['deviceLimit',deviceLimit]]) {
      if (Object.hasOwn(body, key) && body[key] !== null && body[key] !== '' && value === null) {
        return c.json({ error: `${key} must be a positive integer or null.` }, 400)
      }
    }

    const result = await pool.query(
      `UPDATE msp_licenses
          SET customer_name=$2,status=$3,features=$4::jsonb,
              tenant_limit=$5,user_limit=$6,device_limit=$7,
              expires_at=$8,grace_days=$9,notes=$10,updated_at=now()
        WHERE id=$1
        RETURNING *`,
      [
        id,
        Object.hasOwn(body, 'customerName') ? clean(body.customerName, 180) : current.customer_name,
        status,
        JSON.stringify(features),
        tenantLimit,
        userLimit,
        deviceLimit,
        expiresAt,
        graceDays,
        Object.hasOwn(body, 'notes') ? clean(body.notes, 4000) : current.notes,
      ],
    )
    await audit(c, auth.session, 'msp_license.updated', 'msp_license', id, { fields: Object.keys(body || {}) })
    return c.json({ license: mspLicensePayload(result.rows[0]) })
  })

  app.post('/api/platform/v1/licenses/:id/reset-binding', async (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const id = clean(c.req.param('id'), 80)
    const result = await pool.query(
      `UPDATE msp_licenses
          SET bound_installation_id=NULL,bound_at=NULL,refresh_token_hash=NULL,updated_at=now()
        WHERE id=$1
        RETURNING *`,
      [id],
    )
    if (!result.rowCount) return c.json({ error: 'MSP licence not found.' }, 404)
    await audit(c, auth.session, 'msp_license.binding_reset', 'msp_license', id)
    return c.json({ license: mspLicensePayload(result.rows[0]) })
  })

  app.get('/api/platform/v1/tenants', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT t.id,t.slug,t.company_name,t.status,t.created_at,t.updated_at,
              ts.modules,ts.tenant_url,ts.portal_url,ts.rmm_url,ts.onboarding_completed_at,
              COALESCE(cs.plan_key,'custom') AS plan_key,COALESCE(cs.billing_status,'trial') AS billing_status,
              COALESCE(cs.billing_cycle,'monthly') AS billing_cycle,COALESCE(cs.currency,'GBP') AS currency,
              cs.monthly_price_pence,cs.trial_ends_at,cs.renewal_at,COALESCE(cs.notes,'') AS billing_notes,
              owner.user_id AS owner_user_id,owner.name AS owner_name,owner.email AS owner_email,
              transfer.id AS owner_transfer_id,transfer.proposed_owner_email,
              transfer.proposed_owner_name,transfer.created_at AS owner_transfer_requested_at,
              transfer.expires_at AS owner_transfer_expires_at,
              (SELECT count(*)::int FROM tenant_memberships m WHERE m.tenant_id=t.id) AS user_count,
              (SELECT count(*)::int FROM rmm_agent_devices d WHERE d.tenant_id=t.id) AS device_count
         FROM tenants t
         JOIN tenant_settings ts ON ts.tenant_id=t.id
         LEFT JOIN tenant_commercial_settings cs ON cs.tenant_id=t.id
         LEFT JOIN LATERAL (
           SELECT u.id AS user_id,u.name,u.email
             FROM tenant_memberships m
             JOIN users u ON u.id=m.user_id
            WHERE m.tenant_id=t.id AND m.role='owner'
            ORDER BY m.created_at
            LIMIT 1
         ) owner ON true
         LEFT JOIN LATERAL (
           SELECT r.id,r.proposed_owner_email,pu.name AS proposed_owner_name,r.created_at,r.expires_at
             FROM tenant_owner_transfer_requests r
             LEFT JOIN users pu ON pu.id=r.proposed_owner_user_id
            WHERE r.tenant_id=t.id AND r.approved_at IS NULL AND r.cancelled_at IS NULL
              AND r.expires_at>now()
            ORDER BY r.created_at DESC
            LIMIT 1
         ) transfer ON true
        ORDER BY lower(t.company_name)`,
    )
    return c.json({ items: result.rows })
  })

  app.post('/api/platform/v1/tenants', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const companyName = clean(body?.companyName, 120)
    const slug = clean(body?.slug, 48).toLowerCase()
    if (companyName.length < 2 || !validSlug(slug)) {
      return c.json({ error: 'Company name and a valid tenant slug are required.' }, 400)
    }
    const itsm = body?.modules?.itsm !== false
    const rmm = body?.modules?.rmm === true
    const status = ['pending_verification','active','suspended','closed'].includes(body?.status) ? body.status : 'active'
    const urls = tenantUrls(slug, { rmm })
    try {
      const tenant = await withTransaction(async (db) => {
        const inserted = await db.query(
          `INSERT INTO tenants (slug,company_name,status) VALUES ($1,$2,$3)
           RETURNING id,slug,company_name,status,created_at`,
          [slug, companyName, status],
        )
        const row = inserted.rows[0]
        await db.query(
          `INSERT INTO tenant_settings (tenant_id,modules,onboarding_step,tenant_url,portal_url,rmm_url)
           VALUES ($1,$2::jsonb,'company',$3,$4,$5)`,
          [row.id, JSON.stringify({ itsm, rmm }), urls.tenantUrl, urls.portalUrl, urls.rmmUrl],
        )
        await db.query(
          `INSERT INTO tenant_commercial_settings (tenant_id,plan_key,billing_status,billing_cycle)
           VALUES ($1,$2,$3,$4)`,
          [row.id, clean(body?.planKey,80) || 'custom',
            ['trial','active','past_due','suspended','cancelled'].includes(body?.billingStatus) ? body.billingStatus : 'trial',
            ['monthly','annual','custom'].includes(body?.billingCycle) ? body.billingCycle : 'monthly'],
        )
        await audit(c, auth.session, 'tenant.created', 'tenant', row.id, { slug, companyName, modules: { itsm, rmm } }, db)
        return row
      })
      return c.json({ tenant }, 201)
    } catch (error) {
      if (error?.code === '23505') return c.json({ error: 'That tenant slug already exists.' }, 409)
      throw error
    }
  })

  app.patch('/api/platform/v1/tenants/:id', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    const tenantId = clean(c.req.param('id'), 80)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const touchesBilling = ['planKey','billingStatus','billingCycle','currency','monthlyPricePence','trialEndsAt','renewalAt','billingNotes']
      .some((key) => Object.hasOwn(body || {}, key))
    const touchesTenant = ['companyName','status','modules'].some((key) => Object.hasOwn(body || {}, key))
    if (touchesBilling && !BILLING_ROLES.has(auth.session.role)) return c.json({ error: 'Billing permission required.' }, 403)
    if (touchesTenant && !WRITE_ROLES.has(auth.session.role)) return c.json({ error: 'Platform admin permission required.' }, 403)
    const existing = await pool.query(
      `SELECT t.*,ts.modules FROM tenants t JOIN tenant_settings ts ON ts.tenant_id=t.id WHERE t.id=$1 LIMIT 1`,
      [tenantId],
    )
    if (!existing.rowCount) return c.json({ error: 'Tenant not found.' }, 404)
    const current = existing.rows[0]
    const modules = {
      itsm: body?.modules?.itsm ?? Boolean(current.modules?.itsm),
      rmm: body?.modules?.rmm ?? Boolean(current.modules?.rmm),
    }
    const urls = tenantUrls(current.slug, { rmm: modules.rmm })
    await withTransaction(async (db) => {
      if (touchesTenant) {
        const companyName = Object.hasOwn(body,'companyName') ? clean(body.companyName,120) : current.company_name
        const status = Object.hasOwn(body,'status')
          && ['pending_verification','active','suspended','closed'].includes(body.status) ? body.status : current.status
        await db.query(
          'UPDATE tenants SET company_name=$2,status=$3,updated_at=now() WHERE id=$1',
          [tenantId, companyName, status],
        )
        await db.query(
          `UPDATE tenant_settings SET modules=$2::jsonb,tenant_url=$3,portal_url=$4,rmm_url=$5,updated_at=now()
            WHERE tenant_id=$1`,
          [tenantId, JSON.stringify(modules), urls.tenantUrl, urls.portalUrl, urls.rmmUrl],
        )
      }
      if (touchesBilling) {
        await db.query(
          'INSERT INTO tenant_commercial_settings (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING',
          [tenantId],
        )
        await db.query(
          `UPDATE tenant_commercial_settings SET
             plan_key=COALESCE($2,plan_key),billing_status=COALESCE($3,billing_status),
             billing_cycle=COALESCE($4,billing_cycle),currency=COALESCE($5,currency),
             monthly_price_pence=CASE WHEN $6::boolean THEN $7 ELSE monthly_price_pence END,
             trial_ends_at=CASE WHEN $8::boolean THEN $9::timestamptz ELSE trial_ends_at END,
             renewal_at=CASE WHEN $10::boolean THEN $11::timestamptz ELSE renewal_at END,
             notes=COALESCE($12,notes),updated_at=now()
           WHERE tenant_id=$1`,
          [tenantId,
            Object.hasOwn(body,'planKey') ? clean(body.planKey,80) : null,
            Object.hasOwn(body,'billingStatus') && ['trial','active','past_due','suspended','cancelled'].includes(body.billingStatus) ? body.billingStatus : null,
            Object.hasOwn(body,'billingCycle') && ['monthly','annual','custom'].includes(body.billingCycle) ? body.billingCycle : null,
            Object.hasOwn(body,'currency') ? clean(body.currency,3).toUpperCase() : null,
            Object.hasOwn(body,'monthlyPricePence'), body.monthlyPricePence == null ? null : Math.max(0, Number(body.monthlyPricePence) || 0),
            Object.hasOwn(body,'trialEndsAt'), body.trialEndsAt || null,
            Object.hasOwn(body,'renewalAt'), body.renewalAt || null,
            Object.hasOwn(body,'billingNotes') ? clean(body.billingNotes,4000) : null],
        )
      }
      await audit(c, auth.session, 'tenant.updated', 'tenant', tenantId, { fields: Object.keys(body || {}) }, db)
    })
    return c.json({ ok: true })
  })

  app.post('/api/platform/v1/tenants/:id/owner-transfer', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const tenantId = clean(c.req.param('id'), 80)
    let body = {}
    try { body = await c.req.json() } catch {}
    const proposedEmail = normaliseEmail(body.email)
    if (!validEmail(proposedEmail)) return c.json({ error: 'Enter a valid email address.' }, 400)

    const currentResult = await pool.query(
      `SELECT t.id,t.company_name,u.id AS owner_user_id,u.name AS owner_name,u.email AS owner_email
         FROM tenants t
         JOIN tenant_memberships m ON m.tenant_id=t.id AND m.role='owner'
         JOIN users u ON u.id=m.user_id
        WHERE t.id=$1 LIMIT 1`,
      [tenantId],
    )
    if (!currentResult.rowCount) return c.json({ error: 'Tenant owner could not be resolved.' }, 409)
    const current = currentResult.rows[0]
    if (normaliseEmail(current.owner_email) === proposedEmail) {
      return c.json({ error: 'That email address is already the tenant owner.' }, 409)
    }

    const proposedResult = await pool.query(
      `SELECT u.id,u.name,u.email,m.status
         FROM tenant_memberships m
         JOIN users u ON u.id=m.user_id
        WHERE m.tenant_id=$1 AND lower(u.email)=lower($2)
        LIMIT 1`,
      [tenantId, proposedEmail],
    )
    if (!proposedResult.rowCount || proposedResult.rows[0].status !== 'active') {
      return c.json({ error: 'The new owner must already be an active user in this tenant.' }, 409)
    }
    const proposed = proposedResult.rows[0]
    const token = randomBytes(32).toString('base64url')
    const tokenHash = hash(token)
    const transfer = await withTransaction(async (db) => {
      await db.query(
        `UPDATE tenant_owner_transfer_requests
            SET cancelled_at=COALESCE(cancelled_at,now())
          WHERE tenant_id=$1 AND approved_at IS NULL AND cancelled_at IS NULL`,
        [tenantId],
      )
      const inserted = await db.query(
        `INSERT INTO tenant_owner_transfer_requests
           (tenant_id,current_owner_user_id,proposed_owner_user_id,requested_by_user_id,
            proposed_owner_email,token_hash,expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,now()+interval '24 hours')
         RETURNING id,created_at,expires_at`,
        [tenantId, current.owner_user_id, proposed.id, auth.session.user_id, proposedEmail, tokenHash],
      )
      return inserted.rows[0]
    })

    try {
      await sendTenantOwnerTransferApprovalEmail({
        to: current.owner_email,
        name: current.owner_name,
        companyName: current.company_name,
        proposedOwnerEmail: proposedEmail,
        token,
        requestedBy: auth.session.name || auth.session.email,
      })
    } catch {
      await pool.query(
        'UPDATE tenant_owner_transfer_requests SET cancelled_at=now() WHERE id=$1 AND approved_at IS NULL',
        [transfer.id],
      ).catch(() => {})
      return c.json({ error: 'The transfer was not created because the approval email could not be sent.' }, 503)
    }

    await audit(c, auth.session, 'tenant.owner_transfer.requested', 'tenant', tenantId, {
      transferId: transfer.id,
      currentOwnerEmail: current.owner_email,
      proposedOwnerEmail: proposedEmail,
    })
    return c.json({
      ok: true,
      transfer: {
        id: transfer.id,
        proposedOwnerEmail: proposedEmail,
        proposedOwnerName: proposed.name,
        createdAt: transfer.created_at,
        expiresAt: transfer.expires_at,
      },
    }, 201)
  })

  app.post('/api/platform/v1/tenants/:id/owner-transfer/cancel', async (c) => {
    const auth = await requireAdmin(c, WRITE_ROLES)
    if (auth.error) return auth.error
    const tenantId = clean(c.req.param('id'), 80)
    const result = await pool.query(
      `UPDATE tenant_owner_transfer_requests
          SET cancelled_at=now()
        WHERE tenant_id=$1 AND approved_at IS NULL AND cancelled_at IS NULL
        RETURNING id`,
      [tenantId],
    )
    await audit(c, auth.session, 'tenant.owner_transfer.cancelled', 'tenant', tenantId, {
      transferIds: result.rows.map((row) => row.id),
    })
    return c.json({ ok: true, cancelled: result.rowCount })
  })

  app.get('/api/platform/v1/tenant-owner-transfer/confirm', async (c) => {
    const token = clean(c.req.query('token'), 256)
    const transferResult = token.length >= 32
      ? await pool.query(
          `SELECT r.id,r.expires_at,r.approved_at,r.cancelled_at,r.proposed_owner_email,
                  t.company_name,current_owner.name AS current_owner_name,proposed.name AS proposed_owner_name
             FROM tenant_owner_transfer_requests r
             JOIN tenants t ON t.id=r.tenant_id
             JOIN users current_owner ON current_owner.id=r.current_owner_user_id
             JOIN users proposed ON proposed.id=r.proposed_owner_user_id
            WHERE r.token_hash=$1 LIMIT 1`,
          [hash(token)],
        )
      : { rows: [] }
    const transfer = transferResult.rows[0]
    const invalid = !transfer || transfer.approved_at || transfer.cancelled_at
      || new Date(transfer.expires_at).getTime() <= Date.now()
    if (invalid) {
      return c.html('<!doctype html><html><body style="font-family:Arial,sans-serif;padding:40px;color:#10213f"><h1>Owner transfer unavailable</h1><p>This approval link is invalid, expired, cancelled, or has already been used.</p></body></html>', 410)
    }
    return c.html(`<!doctype html><html><body style="margin:0;background:#f3f6fb;font-family:Arial,sans-serif;color:#10213f">
      <main style="max-width:620px;margin:60px auto;padding:32px;background:#fff;border:1px solid #dfe6ef;border-radius:16px">
        <div style="font-size:13px;color:#6b7890;margin-bottom:10px">HI5CENTRAL · TENANT OWNERSHIP</div>
        <h1 style="margin:0 0 16px">Approve owner change for ${htmlEscape(transfer.company_name)}</h1>
        <p>You are currently the owner. Hi5Central has been asked to transfer ownership to <strong>${htmlEscape(transfer.proposed_owner_name)}</strong> (${htmlEscape(transfer.proposed_owner_email)}).</p>
        <p>Your account will remain active as an Administrator. The new owner will receive the protected Owner role.</p>
        <form method="post" action="/api/platform/v1/tenant-owner-transfer/approve">
          <input type="hidden" name="token" value="${htmlEscape(token)}">
          <button type="submit" style="border:0;border-radius:10px;background:#f59e0b;color:#10213f;padding:14px 20px;font-weight:700;cursor:pointer">Approve ownership transfer</button>
        </form>
        <p style="font-size:13px;color:#6b7890;margin-top:24px">If you did not expect this request, close this page and contact Hi5Central support. No change occurs unless you approve.</p>
      </main></body></html>`)
  })

  app.post('/api/platform/v1/tenant-owner-transfer/approve', async (c) => {
    const form = await c.req.formData().catch(() => null)
    const token = clean(form?.get('token'), 256)
    if (token.length < 32) return c.html('<h1>Invalid approval link</h1>', 400)
    const outcome = await withTransaction(async (db) => {
      const result = await db.query(
        `SELECT r.*,t.company_name,current_owner.name AS current_owner_name,
                proposed.name AS proposed_owner_name,proposed.email AS proposed_owner_email_resolved
           FROM tenant_owner_transfer_requests r
           JOIN tenants t ON t.id=r.tenant_id
           JOIN users current_owner ON current_owner.id=r.current_owner_user_id
           JOIN users proposed ON proposed.id=r.proposed_owner_user_id
          WHERE r.token_hash=$1 FOR UPDATE`,
        [hash(token)],
      )
      if (!result.rowCount) return { error: 'invalid' }
      const transfer = result.rows[0]
      if (transfer.approved_at || transfer.cancelled_at || new Date(transfer.expires_at).getTime() <= Date.now()) {
        return { error: 'expired' }
      }
      const currentOwner = await db.query(
        `SELECT 1 FROM tenant_memberships
          WHERE tenant_id=$1 AND user_id=$2 AND role='owner' AND status='active' LIMIT 1`,
        [transfer.tenant_id, transfer.current_owner_user_id],
      )
      const proposedMember = await db.query(
        `SELECT 1 FROM tenant_memberships
          WHERE tenant_id=$1 AND user_id=$2 AND status='active' LIMIT 1`,
        [transfer.tenant_id, transfer.proposed_owner_user_id],
      )
      if (!currentOwner.rowCount || !proposedMember.rowCount) return { error: 'membership_changed' }

      await ensureDefaultRoles(db, transfer.tenant_id)
      const roles = await db.query(
        `SELECT id,system_key FROM access_roles
          WHERE tenant_id=$1 AND system_key IN ('owner','administrator') AND active=true`,
        [transfer.tenant_id],
      )
      const ownerRoleId = roles.rows.find((row) => row.system_key === 'owner')?.id
      const adminRoleId = roles.rows.find((row) => row.system_key === 'administrator')?.id
      if (!ownerRoleId || !adminRoleId) return { error: 'roles_unavailable' }

      await db.query(
        `UPDATE tenant_memberships SET role='admin'
          WHERE tenant_id=$1 AND role='owner' AND user_id<>$2`,
        [transfer.tenant_id, transfer.proposed_owner_user_id],
      )
      await db.query(
        `UPDATE tenant_memberships SET role='owner'
          WHERE tenant_id=$1 AND user_id=$2`,
        [transfer.tenant_id, transfer.proposed_owner_user_id],
      )
      await db.query(
        'DELETE FROM access_user_roles WHERE tenant_id=$1 AND role_id=$2 AND user_id<>$3',
        [transfer.tenant_id, ownerRoleId, transfer.proposed_owner_user_id],
      )
      await db.query(
        `INSERT INTO access_user_roles (tenant_id,user_id,role_id,assigned_by_user_id)
         VALUES ($1,$2,$3,$2) ON CONFLICT DO NOTHING`,
        [transfer.tenant_id, transfer.current_owner_user_id, adminRoleId],
      )
      await db.query(
        `INSERT INTO access_user_roles (tenant_id,user_id,role_id,assigned_by_user_id)
         VALUES ($1,$2,$3,$2) ON CONFLICT DO NOTHING`,
        [transfer.tenant_id, transfer.proposed_owner_user_id, ownerRoleId],
      )
      await db.query(
        `UPDATE tenant_owner_transfer_requests SET approved_at=now()
          WHERE id=$1`,
        [transfer.id],
      )
      await db.query(
        `UPDATE tenant_owner_transfer_requests SET cancelled_at=now()
          WHERE tenant_id=$1 AND id<>$2 AND approved_at IS NULL AND cancelled_at IS NULL`,
        [transfer.tenant_id, transfer.id],
      )
      await db.query(
        `UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,now()),revoked_reason=COALESCE(revoked_reason,'tenant_owner_changed')
          WHERE tenant_id=$1 AND user_id IN ($2,$3) AND revoked_at IS NULL`,
        [transfer.tenant_id, transfer.current_owner_user_id, transfer.proposed_owner_user_id],
      )
      await audit(c, { user_id: transfer.current_owner_user_id }, 'tenant.owner_transfer.approved', 'tenant', transfer.tenant_id, {
        transferId: transfer.id,
        previousOwnerUserId: transfer.current_owner_user_id,
        newOwnerUserId: transfer.proposed_owner_user_id,
        newOwnerEmail: transfer.proposed_owner_email_resolved,
      }, db)
      return { transfer }
    })

    if (outcome.error) {
      return c.html('<!doctype html><html><body style="font-family:Arial,sans-serif;padding:40px;color:#10213f"><h1>Owner transfer could not be approved</h1><p>The request is no longer valid or the tenant membership changed. Ask Hi5Central to create a new request.</p></body></html>', 409)
    }
    return c.html(`<!doctype html><html><body style="margin:0;background:#f3f6fb;font-family:Arial,sans-serif;color:#10213f"><main style="max-width:620px;margin:60px auto;padding:32px;background:#fff;border:1px solid #dfe6ef;border-radius:16px"><div style="font-size:13px;color:#6b7890">HI5CENTRAL · TENANT OWNERSHIP</div><h1>Ownership transfer approved</h1><p><strong>${htmlEscape(outcome.transfer.proposed_owner_name)}</strong> is now the owner of ${htmlEscape(outcome.transfer.company_name)}. Your account remains active as an Administrator.</p><p style="color:#6b7890">Both accounts will be asked to sign in again so the updated permissions take effect.</p></main></body></html>`)
  })

  app.get('/api/platform/v1/software/catalogue/export.md', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT canonical_name,publisher,target_version,qualification_state,status,installer_type,
              source_metadata->>'installerTechnology' AS installer_technology,
              source_metadata->>'deploymentLimitation' AS deployment_limitation,
              source_metadata->>'latestSource' AS latest_source,updated_at
         FROM rmm_software_catalogue
        WHERE tenant_id IS NULL
        ORDER BY lower(canonical_name)`,
    )
    const generated = new Date().toISOString()
    const lines = [
      '# Hi5Central Software Catalogue',
      '',
      `Generated: ${generated}`,
      '',
      `Total software items: ${result.rowCount}`,
      '',
      '| Software | Publisher | Target version | Qualification | Status | Installer | Technology | Limitation | Source | Updated |',
      '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
      ...result.rows.map((row) => `| ${mdCell(row.canonical_name)} | ${mdCell(row.publisher)} | ${mdCell(row.target_version)} | ${mdCell(row.qualification_state)} | ${mdCell(row.status)} | ${mdCell(row.installer_type)} | ${mdCell(row.installer_technology)} | ${mdCell(row.deployment_limitation)} | ${mdCell(row.latest_source)} | ${mdCell(isoTime(row.updated_at))} |`),
      '',
    ]
    const filename = `hi5central-software-catalogue-${generated.slice(0,10)}.md`
    c.header('Content-Type', 'text/markdown; charset=utf-8')
    c.header('Content-Disposition', `attachment; filename="${filename}"`)
    return c.body(lines.join('\n'))
  })

  app.get('/api/platform/v1/winget', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    try {
      const result = await wingetRepositorySearch({
        query: clean(c.req.query('q'), 160),
        page: Number(c.req.query('page') || 1),
        pageSize: Number(c.req.query('pageSize') || 100),
      })
      if (result.indexRefreshed) {
        await pool.query(
          `INSERT INTO platform_external_sync_state
             (sync_key,status,completed_at,last_success_at,last_error,metadata,updated_at)
           VALUES ('winget_repository','idle',now(),now(),'',$1::jsonb,now())
           ON CONFLICT (sync_key) DO UPDATE SET
             status='idle',completed_at=now(),last_success_at=now(),last_error='',
             metadata=platform_external_sync_state.metadata || EXCLUDED.metadata,updated_at=now()`,
          [JSON.stringify({ totalPackages: result.total, source: result.source })],
        )
      }
      const syncState = await pool.query(
        `SELECT status,started_at,completed_at,last_success_at,last_error,metadata,updated_at
           FROM platform_external_sync_state WHERE sync_key='winget_repository' LIMIT 1`,
      )
      return c.json({ ...result, sync: syncState.rows[0] || null })
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Unable to read the WinGet manifest index.' }, 503)
    }
  })

  app.post('/api/platform/v1/winget/sync', async (c) => {
    const auth = await requireAdmin(c, CATALOGUE_ROLES)
    if (auth.error) return auth.error
    await pool.query(
      `INSERT INTO platform_external_sync_state (sync_key,status,started_at,last_error,updated_at)
       VALUES ('winget_repository','running',now(),'',now())
       ON CONFLICT (sync_key) DO UPDATE SET status='running',started_at=now(),last_error='',updated_at=now()`,
    )
    try {
      const result = await wingetRepositorySearch({ page: 1, pageSize: 10, forceRefresh: true })
      await pool.query(
        `UPDATE platform_external_sync_state SET status='idle',completed_at=now(),last_success_at=now(),
                last_error='',metadata=metadata || $1::jsonb,updated_at=now()
          WHERE sync_key='winget_repository'`,
        [JSON.stringify({ totalPackages: result.total, source: result.source, manualSyncAt: new Date().toISOString() })],
      )
      await audit(c, auth.session, 'winget.repository.synced', 'external_source', 'winget_repository', {
        totalPackages: result.total,
        source: result.source,
      })
      return c.json({ ok: true, total: result.total, source: result.source, syncedAt: new Date().toISOString() })
    } catch (error) {
      const message = clean(error?.message || error, 1000) || 'WinGet sync failed.'
      await pool.query(
        `UPDATE platform_external_sync_state SET status='failed',completed_at=now(),last_error=$1,updated_at=now()
          WHERE sync_key='winget_repository'`,
        [message],
      ).catch(() => {})
      await audit(c, auth.session, 'winget.repository.sync_failed', 'external_source', 'winget_repository', { error: message }).catch(() => {})
      return c.json({ error: message }, 503)
    }
  })

  app.get('/api/platform/v1/software/catalogue', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT id,canonical_name,publisher,target_version,qualification_state,status,installer_type,
              source_metadata->>'installerTechnology' AS installer_technology,
              source_metadata->>'deploymentLimitation' AS deployment_limitation,
              qualification_notes,updated_at
         FROM rmm_software_catalogue
        WHERE tenant_id IS NULL AND status<>'archived'
        ORDER BY lower(canonical_name)
        LIMIT 1500`,
    )
    return c.json({ items: result.rows })
  })

  app.get('/api/platform/v1/qualification', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    const [runners, active, pending, recent] = await Promise.all([
      pool.query(
        `SELECT r.agent_device_id AS id,r.agent_device_id,r.enabled,r.dispatch_enabled,
                r.pause_reason,r.paused_at,r.updated_at,i.name AS hostname,
                a.agent_version,a.websocket_status,a.patch_capabilities->>'patchHostVersion' AS patch_host_version,
                a.last_telemetry_at,a.last_inventory_at
           FROM rmm_software_vendor_qualification_runners r
           LEFT JOIN rmm_agent_devices a ON a.id=r.agent_device_id
           LEFT JOIN rmm_device_inventory i ON i.id=a.inventory_id
          ORDER BY r.updated_at DESC`,
      ),
      pool.query(
        `SELECT q.id,q.catalogue_id,c.canonical_name,c.target_version,q.test_type,q.state,q.priority,
                q.attempt_count,q.last_error,q.runner_agent_device_id,q.agent_job_id,q.cleanup_job_id,
                q.evidence,q.started_at,q.updated_at,
                install_job.status AS install_job_status,
                install_job.created_at AS install_created_at,
                install_job.claimed_at AS install_claimed_at,
                install_job.completed_at AS install_completed_at,
                cleanup_job.status AS cleanup_job_status,
                cleanup_job.job_type AS cleanup_job_type,
                cleanup_job.created_at AS cleanup_created_at,
                cleanup_job.claimed_at AS cleanup_claimed_at,
                cleanup_job.completed_at AS cleanup_completed_at,
                cleanup_job.payload AS cleanup_payload
           FROM rmm_software_qualification_queue q
           JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
           LEFT JOIN rmm_agent_jobs install_job ON install_job.id=q.agent_job_id
           LEFT JOIN rmm_agent_jobs cleanup_job ON cleanup_job.id=q.cleanup_job_id
          WHERE q.state IN ('running','cleanup_pending','cleanup_running')
          ORDER BY q.updated_at LIMIT 100`,
      ),
      pool.query(
        `SELECT row_number() OVER (
                  ORDER BY CASE q.test_type WHEN 'rollback' THEN 0 WHEN 'upgrade' THEN 1 ELSE 2 END,
                           q.priority DESC,q.created_at
                )::int AS position,
                q.id,q.catalogue_id,c.canonical_name,c.target_version,q.test_type,q.state,q.priority,
                q.attempt_count,q.last_error,q.runner_agent_device_id,q.evidence,
                NULLIF(q.evidence->>'retryNotBefore','')::timestamptz AS retry_not_before,
                q.created_at,q.updated_at
           FROM rmm_software_qualification_queue q
           JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
          WHERE q.state='queued'
          ORDER BY CASE q.test_type WHEN 'rollback' THEN 0 WHEN 'upgrade' THEN 1 ELSE 2 END,
                   q.priority DESC,q.created_at`,
      ),
      pool.query(
        `SELECT q.id,q.catalogue_id,c.canonical_name,c.target_version,q.test_type,q.state,q.priority,
                q.attempt_count,q.last_error,q.runner_agent_device_id,q.agent_job_id,q.cleanup_job_id,
                q.evidence,q.started_at,q.completed_at,q.updated_at
           FROM rmm_software_qualification_queue q
           JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
          WHERE q.state IN ('passed','review_required','cancelled')
          ORDER BY q.updated_at DESC LIMIT 150`,
      ),
    ])
    const runnerItems = await Promise.all(runners.rows.map(async (runner) => ({
      ...runner,
      contaminants: await qualificationRunnerContaminantsForAdmin(runner.agent_device_id),
    })))
    const activeItems = active.rows.map((row) => ({
      ...row,
      timing: qualificationTiming(row),
    }))
    return c.json({ runners: runnerItems, active: activeItems, pending: pending.rows, recent: recent.rows })
  })

  app.post('/api/platform/v1/qualification/runners/:agentDeviceId/action', async (c) => {
    const auth = await requireAdmin(c, CATALOGUE_ROLES)
    if (auth.error) return auth.error
    let body = {}
    try { body = await c.req.json() } catch {}
    const agentDeviceId = clean(c.req.param('agentDeviceId'), 80)
    const action = clean(body.action, 40).toLowerCase()
    let result
    if (action === 'pause' || action === 'drain') {
      result = await setQualificationRunnerDispatch(agentDeviceId, {
        dispatchEnabled: false,
        reason: clean(body.reason, 500) || (action === 'drain' ? 'Drain requested from Hi5Central Admin' : 'Paused from Hi5Central Admin'),
        userId: auth.session.user_id,
      })
    } else if (action === 'resume') {
      result = await setQualificationRunnerDispatch(agentDeviceId, {
        dispatchEnabled: true,
        userId: auth.session.user_id,
      })
    } else if (action === 'reconcile') {
      result = await reconcileSoftwareQualificationQueue()
    } else if (action === 'run_next') {
      result = await runSoftwareQualificationQueue({ dispatchLimit: 1 })
    } else if (action === 'cleanup_contaminants') {
      const contaminants = await qualificationRunnerContaminantsForAdmin(agentDeviceId)
      if (!contaminants.length) {
        result = { ok: true, clean: true, contaminants: [] }
      } else {
        const contaminant = contaminants[0]
        result = await forceQualificationCleanup(contaminant.queueId, { userId: auth.session.user_id })
        result.contaminant = contaminant
      }
    } else {
      return c.json({ error: 'Unsupported runner action.' }, 400)
    }
    if (!result) return c.json({ error: 'Qualification runner not found.' }, 404)
    if (result?.ok === false) return c.json({ error: result.reason || 'Runner action could not be completed.', result }, 409)
    await audit(c, auth.session, 'qualification.runner.' + action, 'agent_device', agentDeviceId, { result })
    return c.json({ ok: true, result })
  })

  app.post('/api/platform/v1/qualification/queue/:queueId/action', async (c) => {
    const auth = await requireAdmin(c, CATALOGUE_ROLES)
    if (auth.error) return auth.error
    let body = {}
    try { body = await c.req.json() } catch {}
    const queueId = clean(c.req.param('queueId'), 80)
    const action = clean(body.action, 40).toLowerCase()
    const current = await pool.query(
      `SELECT q.id,q.catalogue_id,q.test_type,q.state,c.canonical_name
         FROM rmm_software_qualification_queue q
         JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
        WHERE q.id=$1 LIMIT 1`,
      [queueId],
    )
    const row = current.rows[0]
    if (!row) return c.json({ error: 'Qualification queue item not found.' }, 404)
    let result
    if (action === 'cancel') {
      result = await cancelSoftwareQualificationQueue(queueId, { userId: auth.session.user_id })
    } else if (action === 'cleanup') {
      result = await forceQualificationCleanup(queueId, { userId: auth.session.user_id })
    } else if (action === 'run_now') {
      const prioritised = await prioritiseSoftwareQualificationQueue(queueId, { priority: body.priority || 50000 })
      if (!prioritised) return c.json({ error: 'Only queued qualification items can be run now.' }, 409)
      result = { prioritised, dispatch: await runSoftwareQualificationQueue({ dispatchLimit: 1 }) }
    } else if (action === 'set_priority') {
      result = await setSoftwareQualificationPriority(queueId, {
        priority: body.priority,
        userId: auth.session.user_id,
      })
      if (!result) return c.json({ error: 'Only queued qualification items can have their priority changed.' }, 409)
    } else if (action === 'push_top') {
      result = await pushSoftwareQualificationToTop(queueId, { userId: auth.session.user_id })
      if (!result) return c.json({ error: 'Only queued qualification items can be moved to the top.' }, 409)
    } else if (action === 'requeue') {
      result = await retrySoftwareQualification(row.catalogue_id, { mode: 'clean_only' })
      if (result.queued && body.runNow !== false) {
        await prioritiseSoftwareQualificationQueue(result.queue?.id, { priority: body.priority || 50000 })
        result.dispatch = await runSoftwareQualificationQueue({ dispatchLimit: 1 })
      }
    } else if (action === 'reconcile') {
      result = await reconcileSoftwareQualificationQueue()
    } else {
      return c.json({ error: 'Unsupported qualification queue action.' }, 400)
    }
    if (result?.ok === false || result?.queued === false) {
      return c.json({ error: result.reason || 'Qualification action could not be completed.', result }, 409)
    }
    await audit(c, auth.session, 'qualification.queue.' + action, 'qualification_queue', queueId, {
      catalogueId: row.catalogue_id,
      applicationName: row.canonical_name,
      priorState: row.state,
      result,
    })
    return c.json({ ok: true, result })
  })

  app.get('/api/platform/v1/software/catalogue/:catalogueId', async (c) => {
    const auth = await requireAdmin(c)
    if (auth.error) return auth.error
    const catalogueId = clean(c.req.param('catalogueId'), 80)
    const software = await pool.query(
      `SELECT c.*,
              s.source_key,s.source_type,s.source_url,s.enabled AS source_enabled,
              s.last_success_at AS source_last_success_at,s.last_error AS source_last_error,
              r.id AS release_id,r.version AS release_version,r.installer_url,r.installer_sha256,
              r.installer_type AS release_installer_type,r.trust_state,r.asset_health_state,
              r.source_payload AS release_source_payload,r.trust_evidence,
              b.metadata AS binding_metadata
         FROM rmm_software_catalogue c
         LEFT JOIN rmm_software_vendor_sources s ON s.source_key=c.source_metadata->>'latestSource'
         LEFT JOIN rmm_software_vendor_releases r
           ON r.source_key=s.source_key AND r.provider_package_id=c.external_key AND r.version=c.target_version
         LEFT JOIN rmm_software_vendor_bindings b
           ON b.source_key=s.source_key AND b.provider_package_id=c.external_key AND b.enabled=true
        WHERE c.id=$1 AND c.tenant_id IS NULL
        ORDER BY r.source_priority DESC NULLS LAST,r.last_seen_at DESC NULLS LAST
        LIMIT 1`,
      [catalogueId],
    )
    if (!software.rowCount) return c.json({ error: 'Software catalogue entry not found.' }, 404)
    const [queues, jobs] = await Promise.all([
      pool.query(
        `SELECT id,test_type,state,priority,attempt_count,runner_agent_device_id,agent_job_id,
                cleanup_job_id,last_error,evidence,started_at,completed_at,created_at,updated_at
           FROM rmm_software_qualification_queue
          WHERE catalogue_id=$1 ORDER BY test_type`,
        [catalogueId],
      ),
      pool.query(
        `SELECT id,job_type,status,error_message,request_metadata,result,created_at,claimed_at,completed_at
           FROM rmm_agent_jobs
          WHERE request_metadata->>'catalogue_id'=$1
             OR request_metadata->>'catalogueId'=$1
          ORDER BY created_at DESC LIMIT 40`,
        [catalogueId],
      ),
    ])
    return c.json({ software: software.rows[0], queues: queues.rows, jobs: jobs.rows })
  })

  app.patch('/api/platform/v1/software/catalogue/:catalogueId', async (c) => {
    const auth = await requireAdmin(c, CATALOGUE_ROLES)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const catalogueId = clean(c.req.param('catalogueId'), 80)
    const currentResult = await pool.query(
      `SELECT * FROM rmm_software_catalogue WHERE id=$1 AND tenant_id IS NULL LIMIT 1`,
      [catalogueId],
    )
    const current = currentResult.rows[0]
    if (!current) return c.json({ error: 'Software catalogue entry not found.' }, 404)
    const active = await pool.query(
      `SELECT id,state FROM rmm_software_qualification_queue
        WHERE catalogue_id=$1 AND state IN ('running','cleanup_pending','cleanup_running') LIMIT 1`,
      [catalogueId],
    )
    const touchesValidation = ['canonicalName','publisher','installArguments','installerTechnology','expectedSigner','verification']
      .some((key) => Object.hasOwn(body || {}, key))
    if (touchesValidation && active.rowCount) {
      return c.json({ error: 'Finish or safely cancel the active qualification before editing validation settings.', state: active.rows[0].state }, 409)
    }
    const canonicalName = Object.hasOwn(body,'canonicalName') ? clean(body.canonicalName, 180) : current.canonical_name
    const publisher = Object.hasOwn(body,'publisher') ? clean(body.publisher, 180) : current.publisher
    const status = Object.hasOwn(body,'status') && ['active','disabled','archived'].includes(clean(body.status))
      ? clean(body.status) : current.status
    if (!canonicalName) return c.json({ error: 'Canonical name is required.' }, 400)
    const execution = { ...(current.execution || {}) }
    const verification = { ...(current.verification || {}) }
    const sourceMetadata = { ...(current.source_metadata || {}) }
    if (Object.hasOwn(body,'installArguments')) execution.installArguments = clean(body.installArguments, 4000)
    if (body.verification && typeof body.verification === 'object') Object.assign(verification, body.verification)
    if (Object.hasOwn(body,'installerTechnology')) sourceMetadata.installerTechnology = clean(body.installerTechnology, 80)
    if (Object.hasOwn(body,'expectedSigner')) sourceMetadata.expectedSigner = clean(body.expectedSigner, 500)
    if (Object.hasOwn(body,'deploymentLimitation')) sourceMetadata.deploymentLimitation = clean(body.deploymentLimitation, 160)
    const qualificationNotes = Object.hasOwn(body,'qualificationNotes')
      ? clean(body.qualificationNotes, 4000) : current.qualification_notes
    const latestSource = clean(sourceMetadata.latestSource)
    await withTransaction(async (db) => {
      await db.query(
        `UPDATE rmm_software_catalogue
            SET canonical_name=$2,publisher=$3,status=$4,execution=$5::jsonb,verification=$6::jsonb,
                source_metadata=$7::jsonb,qualification_notes=$8,updated_by_user_id=$9,
                qualification_state=CASE WHEN $10::boolean AND qualification_state<>'blocked' THEN 'deployment_candidate' ELSE qualification_state END,
                qualification_version=CASE WHEN $10::boolean THEN '' ELSE qualification_version END,
                qualified_at=CASE WHEN $10::boolean THEN NULL ELSE qualified_at END,
                qualification_evidence=CASE WHEN $10::boolean THEN
                  qualification_evidence
                    - 'cleanInstallVerified' - 'cleanInstallVersion' - 'cleanInstallVerifiedAt'
                    - 'uninstallVerified' - 'uninstallVerifiedAt'
                    - 'automaticAdmissionVerified' - 'automaticAdmissionState'
                  ELSE qualification_evidence END,
                updated_at=now()
          WHERE id=$1`,
        [catalogueId, canonicalName, publisher, status, JSON.stringify(execution), JSON.stringify(verification),
          JSON.stringify(sourceMetadata), qualificationNotes, auth.session.user_id, touchesValidation],
      )
      if (latestSource) {
        const bindingPatch = {
          ...(Object.hasOwn(body,'installArguments') ? { installArguments: execution.installArguments, manualExecutionOverride: true, manualExecutionOverrideAt: new Date().toISOString() } : {}),
          ...(Object.hasOwn(body,'installerTechnology') ? { installerTechnology: sourceMetadata.installerTechnology } : {}),
          ...(Object.hasOwn(body,'expectedSigner') ? { expectedSigner: sourceMetadata.expectedSigner } : {}),
          ...(body.verification ? { verificationConfig: verification } : {}),
        }
        if (Object.keys(bindingPatch).length) {
          await db.query(
            `UPDATE rmm_software_vendor_bindings
                SET metadata=metadata || $3::jsonb
              WHERE source_key=$1 AND provider_package_id=$2 AND enabled=true`,
            [latestSource, current.external_key, JSON.stringify(bindingPatch)],
          )
          await db.query(
            `UPDATE rmm_software_vendor_releases
                SET source_payload=source_payload || $3::jsonb,
                    trust_state=CASE WHEN $4::boolean THEN 'asset_candidate' ELSE trust_state END
              WHERE source_key=$1 AND provider_package_id=$2 AND version=$5`,
            [latestSource, current.external_key, JSON.stringify({
              ...(Object.hasOwn(body,'installerTechnology') ? { installerTechnology: sourceMetadata.installerTechnology } : {}),
              ...(Object.hasOwn(body,'installArguments') ? { installArguments: execution.installArguments } : {}),
              ...(Object.hasOwn(body,'expectedSigner') ? { expectedSigner: sourceMetadata.expectedSigner } : {}),
              ...(body.verification ? { verification } : {}),
            }), Object.hasOwn(body,'expectedSigner'), current.target_version],
          )
        }
      }
      if (touchesValidation) {
        await db.query(
          `UPDATE rmm_software_qualification_queue
              SET state='cancelled',last_error='admin_software_edit',completed_at=now(),updated_at=now()
            WHERE catalogue_id=$1 AND state NOT IN ('running','cleanup_pending','cleanup_running')`,
          [catalogueId],
        )
      }
      await audit(c, auth.session, 'software.updated', 'software_catalogue', catalogueId, {
        fields: Object.keys(body || {}),
        qualificationReset: touchesValidation,
      }, db)
    })
    return c.json({ ok: true, qualificationReset: touchesValidation })
  })

  app.post('/api/platform/v1/software/catalogue/:catalogueId/requeue', async (c) => {
    const auth = await requireAdmin(c, CATALOGUE_ROLES)
    if (auth.error) return auth.error
    const catalogueId = clean(c.req.param('catalogueId'), 80)
    let body = {}
    try { body = await c.req.json() } catch {}
    const result = await retrySoftwareQualification(catalogueId, { mode: 'clean_only' })
    if (!result.queued) return c.json({ error: result.reason || 'Software could not be requeued.', result }, 409)
    if (body.runNow !== false) {
      await prioritiseSoftwareQualificationQueue(result.queue?.id, { priority: body.priority || 50000 })
      result.dispatch = await runSoftwareQualificationQueue({ dispatchLimit: 1 })
    }
    await audit(c, auth.session, 'software.requeued', 'software_catalogue', catalogueId, { result })
    return c.json({ ok: true, result })
  })

  app.post('/api/platform/v1/software/catalogue/:catalogueId/revalidate', async (c) => {
    const auth = await requireAdmin(c, CATALOGUE_ROLES)
    if (auth.error) return auth.error
    const catalogueId = clean(c.req.param('catalogueId'), 80)
    const current = await pool.query(
      `SELECT source_metadata->>'latestSource' AS source_key,canonical_name
         FROM rmm_software_catalogue WHERE id=$1 AND tenant_id IS NULL LIMIT 1`,
      [catalogueId],
    )
    if (!current.rowCount) return c.json({ error: 'Software catalogue entry not found.' }, 404)
    const sourceKey = clean(current.rows[0].source_key)
    if (!sourceKey) return c.json({ error: 'This software has no vendor source to revalidate.' }, 409)
    const result = await syncSoftwareVendorSource(sourceKey)
    await audit(c, auth.session, 'software.source_revalidated', 'software_catalogue', catalogueId, { sourceKey, result })
    return c.json({ ok: true, result })
  })

  app.post('/api/platform/v1/software/catalogue/:catalogueId/classify', async (c) => {
    const auth = await requireAdmin(c, CATALOGUE_ROLES)
    if (auth.error) return auth.error
    let body = {}
    try { body = await c.req.json() } catch {}
    const catalogueId = clean(c.req.param('catalogueId'), 80)
    const allowed = new Set([
      '', 'user_scope_only', 'vendor_install_failure', 'vendor_install_rollback',
      'response_file_required', 'reboot_prerequisite', 'vendor_silent_uninstall_unsupported',
      'interactive_setup_required', 'source_unavailable', 'architecture_unsupported', 'other',
    ])
    const classification = clean(body.classification, 160)
    if (!allowed.has(classification)) return c.json({ error: 'Unsupported limitation classification.' }, 400)
    const notes = clean(body.notes, 4000)
    const result = await pool.query(
      `UPDATE rmm_software_catalogue
          SET source_metadata=(source_metadata - 'deploymentLimitation') || CASE
                WHEN $2='' THEN '{}'::jsonb
                ELSE jsonb_build_object('deploymentLimitation',$2::text,'deploymentLimitationUpdatedAt',now())
              END,
              qualification_notes=CASE WHEN $3<>'' THEN $3 ELSE qualification_notes END,
              updated_by_user_id=$4,updated_at=now()
        WHERE id=$1 AND tenant_id IS NULL
        RETURNING id,canonical_name,qualification_state,qualification_notes,
                  source_metadata->>'deploymentLimitation' AS deployment_limitation`,
      [catalogueId, classification, notes, auth.session.user_id],
    )
    if (!result.rowCount) return c.json({ error: 'Software catalogue entry not found.' }, 404)
    await audit(c, auth.session, 'software.classified', 'software_catalogue', catalogueId, {
      classification, notes,
    })
    return c.json({ ok: true, software: result.rows[0] })
  })

  app.get('/api/platform/v1/audit', async (c) => {
    const auth = await requireAdmin(c, new Set(['owner','admin','read_only']))
    if (auth.error) return auth.error
    const result = await pool.query(
      `SELECT a.id,a.action,a.target_type,a.target_id,a.metadata,a.created_at,u.name AS actor_name
         FROM platform_admin_audit_events a LEFT JOIN users u ON u.id=a.actor_user_id
        ORDER BY a.created_at DESC LIMIT 200`,
    )
    return c.json({ items: result.rows })
  })
}
