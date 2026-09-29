import { createHash, randomBytes } from 'node:crypto'
import { attachAccess, effectiveAccessForUser, ensureDefaultRoles, hasPermission } from './access.js'
import { pool, withTransaction } from './db.js'
import { sendPortalActivationEmail } from './mailer.js'
import { hashPassword, passwordPolicyResult, verifyPassword } from './password.js'
import { registerPortalRequestViewRoutes } from './portalRequestViews.js'
import { hasAssignedPortalApproval, portalApprovalCapabilities, registerPortalApprovalRoutes } from './portalApprovals.js'
import { ensureRedisConnected } from './redis.js'
import { recordSecurityEvent, requestIp, requestUserAgent } from './securityAudit.js'
import { securitySettings, sessionTtlSeconds } from './securityPolicy.js'
import { originMatchesPortalTenant } from './deploymentConfig.js'
import {
  createSession,
  resolveSession,
  revokeCurrentSession,
  sessionPayload,
  setPortalSessionCookie,
} from './session.js'

function normaliseEmail(value = '') { return String(value).trim().toLowerCase() }
function normaliseSlug(value = '') { return String(value).trim().toLowerCase() }
function validSlug(slug) { return /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/.test(slug) && !slug.includes('--') }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254 }
function hashToken(value) { return createHash('sha256').update(String(value || '')).digest('hex') }

function portalOrigin(c, slug) {
  return originMatchesPortalTenant(c.req.header('origin'), c.req.header('referer'), slug)
}

async function rateLimit(key, max, seconds) {
  const redis = await ensureRedisConnected()
  const count = await redis.incr(key)
  if (count === 1) await redis.expire(key, seconds)
  return count <= max
}

async function portalAccount(tenantSlug, email) {
  const result = await pool.query(
    `SELECT t.id AS tenant_id,t.slug,t.company_name,t.status AS tenant_status,
            u.id AS user_id,u.email,u.name,u.password_hash,
            m.role AS tenant_role,m.status AS membership_status,
            ts.modules,ts.onboarding_step,ts.onboarding_completed_at,ts.onboarding_data,ts.configuration,
            ts.tenant_url,ts.portal_url,ts.rmm_url
     FROM tenants t
     JOIN tenant_memberships m ON m.tenant_id=t.id
     JOIN users u ON u.id=m.user_id
     JOIN tenant_settings ts ON ts.tenant_id=t.id
     WHERE t.slug=$1 AND u.email=$2
     LIMIT 1`,
    [tenantSlug, email],
  )
  return result.rows[0] || null
}

async function requesterPerson(tenantSlug, email) {
  const result = await pool.query(
    `SELECT t.id AS tenant_id,t.slug,t.company_name,t.status AS tenant_status,
            ts.portal_url,ts.onboarding_completed_at,ts.configuration,ts.onboarding_data,
            p.id AS person_id,p.external_key,p.user_id,p.name,p.email,p.active,p.access_profile
     FROM tenants t
     JOIN tenant_settings ts ON ts.tenant_id=t.id
     JOIN organisation_people p ON p.tenant_id=t.id
     WHERE t.slug=$1 AND lower(p.email)=$2 AND p.active=true
     LIMIT 1`,
    [tenantSlug, email],
  )
  return result.rows[0] || null
}

function portalSessionPayload(session, capabilities = { requests: true, approvals: false }) {
  const payload = sessionPayload(session)
  return { ...payload, portal: true, portalCapabilities: capabilities, user: { ...payload.user, role: 'requester' } }
}

async function requirePortalSession(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!portalOrigin(c, session.slug)) return { error: c.json({ error: 'Portal session mismatch.' }, 403) }
  if (!session.onboarding_completed_at) return { error: c.json({ error: 'This tenant has not completed setup.' }, 403) }
  const capabilities = await portalApprovalCapabilities(session)
  if (!capabilities.requests && !capabilities.approvals) return { error: c.json({ error: 'Requester Portal or approval access is required.' }, 403) }
  return { session, capabilities }
}

export function registerPortalAuthRoutes(app) {
  registerPortalRequestViewRoutes(app)
  registerPortalApprovalRoutes(app)

  app.get('/api/v1/portal/auth/session', async (c) => {
    const auth = await requirePortalSession(c)
    if (auth.error) return auth.error
    return c.json(portalSessionPayload(auth.session, auth.capabilities))
  })

  app.post('/api/v1/portal/auth/login', async (c) => {
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const tenantSlug = normaliseSlug(body?.tenantSlug)
    const email = normaliseEmail(body?.email)
    const password = String(body?.password || '')
    if (!validSlug(tenantSlug) || !validEmail(email) || !password) return c.json({ error: 'Enter a valid email address and password.' }, 400)
    if (!portalOrigin(c, tenantSlug)) return c.json({ error: 'Portal sign-in origin mismatch.' }, 403)

    const allowed = await rateLimit(`portal-login:${requestIp(c)}:${tenantSlug}:${email}`, 10, 900)
    if (!allowed) return c.json({ error: 'Too many sign-in attempts. Please try again later.' }, 429)

    const account = await portalAccount(tenantSlug, email)
    if (!account || account.tenant_status !== 'active' || account.membership_status !== 'active' || !account.onboarding_completed_at) {
      return c.json({ error: 'Email address or password is incorrect.' }, 401)
    }
    if (!await verifyPassword(password, account.password_hash)) {
      await recordSecurityEvent({ tenantId: account.tenant_id, actorUserId: account.user_id, eventType: 'portal.login', outcome: 'failure', ipAddress: requestIp(c), userAgent: requestUserAgent(c) })
      return c.json({ error: 'Email address or password is incorrect.' }, 401)
    }

    const access = await effectiveAccessForUser(pool, account.tenant_id, account.user_id, account.tenant_role)
    const assignedApprovalAccess = await hasAssignedPortalApproval(pool, account.tenant_id, account.user_id)
    if (!access.portalAccess && !assignedApprovalAccess) {
      await recordSecurityEvent({
        tenantId: account.tenant_id,
        actorUserId: account.user_id,
        eventType: 'portal.login',
        outcome: 'failure',
        ipAddress: requestIp(c),
        userAgent: requestUserAgent(c),
        metadata: { reason: 'portal_access_denied' },
      })
      return c.json({
        error: 'This account does not have access to the requester portal and has no approvals assigned to it.',
      }, 403)
    }
    const resolvedAccount = attachAccess(account, access, 'portal')
    const capabilities = {
      requests: access.portalAccess,
      approvals: hasPermission(access, 'portal.approvals.view') || assignedApprovalAccess,
    }

    const token = await withTransaction(async (client) => {
      const sessionToken = await createSession(client, { tenantId: account.tenant_id, userId: account.user_id, surface: 'portal' })
      await client.query(
        `UPDATE auth_sessions SET ip_address=$2,user_agent=$3 WHERE token_hash=$1`,
        [hashToken(sessionToken), requestIp(c), requestUserAgent(c)],
      )
      await recordSecurityEvent({ db: client, tenantId: account.tenant_id, actorUserId: account.user_id, eventType: 'portal.login', outcome: 'success', ipAddress: requestIp(c), userAgent: requestUserAgent(c) })
      return sessionToken
    })

    setPortalSessionCookie(c, token, sessionTtlSeconds(account))
    return c.json(portalSessionPayload(resolvedAccount, capabilities))
  })

  app.post('/api/v1/portal/auth/logout', async (c) => {
    const session = await resolveSession(c)
    if (session && hasPermission(session.access, 'portal.access')) {
      await recordSecurityEvent({ tenantId: session.tenant_id, actorUserId: session.user_id, sessionId: session.session_id, eventType: 'portal.logout', ipAddress: requestIp(c), userAgent: requestUserAgent(c) })
    }
    await revokeCurrentSession(c)
    return c.json({ signedOut: true })
  })

  app.post('/api/v1/portal/auth/activate/request', async (c) => {
    let body
    try { body = await c.req.json() } catch { body = {} }
    const tenantSlug = normaliseSlug(body?.tenantSlug)
    const email = normaliseEmail(body?.email)
    const generic = { status: 'accepted', message: 'If your organisation has enabled Portal access for that email, an activation email has been sent.' }
    if (!validSlug(tenantSlug) || !validEmail(email) || !portalOrigin(c, tenantSlug)) return c.json(generic)

    const allowed = await rateLimit(`portal-activate:${requestIp(c)}:${tenantSlug}:${email}`, 5, 900)
    if (!allowed) return c.json(generic)
    const person = await requesterPerson(tenantSlug, email)
    if (!person || person.tenant_status !== 'active' || !person.onboarding_completed_at || !person.portal_url) return c.json(generic)

    if (person.user_id) {
      const linked = await pool.query('SELECT role,status FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2 LIMIT 1', [person.tenant_id, person.user_id])
      if (linked.rowCount && linked.rows[0].status === 'active') {
        const access = await effectiveAccessForUser(pool, person.tenant_id, person.user_id, linked.rows[0].role)
        if (access.portalAccess) return c.json(generic)
      }
    }

    const token = randomBytes(32).toString('base64url')
    await withTransaction(async (client) => {
      await client.query('UPDATE portal_access_tokens SET used_at=COALESCE(used_at,now()) WHERE tenant_id=$1 AND person_id=$2 AND used_at IS NULL', [person.tenant_id, person.person_id])
      await client.query('INSERT INTO portal_access_tokens (tenant_id,person_id,email,token_hash,expires_at) VALUES ($1,$2,$3,$4,now()+interval \'60 minutes\')', [person.tenant_id, person.person_id, email, hashToken(token)])
    })

    try {
      await sendPortalActivationEmail({ to: email, name: person.name, companyName: person.company_name, token, portalUrl: person.portal_url })
    } catch (error) {
      console.error('Portal activation email delivery failed', error)
    }

    if (process.env.NODE_ENV !== 'production') return c.json({ ...generic, activationToken: token, activationUrl: `${person.portal_url}/activate?token=${encodeURIComponent(token)}` })
    return c.json(generic)
  })

  app.post('/api/v1/portal/auth/activate/complete', async (c) => {
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const tenantSlug = normaliseSlug(body?.tenantSlug)
    const token = String(body?.token || '')
    const password = String(body?.password || '')
    if (!validSlug(tenantSlug) || token.length < 20 || !portalOrigin(c, tenantSlug)) return c.json({ error: 'This activation link is invalid or has expired.' }, 400)

    try {
      const result = await withTransaction(async (client) => {
        const tokenResult = await client.query(
          `SELECT pat.id AS token_id,pat.tenant_id,pat.person_id,pat.email,
                  t.slug,t.company_name,t.status AS tenant_status,
                  ts.onboarding_completed_at,ts.configuration,ts.onboarding_data,
                  p.name,p.user_id
           FROM portal_access_tokens pat
           JOIN tenants t ON t.id=pat.tenant_id
           JOIN tenant_settings ts ON ts.tenant_id=pat.tenant_id
           JOIN organisation_people p ON p.id=pat.person_id AND p.tenant_id=pat.tenant_id
           WHERE pat.token_hash=$1 AND pat.used_at IS NULL AND pat.expires_at>now() AND t.slug=$2 AND p.active=true
           LIMIT 1 FOR UPDATE OF pat`,
          [hashToken(token), tenantSlug],
        )
        if (!tokenResult.rowCount) { const error = new Error('This activation link is invalid or has expired.'); error.status = 400; throw error }
        const activation = tokenResult.rows[0]
        if (activation.tenant_status !== 'active' || !activation.onboarding_completed_at) { const error = new Error('This Help Centre is not available yet.'); error.status = 409; throw error }

        const policy = securitySettings(activation).passwordPolicy
        const passwordCheck = passwordPolicyResult(password, policy)
        if (!passwordCheck.ok) { const error = new Error(passwordCheck.message); error.status = 400; error.policy = policy; throw error }

        let userId = activation.user_id
        let existingAccount = false
        if (!userId) {
          const existing = await client.query('SELECT id FROM users WHERE email=$1 LIMIT 1', [activation.email])
          if (existing.rowCount) { userId = existing.rows[0].id; existingAccount = true }
          else {
            const passwordHash = await hashPassword(password)
            const user = await client.query('INSERT INTO users (email,name,password_hash,email_verified_at) VALUES ($1,$2,$3,now()) RETURNING id', [activation.email, activation.name, passwordHash])
            userId = user.rows[0].id
          }
        }

        const membership = await client.query('SELECT role,status FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2 LIMIT 1', [activation.tenant_id, userId])
        if (!membership.rowCount) {
          await client.query("INSERT INTO tenant_memberships (tenant_id,user_id,role,status) VALUES ($1,$2,'requester','active')", [activation.tenant_id, userId])
        } else {
          await client.query("UPDATE tenant_memberships SET status='active' WHERE tenant_id=$1 AND user_id=$2", [activation.tenant_id, userId])
        }

        await ensureDefaultRoles(client, activation.tenant_id)
        await client.query(
          `INSERT INTO access_user_roles (tenant_id,user_id,role_id)
           SELECT $1,$2,id FROM access_roles WHERE tenant_id=$1 AND system_key='requester' AND active=true
           ON CONFLICT DO NOTHING`,
          [activation.tenant_id, userId],
        )

        await client.query('UPDATE organisation_people SET user_id=$2,updated_at=now() WHERE id=$1 AND tenant_id=$3', [activation.person_id, userId, activation.tenant_id])
        await client.query('UPDATE portal_access_tokens SET used_at=now() WHERE id=$1', [activation.token_id])
        await recordSecurityEvent({ db: client, tenantId: activation.tenant_id, actorUserId: userId, eventType: 'portal.activated', ipAddress: requestIp(c), userAgent: requestUserAgent(c), metadata: { personId: activation.person_id, existingAccount } })
        return { activated: true, existingAccount, email: activation.email }
      })
      return c.json(result)
    } catch (error) {
      if (error?.status) return c.json({ error: error.message, ...(error.policy ? { policy: error.policy } : {}) }, error.status)
      throw error
    }
  })
}
