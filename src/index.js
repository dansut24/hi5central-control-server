import { createHash, randomBytes, scrypt } from 'node:crypto'
import { promisify } from 'node:util'
import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { secureHeaders } from 'hono/secure-headers'
import { attachAccess, effectiveAccessForUser } from './access.js'
import { enforceWorkspacePermissions } from './accessGate.js'
import { registerCatalogueRoutes } from './catalogue.js'
import { registerLicensingRoutes } from './licensing.js'
import { registerMicrosoftRoutes, startMicrosoftSyncScheduler } from './microsoftIntegration.js'
import { attachRmmAgentWebSocket, registerRmmAgentRoutes } from './rmmAgent.js'
import { registerRmmAutomationRoutes } from './rmmAutomation.js'
import { registerRmmActivityRoutes } from './rmmActivity.js'
import { attachRmmDeviceToolWebSocket, registerRmmDeviceToolRoutes } from './rmmDeviceTools.js'
import { attachRmmViewerWebSocket, registerRmmRemoteRoutes } from './rmmRemote.js'
import { attachRmmConnectWebSockets, registerRmmConnectRoutes } from './rmmConnect.js'
import { registerRmmScopeRoutes } from './rmmScope.js'
import { registerRmmPatchingRoutes } from './rmmPatching.js'
import { registerRmmAppPortalRoutes } from './rmmAppPortal.js'
import { registerRmmNetworkDiscoveryRoutes, startRmmNetworkDiscoveryScheduler } from './rmmNetworkDiscovery.js'
import { startRmmMacOuiScheduler } from './rmmMacOui.js'
import { registerRmmRecoveryKeyRoutes } from './rmmRecoveryKeys.js'
import { startRmmVulnerabilitySyncScheduler } from './rmmVulnerabilityIntel.js'
import { startSoftwareVendorSyncScheduler } from './rmmSoftwareVendorIntel.js'
import { startTenantVendorSourceScheduler } from './rmmTenantVendorSources.js'
import {
  allowedRequestOrigin,
  deployment,
  originMatchesTenant,
  tenantUrls,
} from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { sendVerificationEmail, verifySmtpConnection } from './mailer.js'
import { registerOrganisationRoutes } from './organisation.js'
import { registerPlatformAdminRoutes } from './platformAdmin.js'
import { verifyPassword } from './password.js'
import { ensureRedisConnected, redis } from './redis.js'
import { registerSettingsRoutes } from './settings.js'
import {
  createSession,
  resolveSession,
  revokeCurrentSession,
  sessionPayload,
  setSessionCookie,
} from './session.js'

const scryptAsync = promisify(scrypt)
const app = new Hono()
const port = Number(process.env.PORT || 3001)
const marketingUrl = deployment.marketingUrl || deployment.appUrl || `https://${deployment.rootDomain}`

const reservedSlugs = new Set([
  'admin', 'api', 'app', 'auth', 'connect', 'downloads', 'help', 'login', 'mail', 'portal',
  'reseller', 'rmm', 'signup', 'smtp', 'status', 'support', 'turn', 'www',
])

function normaliseEmail(value = '') { return String(value).trim().toLowerCase() }
function normaliseSlug(value = '') { return String(value).trim().toLowerCase() }
function validSlug(slug) {
  return /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/.test(slug)
    && !slug.includes('--') && !slug.endsWith('-portal') && !slug.endsWith('-rmm') && !reservedSlugs.has(slug)
}
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254 }

async function hashPassword(password) {
  const salt = randomBytes(16)
  const derived = await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })
  return `scrypt$16384$8$1$${salt.toString('base64url')}$${Buffer.from(derived).toString('base64url')}`
}
function hashToken(token) { return createHash('sha256').update(token).digest('hex') }
function requestIp(c) {
  const forwarded = c.req.header('x-forwarded-for')
  if (forwarded) return forwarded.split(',')[0].trim()
  return c.req.header('x-real-ip') || 'unknown'
}
function allowedOrigin(origin) { return allowedRequestOrigin(origin) }
function originMatchesSession(c, session) { return originMatchesTenant(c.req.header('origin'), session.slug) }
function onboardingSequence(modules = {}) {
  return ['company','theme','users','groups','permissions','security',modules?.itsm ? 'itsm' : null,modules?.rmm ? 'rmm' : null,'billing','finish'].filter(Boolean)
}
async function rateLimit(redisClient, key, max, seconds) {
  const attempts = await redisClient.incr(key)
  if (attempts === 1) await redisClient.expire(key, seconds)
  return attempts <= max
}

async function recordVerificationDelivery(tokenHash, result) {
  if (result.ok) {
    await pool.query('UPDATE user_email_verifications SET sent_at=now(),send_attempts=send_attempts+1,last_send_error=NULL WHERE token_hash=$1', [tokenHash])
    return
  }
  await pool.query(
    'UPDATE user_email_verifications SET send_attempts=send_attempts+1,last_send_error=$2 WHERE token_hash=$1',
    [tokenHash, String(result.error?.message || result.error || 'Unknown SMTP error').slice(0, 1000)],
  )
}

async function deliverVerification({ token, email, name, companyName, tenantUrl }) {
  const tokenHash = hashToken(token)
  try {
    const info = await sendVerificationEmail({ to: email, name, companyName, token, tenantUrl })
    await recordVerificationDelivery(tokenHash, { ok: true })
    return { status: 'sent', messageId: info?.messageId || null }
  } catch (error) {
    console.error('Verification email delivery failed', error)
    await recordVerificationDelivery(tokenHash, { ok: false, error })
    return { status: 'failed' }
  }
}

app.use('*', secureHeaders())
app.use('/api/*', cors({
  origin: allowedOrigin,
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Hi5-Filename'],
  credentials: true,
  maxAge: 600,
}))
app.use('/api/v1/*', enforceWorkspacePermissions)

app.get('/live', (c) => c.json({ status: 'ok', service: 'hi5central-api' }))
app.get('/health', async (c) => {
  try {
    await pool.query('SELECT 1')
    const redisClient = await ensureRedisConnected()
    await redisClient.ping()
    return c.json({ status: 'ok', postgres: 'ok', redis: 'ok' })
  } catch (error) {
    console.error('Health check failed', error)
    return c.json({ status: 'error' }, 503)
  }
})

app.get('/api/v1/system/deployment', (c) => c.json({
  deploymentMode: deployment.deploymentMode,
  tenancyMode: deployment.tenancyMode,
  rootDomain: deployment.rootDomain,
  primaryTenantSlug: deployment.primaryTenantSlug,
  appUrl: deployment.appUrl,
  apiUrl: deployment.apiUrl,
  portalUrl: deployment.portalUrl,
  rmmUrl: deployment.rmmUrl,
}))

app.get('/api/v1/system/smtp-health', async (c) => {
  try {
    await verifySmtpConnection()
    return c.json({ status: 'ok', smtp: 'ok' })
  } catch (error) {
    console.error('SMTP health check failed', error)
    return c.json({ status: 'error', smtp: 'error' }, 503)
  }
})

app.get('/api/v1/auth/tenant-slug/:slug', async (c) => {
  const slug = normaliseSlug(c.req.param('slug'))
  if (!validSlug(slug)) return c.json({ slug, available: false, reason: 'invalid' }, 200)
  if (deployment.tenancyMode === 'single' && slug !== deployment.primaryTenantSlug) return c.json({ slug, available: false, reason: 'single_tenant' }, 200)
  const result = await pool.query('SELECT 1 FROM tenants WHERE slug=$1 LIMIT 1', [slug])
  return c.json({ slug, available: result.rowCount === 0 })
})

app.get('/api/v1/auth/tenant-state/:slug', async (c) => {
  const slug = normaliseSlug(c.req.param('slug'))
  if (!validSlug(slug)) return c.json({ managed: false, slug }, 200)
  const result = await pool.query('SELECT t.slug,t.company_name,t.status FROM tenants t WHERE t.slug=$1 LIMIT 1', [slug])
  if (!result.rowCount) return c.json({ managed: false, slug })
  const tenant = result.rows[0]
  return c.json({ managed: true, slug: tenant.slug, companyName: tenant.company_name, status: tenant.status })
})

app.post('/api/v1/auth/login', async (c) => {
  let body
  try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
  const tenantSlug = normaliseSlug(body?.tenantSlug || (deployment.tenancyMode === 'single' ? deployment.primaryTenantSlug : ''))
  const email = normaliseEmail(body?.email)
  const password = String(body?.password || '')
  if (!validSlug(tenantSlug) || !validEmail(email) || !password) return c.json({ error: 'Enter a valid email address and password.' }, 400)

  const origin = c.req.header('origin')
  if (process.env.NODE_ENV === 'production' && origin && !originMatchesTenant(origin, tenantSlug)) return c.json({ error: 'Tenant sign-in origin mismatch.' }, 403)
  const redisClient = await ensureRedisConnected()
  const allowed = await rateLimit(redisClient, `login:${requestIp(c)}:${tenantSlug}:${email}`, 10, 900)
  if (!allowed) return c.json({ error: 'Too many sign-in attempts. Please try again later.' }, 429)

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
     WHERE t.slug=$1 AND u.email=$2 LIMIT 1`,
    [tenantSlug, email],
  )
  if (!result.rowCount) return c.json({ error: 'Email address or password is incorrect.' }, 401)
  const account = result.rows[0]
  if (account.tenant_status === 'pending_verification' || account.membership_status === 'pending_verification') return c.json({ error: 'Verify your email address before signing in.' }, 403)
  if (account.tenant_status !== 'active' || account.membership_status !== 'active') return c.json({ error: 'This Hi5Central account is not currently active.' }, 403)
  const valid = await verifyPassword(password, account.password_hash)
  if (!valid) return c.json({ error: 'Email address or password is incorrect.' }, 401)

  const access = await effectiveAccessForUser(pool, account.tenant_id, account.user_id, account.tenant_role)
  if (!access.workspaceAccess) return c.json({ error: 'Your Hi5Central roles do not include access to this workspace. Use the requester portal instead.' }, 403)
  const resolvedAccount = attachAccess(account, access, 'workspace')
  const token = await withTransaction((client) => createSession(client, { tenantId: account.tenant_id, userId: account.user_id, surface: 'workspace' }))
  setSessionCookie(c, token)
  return c.json(sessionPayload(resolvedAccount))
})

app.post('/api/v1/auth/signup', async (c) => {
  const redisClient = await ensureRedisConnected()
  const allowed = await rateLimit(redisClient, `signup:${requestIp(c)}:${Math.floor(Date.now() / 60000)}`, 5, 60)
  if (!allowed) return c.json({ error: 'Too many signup attempts. Please try again shortly.' }, 429)
  let body
  try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }

  const companyName = String(body?.companyName || '').trim()
  const tenantSlug = normaliseSlug(body?.tenantSlug || (deployment.tenancyMode === 'single' ? deployment.primaryTenantSlug : ''))
  const name = String(body?.name || '').trim()
  const email = normaliseEmail(body?.email)
  const password = String(body?.password || '')
  const requestedModules = Array.isArray(body?.modules) ? body.modules.map(String) : ['itsm']
  const modules = [...new Set(requestedModules.filter((item) => ['itsm','rmm'].includes(item)))]
  if (companyName.length < 2 || companyName.length > 120) return c.json({ error: 'Company name must be between 2 and 120 characters.' }, 400)
  if (!validSlug(tenantSlug)) return c.json({ error: 'Choose a valid tenant URL using 3-48 lowercase letters, numbers or hyphens.' }, 400)
  if (deployment.tenancyMode === 'single' && tenantSlug !== deployment.primaryTenantSlug) return c.json({ error: `This installation is assigned to tenant ${deployment.primaryTenantSlug}.`, field: 'tenantSlug' }, 400)
  if (name.length < 2 || name.length > 120) return c.json({ error: 'Your name must be between 2 and 120 characters.' }, 400)
  if (!validEmail(email)) return c.json({ error: 'Enter a valid email address.' }, 400)
  if (password.length < 12 || password.length > 256) return c.json({ error: 'Use a password or passphrase of at least 12 characters.' }, 400)
  if (!modules.length) return c.json({ error: 'Select at least one Hi5Central product.' }, 400)

  const [slugExists, emailExists, tenantCount] = await Promise.all([
    pool.query('SELECT 1 FROM tenants WHERE slug=$1 LIMIT 1', [tenantSlug]),
    pool.query('SELECT 1 FROM users WHERE email=$1 LIMIT 1', [email]),
    deployment.tenancyMode === 'single' ? pool.query('SELECT count(*)::int AS count FROM tenants') : Promise.resolve({ rows: [{ count: 0 }] }),
  ])
  if (deployment.tenancyMode === 'single' && Number(tenantCount.rows[0]?.count || 0) > 0) return c.json({ error: 'This single-tenant installation has already been initialised.' }, 409)
  if (slugExists.rowCount) return c.json({ error: 'That tenant URL is already in use.', field: 'tenantSlug' }, 409)
  if (emailExists.rowCount) return c.json({ error: 'An account already exists for that email address.', field: 'email' }, 409)

  const passwordHash = await hashPassword(password)
  const verificationToken = randomBytes(32).toString('base64url')
  const verificationTokenHash = hashToken(verificationToken)
  const generatedUrls = tenantUrls(tenantSlug, { rmm: modules.includes('rmm') })
  const { tenantUrl, portalUrl, rmmUrl } = generatedUrls

  try {
    const result = await withTransaction(async (client) => {
      const tenantResult = await client.query('INSERT INTO tenants (slug,company_name) VALUES ($1,$2) RETURNING id,slug,company_name,status', [tenantSlug, companyName])
      const tenant = tenantResult.rows[0]
      const userResult = await client.query('INSERT INTO users (email,name,password_hash) VALUES ($1,$2,$3) RETURNING id,email,name', [email, name, passwordHash])
      const user = userResult.rows[0]
      await client.query("INSERT INTO tenant_memberships (tenant_id,user_id,role) VALUES ($1,$2,'owner')", [tenant.id, user.id])
      await client.query(
        `INSERT INTO tenant_settings (tenant_id,modules,onboarding_step,tenant_url,portal_url,rmm_url)
         VALUES ($1,$2::jsonb,'verify_email',$3,$4,$5)`,
        [tenant.id, JSON.stringify({ itsm: modules.includes('itsm'), rmm: modules.includes('rmm') }), tenantUrl, portalUrl, rmmUrl],
      )
      await client.query(
        `INSERT INTO user_email_verifications (tenant_id,user_id,token_hash,redirect_url,expires_at)
         VALUES ($1,$2,$3,$4,now()+interval '24 hours')`,
        [tenant.id, user.id, verificationTokenHash, tenantUrl],
      )
      return { tenant, user }
    })

    const delivery = await deliverVerification({ token: verificationToken, email: result.user.email, name: result.user.name, companyName: result.tenant.company_name, tenantUrl })
    return c.json({
      status: 'pending_verification', verificationRequired: true, verificationDelivery: delivery.status, onboardingStep: 'verify_email',
      tenant: { slug: result.tenant.slug, companyName: result.tenant.company_name, tenantUrl, portalUrl, rmmUrl },
      admin: { name: result.user.name, email: result.user.email },
    }, 201)
  } catch (error) {
    if (error?.code === '23505') return c.json({ error: 'That tenant URL or email address is already registered.' }, 409)
    throw error
  }
})

app.post('/api/v1/auth/resend-verification', async (c) => {
  const redisClient = await ensureRedisConnected()
  const allowed = await rateLimit(redisClient, `verify-resend:${requestIp(c)}`, 3, 900)
  if (!allowed) return c.json({ error: 'Too many verification requests. Please try again later.' }, 429)
  let body
  try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
  const email = normaliseEmail(body?.email)
  const tenantSlug = normaliseSlug(body?.tenantSlug || (deployment.tenancyMode === 'single' ? deployment.primaryTenantSlug : ''))
  if (!validEmail(email) || !validSlug(tenantSlug)) return c.json({ status: 'accepted' }, 202)

  const lookup = await pool.query(
    `SELECT t.id AS tenant_id,t.slug,t.company_name,t.status,u.id AS user_id,u.email,u.name,ts.tenant_url
     FROM tenants t
     JOIN tenant_memberships m ON m.tenant_id=t.id AND m.role='owner'
     JOIN users u ON u.id=m.user_id
     JOIN tenant_settings ts ON ts.tenant_id=t.id
     WHERE t.slug=$1 AND u.email=$2 LIMIT 1`,
    [tenantSlug, email],
  )
  if (!lookup.rowCount || lookup.rows[0].status !== 'pending_verification') return c.json({ status: 'accepted' }, 202)
  const account = lookup.rows[0]
  const token = randomBytes(32).toString('base64url')
  const tokenHash = hashToken(token)
  await withTransaction(async (client) => {
    await client.query('UPDATE user_email_verifications SET used_at=COALESCE(used_at,now()) WHERE tenant_id=$1 AND user_id=$2 AND used_at IS NULL', [account.tenant_id, account.user_id])
    await client.query("INSERT INTO user_email_verifications (tenant_id,user_id,token_hash,redirect_url,expires_at) VALUES ($1,$2,$3,$4,now()+interval '24 hours')", [account.tenant_id, account.user_id, tokenHash, account.tenant_url])
  })
  const delivery = await deliverVerification({ token, email: account.email, name: account.name, companyName: account.company_name, tenantUrl: account.tenant_url })
  return c.json({ status: delivery.status === 'sent' ? 'sent' : 'accepted' }, 202)
})

app.get('/api/v1/auth/verify-email', async (c) => {
  const token = String(c.req.query('token') || '')
  if (token.length < 32 || token.length > 256) return c.redirect(`${marketingUrl}/signup?verification=invalid`, 302)
  const tokenHash = hashToken(token)
  const sessionToken = await withTransaction(async (client) => {
    const verificationResult = await client.query(
      `SELECT v.id,v.tenant_id,v.user_id,v.expires_at,v.used_at,t.slug,ts.tenant_url
       FROM user_email_verifications v
       JOIN tenants t ON t.id=v.tenant_id
       JOIN tenant_settings ts ON ts.tenant_id=v.tenant_id
       WHERE v.token_hash=$1 FOR UPDATE`,
      [tokenHash],
    )
    if (!verificationResult.rowCount) return null
    const verification = verificationResult.rows[0]
    if (verification.used_at || new Date(verification.expires_at).getTime() <= Date.now()) return null
    await client.query('UPDATE user_email_verifications SET used_at=now() WHERE id=$1', [verification.id])
    await client.query('UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()),updated_at=now() WHERE id=$1', [verification.user_id])
    await client.query("UPDATE tenants SET status='active',updated_at=now() WHERE id=$1 AND status='pending_verification'", [verification.tenant_id])
    await client.query("UPDATE tenant_memberships SET status='active' WHERE tenant_id=$1 AND user_id=$2", [verification.tenant_id, verification.user_id])
    await client.query("UPDATE tenant_settings SET onboarding_step=CASE WHEN onboarding_completed_at IS NULL THEN 'company' ELSE onboarding_step END,updated_at=now() WHERE tenant_id=$1", [verification.tenant_id])
    const rawSessionToken = await createSession(client, { tenantId: verification.tenant_id, userId: verification.user_id, surface: 'workspace' })
    return { token: rawSessionToken, tenantUrl: verification.tenant_url }
  })
  if (!sessionToken) return c.redirect(`${marketingUrl}/signup?verification=invalid`, 302)
  setSessionCookie(c, sessionToken.token)
  return c.redirect(`${sessionToken.tenantUrl}/onboarding`, 302)
})

app.get('/api/v1/auth/session', async (c) => {
  const session = await resolveSession(c)
  if (!session) return c.json({ authenticated: false }, 401)
  if (!originMatchesSession(c, session)) return c.json({ error: 'Tenant session mismatch.' }, 403)
  return c.json(sessionPayload(session))
})

app.post('/api/v1/auth/logout', async (c) => {
  await revokeCurrentSession(c)
  return c.json({ status: 'signed_out' })
})

app.post('/api/v1/onboarding/step', async (c) => {
  const session = await resolveSession(c)
  if (!session) return c.json({ error: 'Authentication required.' }, 401)
  if (!originMatchesSession(c, session)) return c.json({ error: 'Tenant session mismatch.' }, 403)
  if (session.onboarding_completed_at) return c.json(sessionPayload(session))
  let body
  try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
  const step = String(body?.step || '')
  const data = body?.data && typeof body.data === 'object' && !Array.isArray(body.data) ? body.data : {}
  const sequence = onboardingSequence(session.modules || {})
  const currentIndex = sequence.indexOf(session.onboarding_step)
  if (currentIndex < 0 || step !== session.onboarding_step) return c.json({ error: 'This onboarding step is no longer current. Refresh and continue from the active step.' }, 409)
  const nextStep = sequence[Math.min(currentIndex + 1, sequence.length - 1)]
  if (JSON.stringify(data).length > 20_000) return c.json({ error: 'Onboarding data is too large.' }, 413)
  await pool.query(
    `UPDATE tenant_settings SET onboarding_data=COALESCE(onboarding_data,'{}'::jsonb)||jsonb_build_object($2::text,$3::jsonb),onboarding_step=$4,updated_at=now() WHERE tenant_id=$1`,
    [session.tenant_id, step, JSON.stringify(data), nextStep],
  )
  const refreshed = await resolveSession(c)
  return c.json(sessionPayload(refreshed))
})

app.post('/api/v1/onboarding/complete', async (c) => {
  const session = await resolveSession(c)
  if (!session) return c.json({ error: 'Authentication required.' }, 401)
  if (!originMatchesSession(c, session)) return c.json({ error: 'Tenant session mismatch.' }, 403)
  if (session.onboarding_completed_at) return c.json(sessionPayload(session))
  if (session.onboarding_step !== 'finish') return c.json({ error: 'Complete the remaining onboarding steps first.' }, 409)
  await pool.query(
    `UPDATE tenant_settings SET onboarding_step='complete',onboarding_completed_at=now(),configuration=CASE WHEN configuration='{}'::jsonb THEN onboarding_data ELSE configuration END,updated_at=now() WHERE tenant_id=$1`,
    [session.tenant_id],
  )
  const refreshed = await resolveSession(c)
  return c.json(sessionPayload(refreshed))
})

registerPlatformAdminRoutes(app)
registerLicensingRoutes(app)
registerCatalogueRoutes(app)
registerOrganisationRoutes(app)
registerSettingsRoutes(app)
registerMicrosoftRoutes(app)
registerRmmAgentRoutes(app)
registerRmmAutomationRoutes(app)
registerRmmActivityRoutes(app)
registerRmmDeviceToolRoutes(app)
registerRmmRemoteRoutes(app)
registerRmmConnectRoutes(app)
registerRmmScopeRoutes(app)
registerRmmPatchingRoutes(app)
registerRmmAppPortalRoutes(app)
registerRmmNetworkDiscoveryRoutes(app)
registerRmmRecoveryKeyRoutes(app)

app.notFound((c) => c.json({ error: 'Not found' }, 404))
app.onError((error, c) => {
  console.error('Unhandled API error', error)
  if (error?.status && Number.isInteger(Number(error.status))) return c.json({ error: error.message || 'Request failed.' }, Number(error.status))
  return c.json({ error: 'Internal server error' }, 500)
})

await pool.query('SELECT 1')
await ensureRedisConnected()
startMicrosoftSyncScheduler()
startRmmVulnerabilitySyncScheduler()
startSoftwareVendorSyncScheduler()
startTenantVendorSourceScheduler()
startRmmNetworkDiscoveryScheduler()
startRmmMacOuiScheduler()
const server = serve({ fetch: app.fetch, hostname: '0.0.0.0', port })
attachRmmAgentWebSocket(server)
attachRmmViewerWebSocket(server)
attachRmmConnectWebSockets(server)
attachRmmDeviceToolWebSocket(server)
console.log(`Hi5Central API listening on port ${port}`)

async function shutdown(signal) {
  console.log(`Received ${signal}; shutting down`)
  server.close(async () => {
    try {
      if (redis.isOpen) await redis.quit()
      await pool.end()
    } finally {
      process.exit(0)
    }
  })
}
process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))
