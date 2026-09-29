import { createHash, createHmac, randomBytes } from 'node:crypto'
import pg from 'pg'
import { hashPassword } from '../src/password.js'

const { Client } = pg
const API = 'http://127.0.0.1:3001'
const ORIGIN = 'https://ci-controls.hi5central.com'
const TENANT_ID = '00000000-0000-4000-8000-000000000301'
const USER_ID = '00000000-0000-4000-8000-000000000302'
const password = `CiControls-${randomBytes(14).toString('base64url')}Aa1`
const changedPassword = `Changed-${randomBytes(14).toString('base64url')}Bb2`
const resetPassword = `Reset-${randomBytes(14).toString('base64url')}Cc3`
const sessionToken = randomBytes(32).toString('base64url')
const sessionHash = createHash('sha256').update(sessionToken).digest('hex')
const cookie = `hi5central_session=${sessionToken}`
const db = new Client({ connectionString: process.env.DATABASE_URL })

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

async function json(path, { method = 'GET', body, auth = true, headers = {} } = {}) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: {
      Origin: ORIGIN,
      ...(auth ? { Cookie: cookie } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const payload = await response.json().catch(() => ({}))
  return { response, payload }
}

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  const output = []
  for (const ch of String(input).replace(/=+$/g, '').toUpperCase()) {
    const index = alphabet.indexOf(ch)
    if (index < 0) continue
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Buffer.from(output)
}

function totp(secret) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const digest = createHmac('sha1', base32Decode(secret)).update(counter).digest()
  const offset = digest[digest.length - 1] & 15
  const binary = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) >>> 0
  return String(binary % 1_000_000).padStart(6, '0')
}

await db.connect()
try {
  const passwordHash = await hashPassword(password)
  await db.query('BEGIN')
  await db.query(`INSERT INTO tenants (id,slug,company_name,status) VALUES ($1,'ci-controls','CI Controls','active')`, [TENANT_ID])
  await db.query(`INSERT INTO users (id,email,name,password_hash,email_verified_at) VALUES ($1,'owner@ci-controls.test','CI Controls Owner',$2,now())`, [USER_ID, passwordHash])
  await db.query(`INSERT INTO tenant_memberships (tenant_id,user_id,role,status) VALUES ($1,$2,'owner','active')`, [TENANT_ID, USER_ID])
  await db.query(`INSERT INTO tenant_settings (tenant_id,modules,onboarding_step,tenant_url,portal_url,onboarding_data,configuration) VALUES ($1,'{"itsm":true,"rmm":false}'::jsonb,'security','https://ci-controls.hi5central.com','https://ci-controls-portal.hi5central.com','{"company":{"displayName":"CI Controls"}}'::jsonb,'{}'::jsonb)`, [TENANT_ID])
  await db.query(`INSERT INTO auth_sessions (tenant_id,user_id,token_hash,expires_at) VALUES ($1,$2,$3,now()+interval '12 hours')`, [TENANT_ID, USER_ID, sessionHash])
  await db.query('COMMIT')

  console.log('Checking onboarding MFA cannot be bypassed')
  const blocked = await json('/api/v1/onboarding/step', {
    method: 'POST',
    body: { step: 'security', data: { requireMfa: true, sessionHours: '8', passwordPolicy: 'strong', auditRetention: '90' } },
  })
  assert(!blocked.response.ok, 'Required MFA onboarding unexpectedly advanced before enrollment')
  const currentStep = await db.query('SELECT onboarding_step FROM tenant_settings WHERE tenant_id=$1', [TENANT_ID])
  assert(currentStep.rows[0]?.onboarding_step === 'security', 'Blocked onboarding changed the active step')

  console.log('Enrolling authenticator during onboarding')
  const setup = await json('/api/v1/mfa/setup', { method: 'POST', body: {} })
  assert(setup.response.ok && setup.payload.secret && setup.payload.setupToken, 'MFA setup failed')
  const confirm = await json('/api/v1/mfa/confirm', {
    method: 'POST',
    body: { setupToken: setup.payload.setupToken, code: totp(setup.payload.secret) },
  })
  assert(confirm.response.ok && confirm.payload.enrolled === true, 'MFA confirmation failed')
  assert(Array.isArray(confirm.payload.recoveryCodes) && confirm.payload.recoveryCodes.length === 10, 'Recovery codes were not issued')
  const recoveryCode = confirm.payload.recoveryCodes[0]

  const saveSecurity = await json('/api/v1/onboarding/step', {
    method: 'POST',
    body: { step: 'security', data: { requireMfa: true, sessionHours: '8', passwordPolicy: 'strong', auditRetention: '90' } },
  })
  assert(saveSecurity.response.ok && saveSecurity.payload.onboarding?.step === 'itsm', 'Security onboarding did not advance after MFA enrollment')
  await db.query(`UPDATE tenant_settings SET onboarding_step='finish' WHERE tenant_id=$1`, [TENANT_ID])
  const complete = await json('/api/v1/onboarding/complete', { method: 'POST' })
  assert(complete.response.ok && complete.payload.onboarding?.step === 'complete', 'Onboarding completion failed')

  console.log('Checking MFA login and session evidence')
  const login = await json('/api/v1/auth/login-secure', {
    method: 'POST',
    auth: false,
    headers: { 'User-Agent': 'Hi5Central-CI-SecurityControls/1.0', 'X-Forwarded-For': '203.0.113.55' },
    body: { tenantSlug: 'ci-controls', email: 'owner@ci-controls.test', password },
  })
  assert(login.response.ok && login.payload.mfaRequired === true, 'Secure login did not require MFA')
  const verified = await json('/api/v1/auth/mfa/verify', {
    method: 'POST',
    auth: false,
    headers: { 'User-Agent': 'Hi5Central-CI-SecurityControls/1.0', 'X-Forwarded-For': '203.0.113.55' },
    body: { challengeToken: login.payload.challengeToken, code: recoveryCode },
  })
  assert(verified.response.ok && verified.payload.authenticated === true, 'Recovery-code MFA login failed')
  const evidence = await db.query(`SELECT count(*)::int AS count FROM auth_sessions WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL AND ip_address='203.0.113.55' AND user_agent='Hi5Central-CI-SecurityControls/1.0'`, [TENANT_ID, USER_ID])
  assert(evidence.rows[0]?.count === 1, 'New session device evidence was not stored')

  const sessions = await json('/api/v1/security/sessions')
  assert(sessions.response.ok && sessions.payload.items.filter((item) => !item.revokedAt).length >= 2, 'Active sessions were not returned')

  console.log('Checking password policy and session revocation')
  const weak = await json('/api/v1/security/password/change', { method: 'POST', body: { currentPassword: password, newPassword: 'weakpassword' } })
  assert(weak.response.status === 400, 'Strong password policy accepted a weak password')
  const changed = await json('/api/v1/security/password/change', { method: 'POST', body: { currentPassword: password, newPassword: changedPassword } })
  assert(changed.response.ok && changed.payload.changed === true && changed.payload.otherSessionsRevoked === true, 'Password change failed')
  const otherSessions = await db.query('SELECT count(*)::int AS count FROM auth_sessions WHERE tenant_id=$1 AND user_id=$2 AND token_hash<>$3 AND revoked_at IS NULL', [TENANT_ID, USER_ID, sessionHash])
  assert(otherSessions.rows[0]?.count === 0, 'Password change did not revoke other sessions')

  const removeMfa = await json('/api/v1/security/mfa/remove', { method: 'POST', body: { password: changedPassword } })
  assert(removeMfa.response.status === 409, 'Required MFA policy allowed authenticator removal')

  console.log('Checking audit retention and authentication audit')
  await db.query(`INSERT INTO security_audit_events (tenant_id,actor_user_id,event_type,created_at) VALUES ($1,$2,'ci.old_event',now()-interval '100 days')`, [TENANT_ID, USER_ID])
  const audit = await json('/api/v1/security/audit?limit=200')
  assert(audit.response.ok && audit.payload.retentionDays === 90, 'Audit retention setting was not applied')
  const types = new Set(audit.payload.items.map((item) => item.type))
  assert(types.has('password.changed'), 'Password change audit event missing')
  assert(types.has('login.success'), 'Login success audit event missing')
  assert(types.has('mfa.recovery_code_used'), 'Recovery-code audit event missing')
  assert(!types.has('ci.old_event'), 'Expired audit event was returned')
  const oldAudit = await db.query(`SELECT count(*)::int AS count FROM security_audit_events WHERE tenant_id=$1 AND event_type='ci.old_event'`, [TENANT_ID])
  assert(oldAudit.rows[0]?.count === 0, 'Expired audit event was not pruned')

  console.log('Checking one-time password reset and all-session revocation')
  const resetToken = randomBytes(32).toString('base64url')
  const resetHash = createHash('sha256').update(resetToken).digest('hex')
  await db.query(`INSERT INTO password_reset_tokens (tenant_id,user_id,token_hash,expires_at) VALUES ($1,$2,$3,now()+interval '1 hour')`, [TENANT_ID, USER_ID, resetHash])
  const reset = await json('/api/v1/auth/password/reset', { method: 'POST', auth: false, body: { tenantSlug: 'ci-controls', token: resetToken, newPassword: resetPassword } })
  assert(reset.response.ok && reset.payload.changed === true, 'Password reset failed')
  const activeAfterReset = await db.query('SELECT count(*)::int AS count FROM auth_sessions WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL', [TENANT_ID, USER_ID])
  assert(activeAfterReset.rows[0]?.count === 0, 'Password reset did not revoke all sessions')
  const reuse = await json('/api/v1/auth/password/reset', { method: 'POST', auth: false, body: { tenantSlug: 'ci-controls', token: resetToken, newPassword: changedPassword } })
  assert(reuse.response.status === 400, 'Password reset token was reusable')

  console.log('Security Controls E2E passed')
} finally {
  await db.end()
}
