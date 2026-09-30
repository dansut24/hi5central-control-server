import { createHash, createPublicKey, randomBytes } from 'node:crypto'
import { deployment } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { buildLicenseEnvelope, signLicenseEnvelope } from './licenseEnvelope.js'

function hash(value) {
  return createHash('sha256').update(String(value || '')).digest('hex')
}

function clean(value, max = 500) {
  return String(value ?? '').trim().slice(0, max)
}

function positiveLimit(value) {
  if (value === null || value === undefined || value === '') return null
  const number = Math.floor(Number(value))
  return Number.isFinite(number) && number >= 1 ? number : null
}

function graceUntil(expiresAt, graceDays) {
  if (!expiresAt) return null
  const expiry = new Date(expiresAt)
  if (Number.isNaN(expiry.getTime())) return null
  return new Date(expiry.getTime() + Math.max(0, Number(graceDays) || 0) * 86400000)
}

function authorityError(message, status = 400, code = 'LICENSE_ERROR') {
  const error = new Error(message)
  error.status = status
  error.code = code
  return error
}
function entitlementPayload(row) {
  return {
    edition: 'msp',
    products: Array.isArray(row.products) ? row.products : ['itsm', 'rmm'],
    features: row.features && typeof row.features === 'object' ? row.features : {},
    limits: {
      tenants: row.tenant_limit == null ? null : Number(row.tenant_limit),
      users: row.user_limit == null ? null : Number(row.user_limit),
      devices: row.device_limit == null ? null : Number(row.device_limit),
    },
    supportUntil: row.expires_at || null,
    updatesUntil: row.expires_at || null,
  }
}

function signedResponse(row, installationId, refreshToken = null) {
  const issuedAt = new Date()
  const payload = entitlementPayload(row)
  const envelope = buildLicenseEnvelope({
    installationId,
    entitlementPayload: payload,
    issuedAt,
    expiresAt: row.expires_at,
    graceUntil: graceUntil(row.expires_at, row.grace_days),
  })
  const signature = signLicenseEnvelope(envelope, process.env.LICENSING_PRIVATE_KEY_PEM)
  return {
    envelope,
    signature,
    refreshToken,
    serverTime: issuedAt.toISOString(),
  }
}

function authorityPublicKeyPem() {
  const configured = String(process.env.LICENSING_PUBLIC_KEY_PEM || '').trim().replace(/\\n/g, '\n')
  if (configured) return configured
  const privateKey = String(process.env.LICENSING_PRIVATE_KEY_PEM || '').trim().replace(/\\n/g, '\n')
  if (!privateKey) return ''
  try {
    return createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString()
  } catch {
    return ''
  }
}

function ensureManagedAuthority() {
  if (deployment.deploymentMode !== 'managed') {
    throw authorityError('Licensing authority is only available in managed deployments.', 404, 'NOT_FOUND')
  }
  if (!String(process.env.LICENSING_PRIVATE_KEY_PEM || '').trim()) {
    throw authorityError('Licensing authority is not configured.', 503, 'LICENSING_AUTHORITY_UNAVAILABLE')
  }
}
export async function issueMspLicense(input = {}) {
  ensureManagedAuthority()
  const customerName = clean(input.customerName, 180)
  if (customerName.length < 2) throw authorityError('Customer name is required.')

  const licenseKey = `hi5_msp_${randomBytes(24).toString('base64url')}`
  const expiresAt = input.expiresAt ? new Date(input.expiresAt) : null
  if (expiresAt && Number.isNaN(expiresAt.getTime())) throw authorityError('expiresAt is invalid.')
  const graceDays = Math.max(0, Math.min(90, Math.floor(Number(input.graceDays ?? 30))))
  const defaultFeatures = {
    multiTenant: true,
    whiteLabel: true,
    platformAdmin: true,
    customerPortals: true,
    customDomains: true,
  }
  const features = { ...defaultFeatures, ...(input.features && typeof input.features === 'object' ? input.features : {}) }

  const result = await pool.query(
    `INSERT INTO msp_licenses
       (license_key_hash,display_key_suffix,customer_name,products,features,
        tenant_limit,user_limit,device_limit,expires_at,grace_days,notes)
     VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11)
     RETURNING *`,
    [
      hash(licenseKey),
      licenseKey.slice(-8),
      customerName,
      JSON.stringify(['itsm', 'rmm']),
      JSON.stringify(features),
      positiveLimit(input.tenantLimit),
      positiveLimit(input.userLimit),
      positiveLimit(input.deviceLimit),
      expiresAt,
      graceDays,
      clean(input.notes, 4000),
    ],
  )
  return { licenseKey, license: result.rows[0] }
}
export async function activateMspLicense({ licenseKey, installationId }) {
  ensureManagedAuthority()
  const key = String(licenseKey || '').trim()
  const installation = String(installationId || '').trim()
  if (!key.startsWith('hi5_msp_') || !installation) {
    throw authorityError('A valid MSP licence key and installation ID are required.')
  }

  return withTransaction(async (db) => {
    const result = await db.query(
      'SELECT * FROM msp_licenses WHERE license_key_hash=$1 FOR UPDATE',
      [hash(key)],
    )
    if (!result.rowCount) throw authorityError('Licence key is invalid.', 401, 'LICENSE_INVALID')
    const row = result.rows[0]
    if (row.status !== 'active') throw authorityError('Licence is not active.', 403, 'LICENSE_INACTIVE')
    if (new Date(row.starts_at).getTime() > Date.now()) {
      throw authorityError('Licence is not active yet.', 403, 'LICENSE_NOT_STARTED')
    }
    const finalGrace = graceUntil(row.expires_at, row.grace_days)
    if (finalGrace && finalGrace.getTime() < Date.now()) {
      throw authorityError('Licence has expired.', 403, 'LICENSE_EXPIRED')
    }
    if (row.bound_installation_id && String(row.bound_installation_id) !== installation) {
      throw authorityError('Licence is already bound to another installation.', 409, 'LICENSE_ALREADY_BOUND')
    }

    const refreshToken = `hi5_refresh_${randomBytes(32).toString('base64url')}`
    const updated = await db.query(
      `UPDATE msp_licenses
          SET bound_installation_id=$2,bound_at=COALESCE(bound_at,now()),
              refresh_token_hash=$3,last_activated_at=now(),updated_at=now()
        WHERE id=$1
        RETURNING *`,
      [row.id, installation, hash(refreshToken)],
    )
    return signedResponse(updated.rows[0], installation, refreshToken)
  })
}
export async function refreshMspLicense({ refreshToken, installationId }) {
  ensureManagedAuthority()
  const token = String(refreshToken || '').trim()
  const installation = String(installationId || '').trim()
  if (!token.startsWith('hi5_refresh_') || !installation) {
    throw authorityError('A valid refresh credential and installation ID are required.')
  }

  return withTransaction(async (db) => {
    const result = await db.query(
      `SELECT * FROM msp_licenses
        WHERE bound_installation_id=$1 AND refresh_token_hash=$2
        FOR UPDATE`,
      [installation, hash(token)],
    )
    if (!result.rowCount) throw authorityError('Refresh credential is invalid.', 401, 'REFRESH_INVALID')
    const row = result.rows[0]
    if (row.status !== 'active') throw authorityError('Licence is not active.', 403, 'LICENSE_INACTIVE')
    const finalGrace = graceUntil(row.expires_at, row.grace_days)
    if (finalGrace && finalGrace.getTime() < Date.now()) {
      throw authorityError('Licence has expired.', 403, 'LICENSE_EXPIRED')
    }
    await db.query(
      'UPDATE msp_licenses SET last_refreshed_at=now(),updated_at=now() WHERE id=$1',
      [row.id],
    )
    return signedResponse(row, installation)
  })
}
function errorResponse(c, error) {
  const status = Number(error?.status) || 500
  const safeStatus = status >= 400 && status <= 599 ? status : 500
  return c.json({
    error: safeStatus === 500 ? 'Licensing request failed.' : error.message,
    code: error?.code || 'LICENSE_ERROR',
  }, safeStatus)
}

export function registerLicenseAuthorityRoutes(app) {
  app.get('/api/licensing/v1/public-key', (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    const publicKeyPem = authorityPublicKeyPem()
    if (!publicKeyPem) {
      return c.json({ error: 'Licensing authority is not configured.', code: 'LICENSING_AUTHORITY_UNAVAILABLE' }, 503)
    }
    return c.json({
      algorithm: 'Ed25519',
      keyId: createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 24),
      publicKeyPem,
    })
  })

  app.get('/api/licensing/v1/public-key.pem', (c) => {
    if (deployment.deploymentMode !== 'managed') return c.text('Not found.\n', 404)
    const publicKeyPem = authorityPublicKeyPem()
    if (!publicKeyPem) return c.text('Licensing authority is not configured.\n', 503)
    c.header('content-type', 'application/x-pem-file')
    c.header('cache-control', 'public, max-age=3600')
    return c.body(publicKeyPem.endsWith('\n') ? publicKeyPem : `${publicKeyPem}\n`)
  })

  app.post('/api/licensing/v1/activate', async (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    try {
      return c.json(await activateMspLicense(body))
    } catch (error) {
      return errorResponse(c, error)
    }
  })

  app.post('/api/licensing/v1/refresh', async (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    try {
      return c.json(await refreshMspLicense(body))
    } catch (error) {
      return errorResponse(c, error)
    }
  })
}
