import { createHash } from 'node:crypto'
import { deployment } from './deploymentConfig.js'
import { buildLicenseEnvelope, verifyLicenseEnvelope } from './licenseEnvelope.js'
import { pool } from './db.js'

const PAID_FEATURES = ['multiTenant', 'whiteLabel', 'platformAdmin', 'customerPortals', 'customDomains']

const STANDARD_ENTITLEMENTS = Object.freeze({
  edition: 'standard',
  products: ['itsm', 'rmm'],
  features: {
    multiTenant: false,
    whiteLabel: false,
    platformAdmin: false,
    customerPortals: false,
    customDomains: false,
  },
  limits: { tenants: 1, users: null, devices: null },
  supportUntil: null,
  updatesUntil: null,
})

const MANAGED_ENTITLEMENTS = Object.freeze({
  edition: 'managed',
  products: ['itsm', 'rmm'],
  features: Object.fromEntries(PAID_FEATURES.map((feature) => [feature, true])),
  limits: { tenants: null, users: null, devices: null },
  supportUntil: null,
  updatesUntil: null,
})
function safeNumber(value) {
  const number = Number(value)
  return Number.isFinite(number) && number >= 0 ? number : null
}

function normalisePayload(payload = {}) {
  const products = Array.isArray(payload.products)
    ? payload.products.map(String).map((value) => value.toLowerCase()).filter((value) => ['itsm', 'rmm'].includes(value))
    : []
  const suppliedFeatures = payload.features && typeof payload.features === 'object' ? payload.features : {}
  const features = Object.fromEntries(PAID_FEATURES.map((feature) => [feature, suppliedFeatures[feature] === true]))
  const limits = payload.limits && typeof payload.limits === 'object' ? payload.limits : {}

  return {
    edition: String(payload.edition || 'msp').slice(0, 80),
    products: [...new Set(products)],
    features,
    limits: {
      tenants: safeNumber(limits.tenants),
      users: safeNumber(limits.users ?? payload.userLimit),
      devices: safeNumber(limits.devices ?? payload.deviceLimit),
    },
    supportUntil: payload.supportUntil || null,
    updatesUntil: payload.updatesUntil || null,
  }
}

function signedEnvelope(row) {
  return buildLicenseEnvelope({
    installationId: row?.installation_id,
    entitlementPayload: row?.entitlement_payload || {},
    issuedAt: row?.issued_at,
    expiresAt: row?.expires_at,
    graceUntil: row?.grace_until,
  })
}

function entitlementSignatureValid(row) {
  return verifyLicenseEnvelope(
    signedEnvelope(row),
    row?.entitlement_signature,
    process.env.LICENSING_PUBLIC_KEY_PEM,
  )
}

function rowState(row, signatureValid, now = new Date()) {
  if (deployment.deploymentMode === 'managed') return 'managed'
  if (deployment.selfHostEdition === 'standard') return 'free'

  const nowMs = now.getTime()
  const expiresAt = row?.expires_at ? new Date(row.expires_at).getTime() : 0
  const graceUntil = row?.grace_until ? new Date(row.grace_until).getTime() : 0

  if (row?.license_status === 'suspended') return 'suspended'
  if (!signatureValid) return row?.license_status === 'evaluation' ? 'unlicensed' : 'invalid'
  if (row?.license_status === 'active') {
    if (!expiresAt || expiresAt > nowMs) return 'active'
    if (graceUntil > nowMs) return 'grace'
    return 'expired'
  }
  if (row?.license_status === 'grace') return graceUntil > nowMs ? 'grace' : 'expired'
  return 'unlicensed'
}
function effectiveEntitlements(row, state) {
  if (state === 'managed') return MANAGED_ENTITLEMENTS
  if (state === 'free') return STANDARD_ENTITLEMENTS

  const payload = normalisePayload(row?.entitlement_payload || {})
  if (['active', 'grace'].includes(state)) {
    return { ...payload, edition: 'msp' }
  }

  // Expiration or licensing failure must not make customer data inaccessible.
  // Paid control-plane capabilities are disabled, while the API can continue to
  // expose existing operational data for recovery/export.
  return {
    ...payload,
    edition: 'msp',
    features: Object.fromEntries(PAID_FEATURES.map((feature) => [feature, false])),
  }
}

export async function installationLicense() {
  if (deployment.deploymentMode === 'managed') {
    return {
      installationId: 'managed',
      deploymentMode: 'managed',
      edition: 'managed',
      status: 'managed',
      licensingRequired: false,
      entitlements: MANAGED_ENTITLEMENTS,
      offlineCapable: true,
    }
  }

  const result = await pool.query(
    `SELECT installation_id, license_status, entitlement_payload, entitlement_signature,
            evaluation_started_at, evaluation_ends_at, issued_at, expires_at,
            last_contact_at, last_validated_at, grace_until, refresh_token
       FROM installation_licensing
      WHERE singleton = true
      LIMIT 1`,
  )
  if (!result.rowCount) {
    await pool.query(
      `INSERT INTO installation_licensing (singleton)
       VALUES (true)
       ON CONFLICT (singleton) DO NOTHING`,
    )
    return installationLicense()
  }

  const row = result.rows[0]
  const signatureValid = entitlementSignatureValid(row)
  const status = rowState(row, signatureValid)
  return {
    installationId: row.installation_id,
    deploymentMode: deployment.deploymentMode,
    edition: deployment.selfHostEdition,
    status,
    licensingRequired: deployment.selfHostEdition === 'msp',
    entitlements: effectiveEntitlements(row, status),
    evaluationStartedAt: row.evaluation_started_at,
    evaluationEndsAt: row.evaluation_ends_at,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    graceUntil: row.grace_until,
    lastContactAt: row.last_contact_at,
    lastValidatedAt: row.last_validated_at,
    signatureValid: deployment.selfHostEdition === 'msp' ? signatureValid : null,
    offlineCapable: true,
  }
}

export async function productEntitled(product) {
  const license = await installationLicense()
  if (['managed', 'free'].includes(license.status)) return license.entitlements.products.includes(String(product || '').toLowerCase())
  if (!['active', 'grace'].includes(license.status)) return false
  return license.entitlements.products.includes(String(product || '').toLowerCase())
}

export async function featureEntitled(feature) {
  const license = await installationLicense()
  if (license.status === 'managed') return true
  if (!['active', 'grace'].includes(license.status)) return false
  return license.entitlements.features?.[feature] === true
}

function licensingServerUrl() {
  return String(process.env.LICENSING_SERVER_URL || 'https://licensing.hi5central.com').trim().replace(/\/$/, '')
}

async function authorityRequest(path, body) {
  const server = licensingServerUrl()
  if (!server) throw new Error('LICENSING_SERVER_URL is not configured.')
  const response = await fetch(`${server}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
  })
  let payload = {}
  try { payload = await response.json() } catch {}
  if (!response.ok) {
    const error = new Error(payload?.error || `Licensing service returned HTTP ${response.status}.`)
    error.code = payload?.code || 'LICENSING_SERVICE_ERROR'
    error.status = response.status
    throw error
  }
  return payload
}

async function persistAuthorityResponse(response, installationId, { keyHash = null, refreshToken = null } = {}) {
  const envelope = response?.envelope
  const signature = String(response?.signature || '')
  const publicKey = String(process.env.LICENSING_PUBLIC_KEY_PEM || '').trim()
  if (!publicKey) throw new Error('LICENSING_PUBLIC_KEY_PEM is not configured.')
  if (!envelope || String(envelope.installationId) !== String(installationId)) {
    throw new Error('Licensing service returned an entitlement for a different installation.')
  }
  if (String(envelope?.entitlementPayload?.edition || '') !== 'msp') {
    throw new Error('Licensing service returned an invalid entitlement edition.')
  }
  const authorityStatus = String(envelope?.entitlementPayload?.licenseStatus || 'active')
  if (!['active', 'suspended'].includes(authorityStatus)) {
    throw new Error('Licensing service returned an invalid entitlement status.')
  }
  if (!verifyLicenseEnvelope(envelope, signature, publicKey)) {
    throw new Error('Licensing service returned an invalid entitlement signature.')
  }

  await pool.query(
    `UPDATE installation_licensing
        SET license_status=$9,
            license_key_hash=COALESCE($2,license_key_hash),
            entitlement_payload=$3::jsonb,
            entitlement_signature=$4,
            issued_at=$5,
            expires_at=$6,
            grace_until=$7,
            refresh_token=COALESCE($8,refresh_token),
            last_contact_at=now(),
            last_validated_at=now(),
            updated_at=now()
      WHERE singleton=true AND installation_id=$1`,
    [
      installationId,
      keyHash,
      JSON.stringify(envelope.entitlementPayload || {}),
      signature,
      envelope.issuedAt || null,
      envelope.expiresAt || null,
      envelope.graceUntil || null,
      refreshToken,
      authorityStatus,
    ],
  )
}

export async function activateInstallationLicense(licenseKey) {
  if (deployment.deploymentMode !== 'self_hosted' || deployment.selfHostEdition !== 'msp') {
    const error = new Error('MSP licence activation is only available for the self-hosted MSP edition.')
    error.status = 409
    throw error
  }
  const key = String(licenseKey || '').trim()
  if (!key.startsWith('hi5_msp_')) {
    const error = new Error('Enter a valid Hi5Central MSP licence key.')
    error.status = 400
    throw error
  }
  const current = await installationLicense()
  const response = await authorityRequest('/api/licensing/v1/activate', {
    licenseKey: key,
    installationId: current.installationId,
  })
  if (!String(response?.refreshToken || '').startsWith('hi5_refresh_')) {
    throw new Error('Licensing service did not return a refresh credential.')
  }
  await persistAuthorityResponse(response, current.installationId, {
    keyHash: licenseKeyHash(key),
    refreshToken: response.refreshToken,
  })
  return installationLicense()
}

export async function refreshInstallationLicense() {
  if (deployment.deploymentMode !== 'self_hosted' || deployment.selfHostEdition !== 'msp') return false
  const result = await pool.query(
    'SELECT installation_id,refresh_token FROM installation_licensing WHERE singleton=true LIMIT 1',
  )
  const row = result.rows[0]
  if (!row?.refresh_token) return false
  const response = await authorityRequest('/api/licensing/v1/refresh', {
    installationId: row.installation_id,
    refreshToken: row.refresh_token,
  })
  await persistAuthorityResponse(response, row.installation_id)
  return true
}

let refreshTimer = null
export function startLicensingRefreshScheduler() {
  if (refreshTimer || deployment.deploymentMode !== 'self_hosted' || deployment.selfHostEdition !== 'msp') return
  const requested = Number(process.env.LICENSING_REFRESH_INTERVAL_MS || 12 * 60 * 60 * 1000)
  const interval = Math.max(60 * 60 * 1000, Number.isFinite(requested) ? requested : 12 * 60 * 60 * 1000)
  const refresh = () => refreshInstallationLicense().catch((error) => {
    console.warn(`MSP licence refresh deferred: ${error?.message || error}`)
  })
  refreshTimer = setInterval(refresh, interval)
  refreshTimer.unref?.()
  const requestedInitial = Number(process.env.LICENSING_INITIAL_REFRESH_DELAY_MS || 30000)
  const initialDelay = Math.max(1000, Number.isFinite(requestedInitial) ? requestedInitial : 30000)
  const initial = setTimeout(refresh, initialDelay)
  initial.unref?.()
}

export function licenseKeyHash(value) {
  return createHash('sha256').update(String(value || '')).digest('hex')
}

export function registerLicensingRoutes(app) {
  app.get('/api/v1/system/license', async (c) => {
    const license = await installationLicense()
    return c.json(license)
  })

  app.post('/api/v1/system/license/activate', async (c) => {
    if (deployment.deploymentMode !== 'self_hosted' || deployment.selfHostEdition !== 'msp') {
      return c.json({ error: 'This installation does not require an MSP licence.', code: 'LICENSE_NOT_REQUIRED' }, 409)
    }
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    try {
      const license = await activateInstallationLicense(body?.licenseKey)
      return c.json({ activated: true, license })
    } catch (error) {
      const status = Number(error?.status) || 502
      return c.json({
        error: error?.message || 'Licence activation failed.',
        code: error?.code || 'LICENSE_ACTIVATION_FAILED',
      }, status >= 400 && status <= 599 ? status : 502)
    }
  })

  app.get('/api/v1/system/edition', async (c) => {
    const license = await installationLicense()
    return c.json({
      deploymentMode: deployment.deploymentMode,
      runtimeEnvironment: deployment.runtimeEnvironment,
      featureMode: deployment.featureMode,
      edition: license.edition,
      status: license.status,
      licensingRequired: license.licensingRequired,
      features: license.entitlements.features,
      limits: license.entitlements.limits,
    })
  })
}
