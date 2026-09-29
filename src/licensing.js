import { createHash } from 'node:crypto'
import { deployment } from './deploymentConfig.js'
import { pool } from './db.js'

const DEFAULT_EVALUATION_PRODUCTS = ['itsm', 'rmm']

function configuredEvaluationProducts() {
  const configured = String(process.env.SELF_HOST_EVALUATION_PRODUCTS || '')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter((value) => ['itsm', 'rmm'].includes(value))
  return configured.length ? [...new Set(configured)] : DEFAULT_EVALUATION_PRODUCTS
}

function safeNumber(value) {
  const number = Number(value)
  return Number.isFinite(number) && number >= 0 ? number : null
}

function normalisePayload(payload = {}) {
  const products = Array.isArray(payload.products)
    ? payload.products.map(String).map((value) => value.toLowerCase()).filter((value) => ['itsm', 'rmm'].includes(value))
    : []

  return {
    edition: String(payload.edition || 'self-hosted').slice(0, 80),
    products: [...new Set(products)],
    userLimit: safeNumber(payload.userLimit),
    deviceLimit: safeNumber(payload.deviceLimit),
    supportUntil: payload.supportUntil || null,
    updatesUntil: payload.updatesUntil || null,
  }
}

function rowState(row, now = new Date()) {
  if (deployment.deploymentMode === 'managed') return 'managed'

  const nowMs = now.getTime()
  const evaluationEnds = row?.evaluation_ends_at ? new Date(row.evaluation_ends_at).getTime() : 0
  const expiresAt = row?.expires_at ? new Date(row.expires_at).getTime() : 0
  const graceUntil = row?.grace_until ? new Date(row.grace_until).getTime() : 0

  if (row?.license_status === 'suspended') return 'suspended'
  if (row?.license_status === 'evaluation') return evaluationEnds > nowMs ? 'evaluation' : 'expired'
  if (row?.license_status === 'active') {
    if (!expiresAt || expiresAt > nowMs) return 'active'
    if (graceUntil > nowMs) return 'grace'
    return 'expired'
  }
  if (row?.license_status === 'grace') return graceUntil > nowMs ? 'grace' : 'expired'
  return 'expired'
}

function effectiveEntitlements(row, state) {
  if (state === 'managed') {
    return {
      edition: 'managed-cloud',
      products: ['itsm', 'rmm'],
      userLimit: null,
      deviceLimit: null,
      supportUntil: null,
      updatesUntil: null,
    }
  }

  const payload = normalisePayload(row?.entitlement_payload || {})
  if (['active', 'grace'].includes(state) && payload.products.length) return payload

  if (state === 'evaluation') {
    return {
      edition: 'evaluation',
      products: configuredEvaluationProducts(),
      userLimit: safeNumber(process.env.SELF_HOST_EVALUATION_USER_LIMIT) ?? 25,
      deviceLimit: safeNumber(process.env.SELF_HOST_EVALUATION_DEVICE_LIMIT) ?? 100,
      supportUntil: null,
      updatesUntil: null,
    }
  }

  // Expiration should never make customer data inaccessible. Product writes or
  // premium features may be restricted later, but read/export/recovery access
  // remains available so a licensing outage cannot become an operational outage.
  return {
    ...payload,
    products: payload.products,
  }
}

export async function installationLicense() {
  if (deployment.deploymentMode === 'managed') {
    const entitlements = effectiveEntitlements(null, 'managed')
    return {
      installationId: 'managed',
      deploymentMode: 'managed',
      status: 'managed',
      entitlements,
      evaluationEndsAt: null,
      expiresAt: null,
      graceUntil: null,
      lastValidatedAt: null,
      offlineCapable: true,
    }
  }

  const result = await pool.query(
    `SELECT installation_id, license_status, entitlement_payload,
            evaluation_started_at, evaluation_ends_at, issued_at, expires_at,
            last_contact_at, last_validated_at, grace_until
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
  const status = rowState(row)
  return {
    installationId: row.installation_id,
    deploymentMode: deployment.deploymentMode,
    status,
    entitlements: effectiveEntitlements(row, status),
    evaluationStartedAt: row.evaluation_started_at,
    evaluationEndsAt: row.evaluation_ends_at,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    graceUntil: row.grace_until,
    lastContactAt: row.last_contact_at,
    lastValidatedAt: row.last_validated_at,
    offlineCapable: true,
  }
}

export async function productEntitled(product) {
  const license = await installationLicense()
  if (license.status === 'managed') return true
  return license.entitlements.products.includes(String(product || '').toLowerCase())
}

export function licenseKeyHash(value) {
  return createHash('sha256').update(String(value || '')).digest('hex')
}

export function registerLicensingRoutes(app) {
  app.get('/api/v1/system/license', async (c) => {
    const license = await installationLicense()
    return c.json(license)
  })
}
