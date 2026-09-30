import { createPrivateKey, createPublicKey, sign as signBytes, verify as verifyBytes } from 'node:crypto'

function iso(value) {
  if (!value) return null
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date.toISOString()
}

export function canonicaliseLicenseValue(value) {
  if (Array.isArray(value)) return `[${value.map(canonicaliseLicenseValue).join(',')}]`
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort()
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicaliseLicenseValue(value[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

export function buildLicenseEnvelope({
  installationId,
  entitlementPayload,
  issuedAt,
  expiresAt,
  graceUntil,
}) {
  return {
    installationId: String(installationId || ''),
    entitlementPayload: entitlementPayload && typeof entitlementPayload === 'object' ? entitlementPayload : {},
    issuedAt: iso(issuedAt),
    expiresAt: iso(expiresAt),
    graceUntil: iso(graceUntil),
  }
}
function pem(value) {
  return String(value || '').trim().replace(/\\n/g, '\n')
}

export function signLicenseEnvelope(envelope, privateKeyPem) {
  const privateKey = pem(privateKeyPem)
  if (!privateKey) throw new Error('LICENSING_PRIVATE_KEY_PEM is not configured')
  const key = createPrivateKey(privateKey)
  return signBytes(
    null,
    Buffer.from(canonicaliseLicenseValue(envelope)),
    key,
  ).toString('base64url')
}

export function verifyLicenseEnvelope(envelope, signature, publicKeyPem) {
  const publicKey = pem(publicKeyPem)
  if (!publicKey || !signature) return false
  try {
    const key = createPublicKey(publicKey)
    return verifyBytes(
      null,
      Buffer.from(canonicaliseLicenseValue(envelope)),
      key,
      Buffer.from(String(signature), 'base64url'),
    )
  } catch {
    return false
  }
}
