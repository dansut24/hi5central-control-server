import { generateKeyPairSync } from 'node:crypto'
import {
  buildLicenseEnvelope,
  signLicenseEnvelope,
  verifyLicenseEnvelope,
} from '../src/licenseEnvelope.js'

const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
})

const envelope = buildLicenseEnvelope({
  installationId: '00000000-0000-4000-8000-000000000001',
  entitlementPayload: {
    edition: 'msp',
    products: ['itsm', 'rmm'],
    features: { multiTenant: true, platformAdmin: true, whiteLabel: true },
    limits: { tenants: 25, users: null, devices: 500 },
  },
  issuedAt: '2026-09-30T12:00:00.000Z',
  expiresAt: '2027-09-30T12:00:00.000Z',
  graceUntil: '2027-10-30T12:00:00.000Z',
})

const signature = signLicenseEnvelope(envelope, privateKey)
if (!verifyLicenseEnvelope(envelope, signature, publicKey)) {
  throw new Error('Valid licence envelope did not verify')
}

const tampered = structuredClone(envelope)
tampered.entitlementPayload.limits.devices = 5000
if (verifyLicenseEnvelope(tampered, signature, publicKey)) {
  throw new Error('Tampered entitlement unexpectedly verified')
}

const rebound = { ...envelope, installationId: '00000000-0000-4000-8000-000000000002' }
if (verifyLicenseEnvelope(rebound, signature, publicKey)) {
  throw new Error('Entitlement unexpectedly verified for another installation')
}

console.log('Licence envelope signing, binding and tamper detection passed')
