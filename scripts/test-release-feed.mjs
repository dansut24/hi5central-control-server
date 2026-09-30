import { generateKeyPairSync } from 'node:crypto'

process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://release-test:release-test@127.0.0.1:1/release-test'
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
process.env.RELEASE_SIGNING_PRIVATE_KEY_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
process.env.RELEASE_SIGNING_PUBLIC_KEY_PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString()

const { releaseFeedInternals } = await import('../src/releaseFeed.js')
const envelope = {
  schemaVersion: 1,
  channel: 'preview',
  releaseRef: 'test-release-1',
  publishedAt: new Date().toISOString(),
  artifactManifest: {
    controlServer: 'ghcr.io/dansut24/hi5central-control-server@sha256:' + '1'.repeat(64),
    itsm: 'ghcr.io/dansut24/hi5central-itsm@sha256:' + '2'.repeat(64),
    rmm: 'ghcr.io/dansut24/hi5central-rmm@sha256:' + '3'.repeat(64),
    admin: 'ghcr.io/dansut24/hi5central-admin@sha256:' + '4'.repeat(64),
  },
  changes: [{ changeKey: 'H5C-TEST', title: 'Test change', component: 'platform' }],
}
const signature = releaseFeedInternals.signEnvelope(envelope)
const publicPem = process.env.RELEASE_SIGNING_PUBLIC_KEY_PEM
if (!releaseFeedInternals.verifyEnvelope(envelope, signature, publicPem)) {
  throw new Error('Valid release envelope did not verify.')
}
const tampered = { ...envelope, releaseRef: 'tampered' }
if (releaseFeedInternals.verifyEnvelope(tampered, signature, publicPem)) {
  throw new Error('Tampered release envelope verified unexpectedly.')
}
if (!releaseFeedInternals.validManifest(releaseFeedInternals.cleanManifest(envelope.artifactManifest))) {
  throw new Error('Immutable manifest validation failed.')
}
console.log('Signed release feed verification and tamper detection passed')
