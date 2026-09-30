import { createHash, createPrivateKey, createPublicKey, sign as signBytes, verify as verifyBytes } from 'node:crypto'
import { pool, withTransaction } from './db.js'
import { deployment } from './deploymentConfig.js'
import { canonicaliseLicenseValue } from './licenseEnvelope.js'

function pem(value) {
  return String(value || '').trim().replace(/\\n/g, '\n')
}

function releasePrivateKeyPem() {
  const explicit = pem(process.env.RELEASE_SIGNING_PRIVATE_KEY_PEM)
  if (explicit) return explicit
  if (deployment.deploymentMode === 'managed' && deployment.runtimeEnvironment !== 'live') {
    return pem(process.env.LICENSING_PRIVATE_KEY_PEM)
  }
  return ''
}

function releasePublicKeyPem() {
  const explicit = pem(process.env.RELEASE_SIGNING_PUBLIC_KEY_PEM)
  if (explicit) return explicit
  if (deployment.deploymentMode === 'managed' && deployment.runtimeEnvironment !== 'live') {
    return pem(process.env.LICENSING_PUBLIC_KEY_PEM)
  }
  return ''
}

function derivedPublicKeyPem() {
  const configured = releasePublicKeyPem()
  if (configured) return configured
  const privatePem = releasePrivateKeyPem()
  if (!privatePem) return ''
  return createPublicKey(createPrivateKey(privatePem)).export({ type: 'spki', format: 'pem' }).toString()
}

function signEnvelope(envelope) {
  const privatePem = releasePrivateKeyPem()
  if (!privatePem) throw new Error('RELEASE_SIGNING_PRIVATE_KEY_PEM is not configured.')
  return signBytes(
    null,
    Buffer.from(canonicaliseLicenseValue(envelope)),
    createPrivateKey(privatePem),
  ).toString('base64url')
}

function verifyEnvelope(envelope, signature, publicKeyPem) {
  try {
    if (!signature || !publicKeyPem) return false
    return verifyBytes(
      null,
      Buffer.from(canonicaliseLicenseValue(envelope)),
      createPublicKey(pem(publicKeyPem)),
      Buffer.from(String(signature), 'base64url'),
    )
  } catch {
    return false
  }
}

function publicKeyFingerprint(publicKeyPem) {
  if (!publicKeyPem) return ''
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' })
  return createHash('sha256').update(der).digest('hex')
}

function cleanManifest(value) {
  const input = value && typeof value === 'object' && !Array.isArray(value) ? value : {}
  const keys = ['controlServer','itsm','rmm','admin']
  return Object.fromEntries(keys.map((key) => [key, String(input[key] || '').trim()]))
}

function validManifest(manifest) {
  return Object.values(manifest).every((value) => value.includes('@sha256:'))
}

async function publishedRelease(channel) {
  const target = channel === 'preview' ? 'uat' : 'live'
  const promotion = await pool.query(
    `SELECT id,release_ref,artifact_manifest,completed_at
       FROM platform_release_promotions
      WHERE to_environment=$1 AND status='succeeded'
      ORDER BY completed_at DESC NULLS LAST,requested_at DESC
      LIMIT 1`,
    [target],
  )
  if (!promotion.rowCount) return null
  const row = promotion.rows[0]
  const manifest = cleanManifest(row.artifact_manifest)
  if (!validManifest(manifest)) return null

  const changes = await pool.query(
    `SELECT c.change_key,c.title,c.description,c.component,c.feature_key,c.version,c.risk,c.source_ref,
            COALESCE(f.title,'') AS feature_title,
            COALESCE(f.description,'') AS feature_description,
            COALESCE(f.component,c.component) AS feature_component
       FROM platform_release_promotion_items i
       JOIN platform_release_changes c ON c.id=i.change_id
       LEFT JOIN platform_feature_definitions f ON f.feature_key=c.feature_key
      WHERE i.promotion_id=$1
      ORDER BY c.change_key`,
    [row.id],
  )

  return {
    schemaVersion: 1,
    channel,
    releaseRef: String(row.release_ref || '').trim() || `${channel}-${row.id}`,
    publishedAt: row.completed_at ? new Date(row.completed_at).toISOString() : new Date().toISOString(),
    artifactManifest: manifest,
    changes: changes.rows.map((change) => ({
      changeKey: change.change_key,
      title: change.title,
      description: change.description || '',
      component: change.component,
      featureKey: change.feature_key || '',
      feature: change.feature_key ? {
        key: change.feature_key,
        title: change.feature_title || change.title,
        description: change.feature_description || '',
        component: change.feature_component || change.component,
      } : null,
      version: change.version || '',
      risk: change.risk,
      sourceRef: change.source_ref || '',
    })),
  }
}

export function registerReleaseFeedRoutes(app) {
  app.get('/api/releases/v1/public-key', (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    const publicKey = derivedPublicKeyPem()
    if (!publicKey) return c.json({ error: 'Release signing authority is not configured.' }, 503)
    return c.json({
      algorithm: 'Ed25519',
      publicKey,
      fingerprintSha256: publicKeyFingerprint(publicKey),
    })
  })

  app.get('/api/releases/v1/feed', async (c) => {
    if (deployment.deploymentMode !== 'managed') return c.json({ error: 'Not found.' }, 404)
    const channel = String(c.req.query('channel') || 'stable').trim().toLowerCase()
    if (!['stable','preview'].includes(channel)) return c.json({ error: 'channel must be stable or preview.' }, 400)
    const envelope = await publishedRelease(channel)
    if (!envelope) return c.json({ error: `No ${channel} release is published yet.`, code: 'RELEASE_NOT_PUBLISHED' }, 404)
    try {
      const signature = signEnvelope(envelope)
      return c.json({
        envelope,
        signature,
        algorithm: 'Ed25519',
        fingerprintSha256: publicKeyFingerprint(derivedPublicKeyPem()),
      })
    } catch (error) {
      return c.json({ error: error?.message || 'Release signing failed.' }, 503)
    }
  })
}

function feedUrl() {
  return String(process.env.RELEASE_FEED_URL || 'https://api.hi5central.com/api/releases/v1/feed').trim()
}

function configuredReleasePublicKey() {
  return pem(process.env.RELEASE_SIGNING_PUBLIC_KEY_PEM || process.env.LICENSING_PUBLIC_KEY_PEM)
}

async function fetchFeed(channel) {
  const base = feedUrl()
  if (!base) throw new Error('RELEASE_FEED_URL is not configured.')
  const separator = base.includes('?') ? '&' : '?'
  const response = await fetch(`${base}${separator}channel=${encodeURIComponent(channel)}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(15000),
  })
  let payload = {}
  try { payload = await response.json() } catch {}
  if (response.status === 404 && payload?.code === 'RELEASE_NOT_PUBLISHED') return null
  if (!response.ok) throw new Error(payload?.error || `Release feed returned HTTP ${response.status}.`)
  return payload
}

async function importFeedPayload(feed, channel, sourceUrl) {
  const envelope = feed?.envelope
  const signature = String(feed?.signature || '')
  const publicKey = configuredReleasePublicKey()
  if (!publicKey) throw new Error('RELEASE_SIGNING_PUBLIC_KEY_PEM is not configured.')
  if (!envelope || envelope.schemaVersion !== 1 || envelope.channel !== channel) {
    throw new Error('Release feed returned an incompatible envelope.')
  }
  const manifest = cleanManifest(envelope.artifactManifest)
  if (!validManifest(manifest)) throw new Error('Release feed artifact manifest is not immutable.')
  if (!verifyEnvelope(envelope, signature, publicKey)) throw new Error('Release feed signature verification failed.')

  return withTransaction(async (db) => {
    const existing = await db.query(
      'SELECT id FROM platform_release_feed_receipts WHERE release_ref=$1 AND channel=$2 LIMIT 1',
      [envelope.releaseRef,channel],
    )
    if (existing.rowCount) {
      await db.query(
        `UPDATE platform_release_preferences
            SET last_feed_sync_at=now(),last_release_seen=$1,updated_at=now()
          WHERE preference_key='deployment'`,
        [envelope.releaseRef],
      )
      return { imported: false, releaseRef: envelope.releaseRef, changeIds: [], manifest }
    }

    const changeIds = []
    for (const change of Array.isArray(envelope.changes) ? envelope.changes : []) {
      const featureKey = String(change?.featureKey || '').trim().toLowerCase() || null
      if (featureKey && change?.feature) {
        await db.query(
          `INSERT INTO platform_feature_definitions
            (feature_key,title,description,component,default_enabled,status)
           VALUES ($1,$2,$3,$4,false,'active')
           ON CONFLICT (feature_key) DO UPDATE
           SET title=EXCLUDED.title,description=EXCLUDED.description,component=EXCLUDED.component,status='active',updated_at=now()`,
          [
            featureKey,
            String(change.feature.title || change.title || featureKey).slice(0,180),
            String(change.feature.description || '').slice(0,4000),
            String(change.feature.component || change.component || 'platform').slice(0,80),
          ],
        )
      }

      const upserted = await db.query(
        `INSERT INTO platform_release_changes
          (change_key,title,description,component,feature_key,source_ref,version,risk,state)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'ready_for_test')
         ON CONFLICT (change_key) DO UPDATE
         SET title=EXCLUDED.title,description=EXCLUDED.description,component=EXCLUDED.component,
             feature_key=EXCLUDED.feature_key,source_ref=EXCLUDED.source_ref,version=EXCLUDED.version,
             risk=EXCLUDED.risk,
             state=CASE
               WHEN platform_release_changes.state='promoted' THEN platform_release_changes.state
               ELSE 'ready_for_test'
             END,
             updated_at=now()
         RETURNING id`,
        [
          String(change.changeKey || '').slice(0,80),
          String(change.title || change.changeKey || 'Release change').slice(0,220),
          String(change.description || '').slice(0,8000),
          String(change.component || 'platform').slice(0,80),
          featureKey,
          String(change.sourceRef || envelope.releaseRef || '').slice(0,300),
          String(change.version || '').slice(0,120),
          ['low','medium','high'].includes(String(change.risk)) ? String(change.risk) : 'medium',
        ],
      )
      changeIds.push(upserted.rows[0].id)
    }

    await db.query(
      `INSERT INTO platform_release_feed_receipts
        (release_ref,channel,envelope,signature,source_url)
       VALUES ($1,$2,$3::jsonb,$4,$5)`,
      [envelope.releaseRef,channel,JSON.stringify(envelope),signature,sourceUrl],
    )
    await db.query(
      `UPDATE platform_release_preferences
          SET last_feed_sync_at=now(),last_release_seen=$1,updated_at=now()
        WHERE preference_key='deployment'`,
      [envelope.releaseRef],
    )
    return { imported: true, releaseRef: envelope.releaseRef, changeIds, manifest }
  })
}

export async function syncReleaseFeed() {
  if (deployment.deploymentMode !== 'self_hosted' || deployment.runtimeEnvironment !== 'live') return { skipped: true }
  const preferenceResult = await pool.query(
    `SELECT * FROM platform_release_preferences WHERE preference_key='deployment' LIMIT 1`,
  )
  const preference = preferenceResult.rows[0]
  if (!preference) return { skipped: true }

  const channel = String(preference.release_channel || 'stable')
  const sourceUrl = feedUrl()
  const feed = await fetchFeed(channel)
  if (!feed) {
    await pool.query(
      `UPDATE platform_release_preferences SET last_feed_sync_at=now(),updated_at=now()
        WHERE preference_key='deployment'`,
    )
    return { imported: false, empty: true }
  }

  const imported = await importFeedPayload(feed, channel, sourceUrl)
  if (!imported.imported || !preference.test_auto_sync) return imported

  const duplicate = await pool.query(
    `SELECT id FROM platform_environment_actions
      WHERE environment='test' AND action='deploy'
        AND status IN ('requested','running')
        AND payload->>'releaseRef'=$1
      LIMIT 1`,
    [imported.releaseRef],
  )
  if (!duplicate.rowCount) {
    await pool.query(
      `INSERT INTO platform_environment_actions
        (environment,action,payload,not_before)
       VALUES ('test','deploy',$1::jsonb,now())`,
      [JSON.stringify({
        releaseRef: imported.releaseRef,
        changeIds: imported.changeIds,
        manifest: imported.manifest,
        source: 'signed-release-feed',
        channel,
      })],
    )
  }
  return imported
}

let feedTimer = null
export function startReleaseFeedScheduler() {
  if (feedTimer || deployment.deploymentMode !== 'self_hosted' || deployment.runtimeEnvironment !== 'live') return
  const requested = Number(process.env.RELEASE_FEED_SYNC_INTERVAL_MS || 6 * 60 * 60 * 1000)
  const interval = Math.max(15 * 60 * 1000, Number.isFinite(requested) ? requested : 6 * 60 * 60 * 1000)
  const run = () => syncReleaseFeed().catch((error) => {
    console.warn(`Release feed sync deferred: ${error?.message || error}`)
  })
  feedTimer = setInterval(run, interval)
  feedTimer.unref?.()
  const initialRequested = Number(process.env.RELEASE_FEED_INITIAL_SYNC_DELAY_MS || 45000)
  const initialDelay = Math.max(5000, Number.isFinite(initialRequested) ? initialRequested : 45000)
  const initial = setTimeout(run, initialDelay)
  initial.unref?.()
}

export const releaseFeedInternals = {
  signEnvelope,
  verifyEnvelope,
  cleanManifest,
  validManifest,
}
