import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { recordRmmActivity } from './rmmActivity.js'
import {
  microsoftBitLockerRecoveryKeysForInventory,
  revealMicrosoftBitLockerRecoveryKeyForInventory,
} from './microsoftIntegration.js'
import { resolveSession } from './session.js'

function clean(value = '', max = 2048) { return String(value ?? '').trim().slice(0, max) }
function hash(value = '') { return createHash('sha256').update(String(value)).digest('hex') }

function recoveryEncryptionKey() {
  const dedicated = clean(process.env.RMM_RECOVERY_KEY_ENCRYPTION_KEY || '', 1024)
  if (!dedicated) {
    const error = new Error('RMM recovery-key encryption is not configured.')
    error.status = 503
    throw error
  }
  let key = null
  if (/^[0-9a-f]{64}$/i.test(dedicated)) key = Buffer.from(dedicated, 'hex')
  else {
    try { key = Buffer.from(dedicated, 'base64url') } catch { key = null }
  }
  if (!key || key.length !== 32) {
    const error = new Error('RMM_RECOVERY_KEY_ENCRYPTION_KEY must contain exactly 32 bytes of key material.')
    error.status = 503
    throw error
  }
  return key
}

function encryptRecoveryPassword(password) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', recoveryEncryptionKey(), iv)
  const ciphertext = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `v1.${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`
}

function decryptRecoveryPassword(envelope) {
  const [version, ivValue, tagValue, ciphertextValue] = clean(envelope, 8192).split('.')
  if (version !== 'v1' || !ivValue || !tagValue || !ciphertextValue) throw new Error('Stored BitLocker recovery key is invalid.')
  const decipher = createDecipheriv('aes-256-gcm', recoveryEncryptionKey(), Buffer.from(ivValue, 'base64url'))
  decipher.setAuthTag(Buffer.from(tagValue, 'base64url'))
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextValue, 'base64url')),
    decipher.final(),
  ]).toString('utf8')
}

function validRecoveryPassword(value) {
  return /^\d{6}(?:-\d{6}){7}$/.test(clean(value, 128))
}

function recoveryProtectorIds(payload = {}) {
  const volumes = Array.isArray(payload?.security?.bitlocker) ? payload.security.bitlocker : []
  const ids = []
  for (const volume of volumes) {
    const protectors = Array.isArray(volume?.key_protectors) ? volume.key_protectors : []
    for (const protector of protectors) {
      if (clean(protector?.type, 64).toLowerCase() !== 'recoverypassword') continue
      const protectorId = clean(protector?.id, 256)
      if (protectorId) ids.push(protectorId)
    }
  }
  return [...new Set(ids)]
}

export async function bitLockerRecoveryEscrowNeeded(agent, inventoryPayload = {}) {
  const protectorIds = recoveryProtectorIds(inventoryPayload)
  if (!protectorIds.length) return false
  const result = await pool.query(
    `SELECT protector_id
       FROM rmm_bitlocker_recovery_keys
      WHERE tenant_id=$1 AND agent_device_id=$2 AND revoked_at IS NULL
        AND protector_id=ANY($3::text[])`,
    [agent.tenant_id, agent.id, protectorIds],
  )
  const escrowed = new Set(result.rows.map((row) => clean(row.protector_id, 256)))
  return protectorIds.some((id) => !escrowed.has(id))
}

export async function ingestBitLockerRecoveryEscrow(agent, payload = {}) {
  const entries = Array.isArray(payload.entries) ? payload.entries : []
  const accepted = []
  for (const item of entries.slice(0, 32)) {
    const drive = clean(item?.drive, 32)
    const protectorId = clean(item?.protector_id || item?.protectorId, 256)
    const protectorType = clean(item?.protector_type || item?.protectorType || 'RecoveryPassword', 64)
    const password = clean(item?.recovery_password || item?.recoveryPassword, 128)
    if (!drive || !protectorId || protectorType.toLowerCase() !== 'recoverypassword' || !validRecoveryPassword(password)) continue
    accepted.push({ drive, protectorId, protectorType, password })
  }
  if (!accepted.length) return { accepted: 0 }

  await withTransaction(async (client) => {
    for (const item of accepted) {
      const passwordHash = hash(item.password)
      await client.query(
        `UPDATE rmm_bitlocker_recovery_keys
            SET revoked_at=COALESCE(revoked_at,now()),updated_at=now()
          WHERE tenant_id=$1 AND agent_device_id=$2 AND lower(drive)=lower($3)
            AND protector_id<>$4 AND revoked_at IS NULL`,
        [agent.tenant_id, agent.id, item.drive, item.protectorId],
      )
      await client.query(
        `INSERT INTO rmm_bitlocker_recovery_keys
           (tenant_id,agent_device_id,inventory_id,drive,protector_id,protector_type,recovery_password_encrypted,recovery_password_hash,source,first_escrowed_at,last_seen_at,updated_at,revoked_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'agent_escrow',now(),now(),now(),NULL)
         ON CONFLICT (tenant_id,agent_device_id,protector_id) DO UPDATE SET
           inventory_id=EXCLUDED.inventory_id,
           drive=EXCLUDED.drive,
           protector_type=EXCLUDED.protector_type,
           recovery_password_encrypted=CASE
             WHEN rmm_bitlocker_recovery_keys.recovery_password_hash<>EXCLUDED.recovery_password_hash THEN EXCLUDED.recovery_password_encrypted
             ELSE rmm_bitlocker_recovery_keys.recovery_password_encrypted
           END,
           recovery_password_hash=EXCLUDED.recovery_password_hash,
           source='agent_escrow',last_seen_at=now(),updated_at=now(),revoked_at=NULL`,
        [agent.tenant_id, agent.id, agent.inventory_id, item.drive, item.protectorId, item.protectorType, encryptRecoveryPassword(item.password), passwordHash],
      )
    }
  })
  return { accepted: accepted.length }
}

async function requireDeviceView(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (!hasPermission(session.access, 'rmm.devices.view') && !hasPermission(session.access, 'rmm.devices.control')) {
    return { error: c.json({ error: 'You do not have permission to view RMM devices.' }, 403) }
  }
  return { session }
}

async function managedAgent(tenantId, agentDeviceId) {
  const result = await pool.query(
    `SELECT a.id,a.inventory_id,i.name,i.reference
       FROM rmm_agent_devices a
       JOIN rmm_device_inventory i ON i.id=a.inventory_id
      WHERE a.id::text=$1 AND a.tenant_id=$2 AND a.disabled_at IS NULL AND i.active=true LIMIT 1`,
    [clean(agentDeviceId, 128), tenantId],
  )
  return result.rows[0] || null
}

export function registerRmmRecoveryKeyRoutes(app) {
  app.get('/api/v1/rmm/devices/:agentDeviceId/bitlocker-recovery', async (c) => {
    const auth = await requireDeviceView(c)
    if (auth.error) return auth.error
    const device = await managedAgent(auth.session.tenant_id, c.req.param('agentDeviceId'))
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const result = await pool.query(
      `SELECT id,drive,protector_id,protector_type,source,first_escrowed_at,last_seen_at,last_revealed_at,reveal_count,revoked_at
         FROM rmm_bitlocker_recovery_keys
        WHERE tenant_id=$1 AND agent_device_id=$2
        ORDER BY revoked_at NULLS FIRST,last_seen_at DESC`,
      [auth.session.tenant_id, device.id],
    )
    let entra = { linked: false, status: 'not_linked', keys: [] }
    try {
      entra = await microsoftBitLockerRecoveryKeysForInventory(auth.session.tenant_id, device.inventory_id)
    } catch (error) {
      entra = { linked: true, status: 'error', keys: [], error: clean(error?.message || 'Microsoft recovery-key lookup failed.', 500) }
    }
    return c.json({
      canReveal: hasPermission(auth.session.access, 'rmm.security.recovery_keys.read'),
      entra,
      items: result.rows.map((row) => ({
        id: row.id,
        drive: row.drive,
        protectorId: row.protector_id,
        protectorType: row.protector_type,
        source: row.source,
        escrowedAt: row.first_escrowed_at,
        lastSeenAt: row.last_seen_at,
        lastRevealedAt: row.last_revealed_at,
        revealCount: Number(row.reveal_count || 0),
        active: !row.revoked_at,
      })),
    })
  })

  app.post('/api/v1/rmm/devices/:agentDeviceId/bitlocker-recovery/:keyId/reveal', async (c) => {
    const auth = await requireDeviceView(c)
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.security.recovery_keys.read')) {
      return c.json({ error: 'You do not have permission to reveal BitLocker recovery keys.' }, 403)
    }
    const device = await managedAgent(auth.session.tenant_id, c.req.param('agentDeviceId'))
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const body = await c.req.json().catch(() => ({}))
    const reason = clean(body.reason, 500)
    if (reason.length < 3) return c.json({ error: 'Enter a reason for revealing this BitLocker recovery key.' }, 400)
    const result = await pool.query(
      `SELECT id,drive,protector_id,recovery_password_encrypted,source,revoked_at
         FROM rmm_bitlocker_recovery_keys
        WHERE id::text=$1 AND tenant_id=$2 AND agent_device_id=$3 LIMIT 1`,
      [clean(c.req.param('keyId'), 128), auth.session.tenant_id, device.id],
    )
    const row = result.rows[0]
    if (!row || row.revoked_at) return c.json({ error: 'Active recovery key not found.' }, 404)
    let recoveryPassword
    try { recoveryPassword = decryptRecoveryPassword(row.recovery_password_encrypted) }
    catch (error) { return c.json({ error: error?.message || 'Unable to decrypt this recovery key.' }, 503) }

    await pool.query(
      `UPDATE rmm_bitlocker_recovery_keys SET last_revealed_at=now(),reveal_count=reveal_count+1,updated_at=now() WHERE id=$1`,
      [row.id],
    )
    await recordRmmActivity({
      tenantId: auth.session.tenant_id,
      agentDeviceId: device.id,
      inventoryId: device.inventory_id,
      actorUserId: auth.session.user_id,
      actorType: 'technician',
      actorLabel: clean(auth.session.name || auth.session.email || 'Technician', 255),
      eventType: 'bitlocker.recovery_key.revealed',
      category: 'security',
      summary: `${clean(auth.session.name || auth.session.email || 'Technician', 255)} revealed a BitLocker recovery key`,
      detail: `${row.drive} · Protector ${row.protector_id} · Reason: ${reason}`,
      outcome: 'success',
      severity: 'warning',
      metadata: { recoveryKeyId: row.id, drive: row.drive, protectorId: row.protector_id, source: row.source, reason },
    }).catch(() => {})
    c.header('Cache-Control', 'no-store, private')
    c.header('Pragma', 'no-cache')
    return c.json({ id: row.id, drive: row.drive, protectorId: row.protector_id, recoveryPassword })
  })

  app.post('/api/v1/rmm/devices/:agentDeviceId/bitlocker-recovery/entra/:keyId/reveal', async (c) => {
    const auth = await requireDeviceView(c)
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.security.recovery_keys.read')) {
      return c.json({ error: 'You do not have permission to reveal BitLocker recovery keys.' }, 403)
    }
    const device = await managedAgent(auth.session.tenant_id, c.req.param('agentDeviceId'))
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const body = await c.req.json().catch(() => ({}))
    const reason = clean(body.reason, 500)
    if (reason.length < 3) return c.json({ error: 'Enter a reason for revealing this BitLocker recovery key.' }, 400)
    let revealed
    try {
      revealed = await revealMicrosoftBitLockerRecoveryKeyForInventory(
        auth.session.tenant_id,
        device.inventory_id,
        clean(c.req.param('keyId'), 128),
      )
    } catch (error) {
      return c.json({ error: error?.message || 'Microsoft Entra recovery key could not be revealed.' }, Number(error?.status) || 502)
    }
    if (!validRecoveryPassword(revealed.recoveryPassword)) {
      return c.json({ error: 'Microsoft Entra returned an invalid BitLocker recovery password.' }, 502)
    }
    const actorLabel = clean(auth.session.name || auth.session.email || 'Technician', 255)
    await recordRmmActivity({
      tenantId: auth.session.tenant_id,
      agentDeviceId: device.id,
      inventoryId: device.inventory_id,
      actorUserId: auth.session.user_id,
      actorType: 'technician',
      actorLabel,
      eventType: 'bitlocker.recovery_key.revealed',
      category: 'security',
      summary: `${actorLabel} revealed a Microsoft Entra BitLocker recovery key`,
      detail: `Microsoft Entra · Key ${revealed.id} · Reason: ${reason}`,
      outcome: 'success',
      severity: 'warning',
      metadata: {
        recoveryKeyId: revealed.id,
        source: 'microsoft_entra',
        connectionName: revealed.connectionName || '',
        deviceId: revealed.deviceId || '',
        volumeType: revealed.volumeType || null,
        reason,
      },
    }).catch(() => {})
    c.header('Cache-Control', 'no-store, private')
    c.header('Pragma', 'no-cache')
    return c.json({
      id: revealed.id,
      source: 'microsoft_entra',
      recoveryPassword: revealed.recoveryPassword,
      createdDateTime: revealed.createdDateTime,
      volumeType: revealed.volumeType,
    })
  })

}
