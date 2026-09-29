import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { ensureDefaultRoles, hasPermission } from './access.js'
import { deployment, originMatchesTenant, tenantUrls } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { hashPassword } from './password.js'
import { ensureRedisConnected } from './redis.js'
import { createSession, resolveSession, setPortalSessionCookie, setSessionCookie } from './session.js'

const CLIENT_ID = String(process.env.MICROSOFT_CLIENT_ID || '').trim()
function microsoftClientSecret() {
  const secretFile = String(process.env.MICROSOFT_CLIENT_SECRET_FILE || '').trim()
  if (secretFile) {
    try { return String(readFileSync(secretFile, 'utf8') || '').trim() } catch { /* Fall back to legacy env configuration. */ }
  }
  return String(process.env.MICROSOFT_CLIENT_SECRET || '').trim()
}
const CLIENT_SECRET = microsoftClientSecret()
const CALLBACK_URI = String(process.env.MICROSOFT_REDIRECT_URI || `${deployment.apiUrl}/api/v1/auth/microsoft/callback`).trim()
const GRAPH_BASE = 'https://graph.microsoft.com/v1.0'
const STATE_TTL_SECONDS = 600
const MICROSOFT_PROVIDER = 'microsoft_entra'

function connectorConfigured() { return Boolean(CLIENT_ID && CLIENT_SECRET && CALLBACK_URI) }
function credentialPreview(value = '') {
  const normalized = String(value || '').trim()
  return normalized ? `${normalized.slice(0, 4)}••••••••` : null
}
function normaliseEmail(value = '') { return String(value || '').trim().toLowerCase() }
function clean(value = '') { return String(value ?? '').trim() }
function hashText(value = '') { return createHash('sha256').update(String(value)).digest('hex').slice(0, 16) }
function randomToken(bytes = 32) { return randomBytes(bytes).toString('base64url') }
function stateKey(state) { return `microsoft-oauth:${state}` }
function isGuid(value = '') { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value)) }

async function storeState(payload) {
  const redis = await ensureRedisConnected()
  const state = randomToken(24)
  await redis.set(stateKey(state), JSON.stringify(payload), { EX: STATE_TTL_SECONDS })
  return state
}

async function consumeState(state) {
  if (!state) return null
  const redis = await ensureRedisConnected()
  const key = stateKey(state)
  const raw = await redis.get(key)
  if (!raw) return null
  await redis.del(key)
  try { return JSON.parse(raw) } catch { return null }
}

async function requireIntegrationManager(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (!hasPermission(session.access, 'integrations.manage') && !hasPermission(session.access, 'settings.integrations.manage')) {
    return { error: c.json({ error: 'You do not have permission to manage integrations.' }, 403) }
  }
  return { session }
}

async function clientCredentialToken(directoryTenantId) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    grant_type: 'client_credentials',
    scope: 'https://graph.microsoft.com/.default',
  })
  const response = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(directoryTenantId)}/oauth2/v2.0/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok || !payload.access_token) throw new Error(payload.error_description || payload.error || 'Microsoft token request failed.')
  return payload.access_token
}

async function bitLockerGraphRequest(token, path) {
  const url = path.startsWith('http') ? path : `${GRAPH_BASE}${path}`
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
      'User-Agent': 'Hi5Central-RMM/1.0',
      'ocp-client-name': 'Hi5Central RMM',
      'ocp-client-version': '1.0',
    },
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    const message = payload?.error?.message || payload?.error?.code || `Microsoft Graph request failed (${response.status}).`
    const error = new Error(message)
    error.status = response.status
    error.graphCode = payload?.error?.code || ''
    throw error
  }
  return payload
}

async function linkedIntuneIdentity(tenantId, agentInventoryId) {
  const result = await pool.query(
    `SELECT d.directory_device_id,d.microsoft_connection_id,c.directory_tenant_id,c.connection_name
       FROM rmm_device_inventory agent
       JOIN LATERAL (
         SELECT candidate.*
           FROM rmm_device_inventory candidate
          WHERE candidate.tenant_id=agent.tenant_id
            AND candidate.source='intune'
            AND candidate.active=true
            AND candidate.microsoft_connection_id IS NOT NULL
            AND COALESCE(candidate.directory_device_id,'')<>''
            AND (
              (COALESCE(agent.serial_number,'')<>'' AND lower(candidate.serial_number)=lower(agent.serial_number))
              OR lower(candidate.name)=lower(agent.name)
            )
          ORDER BY
            CASE WHEN COALESCE(agent.serial_number,'')<>'' AND lower(candidate.serial_number)=lower(agent.serial_number) THEN 0 ELSE 1 END,
            candidate.last_imported_at DESC NULLS LAST
          LIMIT 1
       ) d ON true
       JOIN tenant_microsoft_connections c
         ON c.id=d.microsoft_connection_id
        AND c.tenant_id=agent.tenant_id
        AND c.status='connected'
      WHERE agent.id=$1 AND agent.tenant_id=$2
      LIMIT 1`,
    [agentInventoryId, tenantId],
  )
  return result.rows[0] || null
}

export async function microsoftBitLockerRecoveryKeysForInventory(tenantId, agentInventoryId) {
  const identity = await linkedIntuneIdentity(tenantId, agentInventoryId)
  if (!identity) return { linked: false, status: 'not_linked', keys: [] }
  const token = await clientCredentialToken(identity.directory_tenant_id)
  const query = new URL(`${GRAPH_BASE}/informationProtection/bitlocker/recoveryKeys`)
  query.searchParams.set('$filter', `deviceId eq '${identity.directory_device_id}'`)
  query.searchParams.set('$select', 'id,createdDateTime,deviceId,volumeType')
  try {
    const payload = await bitLockerGraphRequest(token, query.toString())
    return {
      linked: true,
      status: 'available',
      connectionName: identity.connection_name,
      directoryDeviceId: identity.directory_device_id,
      keys: (Array.isArray(payload.value) ? payload.value : []).map((item) => ({
        id: clean(item.id),
        createdDateTime: item.createdDateTime || null,
        deviceId: clean(item.deviceId),
        volumeType: item.volumeType || null,
      })),
    }
  } catch (error) {
    if ([401, 403].includes(Number(error.status))) {
      return {
        linked: true,
        status: 'permission_required',
        connectionName: identity.connection_name,
        directoryDeviceId: identity.directory_device_id,
        keys: [],
      }
    }
    throw error
  }
}

export async function revealMicrosoftBitLockerRecoveryKeyForInventory(tenantId, agentInventoryId, keyId) {
  const identity = await linkedIntuneIdentity(tenantId, agentInventoryId)
  if (!identity) {
    const error = new Error('This endpoint is not linked to an active Microsoft Intune device.')
    error.status = 404
    throw error
  }
  const token = await clientCredentialToken(identity.directory_tenant_id)
  const list = await microsoftBitLockerRecoveryKeysForInventory(tenantId, agentInventoryId)
  const allowed = list.keys.some((item) => clean(item.id).toLowerCase() === clean(keyId).toLowerCase())
  if (!allowed) {
    const error = new Error(list.status === 'permission_required'
      ? 'Microsoft BitLocker recovery permission has not been granted to Hi5Central.'
      : 'Microsoft Entra recovery key was not found for this device.')
    error.status = list.status === 'permission_required' ? 403 : 404
    throw error
  }
  const query = new URL(`${GRAPH_BASE}/informationProtection/bitlocker/recoveryKeys/${encodeURIComponent(clean(keyId))}`)
  query.searchParams.set('$select', 'id,key,createdDateTime,deviceId,volumeType')
  const payload = await bitLockerGraphRequest(token, query.toString())
  return {
    id: clean(payload.id || keyId),
    recoveryPassword: clean(payload.key),
    createdDateTime: payload.createdDateTime || null,
    deviceId: clean(payload.deviceId || identity.directory_device_id),
    volumeType: payload.volumeType || null,
    connectionName: identity.connection_name,
  }
}

async function graphCollection(token, path) {
  const rows = []
  let url = path.startsWith('http') ? path : `${GRAPH_BASE}${path}`
  while (url) {
    const response = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) {
      const message = payload?.error?.message || payload?.error?.code || `Microsoft Graph request failed (${response.status}).`
      const error = new Error(message)
      error.status = response.status
      error.graphCode = payload?.error?.code || ''
      throw error
    }
    rows.push(...(Array.isArray(payload.value) ? payload.value : []))
    url = payload['@odata.nextLink'] || ''
  }
  return rows
}

async function upsertDepartment(client, tenantId, name) {
  const value = clean(name)
  if (!value) return null
  const source = { provider: 'microsoft365', label: 'Microsoft 365 / Entra ID', managedFields: ['name'], externalId: `department:${value}` }
  const result = await client.query(
    `INSERT INTO organisation_departments (tenant_id,external_key,name,source,active)
     VALUES ($1,$2,$3,$4::jsonb,true)
     ON CONFLICT (tenant_id,name) DO UPDATE SET source=EXCLUDED.source,active=true,updated_at=now()
     RETURNING id`,
    [tenantId, `entra-dept:${hashText(value.toLowerCase())}`, value, JSON.stringify(source)],
  )
  return result.rows[0]?.id || null
}

async function upsertSite(client, tenantId, name) {
  const value = clean(name)
  if (!value) return null
  const source = { provider: 'microsoft365', label: 'Microsoft 365 / Entra ID', managedFields: ['name'], externalId: `office:${value}` }
  const code = `MS-${hashText(value.toLowerCase()).slice(0, 8).toUpperCase()}`
  const result = await client.query(
    `INSERT INTO organisation_sites (tenant_id,external_key,code,name,source,active)
     VALUES ($1,$2,$3,$4,$5::jsonb,true)
     ON CONFLICT (tenant_id,name) DO UPDATE SET source=EXCLUDED.source,active=true,updated_at=now()
     RETURNING id`,
    [tenantId, `entra-site:${hashText(value.toLowerCase())}`, code, value, JSON.stringify(source)],
  )
  return result.rows[0]?.id || null
}

async function syncDirectoryUsers(client, tenantId, connection, graphUsers) {
  const byObjectId = new Map()
  const byEmail = new Map()
  let imported = 0
  let updated = 0

  for (const user of graphUsers) {
    const email = normaliseEmail(user.mail || user.userPrincipalName)
    if (!email || !user.id) continue
    const departmentId = await upsertDepartment(client, tenantId, user.department)
    const siteId = await upsertSite(client, tenantId, user.officeLocation)
    const phone = clean(user.mobilePhone || (Array.isArray(user.businessPhones) ? user.businessPhones[0] : ''))
    const source = {
      provider: 'microsoft365', label: connection.connection_name || 'Microsoft 365 / Entra ID', externalId: user.id,
      directoryTenantId: connection.directory_tenant_id, connectionId: connection.id,
      managedFields: ['name','email','phone','jobTitle','department','site','active'], lastSyncedAt: new Date().toISOString(),
    }
    const existing = await client.query(
      `SELECT p.id,p.external_key
       FROM organisation_people p
       LEFT JOIN organisation_person_external_identities x
         ON x.tenant_id=p.tenant_id AND x.person_id=p.id AND x.provider=$3 AND x.issuer_tenant_id=$4 AND x.object_id=$5
       WHERE p.tenant_id=$1 AND (x.id IS NOT NULL OR lower(p.email)=lower($2))
       ORDER BY CASE WHEN x.id IS NOT NULL THEN 0 ELSE 1 END LIMIT 1`,
      [tenantId, email, MICROSOFT_PROVIDER, connection.directory_tenant_id, user.id],
    )
    let personId
    if (existing.rowCount) {
      personId = existing.rows[0].id
      await client.query(
        `UPDATE organisation_people SET name=$3,email=$4,phone=$5,job_title=$6,department_id=$7,site_id=$8,
         directory_source=$9::jsonb,active=$10,updated_at=now() WHERE tenant_id=$1 AND id=$2`,
        [tenantId, personId, clean(user.displayName) || email, email, phone, clean(user.jobTitle), departmentId, siteId, JSON.stringify(source), user.accountEnabled !== false],
      )
      updated += 1
    } else {
      const inserted = await client.query(
        `INSERT INTO organisation_people
         (tenant_id,external_key,name,email,phone,job_title,department_id,site_id,directory_source,active)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10) RETURNING id`,
        [tenantId, `entra:${connection.id}:${user.id}`, clean(user.displayName) || email, email, phone, clean(user.jobTitle), departmentId, siteId, JSON.stringify(source), user.accountEnabled !== false],
      )
      personId = inserted.rows[0].id
      imported += 1
    }
    await client.query(
      `INSERT INTO organisation_person_external_identities
       (tenant_id,person_id,provider,microsoft_connection_id,issuer_tenant_id,object_id,principal_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (tenant_id,provider,issuer_tenant_id,object_id) DO UPDATE
       SET person_id=EXCLUDED.person_id,microsoft_connection_id=EXCLUDED.microsoft_connection_id,principal_name=EXCLUDED.principal_name,updated_at=now()`,
      [tenantId, personId, MICROSOFT_PROVIDER, connection.id, connection.directory_tenant_id, user.id, email],
    )
    const explicitlyLinked = await client.query(
      `SELECT user_id FROM user_external_identities
       WHERE tenant_id=$1 AND provider=$2 AND issuer_tenant_id=$3 AND object_id=$4 LIMIT 1`,
      [tenantId, MICROSOFT_PROVIDER, connection.directory_tenant_id, user.id],
    )
    let userId = explicitlyLinked.rows[0]?.user_id || null
    if (!userId) {
      let userResult = await client.query('SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1', [email])
      userId = userResult.rows[0]?.id || null
      if (!userId) {
        const passwordHash = await hashPassword(randomToken(48))
        userResult = await client.query(
          'INSERT INTO users (email,name,password_hash,email_verified_at) VALUES ($1,$2,$3,now()) RETURNING id',
          [email, clean(user.displayName) || email, passwordHash],
        )
        userId = userResult.rows[0].id
      }
    }
    const membership = await client.query(
      'SELECT role,status FROM tenant_memberships WHERE tenant_id=$1 AND user_id=$2 LIMIT 1',
      [tenantId, userId],
    )
    let membershipRole = membership.rows[0]?.role || null
    if (!membership.rowCount) {
      await client.query("INSERT INTO tenant_memberships (tenant_id,user_id,role,status) VALUES ($1,$2,'requester','active')", [tenantId, userId])
      membershipRole = 'requester'
    }
    if (membershipRole === 'requester') {
      await ensureDefaultRoles(client, tenantId)
      await client.query(
        `INSERT INTO access_user_roles (tenant_id,user_id,role_id)
         SELECT $1,$2,id FROM access_roles WHERE tenant_id=$1 AND system_key='requester' AND active=true
         ON CONFLICT DO NOTHING`,
        [tenantId, userId],
      )
    }
    await client.query(
      'UPDATE organisation_people SET user_id=$3,updated_at=now() WHERE tenant_id=$1 AND id=$2',
      [tenantId, personId, userId],
    )
    byObjectId.set(user.id, personId)
    byEmail.set(email, personId)
  }
  return { byObjectId, byEmail, imported, updated }
}

function deviceReference(connectionId, id) {
  const connectionPart = hashText(connectionId).slice(0, 4).toUpperCase()
  const devicePart = String(id || '').replace(/[^a-z0-9]/gi, '').slice(0, 10).toUpperCase()
  return `INTUNE-${connectionPart}-${devicePart}`
}

async function syncDevices(client, tenantId, connection, runId, graphDevices, people) {
  let imported = 0
  let updated = 0
  for (const device of graphDevices) {
    if (!device?.id) continue
    const email = normaliseEmail(device.userPrincipalName || device.emailAddress)
    const personId = people.byObjectId.get(device.userId) || people.byEmail.get(email) || null
    const values = [
      tenantId, connection.id, device.id, deviceReference(connection.id, device.id), clean(device.azureADDeviceId) || null,
      clean(device.deviceName || device.managedDeviceName) || `Intune device ${device.id.slice(0, 8)}`,
      clean(device.operatingSystem) || 'Unknown', clean(device.operatingSystem), clean(device.osVersion), clean(device.manufacturer), clean(device.model), clean(device.serialNumber),
      clean(device.userId) || null, personId, clean(device.userDisplayName), email, clean(device.managedDeviceOwnerType) || 'unknown', clean(device.complianceState) || 'unknown',
      clean(device.managementState) || 'managed', clean(device.managementAgent), clean(device.deviceEnrollmentType), clean(device.deviceRegistrationState), clean(device.deviceCategoryDisplayName),
      typeof device.isEncrypted === 'boolean' ? device.isEncrypted : null, Number.isFinite(Number(device.physicalMemoryInBytes)) ? Number(device.physicalMemoryInBytes) : null,
      Number.isFinite(Number(device.totalStorageSpaceInBytes)) ? Number(device.totalStorageSpaceInBytes) : null,
      Number.isFinite(Number(device.freeStorageSpaceInBytes)) ? Number(device.freeStorageSpaceInBytes) : null,
      clean(device.ethernetMacAddress), clean(device.wiFiMacAddress), device.enrolledDateTime || null, device.lastSyncDateTime || null,
      runId, JSON.stringify(device),
    ]
    const result = await client.query(
      `INSERT INTO rmm_device_inventory
       (tenant_id,microsoft_connection_id,source,source_device_id,reference,directory_device_id,name,platform,operating_system,os_version,manufacturer,model,serial_number,user_id_external,assigned_person_id,user_display_name,user_principal_name,owner_type,compliance_state,management_state,management_agent,enrollment_type,registration_state,category_name,is_encrypted,memory_bytes,storage_total_bytes,storage_free_bytes,ethernet_mac,wifi_mac,enrolled_at,source_last_sync_at,last_imported_at,last_seen_sync_run_id,active,source_payload)
       VALUES ($1,$2,'intune',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,now(),$32,true,$33::jsonb)
       ON CONFLICT (tenant_id,microsoft_connection_id,source_device_id) WHERE source='intune' DO UPDATE SET
       directory_device_id=EXCLUDED.directory_device_id,name=EXCLUDED.name,platform=EXCLUDED.platform,operating_system=EXCLUDED.operating_system,os_version=EXCLUDED.os_version,
       manufacturer=EXCLUDED.manufacturer,model=EXCLUDED.model,serial_number=EXCLUDED.serial_number,user_id_external=EXCLUDED.user_id_external,assigned_person_id=EXCLUDED.assigned_person_id,
       user_display_name=EXCLUDED.user_display_name,user_principal_name=EXCLUDED.user_principal_name,owner_type=EXCLUDED.owner_type,compliance_state=EXCLUDED.compliance_state,
       management_state=EXCLUDED.management_state,management_agent=EXCLUDED.management_agent,enrollment_type=EXCLUDED.enrollment_type,registration_state=EXCLUDED.registration_state,
       category_name=EXCLUDED.category_name,is_encrypted=EXCLUDED.is_encrypted,memory_bytes=EXCLUDED.memory_bytes,storage_total_bytes=EXCLUDED.storage_total_bytes,
       storage_free_bytes=EXCLUDED.storage_free_bytes,ethernet_mac=EXCLUDED.ethernet_mac,wifi_mac=EXCLUDED.wifi_mac,enrolled_at=EXCLUDED.enrolled_at,
       source_last_sync_at=EXCLUDED.source_last_sync_at,last_imported_at=now(),last_seen_sync_run_id=EXCLUDED.last_seen_sync_run_id,active=true,source_payload=EXCLUDED.source_payload,updated_at=now()
       RETURNING (xmax = 0) AS inserted`,
      values,
    )
    if (result.rows[0]?.inserted) imported += 1
    else updated += 1
  }
  const deactivated = await client.query(
    `UPDATE rmm_device_inventory SET active=false,updated_at=now()
     WHERE tenant_id=$1 AND microsoft_connection_id=$2 AND source='intune' AND active=true AND last_seen_sync_run_id IS DISTINCT FROM $3`,
    [tenantId, connection.id, runId],
  )
  return { imported, updated, deactivated: deactivated.rowCount }
}

const USER_SELECT = 'id,displayName,userPrincipalName,mail,jobTitle,department,officeLocation,mobilePhone,businessPhones,accountEnabled'
const DEVICE_SELECT = 'id,userId,deviceName,managedDeviceName,managedDeviceOwnerType,managementState,enrolledDateTime,lastSyncDateTime,operatingSystem,complianceState,managementAgent,osVersion,emailAddress,azureADDeviceId,deviceRegistrationState,deviceCategoryDisplayName,isEncrypted,userPrincipalName,model,manufacturer,serialNumber,userDisplayName,totalStorageSpaceInBytes,freeStorageSpaceInBytes,ethernetMacAddress,wiFiMacAddress,physicalMemoryInBytes,deviceEnrollmentType'

export async function syncMicrosoftConnection(connectionId, startedByUserId = null) {
  const connectionResult = await pool.query('SELECT * FROM tenant_microsoft_connections WHERE id=$1 LIMIT 1', [connectionId])
  const connection = connectionResult.rows[0]
  if (!connection?.directory_tenant_id || connection.status !== 'connected') throw new Error('Microsoft 365 connection is not active.')
  const tenantId = connection.tenant_id
  const run = await pool.query(
    `INSERT INTO microsoft_sync_runs (tenant_id,microsoft_connection_id,sync_type,started_by_user_id) VALUES ($1,$2,'intune_devices',$3) RETURNING id`,
    [tenantId, connection.id, startedByUserId],
  )
  const runId = run.rows[0].id
  await pool.query(`UPDATE tenant_microsoft_connections SET last_sync_started_at=now(),last_sync_status='running',last_sync_error=NULL,updated_at=now() WHERE id=$1`, [connection.id])
  try {
    const token = await clientCredentialToken(connection.directory_tenant_id)
    const [graphUsers, graphDevices] = await Promise.all([
      graphCollection(token, `/users?$select=${encodeURIComponent(USER_SELECT)}&$top=999`),
      graphCollection(token, `/deviceManagement/managedDevices?$select=${encodeURIComponent(DEVICE_SELECT)}&$top=999`),
    ])
    const result = await withTransaction(async (client) => {
      const people = await syncDirectoryUsers(client, tenantId, connection, graphUsers)
      const devices = await syncDevices(client, tenantId, connection, runId, graphDevices, people)
      await client.query(
        `UPDATE microsoft_sync_runs SET status='completed',discovered_count=$2,imported_count=$3,updated_count=$4,deactivated_count=$5,completed_at=now() WHERE id=$1`,
        [runId, graphDevices.length, devices.imported, devices.updated, devices.deactivated],
      )
      await client.query(
        `UPDATE tenant_microsoft_connections SET intune_enabled=true,intune_sync_enabled=true,intune_status='ready',device_count=$2,last_validated_at=now(),last_sync_completed_at=now(),last_sync_status='completed',last_sync_error=NULL,updated_at=now() WHERE id=$1`,
        [connection.id, graphDevices.length],
      )
      return { users: graphUsers.length, peopleImported: people.imported, peopleUpdated: people.updated, devices: graphDevices.length, ...devices }
    })
    return { connectionId: connection.id, connectionName: connection.connection_name, directoryTenantId: connection.directory_tenant_id, runId, ...result }
  } catch (error) {
    await pool.query(`UPDATE microsoft_sync_runs SET status='failed',error_message=$2,completed_at=now() WHERE id=$1`, [runId, String(error.message || error).slice(0, 2000)]).catch(() => {})
    await pool.query(`UPDATE tenant_microsoft_connections SET intune_status='error',last_sync_completed_at=now(),last_sync_status='failed',last_sync_error=$2,updated_at=now() WHERE id=$1`, [connection.id, String(error.message || error).slice(0, 2000)]).catch(() => {})
    throw error
  }
}

export async function syncMicrosoftTenant(tenantId, startedByUserId = null) {
  const connections = await pool.query(`SELECT id FROM tenant_microsoft_connections WHERE tenant_id=$1 AND status='connected' AND intune_sync_enabled=true ORDER BY created_at`, [tenantId])
  if (!connections.rowCount) throw new Error('No active Microsoft 365 connections are available for this tenant.')
  const results = []
  for (const row of connections.rows) {
    try { results.push({ ok: true, ...(await syncMicrosoftConnection(row.id, startedByUserId)) }) }
    catch (error) { results.push({ ok: false, connectionId: row.id, error: error.message || 'Microsoft sync failed.' }) }
  }
  const totals = results.reduce((sum, item) => ({
    users: sum.users + Number(item.users || 0),
    devices: sum.devices + Number(item.devices || 0),
    imported: sum.imported + Number(item.imported || 0),
    updated: sum.updated + Number(item.updated || 0),
    deactivated: sum.deactivated + Number(item.deactivated || 0),
  }), { users: 0, devices: 0, imported: 0, updated: 0, deactivated: 0 })
  return { connections: results, ...totals, failedConnections: results.filter((item) => !item.ok).length }
}

async function microsoftStatus(tenantId) {
  const result = await pool.query(
    `SELECT c.id,c.connection_name,c.directory_tenant_id,c.status,c.sso_enabled,c.intune_enabled,c.intune_sync_enabled,
            c.intune_sync_interval_minutes,c.intune_status,c.device_count,c.last_validated_at,c.last_sync_started_at,c.last_sync_completed_at,
            c.last_sync_status,c.last_sync_error,c.admin_consent_at,c.created_at,
            r.id AS last_run_id,r.status AS last_run_status,r.discovered_count AS last_run_discovered_count,
            r.imported_count AS last_run_imported_count,r.updated_count AS last_run_updated_count,
            r.deactivated_count AS last_run_deactivated_count,r.error_message AS last_run_error,r.started_at AS last_run_started_at,r.completed_at AS last_run_completed_at
     FROM tenant_microsoft_connections c
     LEFT JOIN LATERAL (
       SELECT * FROM microsoft_sync_runs r WHERE r.microsoft_connection_id=c.id ORDER BY r.started_at DESC LIMIT 1
     ) r ON true
     WHERE c.tenant_id=$1 ORDER BY c.created_at,c.connection_name`, [tenantId],
  )
  const connections = result.rows.map((row) => ({
    id: row.id,
    connection_name: row.connection_name,
    directory_tenant_id: row.directory_tenant_id,
    status: row.status,
    sso_enabled: row.sso_enabled,
    intune_enabled: row.intune_enabled,
    intune_sync_enabled: row.intune_sync_enabled,
    intune_sync_interval_minutes: row.intune_sync_interval_minutes,
    intune_status: row.intune_status,
    device_count: row.device_count,
    last_validated_at: row.last_validated_at,
    last_sync_started_at: row.last_sync_started_at,
    last_sync_completed_at: row.last_sync_completed_at,
    last_sync_status: row.last_sync_status,
    last_sync_error: row.last_sync_error,
    admin_consent_at: row.admin_consent_at,
    lastRun: row.last_run_id ? {
      id: row.last_run_id, status: row.last_run_status, discovered_count: row.last_run_discovered_count,
      imported_count: row.last_run_imported_count, updated_count: row.last_run_updated_count,
      deactivated_count: row.last_run_deactivated_count, error_message: row.last_run_error,
      started_at: row.last_run_started_at, completed_at: row.last_run_completed_at,
    } : null,
  }))
  return {
    configured: connectorConfigured(),
    callbackUri: CALLBACK_URI,
    credentials: {
      clientId: credentialPreview(CLIENT_ID),
      clientSecret: credentialPreview(CLIENT_SECRET),
      secretStorage: process.env.MICROSOFT_CLIENT_SECRET_FILE ? 'protected_file' : (CLIENT_SECRET ? 'environment' : 'not_configured'),
    },
    connections,
    connectedCount: connections.filter((item) => item.status === 'connected').length,
    totalDeviceCount: connections.reduce((sum, item) => sum + Number(item.device_count || 0), 0),
  }
}

async function handleAdminConsentCallback(c, state, query) {
  const tenantUrl = state.tenantUrl || `https://${state.tenantSlug}.${deployment.rootDomain}`
  if (query.error) return c.redirect(`${tenantUrl}/settings/integrations?microsoft=error`, 302)
  if (String(query.admin_consent || '').toLowerCase() !== 'true') {
    return c.redirect(`${tenantUrl}/settings/integrations?microsoft=consent_required`, 302)
  }
  const directoryTenantId = clean(query.tenant)
  if (!isGuid(directoryTenantId)) return c.redirect(`${tenantUrl}/settings/integrations?microsoft=invalid_tenant`, 302)
  const requestedName = clean(state.connectionName)
  const defaultName = requestedName || `Microsoft tenant ${directoryTenantId.slice(0, 8)}`
  const connectionResult = await pool.query(
    `INSERT INTO tenant_microsoft_connections
     (tenant_id,connection_name,directory_tenant_id,status,sso_enabled,intune_enabled,intune_sync_enabled,intune_status,connected_by_user_id,admin_consent_at,last_validated_at)
     VALUES ($1,$2,$3,'connected',false,true,true,'ready',$4,now(),now())
     ON CONFLICT (tenant_id,directory_tenant_id) WHERE directory_tenant_id IS NOT NULL DO UPDATE
     SET status='connected',intune_enabled=true,intune_sync_enabled=true,intune_status='ready',connected_by_user_id=EXCLUDED.connected_by_user_id,
         admin_consent_at=now(),last_validated_at=now(),last_sync_error=NULL,updated_at=now()
     RETURNING id,connection_name,directory_tenant_id`,
    [state.tenantId, defaultName, directoryTenantId, state.userId],
  )
  const connection = connectionResult.rows[0]
  try {
    await syncMicrosoftConnection(connection.id, state.userId)
    return c.redirect(`${tenantUrl}/settings/integrations?microsoft=connected&connection=${encodeURIComponent(connection.id)}`, 302)
  } catch (error) {
    console.error('Initial Microsoft sync failed', error)
    return c.redirect(`${tenantUrl}/settings/integrations?microsoft=connected_sync_error&connection=${encodeURIComponent(connection.id)}`, 302)
  }
}

async function handleSsoCallback(c, state, query) {
  const tenantUrl = state.targetUrl || state.tenantUrl || `https://${state.tenantSlug}.${deployment.rootDomain}`
  if (query.error) return c.redirect(`${tenantUrl}/?microsoft=error`, 302)
  const code = clean(query.code)
  if (!code) return c.redirect(`${tenantUrl}/?microsoft=missing_code`, 302)
  const tokenBody = new URLSearchParams({
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'authorization_code', code,
    redirect_uri: CALLBACK_URI, code_verifier: state.codeVerifier, scope: 'openid profile email',
  })
  const tokenResponse = await fetch('https://login.microsoftonline.com/organizations/oauth2/v2.0/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: tokenBody,
  })
  const tokenPayload = await tokenResponse.json().catch(() => ({}))
  if (!tokenResponse.ok || !tokenPayload.id_token) return c.redirect(`${tenantUrl}/?microsoft=token_error`, 302)
  const jwks = createRemoteJWKSet(new URL('https://login.microsoftonline.com/organizations/discovery/v2.0/keys'))
  const verified = await jwtVerify(tokenPayload.id_token, jwks, { audience: CLIENT_ID })
  const claims = verified.payload
  const directoryTenantId = clean(claims.tid)
  if (!isGuid(directoryTenantId)) return c.redirect(`${tenantUrl}/?microsoft=tenant_mismatch`, 302)
  if (clean(claims.iss).toLowerCase() !== `https://login.microsoftonline.com/${directoryTenantId}/v2.0`.toLowerCase()) {
    return c.redirect(`${tenantUrl}/?microsoft=issuer_mismatch`, 302)
  }
  const allowedConnection = await pool.query(
    `SELECT id FROM tenant_microsoft_connections WHERE tenant_id=$1 AND directory_tenant_id=$2 AND status='connected' AND sso_enabled=true LIMIT 1`,
    [state.tenantId, directoryTenantId],
  )
  if (!allowedConnection.rowCount) return c.redirect(`${tenantUrl}/?microsoft=tenant_not_connected`, 302)

  const oid = clean(claims.oid)
  const subject = clean(claims.sub)
  const email = normaliseEmail(claims.preferred_username || claims.email)
  if (!subject || !email) return c.redirect(`${tenantUrl}/?microsoft=identity_missing`, 302)

  const account = await pool.query(
    `SELECT t.id AS tenant_id,t.slug,t.company_name,t.status AS tenant_status,u.id AS user_id,u.email,u.name,m.role AS tenant_role,m.status AS membership_status,
            ts.modules,ts.onboarding_step,ts.onboarding_completed_at,ts.onboarding_data,ts.configuration,ts.tenant_url,ts.portal_url,ts.rmm_url
     FROM tenants t JOIN tenant_memberships m ON m.tenant_id=t.id JOIN users u ON u.id=m.user_id JOIN tenant_settings ts ON ts.tenant_id=t.id
     LEFT JOIN user_external_identities x ON x.tenant_id=t.id AND x.user_id=u.id AND x.provider=$3 AND x.issuer_tenant_id=$4
     WHERE t.id=$1 AND (x.subject=$5 OR x.object_id=$6 OR lower(u.email)=lower($2))
     ORDER BY CASE WHEN x.id IS NOT NULL THEN 0 ELSE 1 END LIMIT 1`,
    [state.tenantId, email, MICROSOFT_PROVIDER, directoryTenantId, subject, oid || null],
  )
  if (!account.rowCount) return c.redirect(`${tenantUrl}/?microsoft=not_assigned`, 302)
  const row = account.rows[0]
  if (row.tenant_status !== 'active' || row.membership_status !== 'active') return c.redirect(`${tenantUrl}/?microsoft=inactive`, 302)
  const amr = Array.isArray(claims.amr) ? claims.amr.map(String) : []
  const microsoftMfa = amr.includes('mfa')
  const requestedSurface = ['portal','rmm'].includes(state.surface) ? state.surface : 'workspace'
  const sessionSurface = row.tenant_role === 'requester' || requestedSurface === 'portal' ? 'portal' : 'workspace'
  const sessionToken = await withTransaction(async (client) => {
    const existingIdentity = await client.query(
      `SELECT id FROM user_external_identities
       WHERE tenant_id=$1 AND provider=$2 AND issuer_tenant_id=$3 AND (subject=$4 OR object_id=$5) LIMIT 1`,
      [row.tenant_id, MICROSOFT_PROVIDER, directoryTenantId, subject, oid || null],
    )
    if (existingIdentity.rowCount) {
      await client.query(
        `UPDATE user_external_identities
         SET user_id=$2,subject=$3,object_id=$4,principal_name=$5,last_login_at=now(),updated_at=now()
         WHERE id=$1`,
        [existingIdentity.rows[0].id, row.user_id, subject, oid || null, email],
      )
    } else {
      await client.query(
        `INSERT INTO user_external_identities (tenant_id,user_id,provider,issuer_tenant_id,subject,object_id,principal_name,last_login_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,now())`,
        [row.tenant_id, row.user_id, MICROSOFT_PROVIDER, directoryTenantId, subject, oid || null, email],
      )
    }
    return createSession(client, { tenantId: row.tenant_id, userId: row.user_id, surface: sessionSurface, mfaVerified: microsoftMfa })
  })
  if (sessionSurface === 'portal') setPortalSessionCookie(c, sessionToken)
  else setSessionCookie(c, sessionToken)
  const requestedReturnTo = String(state.returnTo || '/').startsWith('/') ? state.returnTo : '/'
  const returnTo = sessionSurface === 'portal' && requestedSurface !== 'portal' ? '/' : requestedReturnTo
  const redirectBase = sessionSurface === 'portal' ? (row.portal_url || state.portalUrl || tenantUrl) : tenantUrl
  return c.redirect(`${redirectBase}${returnTo}`, 302)
}

async function discoverMicrosoftLogin(tenantSlug, email) {
  const principal = normaliseEmail(email)
  if (!principal || !connectorConfigured()) return false
  const result = await pool.query(
    `SELECT EXISTS (
       SELECT 1
       FROM user_external_identities x
       JOIN tenant_memberships m ON m.tenant_id=x.tenant_id AND m.user_id=x.user_id AND m.status='active'
       JOIN tenant_microsoft_connections c ON c.tenant_id=x.tenant_id AND c.directory_tenant_id=x.issuer_tenant_id
       JOIN tenants t ON t.id=x.tenant_id
       WHERE t.slug=$1 AND t.status='active' AND x.provider=$2
         AND c.status='connected' AND c.sso_enabled=true
         AND lower(x.principal_name)=lower($3)
       UNION ALL
       SELECT 1
       FROM organisation_person_external_identities x
       JOIN organisation_people p ON p.tenant_id=x.tenant_id AND p.id=x.person_id AND p.user_id IS NOT NULL AND p.active=true
       JOIN tenant_memberships m ON m.tenant_id=p.tenant_id AND m.user_id=p.user_id AND m.status='active'
       JOIN tenant_microsoft_connections c ON c.id=x.microsoft_connection_id AND c.tenant_id=x.tenant_id
       JOIN tenants t ON t.id=x.tenant_id
       WHERE t.slug=$1 AND t.status='active' AND x.provider=$2
         AND c.status='connected' AND c.sso_enabled=true
         AND lower(x.principal_name)=lower($3)
     ) AS enabled`,
    [tenantSlug, MICROSOFT_PROVIDER, principal],
  )
  return Boolean(result.rows[0]?.enabled)
}

async function handleLinkUserCallback(c, state, query) {
  const tenantUrl = state.tenantUrl || `https://${state.tenantSlug}.${deployment.rootDomain}`
  if (query.error) return c.redirect(`${tenantUrl}/settings/integrations?microsoft=link_error`, 302)
  const code = clean(query.code)
  if (!code) return c.redirect(`${tenantUrl}/settings/integrations?microsoft=link_missing_code`, 302)
  const tokenBody = new URLSearchParams({
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'authorization_code', code,
    redirect_uri: CALLBACK_URI, code_verifier: state.codeVerifier, scope: 'openid profile email',
  })
  const tokenResponse = await fetch('https://login.microsoftonline.com/organizations/oauth2/v2.0/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: tokenBody,
  })
  const tokenPayload = await tokenResponse.json().catch(() => ({}))
  if (!tokenResponse.ok || !tokenPayload.id_token) return c.redirect(`${tenantUrl}/settings/integrations?microsoft=link_token_error`, 302)
  const jwks = createRemoteJWKSet(new URL('https://login.microsoftonline.com/organizations/discovery/v2.0/keys'))
  const verified = await jwtVerify(tokenPayload.id_token, jwks, { audience: CLIENT_ID })
  const claims = verified.payload
  const directoryTenantId = clean(claims.tid)
  const oid = clean(claims.oid)
  const subject = clean(claims.sub)
  const principalName = normaliseEmail(claims.preferred_username || claims.email)
  if (!isGuid(directoryTenantId) || !subject || !principalName) return c.redirect(`${tenantUrl}/settings/integrations?microsoft=link_identity_missing`, 302)
  if (clean(claims.iss).toLowerCase() !== `https://login.microsoftonline.com/${directoryTenantId}/v2.0`.toLowerCase()) {
    return c.redirect(`${tenantUrl}/settings/integrations?microsoft=link_issuer_mismatch`, 302)
  }
  const connection = await pool.query(
    `SELECT id FROM tenant_microsoft_connections
     WHERE id=$1 AND tenant_id=$2 AND directory_tenant_id=$3 AND status='connected' AND sso_enabled=true LIMIT 1`,
    [state.connectionId, state.tenantId, directoryTenantId],
  )
  if (!connection.rowCount) return c.redirect(`${tenantUrl}/settings/integrations?microsoft=link_tenant_mismatch`, 302)
  const existingIdentity = await pool.query(
    `SELECT user_id FROM user_external_identities
     WHERE tenant_id=$1 AND provider=$2 AND issuer_tenant_id=$3 AND (subject=$4 OR object_id=$5) LIMIT 1`,
    [state.tenantId, MICROSOFT_PROVIDER, directoryTenantId, subject, oid || null],
  )
  if (existingIdentity.rowCount && existingIdentity.rows[0].user_id !== state.userId) {
    return c.redirect(`${tenantUrl}/settings/integrations?microsoft=link_conflict`, 302)
  }
  await pool.query(
    `INSERT INTO user_external_identities (tenant_id,user_id,provider,issuer_tenant_id,subject,object_id,principal_name,last_login_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,now())
     ON CONFLICT (tenant_id,provider,issuer_tenant_id,subject) DO UPDATE
     SET user_id=EXCLUDED.user_id,object_id=EXCLUDED.object_id,principal_name=EXCLUDED.principal_name,last_login_at=now(),updated_at=now()`,
    [state.tenantId, state.userId, MICROSOFT_PROVIDER, directoryTenantId, subject, oid || null, principalName],
  )
  return c.redirect(`${tenantUrl}/settings/integrations?microsoft=account_linked`, 302)
}

export function registerMicrosoftRoutes(app) {
  app.get('/api/v1/auth/microsoft/status/:slug', async (c) => {
    const slug = clean(c.req.param('slug')).toLowerCase()
    const result = await pool.query(
      `SELECT t.id,
              count(mc.id) FILTER (WHERE mc.status='connected')::int AS connected_count,
              count(mc.id) FILTER (WHERE mc.status='connected' AND mc.sso_enabled=true)::int AS sso_count
       FROM tenants t LEFT JOIN tenant_microsoft_connections mc ON mc.tenant_id=t.id
       WHERE t.slug=$1 GROUP BY t.id LIMIT 1`, [slug],
    )
    const row = result.rows[0] || {}
    return c.json({ configured: connectorConfigured(), connected: Number(row.connected_count || 0) > 0, ssoEnabled: Number(row.sso_count || 0) > 0, connectionCount: Number(row.connected_count || 0) })
  })

  app.get('/api/v1/auth/microsoft/discover/:slug', async (c) => {
    const slug = clean(c.req.param('slug')).toLowerCase()
    const email = normaliseEmail(c.req.query('email'))
    if (!slug || !email) return c.json({ method: 'password' })
    return c.json({ method: await discoverMicrosoftLogin(slug, email) ? 'microsoft' : 'password' })
  })

  app.get('/api/v1/auth/microsoft/start', async (c) => {
    if (!connectorConfigured()) return c.json({ error: 'Microsoft SSO is not configured on this Hi5Central installation.' }, 503)
    const tenantSlug = clean(c.req.query('tenantSlug')).toLowerCase()
    const tenantResult = await pool.query(
      `SELECT t.id,t.slug FROM tenants t WHERE t.slug=$1 LIMIT 1`, [tenantSlug],
    )
    const tenant = tenantResult.rows[0]
    if (!tenant) return c.json({ error: 'Tenant not found.' }, 404)
    const connected = await pool.query(
      `SELECT count(*)::int AS count FROM tenant_microsoft_connections WHERE tenant_id=$1 AND status='connected' AND sso_enabled=true`, [tenant.id],
    )
    if (!Number(connected.rows[0]?.count || 0)) return c.json({ error: 'Microsoft SSO is not enabled for this tenant.' }, 404)
    const requestedSurface = clean(c.req.query('surface')).toLowerCase()
    const loginHint = normaliseEmail(c.req.query('loginHint'))
    if (loginHint && !(await discoverMicrosoftLogin(tenantSlug, loginHint))) return c.json({ error: 'This email address is not linked to Microsoft sign-in for this Hi5Central tenant.' }, 404)
    const urls = tenantUrls(tenant.slug, { rmm: true })
    const targetUrl = requestedSurface === 'portal' && urls.portalUrl ? urls.portalUrl : requestedSurface === 'rmm' && urls.rmmUrl ? urls.rmmUrl : urls.tenantUrl
    const codeVerifier = randomToken(48)
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')
    const state = await storeState({ kind: 'sso', tenantId: tenant.id, tenantSlug: tenant.slug, tenantUrl: urls.tenantUrl, portalUrl: urls.portalUrl, targetUrl, surface: requestedSurface || 'workspace', codeVerifier, returnTo: c.req.query('returnTo') || '/' })
    const params = new URLSearchParams({ client_id: CLIENT_ID, response_type: 'code', redirect_uri: CALLBACK_URI, response_mode: 'query', scope: 'openid profile email', state, code_challenge: codeChallenge, code_challenge_method: 'S256' })
    if (loginHint) params.set('login_hint', loginHint)
    return c.redirect(`https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?${params.toString()}`, 302)
  })

  app.get('/api/v1/auth/microsoft/callback', async (c) => {
    const state = await consumeState(c.req.query('state'))
    if (!state) return c.json({ error: 'Microsoft sign-in state expired or is invalid.' }, 400)
    const query = Object.fromEntries(new URL(c.req.url).searchParams.entries())
    if (state.kind === 'admin_consent') return handleAdminConsentCallback(c, state, query)
    if (state.kind === 'sso') return handleSsoCallback(c, state, query)
    if (state.kind === 'link_user') return handleLinkUserCallback(c, state, query)
    return c.json({ error: 'Unknown Microsoft authentication flow.' }, 400)
  })

  app.get('/api/v1/integrations/microsoft', async (c) => {
    const auth = await requireIntegrationManager(c)
    if (auth.error) return auth.error
    const status = await microsoftStatus(auth.session.tenant_id)
    const linked = await pool.query(
      `SELECT issuer_tenant_id,principal_name FROM user_external_identities
       WHERE tenant_id=$1 AND user_id=$2 AND provider=$3`,
      [auth.session.tenant_id, auth.session.user_id, MICROSOFT_PROVIDER],
    )
    const linkedByTenant = new Map(linked.rows.map((row) => [row.issuer_tenant_id, row.principal_name]))
    status.connections = status.connections.map((connection) => ({ ...connection, current_user_principal: linkedByTenant.get(connection.directory_tenant_id) || null }))
    return c.json(status)
  })

  app.get('/api/v1/integrations/microsoft/connect', async (c) => {
    const auth = await requireIntegrationManager(c)
    if (auth.error) return auth.error
    if (!connectorConfigured()) return c.json({ error: 'Configure MICROSOFT_CLIENT_ID and a protected Microsoft client secret before connecting Microsoft 365.', callbackUri: CALLBACK_URI }, 503)
    const urls = tenantUrls(auth.session.slug, { rmm: true })
    const state = await storeState({
      kind: 'admin_consent', tenantId: auth.session.tenant_id, tenantSlug: auth.session.slug,
      tenantUrl: urls.tenantUrl, userId: auth.session.user_id, connectionName: clean(c.req.query('name')),
    })
    const params = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: CALLBACK_URI, state, scope: 'https://graph.microsoft.com/.default' })
    return c.redirect(`https://login.microsoftonline.com/organizations/v2.0/adminconsent?${params.toString()}`, 302)
  })

  app.get('/api/v1/integrations/microsoft/:connectionId/link-me', async (c) => {
    const auth = await requireIntegrationManager(c)
    if (auth.error) return auth.error
    const connectionId = clean(c.req.param('connectionId'))
    const connection = await pool.query(
      `SELECT id FROM tenant_microsoft_connections
       WHERE id=$1 AND tenant_id=$2 AND status='connected' AND sso_enabled=true LIMIT 1`,
      [connectionId, auth.session.tenant_id],
    )
    if (!connection.rowCount) return c.json({ error: 'Microsoft SSO must be enabled for this connection before linking an account.' }, 409)
    const urls = tenantUrls(auth.session.slug, { rmm: true })
    const codeVerifier = randomToken(48)
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')
    const state = await storeState({
      kind: 'link_user', tenantId: auth.session.tenant_id, tenantSlug: auth.session.slug,
      tenantUrl: urls.tenantUrl, userId: auth.session.user_id, connectionId, codeVerifier,
    })
    const params = new URLSearchParams({
      client_id: CLIENT_ID, response_type: 'code', redirect_uri: CALLBACK_URI, response_mode: 'query',
      scope: 'openid profile email', state, code_challenge: codeChallenge, code_challenge_method: 'S256', prompt: 'select_account',
    })
    return c.redirect(`https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?${params.toString()}`, 302)
  })

  const syncAll = async (c) => {
    const auth = await requireIntegrationManager(c)
    if (auth.error) return auth.error
    try { return c.json({ status: 'completed', ...(await syncMicrosoftTenant(auth.session.tenant_id, auth.session.user_id)) }) }
    catch (error) { return c.json({ error: error.message || 'Microsoft sync failed.' }, Number(error.status) || 502) }
  }
  app.post('/api/v1/integrations/microsoft/sync', syncAll)
  app.post('/api/v1/integrations/microsoft/sync-all', syncAll)

  app.post('/api/v1/integrations/microsoft/:connectionId/sync', async (c) => {
    const auth = await requireIntegrationManager(c)
    if (auth.error) return auth.error
    const connectionId = clean(c.req.param('connectionId'))
    const owned = await pool.query(`SELECT id FROM tenant_microsoft_connections WHERE id=$1 AND tenant_id=$2 LIMIT 1`, [connectionId, auth.session.tenant_id])
    if (!owned.rowCount) return c.json({ error: 'Microsoft connection not found.' }, 404)
    try { return c.json({ status: 'completed', ...(await syncMicrosoftConnection(connectionId, auth.session.user_id)) }) }
    catch (error) { return c.json({ error: error.message || 'Microsoft sync failed.' }, Number(error.status) || 502) }
  })

  app.patch('/api/v1/integrations/microsoft/:connectionId', async (c) => {
    const auth = await requireIntegrationManager(c)
    if (auth.error) return auth.error
    const connectionId = clean(c.req.param('connectionId'))
    const body = await c.req.json().catch(() => ({}))
    const name = body.connectionName === undefined ? null : clean(body.connectionName)
    if (name !== null && (name.length < 2 || name.length > 80)) return c.json({ error: 'Connection name must be between 2 and 80 characters.' }, 400)
    const interval = body.syncIntervalMinutes === undefined ? null : Number(body.syncIntervalMinutes)
    if (interval !== null && (!Number.isInteger(interval) || interval < 15 || interval > 1440)) return c.json({ error: 'Sync interval must be between 15 and 1440 minutes.' }, 400)
    const result = await pool.query(
      `UPDATE tenant_microsoft_connections SET
         connection_name=COALESCE($3,connection_name),
         intune_sync_interval_minutes=COALESCE($4,intune_sync_interval_minutes),
         sso_enabled=COALESCE($5,sso_enabled),
         intune_sync_enabled=COALESCE($6,intune_sync_enabled),updated_at=now()
       WHERE id=$1 AND tenant_id=$2 RETURNING id`,
      [connectionId, auth.session.tenant_id, name, interval, typeof body.ssoEnabled === 'boolean' ? body.ssoEnabled : null, typeof body.syncEnabled === 'boolean' ? body.syncEnabled : null],
    )
    if (!result.rowCount) return c.json({ error: 'Microsoft connection not found.' }, 404)
    return c.json(await microsoftStatus(auth.session.tenant_id))
  })

  app.post('/api/v1/integrations/microsoft/:connectionId/disconnect', async (c) => {
    const auth = await requireIntegrationManager(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `UPDATE tenant_microsoft_connections SET status='disconnected',sso_enabled=false,intune_sync_enabled=false,updated_at=now() WHERE id=$1 AND tenant_id=$2 RETURNING id`,
      [clean(c.req.param('connectionId')), auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Microsoft connection not found.' }, 404)
    return c.json({ status: 'disconnected' })
  })

  app.get('/api/v1/rmm/devices', async (c) => {
    const session = await resolveSession(c)
    if (!session) return c.json({ error: 'Authentication required.' }, 401)
    if (!originMatchesTenant(c.req.header('origin'), session.slug)) return c.json({ error: 'Tenant session mismatch.' }, 403)
    const personId = clean(c.req.query('personId'))
    const params = [session.tenant_id]
    let where = `d.tenant_id=$1 AND d.active=true AND NOT (d.source='hi5central_agent' AND EXISTS (SELECT 1 FROM rmm_device_inventory i WHERE i.tenant_id=d.tenant_id AND i.source='intune' AND i.active=true AND ((NULLIF(trim(d.directory_device_id),'') IS NOT NULL AND NULLIF(trim(i.directory_device_id),'') IS NOT NULL AND lower(trim(i.directory_device_id))=lower(trim(d.directory_device_id))) OR (NULLIF(trim(d.serial_number),'') IS NOT NULL AND NULLIF(trim(i.serial_number),'') IS NOT NULL AND lower(trim(i.serial_number))=lower(trim(d.serial_number)) AND (NULLIF(trim(d.manufacturer),'') IS NULL OR NULLIF(trim(i.manufacturer),'') IS NULL OR lower(trim(i.manufacturer))=lower(trim(d.manufacturer)))))))`
    if (personId) {
      params.push(personId)
      where += ` AND d.assigned_person_id IN (SELECT p2.id FROM organisation_people p2 WHERE p2.tenant_id=$1 AND (p2.id::text=$2 OR p2.external_key=$2))`
    }
    const result = await pool.query(
      `SELECT d.id,d.reference,d.source,d.source_device_id,d.directory_device_id,d.name,d.platform,d.operating_system,d.os_version,d.manufacturer,d.model,d.serial_number,d.user_display_name,d.user_principal_name,d.owner_type,d.compliance_state,d.management_state,d.management_agent,d.enrollment_type,d.registration_state,d.category_name,d.is_encrypted,d.memory_bytes,d.storage_total_bytes,d.storage_free_bytes,d.enrolled_at,d.source_last_sync_at,d.last_imported_at,d.assigned_person_id,d.microsoft_connection_id,
              p.name AS assigned_person_name,p.email AS assigned_person_email,
              os.external_key AS assigned_site_external_key,os.name AS assigned_site_name,
              mc.connection_name AS source_connection_name,mc.directory_tenant_id AS source_directory_tenant_id,mc.status AS source_connection_status,
              CASE WHEN d.source='hi5central_agent' THEN d.reference ELSE agent_match.reference END AS rmm_reference,
              CASE WHEN d.source='hi5central_agent' THEN 'agent' ELSE agent_match.match_method END AS rmm_match_method,
              COALESCE(self_agent.id,agent_match.agent_id) AS agent_device_id,
              COALESCE(self_agent.cpu_percent,agent_match.cpu_percent) AS agent_cpu_percent,
              COALESCE(self_agent.memory_used_percent,agent_match.memory_used_percent) AS agent_memory_used_percent,
              COALESCE(self_agent.memory_total_bytes,agent_match.memory_total_bytes) AS agent_memory_total_bytes,
              COALESCE(self_agent.memory_used_bytes,agent_match.memory_used_bytes) AS agent_memory_used_bytes,
              COALESCE(self_agent.disk_used_percent,agent_match.disk_used_percent) AS agent_disk_used_percent,
              COALESCE(self_agent.uptime_seconds,agent_match.uptime_seconds) AS agent_uptime_seconds,
              COALESCE(self_agent.active_user,agent_match.active_user) AS agent_active_user,
              COALESCE(self_agent.service_status,agent_match.service_status) AS agent_service_status,
              COALESCE(self_agent.websocket_status,agent_match.websocket_status) AS agent_websocket_status,
              COALESCE(self_agent.agent_version,agent_match.agent_version) AS agent_version,
              COALESCE(self_agent.last_telemetry_at,agent_match.last_telemetry_at) AS agent_last_telemetry_at,
              COALESCE(patch_state.current_count,0)::int AS agent_patch_current_count,
              COALESCE(patch_state.pending_count,0)::int AS agent_patch_pending_count,
              COALESCE(patch_state.blocked_count,0)::int AS agent_patch_blocked_count,
              COALESCE(patch_state.total_count,0)::int AS agent_patch_total_count,
              CASE
                WHEN COALESCE(patch_state.total_count,0)>0
                THEN round((100.0 * COALESCE(patch_state.current_count,0)) / patch_state.total_count)::int
                ELSE NULL
              END AS agent_software_patch_compliance,
              CASE
                WHEN COALESCE(self_agent.websocket_status,agent_match.websocket_status)='Connected'
                 AND COALESCE(self_agent.last_telemetry_at,agent_match.last_telemetry_at) > now()-interval '90 seconds'
                THEN true ELSE false
              END AS agent_online,
              CASE WHEN d.source='hi5central_agent' THEN d.source_payload ELSE agent_match.agent_inventory_payload END AS agent_inventory_payload
       FROM rmm_device_inventory d
       LEFT JOIN organisation_people p ON p.tenant_id=d.tenant_id AND p.id=d.assigned_person_id
       LEFT JOIN organisation_sites os ON os.tenant_id=d.tenant_id AND os.id=p.site_id
       LEFT JOIN tenant_microsoft_connections mc ON mc.id=d.microsoft_connection_id
       LEFT JOIN rmm_agent_devices self_agent ON self_agent.inventory_id=d.id AND self_agent.disabled_at IS NULL
       LEFT JOIN LATERAL (
         SELECT a.id AS agent_inventory_id,a.reference,ad.id AS agent_id,ad.cpu_percent,ad.memory_used_percent,ad.memory_total_bytes,ad.memory_used_bytes,ad.disk_used_percent,ad.uptime_seconds,ad.active_user,ad.service_status,ad.websocket_status,ad.agent_version,ad.last_telemetry_at,a.source_payload AS agent_inventory_payload,
                CASE
                  WHEN NULLIF(trim(d.directory_device_id),'') IS NOT NULL AND lower(trim(a.directory_device_id))=lower(trim(d.directory_device_id)) THEN 'directory_device_id'
                  ELSE 'serial_number'
                END AS match_method
         FROM rmm_device_inventory a
         JOIN rmm_agent_devices ad ON ad.inventory_id=a.id AND ad.disabled_at IS NULL
         WHERE a.tenant_id=d.tenant_id
           AND a.source='hi5central_agent'
           AND a.active=true
           AND a.id<>d.id
           AND (
             (NULLIF(trim(d.directory_device_id),'') IS NOT NULL AND NULLIF(trim(a.directory_device_id),'') IS NOT NULL AND lower(trim(a.directory_device_id))=lower(trim(d.directory_device_id)))
             OR
             (NULLIF(trim(d.serial_number),'') IS NOT NULL AND NULLIF(trim(a.serial_number),'') IS NOT NULL
              AND lower(trim(a.serial_number))=lower(trim(d.serial_number))
              AND (NULLIF(trim(d.manufacturer),'') IS NULL OR NULLIF(trim(a.manufacturer),'') IS NULL OR lower(trim(a.manufacturer))=lower(trim(d.manufacturer))))
           )
         ORDER BY CASE WHEN NULLIF(trim(d.directory_device_id),'') IS NOT NULL AND lower(trim(a.directory_device_id))=lower(trim(d.directory_device_id)) THEN 0 ELSE 1 END,
                  a.updated_at DESC
         LIMIT 1
       ) agent_match ON d.source='intune'
       LEFT JOIN LATERAL (
         SELECT
           count(*) FILTER (WHERE patch_status='current') AS current_count,
           count(*) FILTER (WHERE patch_status IN ('update_available','provider_blocked') AND rejected=false) AS pending_count,
           count(*) FILTER (WHERE patch_status='provider_blocked' AND rejected=false) AS blocked_count,
           count(*) FILTER (WHERE patch_status='current' OR (patch_status IN ('update_available','provider_blocked') AND rejected=false)) AS total_count
         FROM (
           SELECT o.patch_status,
                  EXISTS (
                    SELECT 1
                    FROM rmm_device_patch_rejections r
                    WHERE r.tenant_id=d.tenant_id
                      AND r.agent_device_id=COALESCE(self_agent.id,agent_match.agent_id)
                      AND r.catalogue_id=o.catalogue_id
                      AND r.target_version=c.target_version
                      AND r.revoked_at IS NULL
                  ) AS rejected
           FROM rmm_software_patch_observations o
           JOIN rmm_software_catalogue c ON c.id=o.catalogue_id AND c.status='active'
           WHERE o.tenant_id=d.tenant_id
             AND o.inventory_id=COALESCE(self_agent.inventory_id,agent_match.agent_inventory_id)
             AND COALESCE(NULLIF(c.target_version,''),'')<>''
             AND c.qualification_state<>'blocked'
             AND COALESCE(lower(c.source_metadata->>'sourceEnabled'),'true')<>'false'
             AND (
               (
                 c.source_metadata->>'deploymentMode'='winget_preferred'
                 AND COALESCE(c.source_metadata->>'wingetPackageId','')<>''
                 AND lower(COALESCE(c.source_metadata->>'wingetFallbackReady','false'))='true'
               )
               OR (
                 c.source_metadata->>'deploymentMode'='vendor_direct'
                 AND c.source_metadata->>'trustState'='direct_ready'
               )
               OR (c.provider='winget' AND COALESCE(c.provider_package_id,'')<>'')
             )
         ) qualified_patch_state
       ) patch_state ON COALESCE(self_agent.id,agent_match.agent_id) IS NOT NULL
       WHERE ${where} ORDER BY d.name`, params,
    )
    return c.json({ devices: result.rows })
  })
}

let schedulerStarted = false
export function startMicrosoftSyncScheduler() {
  if (schedulerStarted || !connectorConfigured()) return
  schedulerStarted = true
  const runDueSyncs = async () => {
    try {
      const due = await pool.query(
        `SELECT id,tenant_id FROM tenant_microsoft_connections
         WHERE status='connected' AND intune_sync_enabled=true
           AND (last_sync_completed_at IS NULL OR last_sync_completed_at + make_interval(mins=>intune_sync_interval_minutes) <= now())
         ORDER BY coalesce(last_sync_completed_at,'epoch'::timestamptz) LIMIT 20`,
      )
      for (const row of due.rows) {
        await syncMicrosoftConnection(row.id).catch((error) => console.error('Scheduled Microsoft sync failed', row.tenant_id, row.id, error.message))
      }
    } catch (error) { console.error('Microsoft sync scheduler failed', error) }
  }
  setTimeout(runDueSyncs, 10_000).unref?.()
  setInterval(runDueSyncs, 5 * 60 * 1000).unref?.()
}
