import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { isIP } from 'node:net'
import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { sendAgentMessage } from './rmmAgent.js'
import { recordRmmActivity } from './rmmActivity.js'
import { resolveSession } from './session.js'

function clean(value = '', max = 4096) {
  return String(value ?? '').trim().slice(0, max)
}

function secretValue(value = '', max = 8192) {
  return String(value ?? '').slice(0, max)
}

function isUuid(value = '') {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clean(value, 128))
}

function versionParts(value = '') {
  return clean(value, 64).match(/\d+/g)?.slice(0, 4).map(Number) || []
}

function versionAtLeast(value, minimum) {
  const left = versionParts(value)
  const right = versionParts(minimum)
  const length = Math.max(left.length, right.length)
  for (let index = 0; index < length; index += 1) {
    const a = left[index] || 0
    const b = right[index] || 0
    if (a > b) return true
    if (a < b) return false
  }
  return true
}

const SNMP_MIN_AGENT_VERSION = '0.1.232'
const SNMP_V3_MIN_AGENT_VERSION = '0.1.245'
const PRESENCE_MIN_AGENT_VERSION = '0.1.233'
const DYNAMIC_DNSSD_MIN_AGENT_VERSION = '0.1.239'

function normalizeSnmpV3AuthProtocol(value = '') {
  const normalized = clean(value, 32).toLowerCase().replaceAll('-', '')
  if (['sha', 'sha1', 'hmacsha96'].includes(normalized)) return 'sha1'
  if (['sha256', 'hmacsha256'].includes(normalized)) return 'sha256'
  return ''
}

function normalizeSnmpV3PrivacyProtocol(value = '') {
  const normalized = clean(value, 32).toLowerCase().replaceAll('-', '')
  return ['aes', 'aes128', 'cfb128aes128'].includes(normalized) ? 'aes128' : ''
}

function parseKeyMaterial(rawValue, variableName) {
  const raw = clean(rawValue, 4096)
  if (!raw) return null
  let key = null
  if (/^[0-9a-f]{64}$/i.test(raw)) key = Buffer.from(raw, 'hex')
  else {
    try { key = Buffer.from(raw, 'base64url') } catch { key = null }
  }
  if (!key || key.length !== 32) {
    const error = new Error(variableName + ' must contain exactly 32 bytes of key material.')
    error.status = 503
    throw error
  }
  return key
}

function snmpEncryptionKey() {
  const dedicated = parseKeyMaterial(process.env.RMM_SNMP_ENCRYPTION_KEY || '', 'RMM_SNMP_ENCRYPTION_KEY')
  if (dedicated) return dedicated
  const root = parseKeyMaterial(
    process.env.RMM_RECOVERY_KEY_ENCRYPTION_KEY || '',
    'RMM_RECOVERY_KEY_ENCRYPTION_KEY',
  )
  if (!root) {
    const error = new Error('SNMP credential encryption is not configured.')
    error.status = 503
    throw error
  }
  return createHash('sha256')
    .update('hi5central:rmm:snmp:v1', 'utf8')
    .update(root)
    .digest()
}

function encryptSecret(secret) {
  const value = secretValue(secret, 8192)
  if (!value) return ''
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', snmpEncryptionKey(), iv)
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return ['v1', iv.toString('base64url'), tag.toString('base64url'), ciphertext.toString('base64url')].join('.')
}

function decryptSecret(envelope) {
  const value = clean(envelope, 16384)
  if (!value) return ''
  const [version, ivValue, tagValue, ciphertextValue] = value.split('.')
  if (version !== 'v1' || !ivValue || !tagValue || !ciphertextValue) {
    throw new Error('Stored SNMP credential is invalid.')
  }
  const decipher = createDecipheriv('aes-256-gcm', snmpEncryptionKey(), Buffer.from(ivValue, 'base64url'))
  decipher.setAuthTag(Buffer.from(tagValue, 'base64url'))
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextValue, 'base64url')),
    decipher.final(),
  ]).toString('utf8')
}

function parseIpv4(value) {
  if (isIP(value) !== 4) return null
  return value.split('.').reduce((number, octet) => ((number << 8) | Number(octet)) >>> 0, 0)
}

function isPrivateIpv4Number(value) {
  const number = Number(value) >>> 0
  const first = (number >>> 24) & 255
  const second = (number >>> 16) & 255
  return first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168)
}

function ipv4FromNumber(value) {
  const number = Number(value) >>> 0
  return [
    (number >>> 24) & 255,
    (number >>> 16) & 255,
    (number >>> 8) & 255,
    number & 255,
  ].join('.')
}

function netmaskPrefix(mask = '') {
  const octets = clean(mask, 64).split('.').map(Number)
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null
  const binary = octets.map((part) => part.toString(2).padStart(8, '0')).join('')
  if (!/^1*0*$/.test(binary)) return null
  return binary.indexOf('0') === -1 ? 32 : binary.indexOf('0')
}

function suggestedCidrs(network = {}) {
  const suggestions = new Set()
  const add = (address, mask = '') => {
    const ip = parseIpv4(clean(address, 64))
    if (ip == null) return
    const first = Number(String(address).split('.')[0])
    const second = Number(String(address).split('.')[1])
    if (first === 127 || first === 0 || (first === 169 && second === 254)) return
    let prefix = netmaskPrefix(mask)
    if (!Number.isInteger(prefix)) prefix = 24
    if (prefix < 20 || prefix > 32) return

    const addPrefix = (targetPrefix) => {
      const hostBits = 32 - targetPrefix
      const maskNumber = targetPrefix === 32 ? 0xffffffff : (0xffffffff << hostBits) >>> 0
      suggestions.add(ipv4FromNumber((ip & maskNumber) >>> 0) + '/' + targetPrefix)
    }

    // Prefer the local /24 as the quick interactive scan when the actual
    // connected subnet is broader. Keep the full routed subnet as the
    // secondary/deep-scan option.
    if (prefix < 24) addPrefix(24)
    addPrefix(prefix)
  }

  const configurations = Array.isArray(network?.configurations) ? network.configurations : []
  for (const item of configurations) {
    const addresses = Array.isArray(item?.ip_addresses) ? item.ip_addresses : []
    const masks = Array.isArray(item?.subnets) ? item.subnets : []
    const ipv4Index = addresses.findIndex((value) => isIP(clean(value, 64)) === 4)
    if (ipv4Index >= 0) {
      const mask = masks.find((value) => /^\d+\.\d+\.\d+\.\d+$/.test(clean(value, 64))) || ''
      add(addresses[ipv4Index], mask)
    }
  }
  const primary = Array.isArray(network?.primary?.ipv4) ? network.primary.ipv4 : []
  for (const address of primary) add(address)
  if (network?.primary_ipv4) add(network.primary_ipv4)
  return [...suggestions].slice(0, 8)
}

function validateCidr(value) {
  const input = clean(value, 64)
  const [address, prefixValue] = input.split('/')
  const prefix = Number(prefixValue)
  const ip = parseIpv4(address)
  if (ip == null || !Number.isInteger(prefix) || prefix < 20 || prefix > 32) {
    return { ok: false, error: 'Enter an IPv4 CIDR between /20 and /32 (maximum 4,096 addresses per profile).' }
  }
  if (!isPrivateIpv4Number(ip)) {
    return { ok: false, error: 'Network discovery is limited to private RFC1918 IPv4 ranges.' }
  }
  const hostBits = 32 - prefix
  const size = 2 ** hostBits
  const mask = prefix === 0 ? 0 : (0xffffffff << hostBits) >>> 0
  const network = (ip & mask) >>> 0
  const canonical = [
    (network >>> 24) & 255,
    (network >>> 16) & 255,
    (network >>> 8) & 255,
    network & 255,
  ].join('.') + '/' + prefix
  return { ok: true, cidr: canonical, addresses: size }
}

async function validateProfileReferences(tenantId, probeAgentDeviceId, credentialId, siteId = null) {
  const result = await pool.query(
    `SELECT
        EXISTS(
          SELECT 1
            FROM rmm_agent_devices
           WHERE id=$1 AND tenant_id=$4 AND disabled_at IS NULL
        ) AS probe_ok,
        CASE WHEN $2::uuid IS NULL THEN true ELSE EXISTS(
          SELECT 1
            FROM rmm_network_discovery_credentials
           WHERE id=$2::uuid AND tenant_id=$4 AND enabled=true
        ) END AS credential_ok,
        CASE WHEN $3::uuid IS NULL THEN true ELSE EXISTS(
          SELECT 1
            FROM organisation_sites
           WHERE id=$3::uuid AND tenant_id=$4
        ) END AS site_ok`,
    [probeAgentDeviceId, credentialId, siteId, tenantId],
  )
  return result.rows[0] || { probe_ok: false, credential_ok: false, site_ok: false }
}

function credentialSummary(row) {
  return {
    id: row.id,
    name: row.name,
    snmpVersion: row.snmp_version,
    username: row.username,
    securityLevel: row.security_level,
    authProtocol: row.auth_protocol,
    privacyProtocol: row.privacy_protocol,
    contextName: row.context_name,
    secretConfigured: row.snmp_version === 'v3' && row.security_level === 'noAuthNoPriv'
      ? true
      : Boolean(row.community_encrypted || row.auth_secret_encrypted || row.privacy_secret_encrypted),
    enabled: row.enabled,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

async function requireAccess(c, manage = false) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  const allowed = manage
    ? ['rmm.devices.control', 'rmm.policies.manage']
    : ['rmm.devices.view', 'rmm.devices.control', 'rmm.policies.view', 'rmm.policies.manage']
  if (!allowed.some((permission) => hasPermission(session.access, permission))) {
    return { error: c.json({ error: 'You do not have permission to access network discovery.' }, 403) }
  }
  return { session }
}

async function bundle(tenantId) {
  const [credentials, profiles, runs, devices, probes, sites] = await Promise.all([
    pool.query(
      `SELECT id,name,snmp_version,username,security_level,auth_protocol,privacy_protocol,
              context_name,community_encrypted,auth_secret_encrypted,privacy_secret_encrypted,
              enabled,created_at,updated_at
         FROM rmm_network_discovery_credentials
        WHERE tenant_id=$1
        ORDER BY enabled DESC,lower(name)`,
      [tenantId],
    ),
    pool.query(
      `SELECT p.id,p.name,p.cidr::text,p.site_id,p.probe_agent_device_id,p.credential_id,
              p.snmp_port,p.timeout_ms,p.retries,p.concurrency,p.scan_interval_minutes,p.enabled,
              p.presence_enabled,p.snmp_enabled,p.presence_timeout_ms,
              p.last_scan_at,p.next_scan_at,p.created_at,p.updated_at,
              i.name AS probe_name,i.reference AS probe_reference,
              s.name AS site_name,c.name AS credential_name,c.snmp_version
         FROM rmm_network_discovery_profiles p
         JOIN rmm_agent_devices a ON a.id=p.probe_agent_device_id AND a.tenant_id=p.tenant_id
         JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.tenant_id=a.tenant_id
         LEFT JOIN rmm_network_discovery_credentials c ON c.id=p.credential_id AND c.tenant_id=p.tenant_id
         LEFT JOIN organisation_sites s ON s.id=p.site_id AND s.tenant_id=p.tenant_id
        WHERE p.tenant_id=$1
        ORDER BY p.enabled DESC,lower(p.name)`,
      [tenantId],
    ),
    pool.query(
      `SELECT r.id,r.profile_id,r.agent_device_id,r.agent_job_id,r.status,
              r.addresses_total,r.addresses_responded,r.snmp_devices,
              r.presence_devices,r.snmp_enriched_devices,r.error_message,
              r.initiated_by,r.started_at,r.completed_at,r.created_at,p.name AS profile_name
         FROM rmm_network_discovery_runs r
         JOIN rmm_network_discovery_profiles p ON p.id=r.profile_id AND p.tenant_id=r.tenant_id
        WHERE r.tenant_id=$1
        ORDER BY r.created_at DESC
        LIMIT 100`,
      [tenantId],
    ),
    pool.query(
      `SELECT d.id,d.profile_id,d.site_id,d.source_agent_device_id,d.ip_address::text,
              d.mac_address,d.hostname,d.snmp_version,d.sys_name,d.sys_descr,d.sys_object_id,
              d.sys_location,d.sys_contact,d.uptime_ticks,d.interface_count,d.vendor,d.model,
              d.device_type,d.status,d.interfaces,d.metadata,d.discovery_methods,
              d.icmp_reachable,d.latency_ms,d.first_seen_at,d.last_seen_at,
              d.last_presence_at,d.last_snmp_at,
              p.name AS profile_name,p.cidr::text,s.name AS site_name
         FROM rmm_network_devices d
         JOIN rmm_network_discovery_profiles p ON p.id=d.profile_id AND p.tenant_id=d.tenant_id
         LEFT JOIN organisation_sites s ON s.id=d.site_id AND s.tenant_id=d.tenant_id
        WHERE d.tenant_id=$1
        ORDER BY CASE d.status WHEN 'online' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END,
                 d.ip_address
        LIMIT 5000`,
      [tenantId],
    ),
    pool.query(
      `SELECT a.id AS agent_device_id,a.websocket_status,a.last_telemetry_at,a.agent_version,
              i.id AS inventory_id,i.name,i.reference,i.platform,i.operating_system,
              i.manufacturer,i.model,
              i.source_payload->'network' AS network,
              CASE WHEN a.websocket_status='Connected' AND a.last_telemetry_at>now()-interval '90 seconds'
                   THEN true ELSE false END AS online
         FROM rmm_agent_devices a
         JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.tenant_id=a.tenant_id
        WHERE a.tenant_id=$1 AND a.disabled_at IS NULL
        ORDER BY online DESC,lower(i.name)`,
      [tenantId],
    ),
    pool.query(
      `SELECT id,external_key,name
         FROM organisation_sites
        WHERE tenant_id=$1
        ORDER BY lower(name)`,
      [tenantId],
    ),
  ])

  const normalizeMac = (value = '') => clean(value, 128).replace(/[^0-9a-f]/gi, '').toUpperCase()
  const managedByIp = new Map()
  const managedByMac = new Map()

  for (const row of probes.rows) {
    const network = row.network && typeof row.network === 'object' ? row.network : {}
    const identity = {
      agentDeviceId: row.agent_device_id,
      inventoryId: row.inventory_id,
      name: row.name,
      reference: row.reference,
      agentVersion: row.agent_version,
      online: row.online,
      platform: row.platform,
      operatingSystem: row.operating_system,
      manufacturer: row.manufacturer,
      model: row.model,
    }
    const addresses = new Set()
    const macs = new Set()

    const addIp = (value) => {
      const ip = clean(value, 128)
      if (isIP(ip) === 4 && !ip.startsWith('169.254.')) addresses.add(ip)
    }
    const addMac = (value) => {
      const mac = normalizeMac(value)
      if (mac.length === 12) macs.add(mac)
    }

    addIp(network.primary_ipv4)
    addMac(network.mac)
    addMac(network.mac_address)
    for (const value of Array.isArray(network?.primary?.ipv4) ? network.primary.ipv4 : []) addIp(value)
    addMac(network?.primary?.mac)
    addMac(network?.primary?.mac_address)

    for (const adapter of Array.isArray(network.adapters) ? network.adapters : []) {
      for (const value of Array.isArray(adapter?.ipv4) ? adapter.ipv4 : []) addIp(value)
      addMac(adapter?.mac)
      addMac(adapter?.mac_address)
    }
    for (const config of Array.isArray(network.configurations) ? network.configurations : []) {
      for (const value of Array.isArray(config?.ip_addresses) ? config.ip_addresses : []) addIp(value)
      addMac(config?.mac_address)
    }

    for (const ip of addresses) managedByIp.set(ip, identity)
    for (const mac of macs) managedByMac.set(mac, identity)
  }

  const deviceRows = devices.rows.map((row) => {
    const managed = managedByIp.get(clean(row.ip_address, 128))
      || managedByMac.get(normalizeMac(row.mac_address))
      || null
    return {
      ...row,
      managed: Boolean(managed),
      management_state: managed ? 'managed' : 'discovered',
      managed_agent_device_id: managed?.agentDeviceId || null,
      managed_inventory_id: managed?.inventoryId || null,
      managed_device_name: managed?.name || '',
      managed_reference: managed?.reference || '',
      managed_agent_version: managed?.agentVersion || '',
      vendor: row.vendor || managed?.manufacturer || '',
      model: row.model || managed?.model || '',
      device_type: managed
        ? 'computer'
        : (row.device_type || 'network_device'),
      managed_platform: managed?.platform || managed?.operatingSystem || '',
    }
  })

  const onlineDevices = deviceRows.filter((row) => row.status === 'online').length
  const managedDevices = deviceRows.filter((row) => row.managed).length
  const probeRows = probes.rows.map((row) => {
    const { network, ...probe } = row
    return {
      ...probe,
      snmp_capable: versionAtLeast(row.agent_version, SNMP_MIN_AGENT_VERSION),
      snmp_v3_capable: versionAtLeast(row.agent_version, SNMP_V3_MIN_AGENT_VERSION),
      presence_capable: versionAtLeast(row.agent_version, PRESENCE_MIN_AGENT_VERSION),
      dynamic_dnssd_capable: versionAtLeast(row.agent_version, DYNAMIC_DNSSD_MIN_AGENT_VERSION),
      suggested_cidrs: suggestedCidrs(network || {}),
    }
  })
  return {
    credentials: credentials.rows.map(credentialSummary),
    profiles: profiles.rows,
    runs: runs.rows,
    devices: deviceRows,
    probes: probeRows,
    sites: sites.rows,
    summary: {
      profiles: profiles.rows.filter((row) => row.enabled).length,
      devices: deviceRows.length,
      onlineDevices,
      offlineDevices: Math.max(0, deviceRows.length - onlineDevices),
      managedDevices,
      unmanagedDevices: Math.max(0, deviceRows.length - managedDevices),
      onlineProbes: probeRows.filter((row) => row.online).length,
      snmpCapableProbes: probeRows.filter((row) => row.online && row.snmp_capable).length,
      presenceCapableProbes: probeRows.filter((row) => row.online && row.presence_capable).length,
    },
    capabilities: {
      snmpV1: true,
      snmpV2c: true,
      snmpV3: true,
      minAgentVersion: PRESENCE_MIN_AGENT_VERSION,
      minSnmpAgentVersion: SNMP_MIN_AGENT_VERSION,
      minSnmpV3AgentVersion: SNMP_V3_MIN_AGENT_VERSION,
      minPresenceAgentVersion: PRESENCE_MIN_AGENT_VERSION,
      minDynamicDnsSdAgentVersion: DYNAMIC_DNSSD_MIN_AGENT_VERSION,
      presenceDiscovery: true,
      dynamicDnsSd: true,
      methods: ['arp','icmp','reverse_dns','ssdp','mdns','snmp'],
      nameEnrichmentDeferred: true,
      ipv4: true,
      ipv6: false,
      maxAddressesPerProfile: 4096,
    },
  }
}

async function audit(session, eventType, summary, detail = '', metadata = {}) {
  const systemActor = !session.user_id
  await recordRmmActivity({
    tenantId: session.tenant_id,
    actorUserId: session.user_id || null,
    actorType: systemActor ? 'system' : 'technician',
    actorLabel: systemActor ? 'SYSTEM' : (session.name || session.email || 'Technician'),
    eventType,
    category: 'network',
    summary,
    detail,
    outcome: 'success',
    metadata,
  }).catch(() => null)
}

async function loadProfileForDispatch(tenantId, profileId) {
  const result = await pool.query(
    `SELECT p.*,c.name AS credential_name,c.snmp_version,c.community_encrypted,c.username,
            c.security_level,c.auth_protocol,c.auth_secret_encrypted,c.privacy_protocol,
            c.privacy_secret_encrypted,c.context_name,c.enabled AS credential_enabled,
            a.websocket_status,a.last_telemetry_at,a.disabled_at,a.agent_version,
            i.name AS probe_name
       FROM rmm_network_discovery_profiles p
       LEFT JOIN rmm_network_discovery_credentials c
         ON c.id=p.credential_id AND c.tenant_id=p.tenant_id
       JOIN rmm_agent_devices a
         ON a.id=p.probe_agent_device_id AND a.tenant_id=p.tenant_id
       JOIN rmm_device_inventory i
         ON i.id=a.inventory_id AND i.tenant_id=a.tenant_id
      WHERE p.id=$1 AND p.tenant_id=$2
      LIMIT 1`,
    [profileId, tenantId],
  )
  return result.rows[0] || null
}

async function dispatchProfileScan(session, profileId, initiatedBy = 'technician') {
  const profile = await loadProfileForDispatch(session.tenant_id, profileId)
  if (!profile) {
    const error = new Error('Discovery profile not found.')
    error.status = 404
    throw error
  }
  if (!profile.enabled) {
    const error = new Error('Discovery profile is disabled.')
    error.status = 409
    throw error
  }
  const snmpEnabled = Boolean(profile.snmp_enabled && profile.credential_id)
  const presenceEnabled = profile.presence_enabled !== false
  if (!presenceEnabled && !snmpEnabled) {
    const error = new Error('This discovery profile has no enabled discovery methods.')
    error.status = 409
    throw error
  }
  if (snmpEnabled && !profile.credential_enabled) {
    const error = new Error('The SNMP credential assigned to this profile is disabled.')
    error.status = 409
    throw error
  }
  const requiredAgentVersion = profile.snmp_version === 'v3'
    ? SNMP_V3_MIN_AGENT_VERSION
    : (presenceEnabled ? PRESENCE_MIN_AGENT_VERSION : SNMP_MIN_AGENT_VERSION)
  if (!versionAtLeast(profile.agent_version, requiredAgentVersion)) {
    const error = new Error(
      'The selected probe must be upgraded to Hi5Central Agent ' + requiredAgentVersion
      + ' or later before it can run this discovery profile.',
    )
    error.status = 409
    throw error
  }
  const online = profile.websocket_status === 'Connected'
    && profile.last_telemetry_at
    && (Date.now() - new Date(profile.last_telemetry_at).getTime()) < 90000
  if (!online || profile.disabled_at) {
    const error = new Error('The selected discovery probe is offline.')
    error.status = 409
    throw error
  }

  const persistedPayload = {
    protocolVersion: 2,
    profileId: profile.id,
    cidr: String(profile.cidr),
    presenceEnabled,
    presenceTimeoutMs: Number(profile.presence_timeout_ms || 350),
    snmpEnabled,
    snmpPort: Number(profile.snmp_port),
    timeoutMs: Number(profile.timeout_ms),
    retries: Number(profile.retries),
    concurrency: Number(profile.concurrency),
    snmpVersion: snmpEnabled ? profile.snmp_version : '',
  }

  const created = await withTransaction(async (client) => {
    const run = await client.query(
      `INSERT INTO rmm_network_discovery_runs
        (tenant_id,profile_id,agent_device_id,status,initiated_by,initiated_by_user_id,started_at)
       VALUES ($1,$2,$3,'running',$4,$5,now())
       RETURNING id,created_at`,
      [
        session.tenant_id,
        profile.id,
        profile.probe_agent_device_id,
        initiatedBy === 'scheduler' ? 'scheduler' : 'technician',
        initiatedBy === 'scheduler' ? null : session.user_id,
      ],
    )
    const runRow = run.rows[0]
    const payload = { ...persistedPayload, runId: runRow.id }
    const job = await client.query(
      `INSERT INTO rmm_agent_jobs
        (tenant_id,agent_device_id,job_type,payload,status,claimed_at,queued_by_user_id,
         initiated_by,initiated_by_label,request_metadata)
       VALUES ($1,$2,'network.discovery.scan',$3::jsonb,'claimed',now(),$4,$5,$6,$7::jsonb)
       RETURNING id,created_at`,
      [
        session.tenant_id,
        profile.probe_agent_device_id,
        JSON.stringify(payload),
        initiatedBy === 'scheduler' ? null : session.user_id,
        initiatedBy === 'scheduler' ? 'schedule' : 'technician',
        initiatedBy === 'scheduler' ? 'Network discovery scheduler' : (session.name || session.email || 'Technician'),
        JSON.stringify({
          source: 'network_discovery',
          network_discovery_run_id: runRow.id,
          network_discovery_profile_id: profile.id,
        }),
      ],
    )
    await client.query(
      `UPDATE rmm_network_discovery_runs
          SET agent_job_id=$2,updated_at=now()
        WHERE id=$1`,
      [runRow.id, job.rows[0].id],
    )
    return { run: runRow, job: job.rows[0], payload }
  })

  const livePayload = {
    ...created.payload,
    ...(snmpEnabled
      ? {
        credential: profile.snmp_version === 'v3'
          ? {
            version: profile.snmp_version,
            username: profile.username,
            securityLevel: profile.security_level,
            authProtocol: normalizeSnmpV3AuthProtocol(profile.auth_protocol),
            authSecret: decryptSecret(profile.auth_secret_encrypted),
            privacyProtocol: normalizeSnmpV3PrivacyProtocol(profile.privacy_protocol),
            privacySecret: decryptSecret(profile.privacy_secret_encrypted),
            contextName: profile.context_name,
          }
          : {
            version: profile.snmp_version,
            community: decryptSecret(profile.community_encrypted),
          },
      }
      : {}),
  }

  const pushed = sendAgentMessage(profile.probe_agent_device_id, {
    type: 'job_execute',
    job: {
      id: created.job.id,
      job_type: 'network.discovery.scan',
      payload: livePayload,
      created_at: created.job.created_at,
    },
  })

  if (!pushed) {
    await withTransaction(async (client) => {
      await client.query(
        `UPDATE rmm_agent_jobs
            SET status='cancelled',error_message='Probe went offline before dispatch.',
                completed_at=now(),updated_at=now()
          WHERE id=$1 AND tenant_id=$2`,
        [created.job.id, session.tenant_id],
      )
      await client.query(
        `UPDATE rmm_network_discovery_runs
            SET status='cancelled',error_message='Probe went offline before dispatch.',
                completed_at=now(),updated_at=now()
          WHERE id=$1 AND tenant_id=$2`,
        [created.run.id, session.tenant_id],
      )
    })
    const error = new Error('The discovery probe went offline before the scan could start.')
    error.status = 409
    throw error
  }

  await audit(
    session,
    'network.discovery.scan.started',
    'Network discovery scan started',
    profile.name + ' · ' + profile.cidr,
    { profileId: profile.id, runId: created.run.id, agentJobId: created.job.id },
  )
  return { runId: created.run.id, jobId: created.job.id }
}

async function cleanupStaleDiscoveryRuns() {
  const stale = await pool.query(
    `UPDATE rmm_network_discovery_runs
        SET status='failed',
            error_message='Network discovery scan exceeded the 30 minute execution limit.',
            completed_at=now(),
            updated_at=now()
      WHERE status IN ('queued','running')
        AND COALESCE(started_at,created_at) < now() - interval '30 minutes'
    RETURNING id,tenant_id,profile_id,agent_job_id`,
  )
  for (const run of stale.rows) {
    if (run.agent_job_id) {
      await pool.query(
        `UPDATE rmm_agent_jobs
            SET status='failed',
                error_message='Network discovery scan exceeded the 30 minute execution limit.',
                completed_at=now(),
                updated_at=now()
          WHERE id=$1 AND tenant_id=$2 AND status IN ('queued','claimed')`,
        [run.agent_job_id, run.tenant_id],
      ).catch(() => null)
    }
    await pool.query(
      `UPDATE rmm_network_discovery_profiles
          SET next_scan_at=now() + make_interval(mins => scan_interval_minutes),
              updated_at=now()
        WHERE id=$1 AND tenant_id=$2`,
      [run.profile_id, run.tenant_id],
    ).catch(() => null)
  }
}

async function dispatchDueNetworkDiscoveryProfiles() {
  await cleanupStaleDiscoveryRuns()
  const due = await pool.query(
    `SELECT p.id,p.tenant_id,p.presence_enabled,p.snmp_enabled,p.credential_id,
              a.agent_version,c.snmp_version,c.enabled AS credential_enabled
       FROM rmm_network_discovery_profiles p
       LEFT JOIN rmm_network_discovery_credentials c
         ON c.id=p.credential_id AND c.tenant_id=p.tenant_id
       JOIN rmm_agent_devices a
         ON a.id=p.probe_agent_device_id AND a.tenant_id=p.tenant_id
      WHERE p.enabled=true
        AND p.next_scan_at IS NOT NULL
        AND (
          p.presence_enabled=true
          OR (p.snmp_enabled=true AND c.id IS NOT NULL AND c.enabled=true AND c.snmp_version IN ('v1','v2c','v3'))
        )
        AND p.next_scan_at<=now()
        AND a.disabled_at IS NULL
        AND a.websocket_status='Connected'
        AND a.last_telemetry_at>now()-interval '90 seconds'
        AND NOT EXISTS (
          SELECT 1
            FROM rmm_network_discovery_runs r
           WHERE r.profile_id=p.id AND r.tenant_id=p.tenant_id
             AND r.status IN ('queued','running')
        )
      ORDER BY p.next_scan_at,p.id
      LIMIT 10`,
  )
  for (const row of due.rows) {
    const requiredAgentVersion = row.snmp_version === 'v3'
      ? SNMP_V3_MIN_AGENT_VERSION
      : (row.presence_enabled ? PRESENCE_MIN_AGENT_VERSION : SNMP_MIN_AGENT_VERSION)
    if (!versionAtLeast(row.agent_version, requiredAgentVersion)) {
      await pool.query(
        `UPDATE rmm_network_discovery_profiles
            SET next_scan_at=now() + interval '15 minutes',updated_at=now()
          WHERE id=$1 AND tenant_id=$2`,
        [row.id, row.tenant_id],
      ).catch(() => null)
      continue
    }
    const session = {
      tenant_id: row.tenant_id,
      user_id: null,
      name: 'Network discovery scheduler',
      email: '',
    }
    try {
      await dispatchProfileScan(session, row.id, 'scheduler')
    } catch (error) {
      console.error('Scheduled network discovery scan failed', row.id, error?.message || error)
      await pool.query(
        `UPDATE rmm_network_discovery_profiles
            SET next_scan_at=now() + interval '5 minutes',updated_at=now()
          WHERE id=$1 AND tenant_id=$2`,
        [row.id, row.tenant_id],
      ).catch(() => null)
    }
  }
}

let networkDiscoverySchedulerStarted = false
export function startRmmNetworkDiscoveryScheduler() {
  if (networkDiscoverySchedulerStarted) return
  networkDiscoverySchedulerStarted = true
  const run = () => dispatchDueNetworkDiscoveryProfiles()
    .catch((error) => console.error('RMM network discovery scheduler failed', error))
  setTimeout(run, 30_000).unref?.()
  setInterval(run, 60_000).unref?.()
}

export function registerRmmNetworkDiscoveryRoutes(app) {
  app.get('/api/v1/rmm/network-discovery', async (c) => {
    const auth = await requireAccess(c)
    if (auth.error) return auth.error
    return c.json(await bundle(auth.session.tenant_id))
  })

  app.post('/api/v1/rmm/network-discovery/credentials', async (c) => {
    const auth = await requireAccess(c, true)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name, 160)
    const snmpVersion = clean(body.snmpVersion || 'v2c', 16)
    if (!name) return c.json({ error: 'Credential name is required.' }, 400)
    if (!['v1', 'v2c', 'v3'].includes(snmpVersion)) {
      return c.json({ error: 'SNMP version must be v1, v2c or v3.' }, 400)
    }

    let communityEncrypted = ''
    let authEncrypted = ''
    let privacyEncrypted = ''
    const securityLevel = clean(body.securityLevel || 'noAuthNoPriv', 32)
    const username = snmpVersion === 'v3' ? clean(body.username, 32) : ''
    const authProtocol = snmpVersion === 'v3' && securityLevel !== 'noAuthNoPriv'
      ? normalizeSnmpV3AuthProtocol(body.authProtocol)
      : ''
    const privacyProtocol = snmpVersion === 'v3' && securityLevel === 'authPriv'
      ? normalizeSnmpV3PrivacyProtocol(body.privacyProtocol)
      : ''
    const contextName = snmpVersion === 'v3' ? clean(body.contextName, 256) : ''

    if (snmpVersion === 'v1' || snmpVersion === 'v2c') {
      const community = secretValue(body.community, 2048)
      if (!community) return c.json({ error: 'Community string is required.' }, 400)
      communityEncrypted = encryptSecret(community)
    } else {
      if (!username) return c.json({ error: 'SNMPv3 username is required.' }, 400)
      if (Buffer.byteLength(username, 'utf8') > 32) return c.json({ error: 'SNMPv3 username must not exceed 32 octets.' }, 400)
      if (!['noAuthNoPriv', 'authNoPriv', 'authPriv'].includes(securityLevel)) {
        return c.json({ error: 'Invalid SNMPv3 security level.' }, 400)
      }
      if (securityLevel !== 'noAuthNoPriv') {
        const authSecret = secretValue(body.authSecret, 8192)
        if (!['sha1', 'sha256'].includes(authProtocol) || authSecret.length < 8) {
          return c.json({ error: 'SNMPv3 authentication requires SHA-1 or SHA-256 and a passphrase of at least 8 characters.' }, 400)
        }
        authEncrypted = encryptSecret(authSecret)
      }
      if (securityLevel === 'authPriv') {
        const privacySecret = secretValue(body.privacySecret, 8192)
        if (privacyProtocol !== 'aes128' || privacySecret.length < 8) {
          return c.json({ error: 'SNMPv3 privacy requires AES-128 and a passphrase of at least 8 characters.' }, 400)
        }
        privacyEncrypted = encryptSecret(privacySecret)
      }
    }

    try {
      const result = await pool.query(
        `INSERT INTO rmm_network_discovery_credentials
          (tenant_id,name,snmp_version,community_encrypted,username,security_level,
           auth_protocol,auth_secret_encrypted,privacy_protocol,privacy_secret_encrypted,
           context_name,created_by_user_id,updated_by_user_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
         RETURNING id`,
        [
          auth.session.tenant_id, name, snmpVersion, communityEncrypted, username, securityLevel,
          authProtocol, authEncrypted, privacyProtocol, privacyEncrypted, contextName,
          auth.session.user_id,
        ],
      )
      await audit(auth.session, 'network.discovery.credential.created', 'SNMP credential created', name, {
        credentialId: result.rows[0].id,
        snmpVersion,
      })
      return c.json({ success: true, credentialId: result.rows[0].id, bundle: await bundle(auth.session.tenant_id) }, 201)
    } catch (error) {
      if (error?.code === '23505') return c.json({ error: 'A credential with this name already exists.' }, 409)
      throw error
    }
  })

  app.patch('/api/v1/rmm/network-discovery/credentials/:credentialId', async (c) => {
    const auth = await requireAccess(c, true)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const credentialId = clean(c.req.param('credentialId'), 128)
    if (!isUuid(credentialId)) return c.json({ error: 'Credential id is invalid.' }, 400)
    const current = await pool.query(
      `SELECT * FROM rmm_network_discovery_credentials
        WHERE id=$1 AND tenant_id=$2 LIMIT 1`,
      [credentialId, auth.session.tenant_id],
    )
    if (!current.rowCount) return c.json({ error: 'Credential not found.' }, 404)
    const row = current.rows[0]
    const name = clean(body.name ?? row.name, 160)
    const enabled = body.enabled == null ? row.enabled : Boolean(body.enabled)

    let communityEncrypted = row.community_encrypted
    let authEncrypted = row.auth_secret_encrypted
    let privacyEncrypted = row.privacy_secret_encrypted
    if (secretValue(body.community, 8192)) communityEncrypted = encryptSecret(body.community)
    if (secretValue(body.authSecret, 8192)) authEncrypted = encryptSecret(body.authSecret)
    if (secretValue(body.privacySecret, 8192)) privacyEncrypted = encryptSecret(body.privacySecret)

    await pool.query(
      `UPDATE rmm_network_discovery_credentials
          SET name=$3,community_encrypted=$4,auth_secret_encrypted=$5,
              privacy_secret_encrypted=$6,enabled=$7,updated_by_user_id=$8,updated_at=now()
        WHERE id=$1 AND tenant_id=$2`,
      [
        credentialId, auth.session.tenant_id, name, communityEncrypted, authEncrypted,
        privacyEncrypted, enabled, auth.session.user_id,
      ],
    )
    await audit(auth.session, 'network.discovery.credential.updated', 'SNMP credential updated', name, {
      credentialId,
      enabled,
    })
    return c.json({ success: true, bundle: await bundle(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/network-discovery/profiles', async (c) => {
    const auth = await requireAccess(c, true)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name, 160)
    const cidr = validateCidr(body.cidr)
    const probeAgentDeviceId = clean(body.probeAgentDeviceId, 128)
    const credentialId = clean(body.credentialId, 128) || null
    if (!name) return c.json({ error: 'Profile name is required.' }, 400)
    if (!cidr.ok) return c.json({ error: cidr.error }, 400)
    if (!probeAgentDeviceId) {
      return c.json({ error: 'Select a probe endpoint.' }, 400)
    }
    const siteId = clean(body.siteId, 128) || null
    if (!isUuid(probeAgentDeviceId) || (credentialId && !isUuid(credentialId)) || (siteId && !isUuid(siteId))) {
      return c.json({ error: 'Probe, credential or site identifier is invalid.' }, 400)
    }
    const references = await validateProfileReferences(
      auth.session.tenant_id,
      probeAgentDeviceId,
      credentialId,
      siteId,
    )
    if (!references.probe_ok) return c.json({ error: 'Selected probe endpoint is not available.' }, 400)
    if (!references.credential_ok) return c.json({ error: 'Selected SNMP credential is not available.' }, 400)
    if (!references.site_ok) return c.json({ error: 'Selected site is not available.' }, 400)
    const snmpPort = Math.max(1, Math.min(65535, Number(body.snmpPort || 161)))
    const timeoutMs = Math.max(100, Math.min(10000, Number(body.timeoutMs || 800)))
    const presenceTimeoutMs = Math.max(50, Math.min(5000, Number(body.presenceTimeoutMs || 350)))
    const retries = Math.max(0, Math.min(5, Number(body.retries ?? 1)))
    const concurrency = Math.max(1, Math.min(128, Number(body.concurrency || 32)))
    const interval = Math.max(5, Math.min(10080, Number(body.scanIntervalMinutes || 60)))
    const presenceEnabled = body.presenceEnabled !== false
    const snmpEnabled = Boolean(credentialId && body.snmpEnabled !== false)

    try {
      const result = await pool.query(
        `INSERT INTO rmm_network_discovery_profiles
          (tenant_id,name,cidr,site_id,probe_agent_device_id,credential_id,snmp_port,
           timeout_ms,retries,concurrency,scan_interval_minutes,next_scan_at,
           presence_enabled,snmp_enabled,presence_timeout_ms,
           created_by_user_id,updated_by_user_id)
         VALUES ($1,$2,$3::cidr,$4,$5,$6,$7,$8,$9,$10,$11,now(),$12,$13,$14,$15,$15)
         RETURNING id`,
        [
          auth.session.tenant_id, name, cidr.cidr, siteId, probeAgentDeviceId, credentialId,
          snmpPort, timeoutMs, retries, concurrency, interval,
          presenceEnabled, snmpEnabled, presenceTimeoutMs, auth.session.user_id,
        ],
      )
      await audit(auth.session, 'network.discovery.profile.created', 'Network discovery profile created', name + ' · ' + cidr.cidr, {
        profileId: result.rows[0].id,
        addresses: cidr.addresses,
      })
      return c.json({ success: true, profileId: result.rows[0].id, bundle: await bundle(auth.session.tenant_id) }, 201)
    } catch (error) {
      if (error?.code === '23505') return c.json({ error: 'A discovery profile with this name already exists.' }, 409)
      throw error
    }
  })

  app.patch('/api/v1/rmm/network-discovery/profiles/:profileId', async (c) => {
    const auth = await requireAccess(c, true)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const profileId = clean(c.req.param('profileId'), 128)
    if (!isUuid(profileId)) return c.json({ error: 'Discovery profile id is invalid.' }, 400)
    const current = await pool.query(
      `SELECT * FROM rmm_network_discovery_profiles
        WHERE id=$1 AND tenant_id=$2 LIMIT 1`,
      [profileId, auth.session.tenant_id],
    )
    if (!current.rowCount) return c.json({ error: 'Discovery profile not found.' }, 404)
    const row = current.rows[0]
    const name = clean(body.name ?? row.name, 160)
    const cidr = validateCidr(body.cidr ?? String(row.cidr))
    if (!cidr.ok) return c.json({ error: cidr.error }, 400)
    const enabled = body.enabled == null ? row.enabled : Boolean(body.enabled)
    const siteId = clean(body.siteId ?? row.site_id, 128) || null
    const probeAgentDeviceId = clean(body.probeAgentDeviceId ?? row.probe_agent_device_id, 128)
    const credentialId = clean(body.credentialId ?? row.credential_id, 128) || null
    if (!isUuid(probeAgentDeviceId) || (credentialId && !isUuid(credentialId)) || (siteId && !isUuid(siteId))) {
      return c.json({ error: 'Probe, credential or site identifier is invalid.' }, 400)
    }
    const references = await validateProfileReferences(
      auth.session.tenant_id,
      probeAgentDeviceId,
      credentialId,
      siteId,
    )
    if (!references.probe_ok) return c.json({ error: 'Selected probe endpoint is not available.' }, 400)
    if (!references.credential_ok) return c.json({ error: 'Selected SNMP credential is not available.' }, 400)
    if (!references.site_ok) return c.json({ error: 'Selected site is not available.' }, 400)

    const presenceEnabled = body.presenceEnabled == null ? row.presence_enabled : Boolean(body.presenceEnabled)
    const snmpEnabled = credentialId
      ? (body.snmpEnabled == null ? row.snmp_enabled : Boolean(body.snmpEnabled))
      : false
    const presenceTimeoutMs = Math.max(
      50,
      Math.min(5000, Number(body.presenceTimeoutMs ?? row.presence_timeout_ms ?? 350)),
    )

    await pool.query(
      `UPDATE rmm_network_discovery_profiles
          SET name=$3,cidr=$4::cidr,site_id=$5,probe_agent_device_id=$6,credential_id=$7,
              snmp_port=$8,timeout_ms=$9,retries=$10,concurrency=$11,scan_interval_minutes=$12,
              enabled=$13,next_scan_at=CASE WHEN $13 THEN COALESCE(next_scan_at,now()) ELSE NULL END,
              presence_enabled=$14,snmp_enabled=$15,presence_timeout_ms=$16,
              updated_by_user_id=$17,updated_at=now()
        WHERE id=$1 AND tenant_id=$2`,
      [
        profileId,
        auth.session.tenant_id,
        name,
        cidr.cidr,
        siteId,
        probeAgentDeviceId,
        credentialId,
        Math.max(1, Math.min(65535, Number(body.snmpPort ?? row.snmp_port))),
        Math.max(100, Math.min(10000, Number(body.timeoutMs ?? row.timeout_ms))),
        Math.max(0, Math.min(5, Number(body.retries ?? row.retries))),
        Math.max(1, Math.min(128, Number(body.concurrency ?? row.concurrency))),
        Math.max(5, Math.min(10080, Number(body.scanIntervalMinutes ?? row.scan_interval_minutes))),
        enabled,
        presenceEnabled,
        snmpEnabled,
        presenceTimeoutMs,
        auth.session.user_id,
      ],
    )
    await audit(auth.session, 'network.discovery.profile.updated', 'Network discovery profile updated', name + ' · ' + cidr.cidr, {
      profileId,
      enabled,
    })
    return c.json({ success: true, bundle: await bundle(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/network-discovery/profiles/:profileId/scan', async (c) => {
    const auth = await requireAccess(c, true)
    if (auth.error) return auth.error
    try {
      const profileId = clean(c.req.param('profileId'), 128)
      if (!isUuid(profileId)) return c.json({ error: 'Discovery profile id is invalid.' }, 400)
      const started = await dispatchProfileScan(auth.session, profileId)
      return c.json({ success: true, ...started, bundle: await bundle(auth.session.tenant_id) }, 202)
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Unable to start discovery scan.' }, error?.status || 500)
    }
  })
}
