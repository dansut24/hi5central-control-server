import { isIP } from 'node:net'
import { pool, withTransaction } from './db.js'
import { lookupMacVendor } from './rmmMacOui.js'

function clean(value = '', max = 4096) {
  return String(value ?? '').trim().slice(0, max)
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

const NAME_ENRICHMENT_MIN_AGENT_VERSION = '0.1.236'

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function asInteger(value, fallback = null) {
  const number = Number(value)
  return Number.isFinite(number) ? Math.trunc(number) : fallback
}

function normalizeMac(value = '') {
  return clean(value, 64).replace(/[^0-9a-f]/gi, '').toUpperCase()
}

function usableMac(value = '') {
  const mac = normalizeMac(value)
  return mac.length === 12
    && mac !== '000000000000'
    && mac !== 'FFFFFFFFFFFF'
}

function discoveryMethods(raw = {}) {
  const methods = new Set(
    asArray(raw?.discoveryMethods ?? raw?.discovery_methods)
      .map((value) => clean(value, 32).toLowerCase())
      .filter(Boolean),
  )
  if (raw?.icmpReachable ?? raw?.icmp_reachable) methods.add('icmp')
  if (usableMac(raw?.macAddress ?? raw?.mac_address)) methods.add('arp')
  else methods.delete('arp')
  if (clean(raw?.snmpVersion ?? raw?.snmp_version, 32)) methods.add('snmp')
  return [...methods]
}

function inferVendor(sysObjectId = '', sysDescr = '', hostname = '') {
  const oid = clean(sysObjectId, 256)
  const identity = (clean(sysDescr, 4096) + ' ' + clean(hostname, 1024)).toLowerCase()
  const enterprise = [
    ['1.3.6.1.4.1.9', 'Cisco'],
    ['1.3.6.1.4.1.11', 'HPE'],
    ['1.3.6.1.4.1.318', 'APC'],
    ['1.3.6.1.4.1.674', 'Dell'],
    ['1.3.6.1.4.1.253', 'Xerox'],
    ['1.3.6.1.4.1.1248', 'Epson'],
    ['1.3.6.1.4.1.14988', 'MikroTik'],
    ['1.3.6.1.4.1.12356', 'Fortinet'],
    ['1.3.6.1.4.1.14823', 'Aruba'],
    ['1.3.6.1.4.1.41112', 'Ubiquiti'],
    ['1.3.6.1.4.1.6574', 'Synology'],
    ['1.3.6.1.4.1.24681', 'QNAP'],
    ['1.3.6.1.4.1.2435', 'Brother'],
    ['1.3.6.1.4.1.1602', 'Canon'],
    ['1.3.6.1.4.1.2636', 'Juniper'],
    ['1.3.6.1.4.1.25461', 'Palo Alto Networks'],
    ['1.3.6.1.4.1.29671', 'Cisco Meraki'],
    ['1.3.6.1.4.1.4526', 'NETGEAR'],
    ['1.3.6.1.4.1.11863', 'TP-Link'],
    ['1.3.6.1.4.1.1916', 'Extreme Networks'],
    ['1.3.6.1.4.1.25053', 'Ruckus'],
    ['1.3.6.1.4.1.367', 'Ricoh'],
    ['1.3.6.1.4.1.1347', 'Kyocera'],
    ['1.3.6.1.4.1.641', 'Lexmark'],
    ['1.3.6.1.4.1.10642', 'Zebra'],
  ]
  for (const [prefix, vendor] of enterprise) {
    if (oid === prefix || oid.startsWith(prefix + '.')) return vendor
  }
  const words = [
    ['cisco', 'Cisco'], ['hewlett', 'HPE'], ['aruba', 'Aruba'], ['fortinet', 'Fortinet'],
    ['mikrotik', 'MikroTik'], ['ubiquiti', 'Ubiquiti'], ['synology', 'Synology'],
    ['qnap', 'QNAP'], ['brother', 'Brother'], ['xerox', 'Xerox'], ['epson', 'Epson'],
    ['canon', 'Canon'], ['dell', 'Dell'], ['apc', 'APC'], ['eero', 'eero'],
    ['apple', 'Apple'], ['iphone', 'Apple'], ['ipad', 'Apple'], ['samsung', 'Samsung'],
    ['roku', 'Roku'], ['sonos', 'Sonos'], ['ring', 'Ring'], ['netgear', 'NETGEAR'],
    ['tp-link', 'TP-Link'], ['tplink', 'TP-Link'], ['raspberrypi', 'Raspberry Pi'],
  ]
  return words.find(([needle]) => identity.includes(needle))?.[1] || ''
}

function inferModel(sysDescr = '', hostname = '', vendor = '') {
  const description = clean(sysDescr, 4096)
  const identity = (description + ' ' + clean(hostname, 1024)).trim()
  const vendorName = clean(vendor, 256).toLowerCase()
  if (!identity) return ''

  const directPatterns = [
    /\b(Forti(?:Gate|Switch|AP)[- ]?[A-Z0-9-]+)\b/i,
    /\b(PA-\d{3,5}[A-Z0-9-]*)\b/i,
    /\b(WS-C\d+[A-Z0-9-]*|C\d{3,5}[A-Z0-9-]*)\b/i,
    /\b(MS\d{2,3}-\d+[A-Z0-9-]*|MX\d{2,3}[A-Z0-9-]*|MR\d{2,3}[A-Z0-9-]*)\b/i,
    /\b(EX\d{4,5}[A-Z0-9-]*|SRX\d+[A-Z0-9-]*)\b/i,
    /\b(UAP-[A-Z0-9-]+|USW-[A-Z0-9-]+|UDM-[A-Z0-9-]+|UXG-[A-Z0-9-]+)\b/i,
    /\b(DS\d{2,4}[A-Z0-9+.-]*|RS\d{2,4}[A-Z0-9+.-]*)\b/i,
    /\b(TS-\d+[A-Z0-9-]*|TVS-[A-Z0-9-]+)\b/i,
  ]
  for (const pattern of directPatterns) {
    const match = identity.match(pattern)
    if (match?.[1]) return clean(match[1].replace(/\s+/g, '-'), 160)
  }

  if (vendorName.includes('mikrotik')) {
    const match = description.match(/RouterOS[^\n]*?\son\s+([^,;()]+)/i)
    if (match?.[1]) return clean(match[1], 160)
  }

  if (['brother', 'xerox', 'epson', 'canon', 'ricoh', 'kyocera', 'lexmark', 'zebra'].some((name) => vendorName.includes(name))) {
    const candidates = description
      .split(/[;,|]/)
      .map((value) => clean(value, 160))
      .filter((value) => value && !/firmware|version|network|printer|server|ethernet/i.test(value))
    const modelish = candidates.find((value) => /[A-Z].*\d|\d.*[A-Z]/i.test(value))
    if (modelish) return modelish
  }

  return ''
}

function inferDeviceType(sysDescr = '', sysObjectId = '', hostname = '', vendor = '') {
  const value = (
    clean(sysDescr, 4096) + ' '
    + clean(sysObjectId, 256) + ' '
    + clean(hostname, 1024) + ' '
    + clean(vendor, 256)
  ).toLowerCase()
  if (/firewall|fortigate|security appliance/.test(value)) return 'firewall'
  if (/\beero\b|\brouter\b|routing|gateway/.test(value)) return 'router'
  if (/wireless|access point|wi-fi access|\bwlan ap\b/.test(value)) return 'access_point'
  if (/\bswitch\b/.test(value)) return 'switch'
  if (/printer|laserjet|officejet|imageclass|brother.*hl-|epson.*wf-/.test(value)) return 'printer'
  if (/\bups\b|uninterruptible/.test(value)) return 'ups'
  if (/\bnas\b|synology|qnap|network attached storage/.test(value)) return 'storage'
  if (/iphone|ipad|android|pixel|galaxy.*phone/.test(value)) return 'mobile_device'
  if (/smart.?tv|bravia|roku|chromecast|fire.?tv|apple.?tv|sonos/.test(value)) return 'media_device'
  if (/camera|doorbell|\bring\b|arlo|reolink/.test(value)) return 'camera'
  if (/server|proliant|poweredge/.test(value)) return 'server'
  if (/windows|macbook|imac|desktop|laptop|workstation/.test(value)) return 'computer'
  return 'network_device'
}

function networkNameScore(value = '', metadata = {}, methods = []) {
  const name = clean(value, 512)
  if (!name) return -1
  const lower = name.toLowerCase()
  if (['none', 'none-2', 'linux', 'localhost', 'unknown', 'device', 'network device'].includes(lower)) return 0

  let score = 10
  if (lower === 'spotifyconnect' || /^spotifyconnect\s+#\d+$/i.test(name)) score = 4
  else if (/^[0-9a-f]{10,}$/i.test(name)) score = 4
  else if (/^[A-Z0-9]{12,}$/.test(name)) score = 5
  if (/\s/.test(name)) score += 2

  const mdnsScore = Number(metadata?.mdns?.friendlyNameScore)
  if (Number.isFinite(mdnsScore)) score = Math.max(score, mdnsScore)
  if (asArray(methods).map((item) => clean(item, 32).toLowerCase()).includes('reverse_dns')) {
    score += 20
  }
  return score
}

function preferNetworkHostname(existingName, existingMetadata, existingMethods, reportedName, reportedMetadata, reportedMethods) {
  const current = clean(existingName, 512)
  const reported = clean(reportedName, 512)
  if (!current) return reported
  if (!reported) return current
  const currentScore = networkNameScore(current, existingMetadata, existingMethods)
  const reportedScore = networkNameScore(reported, reportedMetadata, reportedMethods)
  return reportedScore > currentScore ? reported : current
}

function matterDeviceTypeName(metadata = {}) {
  const dt = clean(metadata?.mdns?.txt?.dt, 32)
  const names = {
    '34': 'Speaker',
    '35': 'Casting Video Player',
    '36': 'Content App',
    '40': 'Basic Video Player',
    '41': 'Casting Video Client',
    '42': 'Video Remote Control',
  }
  return names[dt] || ''
}

function inferDiscoveryMetadataType(metadata = {}) {
  const mdns = metadata?.mdns && typeof metadata.mdns === 'object' ? metadata.mdns : {}
  const capabilities = new Set(
    asArray(mdns.capabilities).map((value) => clean(value, 64).toLowerCase()).filter(Boolean),
  )
  const matterName = matterDeviceTypeName(metadata)

  if (capabilities.has('gateway') || capabilities.has('eero')) return 'router'
  if (capabilities.has('printing')) return 'printer'
  if (matterName && /speaker|video|content app/i.test(matterName)) return 'media_device'
  if (capabilities.has('google_cast')
      || capabilities.has('airplay')
      || capabilities.has('airplay_audio')
      || capabilities.has('spotify_connect')) return 'media_device'
  if (capabilities.has('workstation') || capabilities.has('smb') || capabilities.has('ssh')) return 'computer'
  if (capabilities.has('homekit') || capabilities.has('matter')) return 'smart_home'
  return 'network_device'
}

export async function reconcileNetworkDiscoveryJobResult(completedJob, resultPayload = {}, success = false) {
  if (completedJob?.job_type !== 'network.discovery.scan') return

  const runId = clean(
    completedJob?.request_metadata?.network_discovery_run_id
      || completedJob?.payload?.runId,
    128,
  )
  if (!runId) return

  const runResult = await pool.query(
    `SELECT r.id,r.tenant_id,r.profile_id,r.agent_device_id,p.site_id,a.agent_version
       FROM rmm_network_discovery_runs r
       JOIN rmm_network_discovery_profiles p
         ON p.id=r.profile_id AND p.tenant_id=r.tenant_id
       JOIN rmm_agent_devices a
         ON a.id=r.agent_device_id AND a.tenant_id=r.tenant_id
      WHERE r.id=$1 AND r.tenant_id=$2
      LIMIT 1`,
    [runId, completedJob.tenant_id],
  )
  if (!runResult.rowCount) return

  const run = runResult.rows[0]
  const devices = asArray(resultPayload.devices)
    .slice(0, 4096)
    .filter((item) => {
      const methods = discoveryMethods(item)
      return Boolean(item?.icmpReachable ?? item?.icmp_reachable)
        || methods.includes('snmp')
        || usableMac(item?.macAddress ?? item?.mac_address)
    })
  const status = success ? 'completed' : 'failed'
  const addressesTotal = asInteger(resultPayload.addressesTotal ?? resultPayload.addresses_total, 0) || 0
  const addressesResponded = devices.length
  const errorMessage = clean(
    completedJob.error_message || resultPayload.error || resultPayload.message,
    2000,
  )
  const enrichmentTargets = success && versionAtLeast(run.agent_version, NAME_ENRICHMENT_MIN_AGENT_VERSION)
    ? [...new Set(
      devices
        .filter((item) => !clean(item?.hostname, 512))
        .map((item) => clean(item?.ipAddress ?? item?.ip_address, 128))
        .filter(Boolean),
    )].slice(0, 512)
    : []
  const snmpEnrichedDevices = devices.filter(
    (item) => discoveryMethods(item).includes('snmp'),
  ).length
  const presenceDevices = devices.filter((item) => {
    const methods = discoveryMethods(item)
    return methods.includes('arp') || methods.includes('icmp') || methods.includes('reverse_dns')
  }).length

  await withTransaction(async (client) => {
    if (success) {
      await client.query(
        `UPDATE rmm_network_devices
            SET status='offline',updated_at=now()
          WHERE tenant_id=$1 AND profile_id=$2`,
        [run.tenant_id, run.profile_id],
      )

      for (const raw of devices) {
        const ipAddress = clean(raw?.ipAddress ?? raw?.ip_address, 128)
        if (!ipAddress) continue
        const methods = discoveryMethods(raw)
        const snmpObserved = methods.includes('snmp')
        const sysDescr = clean(raw?.sysDescr ?? raw?.sys_descr, 8192)
        const sysObjectId = clean(raw?.sysObjectId ?? raw?.sys_object_id, 512)
        const hostname = clean(raw?.hostname, 512)
        const rawMacAddress = raw?.macAddress ?? raw?.mac_address
        const macAddress = usableMac(rawMacAddress) ? clean(rawMacAddress, 64) : ''
        const vendor = clean(raw?.vendor, 256)
          || inferVendor(sysObjectId, sysDescr, hostname)
          || lookupMacVendor(macAddress)
        const model = clean(raw?.model, 512)
          || inferModel(sysDescr, hostname, vendor)
        const deviceType = clean(raw?.deviceType ?? raw?.device_type, 64)
          || inferDeviceType(sysDescr, sysObjectId, hostname, vendor)

        await client.query(
          `INSERT INTO rmm_network_devices
            (tenant_id,profile_id,site_id,source_agent_device_id,ip_address,mac_address,hostname,
             snmp_version,sys_name,sys_descr,sys_object_id,sys_location,sys_contact,uptime_ticks,
             interface_count,vendor,model,device_type,status,interfaces,metadata,
             discovery_methods,icmp_reachable,latency_ms,
             first_seen_at,last_seen_at,last_presence_at,last_snmp_at,updated_at)
           VALUES
            ($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'online',
             $19::jsonb,$20::jsonb,$21::jsonb,$22,$23,
             now(),now(),now(),CASE WHEN $24 THEN now() ELSE NULL END,now())
           ON CONFLICT (profile_id,ip_address)
           DO UPDATE SET
             site_id=EXCLUDED.site_id,
             source_agent_device_id=EXCLUDED.source_agent_device_id,
             mac_address=CASE WHEN EXCLUDED.mac_address<>'' THEN EXCLUDED.mac_address ELSE rmm_network_devices.mac_address END,
             hostname=CASE WHEN EXCLUDED.hostname<>'' THEN EXCLUDED.hostname ELSE rmm_network_devices.hostname END,
             snmp_version=CASE WHEN EXCLUDED.snmp_version<>'' THEN EXCLUDED.snmp_version ELSE rmm_network_devices.snmp_version END,
             sys_name=CASE WHEN EXCLUDED.sys_name<>'' THEN EXCLUDED.sys_name ELSE rmm_network_devices.sys_name END,
             sys_descr=CASE WHEN EXCLUDED.sys_descr<>'' THEN EXCLUDED.sys_descr ELSE rmm_network_devices.sys_descr END,
             sys_object_id=CASE WHEN EXCLUDED.sys_object_id<>'' THEN EXCLUDED.sys_object_id ELSE rmm_network_devices.sys_object_id END,
             sys_location=CASE WHEN EXCLUDED.sys_location<>'' THEN EXCLUDED.sys_location ELSE rmm_network_devices.sys_location END,
             sys_contact=CASE WHEN EXCLUDED.sys_contact<>'' THEN EXCLUDED.sys_contact ELSE rmm_network_devices.sys_contact END,
             uptime_ticks=COALESCE(EXCLUDED.uptime_ticks,rmm_network_devices.uptime_ticks),
             interface_count=COALESCE(EXCLUDED.interface_count,rmm_network_devices.interface_count),
             vendor=CASE WHEN EXCLUDED.vendor<>'' THEN EXCLUDED.vendor ELSE rmm_network_devices.vendor END,
             model=CASE WHEN EXCLUDED.model<>'' THEN EXCLUDED.model ELSE rmm_network_devices.model END,
             device_type=EXCLUDED.device_type,
             status='online',
             interfaces=CASE WHEN EXCLUDED.interfaces<>'[]'::jsonb THEN EXCLUDED.interfaces ELSE rmm_network_devices.interfaces END,
             metadata=EXCLUDED.metadata,
             discovery_methods=EXCLUDED.discovery_methods,
             icmp_reachable=EXCLUDED.icmp_reachable,
             latency_ms=EXCLUDED.latency_ms,
             last_seen_at=now(),
             last_presence_at=now(),
             last_snmp_at=CASE WHEN $24 THEN now() ELSE rmm_network_devices.last_snmp_at END,
             updated_at=now()`,
          [
            run.tenant_id,
            run.profile_id,
            run.site_id,
            run.agent_device_id,
            ipAddress,
            macAddress,
            clean(raw?.hostname, 512),
            clean(raw?.snmpVersion ?? raw?.snmp_version, 32),
            clean(raw?.sysName ?? raw?.sys_name, 1024),
            sysDescr,
            sysObjectId,
            clean(raw?.sysLocation ?? raw?.sys_location, 2048),
            clean(raw?.sysContact ?? raw?.sys_contact, 2048),
            asInteger(raw?.uptimeTicks ?? raw?.uptime_ticks),
            asInteger(raw?.interfaceCount ?? raw?.interface_count),
            vendor,
            model,
            deviceType,
            JSON.stringify(asArray(raw?.interfaces).slice(0, 1024)),
            JSON.stringify(raw?.metadata && typeof raw.metadata === 'object' && !Array.isArray(raw.metadata)
              ? raw.metadata
              : {}),
            JSON.stringify(methods),
            Boolean(raw?.icmpReachable ?? raw?.icmp_reachable),
            asInteger(raw?.latencyMs ?? raw?.latency_ms),
            snmpObserved,
          ],
        )
      }
    }

    await client.query(
      `UPDATE rmm_network_discovery_runs
          SET status=$3,
              addresses_total=$4,
              addresses_responded=$5,
              snmp_devices=$6,
              presence_devices=$7,
              snmp_enriched_devices=$8,
              result=$9::jsonb,
              error_message=$10,
              started_at=COALESCE(
                rmm_network_discovery_runs.started_at,
                job.claimed_started_at,
                rmm_network_discovery_runs.created_at
              ),
              completed_at=now(),
              updated_at=now()
        FROM (
          SELECT id,claimed_at AS claimed_started_at
            FROM rmm_agent_jobs
           WHERE id=$11
        ) job
       WHERE rmm_network_discovery_runs.id=$1
         AND rmm_network_discovery_runs.tenant_id=$2`,
      [
        run.id,
        run.tenant_id,
        status,
        addressesTotal,
        addressesResponded,
        snmpEnrichedDevices,
        presenceDevices,
        snmpEnrichedDevices,
        JSON.stringify(resultPayload),
        errorMessage,
        completedJob.id,
      ],
    )

    await client.query(
      `UPDATE rmm_network_discovery_profiles
          SET last_scan_at=now(),
              next_scan_at=CASE WHEN enabled
                THEN now() + make_interval(mins => scan_interval_minutes)
                ELSE NULL END,
              updated_at=now()
        WHERE id=$1 AND tenant_id=$2`,
      [run.profile_id, run.tenant_id],
    )

    if (enrichmentTargets.length) {
      await client.query(
        `INSERT INTO rmm_agent_jobs
          (tenant_id,agent_device_id,job_type,payload,status,initiated_by,initiated_by_label,request_metadata)
         SELECT $1,$2,'network.discovery.enrich',$3::jsonb,'queued','system',
                'Network discovery enrichment',$4::jsonb
          WHERE NOT EXISTS (
            SELECT 1
              FROM rmm_agent_jobs
             WHERE tenant_id=$1
               AND agent_device_id=$2
               AND job_type='network.discovery.enrich'
               AND status IN ('queued','claimed')
               AND request_metadata->>'network_discovery_profile_id'=$5
          )`,
        [
          run.tenant_id,
          run.agent_device_id,
          JSON.stringify({
            protocolVersion: 1,
            profileId: run.profile_id,
            targets: enrichmentTargets,
          }),
          JSON.stringify({
            source: 'network_discovery_enrichment',
            network_discovery_run_id: run.id,
            network_discovery_profile_id: run.profile_id,
          }),
          run.profile_id,
        ],
      )
    }
  })
}


export async function reconcileNetworkDiscoveryEnrichmentJobResult(
  completedJob,
  resultPayload = {},
  success = false,
) {
  if (completedJob?.job_type !== 'network.discovery.enrich' || !success) return

  const profileId = clean(
    completedJob?.request_metadata?.network_discovery_profile_id
      || completedJob?.payload?.profileId,
    128,
  )
  if (!profileId) return

  const devices = asArray(resultPayload.devices).slice(0, 512)
  if (!devices.length) return

  await withTransaction(async (client) => {
    for (const raw of devices) {
      const ipAddress = clean(raw?.ipAddress ?? raw?.ip_address, 128)
      if (isIP(ipAddress) !== 4) continue

      const hostname = clean(raw?.hostname, 512)
      const reportedVendor = clean(raw?.vendor, 256)
      const reportedModel = clean(raw?.model, 512)
      const reportedType = clean(raw?.deviceType ?? raw?.device_type, 64)
      const methods = [...new Set(
        asArray(raw?.discoveryMethods ?? raw?.discovery_methods)
          .map((value) => clean(value, 32).toLowerCase())
          .filter(Boolean),
      )]
      const metadata = raw?.metadata && typeof raw.metadata === 'object' && !Array.isArray(raw.metadata)
        ? raw.metadata
        : {}

      if (!hostname && !reportedVendor && !reportedModel && !reportedType && !methods.length && !Object.keys(metadata).length) {
        continue
      }

      const current = await client.query(
        `SELECT hostname,vendor,model,device_type,sys_descr,sys_object_id,discovery_methods,metadata
           FROM rmm_network_devices
          WHERE tenant_id=$1 AND profile_id=$2 AND ip_address=$3::inet
          LIMIT 1`,
        [completedJob.tenant_id, profileId, ipAddress],
      )
      if (!current.rowCount) continue

      const existing = current.rows[0]
      const existingMethods = asArray(existing.discovery_methods)
        .map((value) => clean(value, 32).toLowerCase())
        .filter(Boolean)
      const nextHostname = preferNetworkHostname(
        existing.hostname,
        existing.metadata,
        existingMethods,
        hostname,
        metadata,
        methods,
      )
      const vendor = reportedVendor
        || clean(existing.vendor, 256)
        || inferVendor(existing.sys_object_id, existing.sys_descr, nextHostname)
      const model = reportedModel || clean(existing.model, 512)
      const inferredType = inferDeviceType(
        existing.sys_descr,
        existing.sys_object_id,
        nextHostname,
        vendor,
      )
      const metadataType = inferDiscoveryMetadataType(metadata)
      const existingType = clean(existing.device_type, 64)
      const nextType = inferredType && inferredType !== 'network_device'
        ? inferredType
        : metadataType && metadataType !== 'network_device'
          ? metadataType
          : reportedType && reportedType !== 'network_device'
            ? reportedType
            : (existingType && existingType !== 'network_device' ? existingType : 'network_device')

      const mergedMethods = [...new Set([
        ...asArray(existing.discovery_methods).map((value) => clean(value, 32).toLowerCase()).filter(Boolean),
        ...methods,
      ])]
      const matterType = matterDeviceTypeName(metadata)
      const mergedMetadata = {
        ...(existing.metadata && typeof existing.metadata === 'object' && !Array.isArray(existing.metadata)
          ? existing.metadata
          : {}),
        ...metadata,
        ...(metadata?.mdns && typeof metadata.mdns === 'object'
          ? {
            mdns: {
              ...(existing.metadata?.mdns && typeof existing.metadata.mdns === 'object'
                ? existing.metadata.mdns
                : {}),
              ...metadata.mdns,
              ...(matterType ? { matterDeviceType: matterType } : {}),
            },
          }
          : {}),
      }

      await client.query(
        `UPDATE rmm_network_devices
            SET hostname=$4,
                vendor=$5,
                model=$6,
                device_type=$7,
                discovery_methods=$8::jsonb,
                metadata=$9::jsonb,
                updated_at=now()
          WHERE tenant_id=$1 AND profile_id=$2 AND ip_address=$3::inet`,
        [
          completedJob.tenant_id,
          profileId,
          ipAddress,
          nextHostname,
          vendor,
          model,
          nextType,
          JSON.stringify(mergedMethods),
          JSON.stringify(mergedMetadata),
        ],
      )
    }
  })
}
