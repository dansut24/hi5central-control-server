import { pool, withTransaction } from './db.js'
import { fetchPublicJson, normalizedSha256, publicHttpsUrl } from './rmmTenantVendorSources.js'

const EVERGREEN_API = 'https://evergreen-api.stealthpuppy.com'
const MIN_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1000

const mappings = [
  ['sevenzip', '7zip'],
  ['gh_brave_brave_browser', 'BraveBrowser'],
  ['google_chrome', 'GoogleChrome'],
  ['gh_keepassxreboot_keepassxc', 'KeePassXCTeamKeePassXC'],
  ['gh_microsoft_powertoys', 'MicrosoftPowerToys'],
  ['mozilla_firefox', 'MozillaFirefox'],
  ['mozilla_thunderbird', 'MozillaThunderbird'],
  ['nodejs', 'NodeJs'],
  ['python', 'Python'],
  ['gh_sharex_sharex', 'ShareX'],
  ['vlc_media_player', 'VideoLanVlcPlayer'],
  ['gh_winmerge_winmerge', 'WinMerge'],
  ['gh_obsidianmd_obsidian_releases', 'Obsidian'],
  ['hashicorp_boundary', 'HashicorpBoundary'],
  ['hashicorp_consul', 'HashicorpConsul'],
  ['gh_kubernetes_kubernetes', 'KubernetesKubectl'],
  ['hashicorp_nomad', 'HashicorpNomad'],
  ['hashicorp_packer', 'HashicorpPacker'],
  ['hashicorp_terraform', 'HashicorpTerraform'],
  ['hashicorp_vault', 'HashicorpVault'],
]

function clean(value = '') { return String(value ?? '').trim() }
function lower(value = '') { return clean(value).toLowerCase() }
function versionNumbers(value = '') { return clean(value).match(/\d+/g)?.map(Number) || [] }

function versionsEquivalent(left, right) {
  const a = versionNumbers(left)
  const b = versionNumbers(right)
  if (!a.length || !b.length || a.length !== b.length) return false
  return a.every((part, index) => part === b[index])
}

function rowInstallerType(row = {}) {
  const explicit = lower(row.Type)
  if (explicit === 'msi' || explicit === 'exe') return explicit
  const path = (() => {
    try { return new URL(clean(row.URI)).pathname.toLowerCase() } catch { return '' }
  })()
  if (path.endsWith('.msi')) return 'msi'
  if (path.endsWith('.exe')) return 'exe'
  return ''
}

function x64Candidate(row = {}) {
  const architecture = lower(row.Architecture)
  if (architecture && !['x64', 'amd64', 'x86_64', '64-bit'].includes(architecture)) return false
  const uri = lower(row.URI)
  if (/arm64|aarch64/.test(uri)) return false
  if (/(?:^|[-_.])(?:x86|win32|32bit)(?:[-_.]|$)/.test(uri) && !/x86_64|x86-64/.test(uri)) return false
  return true
}

function assetScore(row = {}) {
  const type = rowInstallerType(row)
  if (!type || !x64Candidate(row)) return -Infinity
  const flavour = lower(row.InstallerType)
  if (flavour.includes('portable') || flavour.includes('legacy')) return -Infinity
  let score = type === 'msi' ? 100 : 70
  if (flavour.includes('default') || flavour.includes('enterprise')) score += 20
  if (flavour.includes('silent')) score += 15
  if (flavour.includes('user')) score -= 25
  if (lower(row.URI).includes('x64') || lower(row.URI).includes('amd64')) score += 10
  return score
}

function selectMatchingAsset(rows, targetVersion) {
  return (Array.isArray(rows) ? rows : [])
    .filter((row) => versionsEquivalent(row.Version, targetVersion))
    .map((row) => ({ row, score: assetScore(row) }))
    .filter((item) => Number.isFinite(item.score))
    .sort((a, b) => b.score - a.score)[0]?.row || null
}

async function latestRelease(sourceKey) {
  const result = await pool.query(
    `SELECT DISTINCT ON (source_key,provider_package_id)
            id,source_key,provider_package_id,canonical_name,publisher,version,
            installer_url,installer_sha256,installer_type,trust_state
       FROM rmm_software_vendor_releases
      WHERE source_key=$1
      ORDER BY source_key,provider_package_id,last_seen_at DESC
      LIMIT 1`,
    [sourceKey],
  )
  return result.rows[0] || null
}

async function applyEvidence(release, appId, rows, asset) {
  const observedVersions = [...new Set((Array.isArray(rows) ? rows : [])
    .map((row) => clean(row.Version)).filter(Boolean))].slice(0, 12)
  const evidence = {
    source: 'evergreen',
    appId,
    checkedAt: new Date().toISOString(),
    authoritativeVersion: release.version,
    observedVersions,
    versionMatched: Boolean(asset),
    usableInstaller: false,
  }

  let installerUrl = ''
  let installerSha256 = ''
  let installerType = ''
  if (asset) {
    const safe = await publicHttpsUrl(clean(asset.URI))
    installerUrl = safe.toString()
    installerSha256 = normalizedSha256(asset.Sha256)
    installerType = rowInstallerType(asset)
    evidence.usableInstaller = Boolean(installerUrl && installerType)
    evidence.installerUrl = installerUrl
    evidence.installerType = installerType
    evidence.sha256 = installerSha256
    evidence.architecture = clean(asset.Architecture)
    evidence.installerVariant = clean(asset.InstallerType)
  }

  const promote = release.trust_state === 'version_only' && evidence.usableInstaller
  await withTransaction(async (client) => {
    await client.query(
      `UPDATE rmm_software_vendor_releases
          SET installer_url=CASE WHEN $3 AND installer_url='' THEN $4 ELSE installer_url END,
              installer_sha256=CASE WHEN $3 AND installer_sha256='' AND $5<>'' THEN $5 ELSE installer_sha256 END,
              installer_type=CASE WHEN $3 AND installer_type='' THEN $6 ELSE installer_type END,
              trust_state=CASE WHEN $3 AND trust_state='version_only' THEN 'asset_candidate' ELSE trust_state END,
              trust_evidence=trust_evidence || jsonb_build_object('evergreen',$2::jsonb),
              source_payload=source_payload || jsonb_build_object('evergreen',$2::jsonb),
              last_seen_at=now()
        WHERE id=$1`,
      [release.id, JSON.stringify(evidence), promote, installerUrl, installerSha256, installerType],
    )

    await client.query(
      `UPDATE rmm_software_catalogue
          SET source_metadata=source_metadata
                || jsonb_build_object('evergreen',$2::jsonb)
                || CASE
                     WHEN $3 AND COALESCE(source_metadata->>'trustState','version_only')='version_only'
                       THEN jsonb_build_object('trustState','asset_candidate')
                     ELSE '{}'::jsonb
                   END,
              updated_at=now()
        WHERE tenant_id IS NULL
          AND catalogue_source='vendor'
          AND external_key=$1
          AND status='active'`,
      [release.provider_package_id, JSON.stringify(evidence), promote],
    )
  })

  return {
    sourceKey: release.source_key,
    appId,
    version: release.version,
    evergreenVersions: observedVersions,
    promoted: promote,
    installerType,
    hasSha256: Boolean(installerSha256),
  }
}

let lastSyncAt = 0
let inFlight = null

export async function syncEvergreenCorroboration({ force = false } = {}) {
  if (!force && Date.now() - lastSyncAt < MIN_SYNC_INTERVAL_MS) {
    return { skipped: true, reason: 'interval', results: [] }
  }
  if (inFlight) return inFlight

  inFlight = (async () => {
    const results = []
    for (const [sourceKey, appId] of mappings) {
      const release = await latestRelease(sourceKey)
      if (!release) continue
      try {
        const endpoint = await publicHttpsUrl(
          EVERGREEN_API + '/app/' + encodeURIComponent(appId),
        )
        const rows = await fetchPublicJson(endpoint.toString())
        const asset = selectMatchingAsset(rows, release.version)
        results.push(await applyEvidence(release, appId, rows, asset))
      } catch (error) {
        results.push({
          sourceKey,
          appId,
          version: release.version,
          promoted: false,
          error: clean(error?.message || error),
        })
      }
    }
    lastSyncAt = Date.now()
    return {
      skipped: false,
      checked: results.length,
      promoted: results.filter((item) => item.promoted).length,
      results,
    }
  })()

  try {
    return await inFlight
  } finally {
    inFlight = null
  }
}

export const evergreenMappings = Object.freeze(
  mappings.map(([sourceKey, appId]) => ({ sourceKey, appId })),
)
