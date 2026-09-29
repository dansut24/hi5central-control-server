import fs from 'node:fs'
import zlib from 'node:zlib'
import { DatabaseSync } from 'node:sqlite'
import { pool } from './db.js'
import { normalizeCatalogueVersion } from './rmmSoftwareVersioning.js'

const SOURCE_URL = 'https://cdn.winget.microsoft.com/cache/source2.msix'
const INDEX_DB_PATH = '/tmp/hi5central-winget-index.db'
const CACHE_MS = Math.max(5 * 60 * 1000, Number(process.env.RMM_WINGET_INDEX_CACHE_MS) || 15 * 60 * 1000)
let lastIndexRefreshAt = 0
let lastSummary = null

function clean(value = '') { return String(value ?? '').trim() }
function lower(value = '') { return clean(value).toLowerCase() }
function normalizedName(value = '') {
  return clean(value).toLowerCase().replace(/[^a-z0-9]+/g, '')
}
function githubApiToken() {
  const envToken = clean(process.env.GITHUB_TOKEN)
  if (envToken) return envToken
  const tokenFile = clean(process.env.GITHUB_TOKEN_FILE)
  if (!tokenFile) return ''
  try { return clean(fs.readFileSync(tokenFile, 'utf8')) } catch { return '' }
}
function githubApiHeaders(extra = {}) {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'Hi5Central-WinGet-Manifest/1.0', ...extra }
  const token = githubApiToken()
  if (token) headers.Authorization = 'Bearer ' + token
  return headers
}
function normalizedPublisher(value = '') {
  return normalizedName(value)
    .replace(/(?:incorporated|corporation|company|limited|software|foundation|project|llc|ltd|inc|corp)$/g, '')
}
function versionParts(value = '') {
  const parts = clean(value).match(/\d+/g)
  return parts?.length ? parts.map(Number) : null
}
function compareVersions(leftValue, rightValue) {
  const left = versionParts(leftValue)
  const right = versionParts(rightValue)
  if (!left || !right) return null
  const size = Math.max(left.length, right.length)
  for (let index = 0; index < size; index += 1) {
    const delta = (left[index] || 0) - (right[index] || 0)
    if (delta) return delta < 0 ? -1 : 1
  }
  return 0
}
function u32(buffer, offset) { return buffer.readUInt32LE(offset) }
function u64(buffer, offset) {
  const value = buffer.readBigUInt64LE(offset)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('WinGet source index is too large.')
  return Number(value)
}

function extractIndexDatabase(msix) {
  const eocdSignature = Buffer.from([0x50, 0x4b, 0x05, 0x06])
  const eocd = msix.lastIndexOf(eocdSignature)
  if (eocd < 20) throw new Error('WinGet source is missing its ZIP end record.')
  const locator = eocd - 20
  if (u32(msix, locator) !== 0x07064b50) throw new Error('WinGet source is not ZIP64.')
  const zip64 = u64(msix, locator + 8)
  if (u32(msix, zip64) !== 0x06064b50) throw new Error('WinGet source ZIP64 directory is invalid.')
  const entries = u64(msix, zip64 + 32)
  const centralOffset = u64(msix, zip64 + 48)
  let cursor = centralOffset
  for (let index = 0; index < entries; index += 1) {
    if (u32(msix, cursor) !== 0x02014b50) throw new Error('WinGet central directory is invalid.')
    const method = msix.readUInt16LE(cursor + 10)
    const compressedSize = u32(msix, cursor + 20)
    const nameLength = msix.readUInt16LE(cursor + 28)
    const extraLength = msix.readUInt16LE(cursor + 30)
    const commentLength = msix.readUInt16LE(cursor + 32)
    const localOffset = u32(msix, cursor + 42)
    const name = msix.subarray(cursor + 46, cursor + 46 + nameLength).toString('utf8')
    if (name === 'Public/index.db') {
      if (u32(msix, localOffset) !== 0x04034b50) throw new Error('WinGet index local header is invalid.')
      const localNameLength = msix.readUInt16LE(localOffset + 26)
      const localExtraLength = msix.readUInt16LE(localOffset + 28)
      const start = localOffset + 30 + localNameLength + localExtraLength
      const compressed = msix.subarray(start, start + compressedSize)
      const output = method === 8 ? zlib.inflateRawSync(compressed) : compressed
      if (!output.subarray(0, 16).toString('ascii').startsWith('SQLite format 3')) {
        throw new Error('WinGet Public/index.db is not SQLite.')
      }
      return output
    }
    cursor += 46 + nameLength + extraLength + commentLength
  }
  throw new Error('WinGet source did not contain Public/index.db.')
}

async function downloadIndexDatabase() {
  const response = await fetch(SOURCE_URL, {
    headers: { 'User-Agent': 'Hi5Central-Software-Catalogue/1.0' },
    signal: AbortSignal.timeout(60_000),
  })
  if (!response.ok) throw new Error('WinGet source returned HTTP ' + response.status)
  const length = Number(response.headers.get('content-length') || 0)
  if (length && length > 25 * 1024 * 1024) throw new Error('WinGet source exceeded the size limit.')
  const msix = Buffer.from(await response.arrayBuffer())
  if (msix.length > 25 * 1024 * 1024) throw new Error('WinGet source exceeded the size limit.')
  return extractIndexDatabase(msix)
}

async function ensureIndexDatabase(force = false) {
  const cacheFresh = !force
    && lastIndexRefreshAt
    && Date.now() - lastIndexRefreshAt < CACHE_MS
    && fs.existsSync(INDEX_DB_PATH)
  if (cacheFresh) return { path: INDEX_DB_PATH, refreshed: false }

  const indexBytes = await downloadIndexDatabase()
  fs.writeFileSync(INDEX_DB_PATH, indexBytes)
  lastIndexRefreshAt = Date.now()
  return { path: INDEX_DB_PATH, refreshed: true }
}

function publisherEvidence(db, packageRowId, publisher) {
  const expected = normalizedPublisher(publisher)
  if (!expected) return { matched: false, values: [] }
  const values = db.prepare('SELECT norm_publisher FROM norm_publishers2 WHERE package=? LIMIT 25')
    .all(packageRowId).map((row) => normalizedPublisher(row.norm_publisher)).filter(Boolean)
  const matched = values.some((value) => value === expected || value.includes(expected) || expected.includes(value))
  return { matched, values }
}
async function catalogueBindings() {
  const result = await pool.query(
    `SELECT b.source_key,b.provider_package_id,b.canonical_name,b.publisher,b.metadata,
            c.id AS catalogue_id,c.target_version,c.qualification_state,c.source_metadata,
            vr.trust_state AS vendor_trust_state,vr.installer_url AS vendor_installer_url
       FROM rmm_software_vendor_bindings b
       JOIN rmm_software_vendor_sources s ON s.source_key=b.source_key AND s.enabled=true
       LEFT JOIN rmm_software_catalogue c
         ON c.tenant_id IS NULL AND c.status='active'
        AND c.catalogue_source='vendor' AND c.external_key=b.provider_package_id
       LEFT JOIN LATERAL (
         SELECT r.trust_state,r.installer_url
           FROM rmm_software_vendor_releases r
          WHERE r.source_key=b.source_key
            AND r.provider_package_id=b.provider_package_id
            AND r.channel=b.channel
            AND r.platform=b.platform
            AND r.architecture=b.architecture
          ORDER BY r.last_seen_at DESC
          LIMIT 1
       ) vr ON true
      WHERE b.enabled=true AND b.platform IN ('windows','cross_platform')
        AND b.architecture IN ('x64','amd64','any')
      ORDER BY lower(b.canonical_name)`
  )
  return result.rows
}

export async function syncAutomaticWingetFallbacks({ force = false, dryRun = false } = {}) {
  const index = await ensureIndexDatabase(force)
  const db = new DatabaseSync(index.path, { readOnly: true })
  try {
    const packages = db.prepare('SELECT rowid,id,name,latest_version FROM packages').all()
    const byName = new Map()
    const byId = new Map()
    for (const item of packages) {
      const idKey = clean(item.id).toLowerCase()
      if (idKey) byId.set(idKey, item)
      const key = normalizedName(item.name)
      if (!key) continue
      if (!byName.has(key)) byName.set(key, [])
      byName.get(key).push(item)
    }

    const bindings = await catalogueBindings()
    const mappings = []
    let ambiguous = 0
    let unmatched = 0
    for (const binding of bindings) {
      const metadata = binding.metadata && typeof binding.metadata === 'object' ? binding.metadata : {}
      const automaticPackageId = clean(metadata.autoWingetPackageId)
      const knownPackageId = clean(metadata.wingetPackageId || automaticPackageId)
      const curatedPackageId = Boolean(knownPackageId && !automaticPackageId)
      let match = null
      let confidence = ''
      let publisher = { matched: false, values: [] }

      if (knownPackageId) {
        match = byId.get(knownPackageId.toLowerCase()) || null
        if (!match) {
          unmatched += 1
          continue
        }
        publisher = publisherEvidence(db, match.rowid, binding.publisher)
        confidence = curatedPackageId
          ? (publisher.matched ? 'curated_package_id_publisher' : 'curated_package_id')
          : (publisher.matched ? 'automatic_package_id_publisher' : 'automatic_package_id')
      } else {
        const matches = byName.get(normalizedName(binding.canonical_name)) || []
        if (matches.length !== 1) {
          if (matches.length > 1) ambiguous += 1
          else unmatched += 1
          continue
        }
        match = matches[0]
        publisher = publisherEvidence(db, match.rowid, binding.publisher)
        if (clean(binding.publisher) && !publisher.matched) {
          unmatched += 1
          continue
        }
        confidence = publisher.matched ? 'exact_name_publisher' : 'exact_unique_name'
      }

      const providerVersion = normalizeCatalogueVersion(match.latest_version, { source_metadata: binding.source_metadata }, 'provider')
      const targetVersion = normalizeCatalogueVersion(binding.target_version, { source_metadata: binding.source_metadata }, 'installed')
      const versionComparison = compareVersions(providerVersion, targetVersion)
      mappings.push({
        sourceKey: binding.source_key,
        providerPackageId: binding.provider_package_id,
        catalogueId: binding.catalogue_id,
        packageId: clean(match.id),
        packageName: clean(match.name),
        packageVersion: clean(match.latest_version),
        comparedPackageVersion: providerVersion,
        targetVersion: clean(binding.target_version),
        comparedTargetVersion: targetVersion,
        vendorTrustState: clean(binding.vendor_trust_state || 'version_only'),
        vendorHasAsset: Boolean(clean(binding.vendor_installer_url)),
        vendorDirectReady: clean(binding.vendor_trust_state) === 'direct_ready',
        transportReady: Boolean(clean(binding.target_version))
          && versionComparison !== null
          && versionComparison >= 0,
        confidence,
        curatedPackageId,
      })
    }

    if (!dryRun) {
      for (const mapping of mappings) {
        // A rejected/signer-review vendor artifact must never be used directly, but
        // that failure is transport-specific. A separately version-verified WinGet
        // package can still provide a safe fallback while preserving the vendor
        // failure in vendorTrustState for manual review.
        const terminalVendorTrust = ['rejected','signer_review_required'].includes(mapping.vendorTrustState)
        const effectiveTrustState = mapping.vendorDirectReady
          ? 'direct_ready'
          : mapping.transportReady
            ? 'winget_ready'
            : terminalVendorTrust
              ? mapping.vendorTrustState
              : mapping.vendorHasAsset
                ? 'asset_candidate'
                : 'version_only'
        const evidence = {
          wingetPackageId: mapping.packageId,
          wingetPackageName: mapping.packageName,
          wingetPackageVersion: mapping.packageVersion,
          wingetTargetVersion: mapping.targetVersion,
          wingetPackageConfidence: mapping.confidence,
          wingetPackageSource: SOURCE_URL,
          wingetPackageMappedAt: new Date().toISOString(),
          wingetPackageMapping: mapping.curatedPackageId ? 'curated' : 'automatic',
          wingetFallbackReady: mapping.transportReady,
          hasWingetFallback: mapping.transportReady,
          vendorTrustState: mapping.vendorTrustState,
          deploymentMode: mapping.vendorDirectReady
            ? 'vendor_direct'
            : mapping.transportReady
              ? 'winget_preferred'
              : 'intelligence_only',
          trustState: effectiveTrustState,
        }
        if (!mapping.curatedPackageId) {
          evidence.autoWingetPackageId = mapping.packageId
          evidence.autoWingetPackageName = mapping.packageName
          evidence.autoWingetVersion = mapping.packageVersion
          evidence.autoWingetTargetVersion = mapping.targetVersion
          evidence.autoWingetConfidence = mapping.confidence
          evidence.autoWingetSource = SOURCE_URL
          evidence.autoWingetMappedAt = evidence.wingetPackageMappedAt
        }

        await pool.query(
          `UPDATE rmm_software_vendor_bindings
              SET metadata=metadata || $3::jsonb
            WHERE source_key=$1 AND provider_package_id=$2 AND enabled=true`,
          [mapping.sourceKey, mapping.providerPackageId, JSON.stringify(evidence)],
        )
        await pool.query(
          `UPDATE rmm_software_vendor_releases
              SET trust_state=CASE
                    WHEN trust_state='direct_ready' THEN trust_state
                    WHEN $7::boolean THEN 'winget_ready'
                    WHEN trust_state IN ('rejected','signer_review_required') THEN trust_state
                    ELSE $4
                  END,
                  trust_evidence=trust_evidence || $5::jsonb,
                  source_payload=(source_payload || $6::jsonb)
                    || jsonb_build_object(
                      'trustState',
                      CASE
                        WHEN trust_state='direct_ready' THEN trust_state
                        WHEN $7::boolean THEN 'winget_ready'
                        WHEN trust_state IN ('rejected','signer_review_required') THEN trust_state
                        ELSE $4
                      END
                    ),
                  last_seen_at=now()
            WHERE source_key=$1
              AND provider_package_id=$2
              AND version=$3`,
          [
            mapping.sourceKey,
            mapping.providerPackageId,
            mapping.targetVersion,
            evidence.trustState,
            JSON.stringify({
              wingetPackageId: mapping.packageId,
              wingetPackageVersion: mapping.packageVersion,
              wingetTargetVersion: mapping.targetVersion,
              wingetFallbackReady: mapping.transportReady,
              wingetPackageMapping: evidence.wingetPackageMapping,
            }),
            JSON.stringify({
              trustState: evidence.trustState,
              deploymentMode: evidence.deploymentMode,
              wingetFallbackReady: mapping.transportReady,
            }),
            mapping.transportReady,
          ],
        )
        if (mapping.catalogueId) {
          await pool.query(
            `UPDATE rmm_software_catalogue
                SET source_metadata=source_metadata || $2::jsonb,
                    qualification_evidence=qualification_evidence || $2::jsonb,
                    qualification_state=CASE
                      WHEN qualification_state IN ('qualified','qualified_limited','blocked') THEN qualification_state
                      WHEN $3 OR $4 THEN 'deployment_candidate'
                      ELSE 'intelligence_only'
                    END,
                    qualification_notes=CASE
                      WHEN $4 THEN qualification_notes
                      WHEN $3 THEN 'Vendor feed is authoritative; WinGet is a version-verified fallback transport.'
                      ELSE 'Vendor feed is authoritative; the matched WinGet fallback is behind the vendor target.'
                    END,
                    updated_at=now()
              WHERE id=$1 AND tenant_id IS NULL AND status='active'`,
            [
              mapping.catalogueId,
              JSON.stringify(evidence),
              mapping.transportReady,
              mapping.vendorDirectReady,
            ],
          )
        }
      }
    }

    const summary = {
      checked: bindings.length,
      mapped: mappings.length,
      ambiguous,
      unmatched,
      dryRun,
      source: SOURCE_URL,
      indexRefreshed: index.refreshed,
      mappings,
    }
    if (!dryRun) {
      lastSummary = { ...summary, mappings: mappings.slice(0, 25) }
    }
    return summary
  } finally {
    db.close()
  }
}

export async function wingetRepositoryAllSearch({ query = '', forceRefresh = false } = {}) {
  const index = await ensureIndexDatabase(forceRefresh)
  const db = new DatabaseSync(index.path, { readOnly: true })
  try {
    const q = clean(query).slice(0, 160).toLowerCase()
    const pattern = '%' + q + '%'
    const where = q
      ? `WHERE lower(p.id) LIKE ?
          OR lower(p.name) LIKE ?
          OR lower(COALESCE(p.moniker,'')) LIKE ?
          OR p.rowid IN (
            SELECT np.package
              FROM norm_publishers2 np
             WHERE lower(np.norm_publisher) LIKE ?
          )`
      : ''
    const args = q ? [pattern, pattern, pattern, pattern] : []
    const rows = db.prepare(
      `SELECT p.rowid,p.id,p.name,p.moniker,p.latest_version
         FROM packages p
         ${where}
        ORDER BY lower(p.name),lower(p.id)`,
    ).all(...args)

    const wanted = new Set(rows.map((row) => Number(row.rowid)))
    const publisherMap = new Map()
    if (wanted.size) {
      const publisherRows = db.prepare(
        `SELECT package,norm_publisher
           FROM norm_publishers2
          WHERE norm_publisher<>''
          ORDER BY package,norm_publisher`,
      ).all()
      for (const row of publisherRows) {
        const key = Number(row.package)
        if (!wanted.has(key)) continue
        if (!publisherMap.has(key)) publisherMap.set(key, [])
        const values = publisherMap.get(key)
        const publisher = clean(row.norm_publisher)
        if (publisher && values.length < 4 && !values.includes(publisher)) values.push(publisher)
      }
    }

    return {
      query: clean(query).slice(0, 160),
      total: rows.length,
      source: SOURCE_URL,
      indexRefreshed: index.refreshed,
      indexRefreshedAt: lastIndexRefreshAt ? new Date(lastIndexRefreshAt).toISOString() : null,
      packages: rows.map((row) => ({
        id: clean(row.id),
        name: clean(row.name),
        moniker: clean(row.moniker),
        version: clean(row.latest_version),
        publishers: publisherMap.get(Number(row.rowid)) || [],
      })),
    }
  } finally {
    db.close()
  }
}

export async function wingetRepositorySearch({ query = '', page = 1, pageSize = 50, forceRefresh = false } = {}) {
  const index = await ensureIndexDatabase(forceRefresh)
  const db = new DatabaseSync(index.path, { readOnly: true })
  try {
    const q = clean(query).slice(0, 160).toLowerCase()
    const safePageSize = Math.max(10, Math.min(100, Number(pageSize) || 50))
    const safePage = Math.max(1, Number(page) || 1)
    const pattern = '%' + q + '%'
    const where = q
      ? `WHERE lower(p.id) LIKE ?
          OR lower(p.name) LIKE ?
          OR lower(COALESCE(p.moniker,'')) LIKE ?
          OR p.rowid IN (
            SELECT np.package
              FROM norm_publishers2 np
             WHERE lower(np.norm_publisher) LIKE ?
          )`
      : ''
    const args = q ? [pattern, pattern, pattern, pattern] : []
    const total = Number(db.prepare(`SELECT count(*) AS total FROM packages p ${where}`).get(...args)?.total || 0)
    const pages = Math.max(1, Math.ceil(total / safePageSize))
    const resolvedPage = Math.min(safePage, pages)
    const rows = db.prepare(
      `SELECT p.rowid,p.id,p.name,p.moniker,p.latest_version
         FROM packages p
         ${where}
        ORDER BY lower(p.name),lower(p.id)
        LIMIT ? OFFSET ?`,
    ).all(...args, safePageSize, (resolvedPage - 1) * safePageSize)

    const publisherMap = new Map()
    const rowids = rows.map((row) => Number(row.rowid)).filter(Number.isFinite)
    if (rowids.length) {
      const placeholders = rowids.map(() => '?').join(',')
      const publisherRows = db.prepare(
        `SELECT package,norm_publisher
           FROM norm_publishers2
          WHERE package IN (${placeholders}) AND norm_publisher<>''
          ORDER BY package,norm_publisher`,
      ).all(...rowids)
      for (const row of publisherRows) {
        const key = Number(row.package)
        if (!publisherMap.has(key)) publisherMap.set(key, [])
        const values = publisherMap.get(key)
        if (values.length < 4 && !values.includes(clean(row.norm_publisher))) values.push(clean(row.norm_publisher))
      }
    }

    return {
      query: clean(query).slice(0, 160),
      page: resolvedPage,
      pageSize: safePageSize,
      pages,
      total,
      source: SOURCE_URL,
      indexRefreshed: index.refreshed,
      indexRefreshedAt: lastIndexRefreshAt ? new Date(lastIndexRefreshAt).toISOString() : null,
      packages: rows.map((row) => ({
        id: clean(row.id),
        name: clean(row.name),
        moniker: clean(row.moniker),
        version: clean(row.latest_version),
        publishers: publisherMap.get(Number(row.rowid)) || [],
      })),
    }
  } finally {
    db.close()
  }
}


const WINGET_MANIFEST_ROOT = 'https://raw.githubusercontent.com/microsoft/winget-pkgs/master'
const ENTERPRISE_SEED_CSV = 'https://content.patchmypc.com/downloads/csv/PatchMyPC-SupportedProductsList.csv'

function yamlScalar(value = '') {
  const raw = clean(value)
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1)
  }
  return raw
}

function manifestValue(text, key) {
  const escapedKey = String(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = String(text || '').match(new RegExp('^' + escapedKey + ':\\s*(.+?)\\s*$', 'mi'))
  return yamlScalar(match?.[1] || '')
}

function parseWingetInstallers(text) {
  const source = String(text || '').replaceAll('\r\n', '\n')
  const marker = source.search(/^Installers:\s*$/mi)
  if (marker < 0) return []
  const header = source.slice(0, marker)
  const section = source.slice(marker).replace(/^Installers:\s*\n?/i, '')
  const globalInstallerType = lower(manifestValue(header, 'InstallerType'))
  const appsAndFeaturesInstallerType = lower(yamlScalar(
    header.match(/^AppsAndFeaturesEntries:\s*$[\s\S]*?^\s+InstallerType:\s*(.+?)\s*$/mi)?.[1] || '',
  ))
  const globalScope = lower(manifestValue(header, 'Scope'))
  const globalProductCode = yamlScalar(
    header.match(/^ProductCode:\s*(.+?)\s*$/mi)?.[1]
      || header.match(/^\s*-\s*ProductCode:\s*(.+?)\s*$/mi)?.[1]
      || '',
  )
  const globalSilent = yamlScalar(header.match(/^\s{2}Silent:\s*(.+?)\s*$/mi)?.[1] || '')
  const blocks = section.split(/\n(?=\s*-\s+(?:Architecture|InstallerUrl):)/g)
  const installers = []
  for (const raw of blocks) {
    const url = yamlScalar(raw.match(/^\s*InstallerUrl:\s*(.+?)\s*$/mi)?.[1] || raw.match(/^\s*-\s*InstallerUrl:\s*(.+?)\s*$/mi)?.[1] || '')
    const sha256 = clean(raw.match(/^\s*InstallerSha256:\s*([A-Fa-f0-9]{64})\s*$/mi)?.[1]).toUpperCase()
    if (!url || !sha256) continue
    const architecture = lower(yamlScalar(raw.match(/^\s*-?\s*Architecture:\s*(.+?)\s*$/mi)?.[1] || ''))
    const declaredType = lower(yamlScalar(
      raw.match(/^\s*InstallerType:\s*(.+?)\s*$/mi)?.[1]
      || (globalInstallerType === 'exe' && appsAndFeaturesInstallerType ? appsAndFeaturesInstallerType : globalInstallerType),
    ))
    const scope = lower(yamlScalar(raw.match(/^\s*Scope:\s*(.+?)\s*$/mi)?.[1] || globalScope))
    const silent = yamlScalar(raw.match(/^\s+Silent:\s*(.+?)\s*$/mi)?.[1] || globalSilent)
    const productCode = yamlScalar(raw.match(/^\s*ProductCode:\s*(.+?)\s*$/mi)?.[1] || globalProductCode)
    let path = ''
    try { path = new URL(url).pathname.toLowerCase() } catch {}
    const installerType = path.endsWith('.msi') ? 'msi' : path.endsWith('.exe') ? 'exe' : ''
    installers.push({ architecture, url, sha256, installerType, installerTechnology: declaredType, scope, silent, productCode })
  }
  return installers
}

function acceptableUpstreamInstaller(installer) {
  if (!installer?.url || !installer?.sha256 || !['msi','exe'].includes(clean(installer.installerType))) return false
  let url
  try { url = new URL(installer.url) } catch { return false }
  if (url.protocol !== 'https:') return false
  const host = lower(url.hostname)
  if (
    host === 'cdn.winget.microsoft.com'
    || host.endsWith('.winget.microsoft.com')
    || host === 'apps.microsoft.com'
    || (host === 'www.microsoft.com' && url.pathname.toLowerCase().includes('/store/'))
  ) return false
  return true
}

function wingetManifestPath(packageId, version, suffix = '.installer.yaml') {
  const parts = clean(packageId).split('.').filter(Boolean)
  if (parts.length < 2) return ''
  return [
    'manifests',
    parts[0][0].toLowerCase(),
    ...parts,
    clean(version),
    clean(packageId) + suffix,
  ].map((segment) => encodeURIComponent(segment)).join('/')
}

async function fetchWingetManifest(packageId, version) {
  for (const suffix of ['.installer.yaml', '.yaml']) {
    const path = wingetManifestPath(packageId, version, suffix)
    if (!path) continue
    const url = WINGET_MANIFEST_ROOT + '/' + path
    const response = await fetch(url, {
      headers: { Accept: 'text/plain', 'User-Agent': 'Hi5Central-WinGet-Manifest/1.0' },
      signal: AbortSignal.timeout(20_000),
    })
    if (response.status === 404) continue
    if (!response.ok) throw new Error('WinGet manifest HTTP ' + response.status)
    const text = await response.text()
    if (text.length > 512 * 1024) throw new Error('WinGet manifest exceeded size limit')
    return { url, text }
  }
  return null
}

export async function resolveWingetVendorInstaller(packageId, version = '') {
  const index = await ensureIndexDatabase(false)
  const db = new DatabaseSync(index.path, { readOnly: true })
  try {
    const pkg = db.prepare(
      'SELECT rowid,id,name,latest_version FROM packages WHERE lower(id)=lower(?) LIMIT 1',
    ).get(clean(packageId))
    if (!pkg) return { ok: false, reason: 'winget_package_not_found', packageId: clean(packageId) }
    const resolvedVersion = clean(version || pkg.latest_version)
    const manifest = await fetchWingetManifest(clean(pkg.id), resolvedVersion)
    if (!manifest) return { ok: false, reason: 'winget_installer_manifest_not_found', packageId: clean(pkg.id), version: resolvedVersion }
    const installers = parseWingetInstallers(manifest.text)
      .filter(acceptableUpstreamInstaller)
      .sort((a, b) => {
        const architectureWeight = (item) => item.architecture === 'x64' || item.architecture === 'amd64'
          ? 0 : ['neutral',''].includes(item.architecture) ? 1 : item.architecture === 'x86' ? 2 : 9
        const scopeWeight = (item) => lower(item.scope) === 'machine'
          ? 0 : !clean(item.scope) ? 1 : lower(item.scope) === 'user' ? 2 : 3
        return architectureWeight(a) - architectureWeight(b)
          || scopeWeight(a) - scopeWeight(b)
      })
    const selected = installers.find((item) => !['arm64','arm'].includes(item.architecture))
    if (!selected) {
      return {
        ok: false,
        reason: 'no_upstream_msi_or_exe',
        packageId: clean(pkg.id),
        name: clean(pkg.name),
        version: resolvedVersion,
        manifestUrl: manifest.url,
      }
    }
    const publishers = db.prepare(
      "SELECT DISTINCT norm_publisher FROM norm_publishers2 WHERE package=? AND norm_publisher<>'' ORDER BY norm_publisher LIMIT 6",
    ).all(pkg.rowid).map((row) => clean(row.norm_publisher)).filter(Boolean)
    let installArguments = clean(selected.silent)
    if (
      lower(pkg.id) === '3dconnexion.3dxware.10'
      && selected.installerTechnology === 'burn'
      && !/(^|\s)\/install(?:\s|$)/i.test(installArguments)
    ) {
      installArguments = ['/install', installArguments].filter(Boolean).join(' ')
    }
    return {
      ok: true,
      packageId: clean(pkg.id),
      name: clean(pkg.name),
      version: resolvedVersion,
      publishers,
      manifestUrl: manifest.url,
      installerUrl: selected.url,
      installerSha256: selected.sha256,
      installerType: selected.installerType,
      installerTechnology: selected.installerTechnology,
      architecture: selected.architecture || 'any',
      scope: selected.scope,
      installArguments,
      productCode: /^\{[0-9A-Fa-f-]{36}\}$/.test(clean(selected.productCode)) ? clean(selected.productCode) : '',
      upstreamHost: new URL(selected.url).hostname,
    }
  } finally {
    db.close()
  }
}

function enterpriseSeedName(value = '') {
  return clean(value)
    .replace(/\s*\((?:User[- ]?)?(?:EXE|MSI|MSIX|ARM64|x64|x86|Machine|User)[^)]*\)\s*$/i, '')
    .replace(/\s*\(User[^)]*\)\s*$/i, '')
    .replace(/\s+-\s+MSI Install\s*$/i, '')
    .replace(/\s+Latest\s*$/i, '')
    .replace(/\s+/g, ' ')
    .trim()
}

function parseEnterpriseSeedCsv(text) {
  const rows = []
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = line.match(/^"((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)"\s*$/)
    if (!match || match[1] === 'Product') continue
    rows.push({
      product: match[1].replaceAll('""', '"'),
      vendor: match[2].replaceAll('""', '"'),
      localContent: lower(match[3]) === 'true',
    })
  }
  return rows
}

export async function wingetEnterpriseSeedMatches({ limit = 1200 } = {}) {
  const index = await ensureIndexDatabase(false)
  const db = new DatabaseSync(index.path, { readOnly: true })
  try {
    const response = await fetch(ENTERPRISE_SEED_CSV, {
      headers: { Accept: 'text/csv', 'User-Agent': 'Hi5Central-Catalogue-Seed/1.0' },
      signal: AbortSignal.timeout(30_000),
    })
    if (!response.ok) throw new Error('Enterprise seed catalogue HTTP ' + response.status)
    const rows = parseEnterpriseSeedCsv(await response.text())
    const packages = db.prepare('SELECT rowid,id,name,latest_version FROM packages').all()
    const byName = new Map()
    for (const pkg of packages) {
      const key = normalizedName(pkg.name)
      if (!key) continue
      if (!byName.has(key)) byName.set(key, [])
      byName.get(key).push(pkg)
    }

    const seenPackages = new Set()
    const matches = []
    for (const row of rows) {
      const product = enterpriseSeedName(row.product)
      if (!product || /\b(?:arm64|x86)\b/i.test(row.product)) continue
      const candidates = byName.get(normalizedName(product)) || []
      if (!candidates.length) continue
      let selected = candidates[0]
      if (candidates.length > 1 && row.vendor) {
        selected = candidates.find((pkg) => publisherEvidence(db, pkg.rowid, row.vendor).matched) || selected
      }
      const packageKey = lower(selected.id)
      if (!packageKey || seenPackages.has(packageKey)) continue
      const publisher = publisherEvidence(db, selected.rowid, row.vendor)
      if (row.vendor && !publisher.matched && candidates.length > 1) continue
      seenPackages.add(packageKey)
      matches.push({
        packageId: clean(selected.id),
        packageName: clean(selected.name),
        version: clean(selected.latest_version),
        seedProduct: product,
        seedVendor: clean(row.vendor),
        publishers: publisher.values,
        source: ENTERPRISE_SEED_CSV,
      })
      if (matches.length >= Math.max(1, Math.min(2500, Number(limit) || 1200))) break
    }
    return matches
  } finally {
    db.close()
  }
}

export function automaticWingetFallbackSummary() {
  return lastSummary
}

export async function resolvePreviousWingetVendorInstaller(packageId, currentVersion) {
  const parts=clean(packageId).split('.')
  if(parts.length<2 || parts.some(p=>!/^[a-z0-9_-]+$/i.test(p))) throw new Error('invalid_winget_package_id')
  const path=['manifests',parts[0][0].toLowerCase(),...parts].map(encodeURIComponent).join('/')
  const response=await fetch('https://api.github.com/repos/microsoft/winget-pkgs/contents/'+path,{
    headers:githubApiHeaders(),
    signal:AbortSignal.timeout(20_000),
  })
  if(!response.ok) throw new Error('WinGet version history HTTP '+response.status)
  const payload=await response.json()
  const versions=(Array.isArray(payload)?payload:[]).filter(r=>r.type==='dir')
    .map(r=>clean(r.name)).filter(v=>/^\d+(?:[.\-]\d+)*$/.test(v) && compareVersions(v,currentVersion)<0)
    .sort((a,b)=>compareVersions(b,a)).slice(0,3)
  for(const version of versions) {
    const resolved=await resolveWingetVendorInstaller(packageId,version)
    if(resolved.ok && resolved.scope!=='user' && ['x64','amd64','neutral','any'].includes(resolved.architecture)
      && /^[a-f0-9]{64}$/i.test(resolved.installerSha256)) return resolved
  }
  return null
}
