import fs from 'node:fs'
import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'
import { pool, withTransaction } from './db.js'
import { recalculateAllTenantVulnerabilityExposures } from './rmmVulnerabilityExposure.js'
import {
  htmlHostAllowed,
  normalizeVendorHtmlAutomationPolicy,
  normalizeVendorHtmlRecipe,
  parseVendorHtmlReleases,
  robotsPathAllowed,
} from './vendorHtmlRecipe.js'

function clean(value = '') { return String(value ?? '').trim() }

export function githubApiToken() {
  const envToken = clean(process.env.GITHUB_TOKEN)
  if (envToken) return envToken
  const tokenFile = clean(process.env.GITHUB_TOKEN_FILE)
  if (!tokenFile) return ''
  try { return clean(fs.readFileSync(tokenFile, 'utf8')) } catch { return '' }
}

export function githubApiHeaders(extra = {}) {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'Hi5Central-Software-Catalogue/1.0', ...extra }
  const token = githubApiToken()
  if (token) headers.Authorization = 'Bearer ' + token
  return headers
}

function privateIpv4(address) {
  const parts = address.split('.').map(Number)
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true
  const [a, b, c] = parts
  return a === 0 || a === 10 || a === 127
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 0 && (c === 0 || c === 2))
    || (a === 192 && b === 88 && c === 99)
    || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
    || a >= 224
}

function privateIpv6(address) {
  const value = address.toLowerCase().split('%')[0]
  if (value === '::' || value === '::1') return true
  if (value.startsWith('fc') || value.startsWith('fd') || value.startsWith('ff')) return true
  if (/^fe[89ab]/.test(value) || value.startsWith('2001:db8:')) return true
  if (value.startsWith('::ffff:')) {
    const mapped = value.slice(7)
    return isIP(mapped) === 4 ? privateIpv4(mapped) : true
  }
  return false
}

function privateAddress(address) {
  const family = isIP(address)
  if (family === 4) return privateIpv4(address)
  if (family === 6) return privateIpv6(address)
  return true
}

async function limitedResponseBytes(response, maxBytes) {
  const declared = Number(response.headers.get('content-length') || 0)
  if (declared > maxBytes) throw new Error('Vendor response exceeds the allowed size.')
  if (!response.body) return new Uint8Array()
  const reader = response.body.getReader()
  const chunks = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel().catch(() => {})
      throw new Error('Vendor response exceeds the allowed size.')
    }
    chunks.push(value)
  }
  const output = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    output.set(chunk, offset)
    offset += chunk.byteLength
  }
  return output
}

export async function publicHttpsUrl(value) {
  let url
  try { url = new URL(clean(value)) } catch { throw new Error('A valid HTTPS URL is required.') }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) {
    throw new Error('Vendor URLs must use public HTTPS without embedded credentials or custom ports.')
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '')
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('Private or local vendor URLs are not allowed.')
  }
  if (isIP(hostname)) {
    if (privateAddress(hostname)) throw new Error('Private or reserved vendor addresses are not allowed.')
  } else {
    let addresses = []
    let lastError = null
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        addresses = await lookup(hostname, { all: true, verbatim: true })
        lastError = null
        break
      } catch (error) {
        lastError = error
        if (!['EAI_AGAIN','ETIMEOUT','ESERVFAIL'].includes(clean(error?.code))) throw error
        await new Promise((resolve) => setTimeout(resolve, 150 * (attempt + 1)))
      }
    }
    if (lastError) throw lastError
    if (!addresses.length || addresses.some((item) => privateAddress(item.address))) {
      throw new Error('Vendor hostname resolves to a private or reserved address.')
    }
  }
  return url
}

export async function resolveAllowedPublicDownload(value, allowedHosts = [], redirects = 0) {
  if (redirects > 4) throw new Error('Vendor download redirected too many times.')
  const url = await publicHttpsUrl(value)
  if (!htmlHostAllowed(url.toString(), allowedHosts)) {
    throw new Error('Vendor download host is not present in the HTML recipe allowedHosts list.')
  }

  const headers = { 'User-Agent': 'Hi5Central-Software-Catalogue/1.0' }
  let response = await fetch(url, {
    method: 'HEAD',
    headers,
    redirect: 'manual',
    signal: AbortSignal.timeout(30_000),
  })
  if ([405, 501].includes(response.status)) {
    response = await fetch(url, {
      method: 'GET',
      headers: { ...headers, Range: 'bytes=0-0' },
      redirect: 'manual',
      signal: AbortSignal.timeout(30_000),
    })
    await response.body?.cancel().catch(() => {})
  }

  if ([301,302,303,307,308].includes(response.status)) {
    const location = clean(response.headers.get('location'))
    if (!location) throw new Error('Vendor download returned a redirect without a location.')
    return resolveAllowedPublicDownload(new URL(location,url).toString(), allowedHosts, redirects + 1)
  }
  if (!response.ok && response.status !== 206) {
    throw new Error('Vendor download probe HTTP ' + response.status)
  }
  return {
    url: url.toString(),
    status: response.status,
    contentType: clean(response.headers.get('content-type')),
    contentLength: Number(response.headers.get('content-length') || 0) || null,
  }
}

export async function evaluateVendorHtmlAutomation(sourceUrl, rawPolicy = {}, pollMinutes = 60) {
  const policy = normalizeVendorHtmlAutomationPolicy(rawPolicy)
  if (policy.termsDecision === 'prohibited') throw new Error('vendor_html_automation_prohibited_by_terms')
  if (policy.termsDecision !== 'allowed' || !policy.automatedRetrievalAllowed) {
    throw new Error('vendor_html_terms_review_required')
  }

  const reviewedAt = Date.parse(policy.termsReviewedAt)
  const expiresAt = reviewedAt + policy.reviewExpiresDays * 24 * 60 * 60 * 1000
  if (!Number.isFinite(reviewedAt) || Date.now() > expiresAt) {
    throw new Error('vendor_html_terms_review_expired')
  }
  if (Number(pollMinutes || 0) < Number(policy.minimumPollMinutes || 60)) {
    throw new Error('vendor_html_poll_interval_below_compliance_minimum')
  }

  const source = await publicHttpsUrl(sourceUrl)
  const robotsUrl = new URL('/robots.txt', source.origin)
  let current = robotsUrl
  let response = null

  for (let redirects = 0; redirects <= 3; redirects += 1) {
    response = await fetch(current, {
      headers: { Accept: 'text/plain,*/*;q=0.1', 'User-Agent': policy.robotsUserAgent + '/1.0' },
      redirect: 'manual',
      signal: AbortSignal.timeout(30_000),
    })
    if (![301,302,303,307,308].includes(response.status)) break
    const location = clean(response.headers.get('location'))
    if (!location) throw new Error('vendor_html_robots_redirect_without_location')
    const next = await publicHttpsUrl(new URL(location,current).toString())
    if (next.origin !== source.origin) throw new Error('vendor_html_robots_cross_origin_redirect_blocked')
    current = next
  }

  const status = Number(response?.status || 0)
  if ([404,410].includes(status)) {
    return {
      allowed: true,
      policy,
      robots: { url: current.toString(), status, allowed: true, reason: 'robots_not_published' },
    }
  }
  if ([401,403,429].includes(status) || status >= 500 || !response?.ok) {
    throw new Error('vendor_html_robots_unavailable_or_blocked_http_' + status)
  }

  const bytes = await limitedResponseBytes(response, 1024 * 1024)
  const body = new TextDecoder('utf-8').decode(bytes)
  const decision = robotsPathAllowed(body, source.pathname + source.search, policy.robotsUserAgent)
  if (!decision.allowed) throw new Error('vendor_html_robots_disallowed:' + decision.matchedRule)
  return {
    allowed: true,
    policy,
    robots: { url: current.toString(), status, ...decision },
  }
}

export async function fetchPublicText(value, { accept = '*/*', maxBytes = 5 * 1024 * 1024, redirects = 0 } = {}) {
  if (redirects > 3) throw new Error('Vendor source redirected too many times.')
  const url = await publicHttpsUrl(value)
  const response = await fetch(url, {
    headers: { Accept: accept, 'User-Agent': 'Hi5Central-Software-Catalogue/1.0' },
    redirect: 'manual',
    signal: AbortSignal.timeout(60_000),
  })
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const location = clean(response.headers.get('location'))
    if (!location) throw new Error('Vendor source returned a redirect without a location.')
    return fetchPublicText(new URL(location, url).toString(), { accept, maxBytes, redirects: redirects + 1 })
  }
  if (!response.ok) throw new Error('Vendor source HTTP ' + response.status)
  const bytes = await limitedResponseBytes(response, maxBytes)
  return new TextDecoder('utf-8').decode(bytes)
}

export async function fetchPublicJson(value, redirects = 0) {
  const text = await fetchPublicText(value, { accept: 'application/json', maxBytes: 5 * 1024 * 1024, redirects })
  try { return JSON.parse(text) } catch { throw new Error('Vendor API did not return valid JSON.') }
}

export function repositoryName(value = '') {
  const input = clean(value).replace(/\.git$/i, '')
  const direct = input.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/)
  if (direct) return direct[1] + '/' + direct[2]
  try {
    const url = new URL(input)
    if (url.protocol !== 'https:' || !['github.com', 'www.github.com'].includes(url.hostname.toLowerCase())) return ''
    const parts = url.pathname.split('/').filter(Boolean)
    return parts.length >= 2 ? parts[0] + '/' + parts[1] : ''
  } catch {
    return ''
  }
}

export function globMatcher(pattern = '') {
  const value = clean(pattern)
  if (!value || value.length > 240) return null
  const escaped = value.replace(/[.+^$(){}|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')
  return new RegExp('^' + escaped + '$', 'i')
}
export function releaseVersion(value = '') {
  const version = clean(value)
  return /^v\d/i.test(version) ? version.slice(1) : version
}

export function releaseDate(value = '') {
  const parsed = Date.parse(clean(value))
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null
}

export function installerType(name = '', configured = '') {
  const explicit = clean(configured).toLowerCase()
  if (['msi', 'exe'].includes(explicit)) return explicit
  const lower = clean(name).toLowerCase()
  if (lower.endsWith('.msi')) return 'msi'
  if (lower.endsWith('.exe')) return 'exe'
  return ''
}

export async function latestGithubRelease(repository) {
  const response = await fetch('https://api.github.com/repos/' + repository + '/releases/latest', {
    headers: githubApiHeaders(),
    signal: AbortSignal.timeout(60_000),
  })
  if (!response.ok) throw new Error('GitHub Releases HTTP ' + response.status)
  return response.json()
}
export async function publishedChecksum(assetUrl, installerName) {
  if (!assetUrl) return ''
  const url = new URL(assetUrl)
  if (url.protocol !== 'https:' || !['github.com', 'objects.githubusercontent.com'].includes(url.hostname.toLowerCase())) {
    throw new Error('Checksum asset must be hosted by GitHub.')
  }
  const response = await fetch(assetUrl, {
    headers: { Accept: 'text/plain', 'User-Agent': 'Hi5Central-Software-Catalogue/1.0' },
    signal: AbortSignal.timeout(60_000),
  })
  if (!response.ok) throw new Error('Checksum download HTTP ' + response.status)
  const bytes = await limitedResponseBytes(response, 2 * 1024 * 1024)
  let body = ''
  if (bytes[0] === 0xff && bytes[1] === 0xfe) body = new TextDecoder('utf-16le').decode(bytes)
  else if (bytes[0] === 0xfe && bytes[1] === 0xff) body = new TextDecoder('utf-16be').decode(bytes)
  else body = new TextDecoder('utf-8').decode(bytes)
  const escaped = clean(installerName).replace(/[.*+?^$(){}|[\]\\]/g, '\\$&')
  const match = body.match(new RegExp('([A-Fa-f0-9]{64})\\s+[* ]?' + escaped + '(?:\\s|$)', 'i'))
    || body.match(new RegExp('SHA256\\s*\\(' + escaped + '\\)\\s*=\\s*([A-Fa-f0-9]{64})', 'i'))
  return clean(match?.[1]).toUpperCase()
}

function deploymentMode(value = '') {
  return ['winget_preferred', 'vendor_direct', 'intelligence_only'].includes(clean(value))
    ? clean(value)
    : 'winget_preferred'
}

function sourceType(value = '') {
  return ['github_releases', 'vendor_json', 'vendor_html', 'static_release'].includes(clean(value)) ? clean(value) : 'github_releases'
}

function safeJsonPath(value = '', required = false) {
  const path = clean(value)
  if (!path) {
    if (required) throw new Error('A version JSON path is required.')
    return ''
  }
  if (path.length > 240) throw new Error('JSON paths must be 240 characters or fewer.')
  const parts = path.split('.')
  if (parts.some((part) => !part || !/^(?:[A-Za-z0-9_-]+|\d+)$/.test(part)
    || ['__proto__', 'prototype', 'constructor'].includes(part))) {
    throw new Error('JSON paths may contain only object keys, numeric indexes, underscores and hyphens.')
  }
  return path
}

export function jsonPathValue(payload, path = '') {
  if (!path) return ''
  let value = payload
  for (const part of path.split('.')) {
    if (value === null || value === undefined) return ''
    if (Array.isArray(value) && /^\d+$/.test(part)) value = value[Number(part)]
    else if (typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, part)) value = value[part]
    else return ''
  }
  if (value === null || value === undefined || typeof value === 'object') return ''
  return clean(value)
}

export function normalizedSha256(value = '') {
  const match = clean(value).match(/(?:^|[^A-Fa-f0-9])([A-Fa-f0-9]{64})(?:$|[^A-Fa-f0-9])/)
  return clean(match?.[1]).toUpperCase()
}

function normalizeInput(body = {}) {
  const mode = deploymentMode(body.deploymentMode)
  const type = sourceType(body.sourceType)
  const parser = body.parserConfig && typeof body.parserConfig === 'object' && !Array.isArray(body.parserConfig)
    ? body.parserConfig
    : {}
  const parserConfig = {
    versionPath: safeJsonPath(body.versionPath ?? parser.versionPath, type === 'vendor_json'),
    releaseDatePath: safeJsonPath(body.releaseDatePath ?? parser.releaseDatePath),
    releaseUrlPath: safeJsonPath(body.releaseUrlPath ?? parser.releaseUrlPath),
    installerUrlPath: safeJsonPath(body.installerUrlPath ?? parser.installerUrlPath),
    sha256Path: safeJsonPath(body.sha256Path ?? parser.sha256Path),
    productCodePath: safeJsonPath(body.productCodePath ?? parser.productCodePath),
    staticVersion: clean(body.staticVersion ?? parser.staticVersion).slice(0, 120),
    staticInstallerUrl: clean(body.staticInstallerUrl ?? parser.staticInstallerUrl).slice(0, 2000),
    staticSha256: normalizedSha256(body.staticSha256 ?? parser.staticSha256),
    staticReleaseUrl: clean(body.staticReleaseUrl ?? parser.staticReleaseUrl ?? body.sourceUrl).slice(0, 2000),
    htmlRecipe: type === 'vendor_html' ? normalizeVendorHtmlRecipe(body.htmlRecipe ?? parser.htmlRecipe ?? {}) : {},
    automationPolicy: type === 'vendor_html'
      ? normalizeVendorHtmlAutomationPolicy(body.automationPolicy ?? parser.automationPolicy ?? {})
      : {},
  }
  const verificationSource = body.verificationConfig && typeof body.verificationConfig === 'object' && !Array.isArray(body.verificationConfig)
    ? body.verificationConfig
    : {}
  const verificationMethod = ['winget', 'uninstall_registry', 'file_version'].includes(clean(body.verificationMethod || verificationSource.method))
    ? clean(body.verificationMethod || verificationSource.method)
    : (clean(body.providerPackageId) ? 'winget' : 'uninstall_registry')
  const productCode = clean(body.productCode ?? verificationSource.productCode).slice(0, 80)
  const filePath = clean(body.filePath ?? verificationSource.filePath).slice(0, 520)
  if (productCode && !/^\{[0-9A-Fa-f-]{36}\}$/.test(productCode)) {
    throw new Error('MSI ProductCode must be a braced GUID such as {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.')
  }
  if (filePath && (!/^(?:[A-Za-z]:\\|%ProgramFiles%\\|%ProgramFiles\(x86\)%\\|%ProgramData%\\)/i.test(filePath)
    || filePath.includes('..') || /["\r\n]/.test(filePath))) {
    throw new Error('File-version verification requires a safe local Windows path under a drive, Program Files or ProgramData.')
  }
  const installArguments = clean(body.installArguments).slice(0, 800)
  if (/[\r\n\0]/.test(installArguments)) throw new Error('Installer arguments must be a single command-line argument string.')
  const verificationConfig = {
    method: verificationMethod,
    packageId: clean(body.providerPackageId).slice(0, 240),
    productCode,
    displayNameContains: clean(body.verificationDisplayName ?? verificationSource.displayNameContains ?? body.namePattern ?? body.canonicalName).slice(0, 200),
    publisherContains: clean(body.verificationPublisher ?? verificationSource.publisherContains ?? body.publisherPattern ?? body.publisher).slice(0, 200),
    filePath,
  }
  const input = {
    displayName: clean(body.displayName).slice(0, 160),
    sourceType: type,
    repository: type === 'github_releases' ? repositoryName(body.repository) : '',
    sourceUrl: ['vendor_json', 'vendor_html', 'static_release'].includes(type) ? clean(body.sourceUrl).slice(0, 2000) : '',
    parserConfig,
    verificationConfig,
    canonicalName: clean(body.canonicalName).slice(0, 200),
    publisher: clean(body.publisher).slice(0, 200),
    expectedSigner: clean(body.expectedSigner).slice(0, 300),
    providerPackageId: clean(body.providerPackageId).slice(0, 240),
    namePattern: clean(body.namePattern || body.canonicalName).slice(0, 200),
    publisherPattern: clean(body.publisherPattern || body.publisher).slice(0, 200),
    channel: clean(body.channel || 'stable').slice(0, 80) || 'stable',
    architecture: clean(body.architecture || 'x64').slice(0, 40) || 'x64',
    deploymentMode: mode,
    assetPattern: type === 'github_releases' ? clean(body.assetPattern).slice(0, 240) : '',
    checksumAssetPattern: type === 'github_releases' ? clean(body.checksumAssetPattern).slice(0, 240) : '',
    installerType: clean(body.installerType).toLowerCase().slice(0, 20),
    installArguments,
    pollMinutes: type === 'vendor_html'
      ? Math.max(
          Math.max(15, Math.min(10080, Number(body.pollMinutes) || 60)),
          Number(parserConfig.automationPolicy?.minimumPollMinutes || 60),
        )
      : Math.max(15, Math.min(10080, Number(body.pollMinutes) || 60)),
  }
  if (input.displayName.length < 2 || input.canonicalName.length < 2 || input.namePattern.length < 2) {
    throw new Error('Display name, application name and detection name are required.')
  }
  if (type === 'github_releases' && !input.repository) throw new Error('A valid public GitHub repository is required.')
  if (type === 'vendor_json' || type === 'vendor_html') {
    try {
      const url = new URL(input.sourceUrl)
      if (url.protocol !== 'https:') throw new Error()
    } catch {
      throw new Error(type === 'vendor_html' ? 'A valid HTTPS vendor HTML URL is required.' : 'A valid HTTPS vendor JSON URL is required.')
    }
  }
  if (type === 'static_release') {
    if (!parserConfig.staticVersion) throw new Error('A release version is required for static vendor sources.')
    try {
      const installerUrl = new URL(parserConfig.staticInstallerUrl)
      if (installerUrl.protocol !== 'https:') throw new Error()
    } catch {
      throw new Error('A valid HTTPS installer URL is required for static vendor sources.')
    }
    if (!/^[A-F0-9]{64}$/.test(parserConfig.staticSha256)) throw new Error('A valid SHA-256 is required for static vendor sources.')
    if (parserConfig.staticReleaseUrl) {
      try {
        const releaseUrl = new URL(parserConfig.staticReleaseUrl)
        if (releaseUrl.protocol !== 'https:') throw new Error()
      } catch {
        throw new Error('Static vendor release page URLs must use HTTPS.')
      }
    }
  }
  if (mode === 'winget_preferred' && !input.providerPackageId) {
    throw new Error('A WinGet package ID is required for WinGet-preferred sources.')
  }
  if (verificationMethod === 'winget' && !input.providerPackageId) {
    throw new Error('WinGet verification requires a WinGet package ID.')
  }
  if (verificationMethod === 'uninstall_registry' && !productCode && !verificationConfig.displayNameContains) {
    throw new Error('Registry verification requires an MSI ProductCode or DisplayName match.')
  }
  if (verificationMethod === 'file_version' && !filePath) {
    throw new Error('File-version verification requires the installed EXE or DLL path.')
  }
  if (mode === 'vendor_direct' && type === 'github_releases'
    && (!input.assetPattern || !input.checksumAssetPattern || !input.expectedSigner)) {
    throw new Error('GitHub vendor-direct sources require installer pattern, checksum pattern and expected signer.')
  }
  if (mode === 'vendor_direct' && type === 'vendor_json'
    && (!parserConfig.installerUrlPath || !parserConfig.sha256Path || !input.expectedSigner)) {
    throw new Error('JSON vendor-direct sources require installer URL path, SHA-256 path and expected signer.')
  }
  if (mode === 'vendor_direct' && type === 'vendor_html' && !input.expectedSigner) {
    throw new Error('HTML vendor-direct sources require an expected signer.')
  }
  if (mode === 'vendor_direct' && type === 'static_release' && !input.expectedSigner) {
    throw new Error('Static vendor-direct sources require an expected signer.')
  }
  if (input.installerType && !['msi', 'exe'].includes(input.installerType)) {
    throw new Error('Installer type must be MSI or EXE.')
  }
  if (mode === 'vendor_direct' && input.installerType === 'exe' && !input.installArguments) {
    throw new Error('Vendor-direct EXE sources require explicit silent installer arguments.')
  }
  return input
}

async function sourceById(tenantId, sourceId) {
  const result = await pool.query(
    `SELECT * FROM rmm_tenant_vendor_sources
      WHERE tenant_id=$1 AND id=$2 AND status<>'archived' LIMIT 1`,
    [tenantId, sourceId],
  )
  return result.rows[0] || null
}

function verificationConfigured(source) {
  const verification = source.verification_config && typeof source.verification_config === 'object'
    ? source.verification_config
    : {}
  const method = clean(verification.method || 'winget')
  if (method === 'winget') return Boolean(clean(verification.packageId || source.provider_package_id))
  if (method === 'uninstall_registry') {
    return Boolean(clean(verification.productCode) || clean(verification.displayNameContains) || clean(source.parser_config?.productCodePath))
  }
  if (method === 'file_version') return Boolean(clean(verification.filePath))
  return false
}

function trustState(source, release) {
  if (source.deployment_mode === 'intelligence_only') return 'version_only'
  if (source.deployment_mode === 'winget_preferred') return source.provider_package_id ? 'winget_ready' : 'version_only'
  if (release.installerUrl
    && /^[A-F0-9]{64}$/.test(release.installerSha256)
    && clean(source.expected_signer)
    && ['msi', 'exe'].includes(release.installerType)
    && (release.installerType !== 'exe' || clean(source.install_arguments))
    && verificationConfigured(source)) return 'direct_ready'
  return 'quarantined'
}

async function resolveGithubSource(source) {
  const payload = await latestGithubRelease(source.repository)
  const version = releaseVersion(payload?.tag_name || payload?.name)
  if (!version) throw new Error('GitHub latest release did not contain a usable version.')
  const assets = Array.isArray(payload?.assets) ? payload.assets : []
  const installerMatch = globMatcher(source.asset_pattern)
  const checksumMatch = globMatcher(source.checksum_asset_pattern)
  const installer = installerMatch ? assets.find((asset) => installerMatch.test(clean(asset?.name))) : null
  const checksum = checksumMatch ? assets.find((asset) => checksumMatch.test(clean(asset?.name))) : null
  const release = {
    version,
    releaseDate: releaseDate(payload?.published_at || payload?.created_at),
    releaseUrl: clean(payload?.html_url),
    installerUrl: clean(installer?.browser_download_url),
    installerSha256: '',
    installerType: installerType(installer?.name, source.installer_type),
    installerName: clean(installer?.name),
    checksumName: clean(checksum?.name),
  }
  if (installer && checksum) release.installerSha256 = await publishedChecksum(checksum.browser_download_url, installer.name)
  release.trustState = trustState(source, release)
  return {
    release,
    sourcePayload: { github: { id: payload?.id, tag_name: payload?.tag_name, html_url: payload?.html_url } },
  }
}

async function resolveJsonSource(source) {
  const parser = source.parser_config && typeof source.parser_config === 'object' ? source.parser_config : {}
  const payload = await fetchPublicJson(source.source_url)
  const version = releaseVersion(jsonPathValue(payload, parser.versionPath))
  if (!version) throw new Error('The configured version JSON path returned no scalar value.')
  const releaseDateValue = jsonPathValue(payload, parser.releaseDatePath)
  const releaseUrlValue = jsonPathValue(payload, parser.releaseUrlPath)
  const installerUrlValue = jsonPathValue(payload, parser.installerUrlPath)
  const shaValue = jsonPathValue(payload, parser.sha256Path)
  const productCodeValue = jsonPathValue(payload, parser.productCodePath)
  if (productCodeValue && !/^\{[0-9A-Fa-f-]{36}\}$/.test(productCodeValue)) {
    throw new Error('The configured ProductCode JSON path did not return a braced MSI GUID.')
  }
  let installerUrl = ''
  if (installerUrlValue) {
    let resolvedInstaller = installerUrlValue
    try {
      resolvedInstaller = new URL(installerUrlValue, source.source_url).toString()
    } catch {
      throw new Error('The configured installer URL path did not resolve to a valid URL or relative filename.')
    }
    installerUrl = (await publicHttpsUrl(resolvedInstaller)).toString()
  }
  let releaseUrl = ''
  if (releaseUrlValue) {
    try {
      const parsed = new URL(releaseUrlValue)
      if (parsed.protocol === 'https:') releaseUrl = parsed.toString()
    } catch {}
  }
  const release = {
    version,
    releaseDate: releaseDate(releaseDateValue),
    releaseUrl,
    installerUrl,
    installerSha256: normalizedSha256(shaValue),
    installerType: installerType(installerUrl ? new URL(installerUrl).pathname : '', source.installer_type),
    installerName: installerUrl ? new URL(installerUrl).pathname.split('/').filter(Boolean).pop() || '' : '',
    checksumName: parser.sha256Path ? 'JSON: ' + parser.sha256Path : '',
    verificationProductCode: productCodeValue,
  }
  release.trustState = trustState(source, release)
  return {
    release,
    sourcePayload: {
      json: {
        source_url: source.source_url,
        paths: parser,
        selected: {
          version,
          releaseDate: releaseDateValue,
          releaseUrl: releaseUrlValue,
          installerUrl: installerUrlValue,
          productCode: productCodeValue,
          sha256Present: Boolean(release.installerSha256),
        },
      },
    },
  }
}

async function resolveStaticSource(source) {
  const parser = source.parser_config && typeof source.parser_config === 'object' ? source.parser_config : {}
  const version = releaseVersion(parser.staticVersion)
  if (!version) throw new Error('Static vendor release does not contain a usable version.')
  const installerUrl = (await publicHttpsUrl(parser.staticInstallerUrl)).toString()
  const releaseUrl = parser.staticReleaseUrl ? (await publicHttpsUrl(parser.staticReleaseUrl)).toString() : ''
  const release = {
    version,
    releaseDate: null,
    releaseUrl,
    installerUrl,
    installerSha256: normalizedSha256(parser.staticSha256),
    installerType: installerType(new URL(installerUrl).pathname, source.installer_type),
    installerName: new URL(installerUrl).pathname.split('/').filter(Boolean).pop() || '',
    checksumName: 'Static SHA-256',
    verificationProductCode: '',
  }
  release.trustState = trustState(source, release)
  return {
    release,
    sourcePayload: {
      static: {
        version,
        releaseUrl,
        installerUrl,
        sha256Present: Boolean(release.installerSha256),
      },
    },
  }
}

async function resolveHtmlSource(source) {
  const recipe = normalizeVendorHtmlRecipe(source.parser_config?.htmlRecipe || {})
  if (!htmlHostAllowed(source.source_url, recipe.allowedHosts)) {
    throw new Error('HTML vendor source page host is not in allowedHosts.')
  }
  const compliance = await evaluateVendorHtmlAutomation(
    source.source_url,
    source.parser_config?.automationPolicy || {},
    source.poll_minutes,
  )
  const body = await fetchPublicText(source.source_url, {
    accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
    maxBytes: 8 * 1024 * 1024,
  })
  const candidates = parseVendorHtmlReleases(body, source.source_url, recipe)
  if (!candidates.length) throw new Error('HTML vendor source returned no stable installer candidates.')
  const selected = candidates.at(-1)
  if (!htmlHostAllowed(selected.installerUrl, recipe.allowedHosts)) {
    throw new Error('HTML vendor installer host is not in allowedHosts.')
  }
  const downloadProbe = await resolveAllowedPublicDownload(selected.installerUrl, recipe.allowedHosts)
  const installerUrl = downloadProbe.url
  const release = {
    version: releaseVersion(selected.version),
    releaseDate: releaseDate(selected.releaseDate),
    releaseUrl: selected.releaseUrl || source.source_url,
    installerUrl,
    installerSha256: normalizedSha256(selected.installerSha256),
    installerType: installerType(selected.assetName || new URL(installerUrl).pathname, source.installer_type),
    installerName: selected.assetName,
    checksumName: selected.installerSha256 ? 'HTML-published SHA-256' : '',
    verificationProductCode: '',
  }
  release.trustState = trustState(source, release)
  return {
    release,
    sourcePayload: {
      html: {
        recipeVersion: 1,
        compliance,
        selected,
        finalDownloadUrl: downloadProbe.url,
        downloadContentType: downloadProbe.contentType,
        downloadContentLength: downloadProbe.contentLength,
        allowedHosts: recipe.allowedHosts,
        candidatesSeen: candidates.slice(-Math.max(2, Number(recipe.previousStableCount || 1) + 1)),
      },
    },
  }
}

async function resolveSource(source) {
  if (source.source_type === 'vendor_json') return resolveJsonSource(source)
  if (source.source_type === 'vendor_html') return resolveHtmlSource(source)
  if (source.source_type === 'static_release') return resolveStaticSource(source)
  return resolveGithubSource(source)
}

async function storeRelease(source, release, sourcePayload) {
  const evidence = {
    sourceType: source.source_type,
    repository: source.repository,
    sourceUrl: source.source_url,
    parserConfig: source.parser_config,
    installerAsset: release.installerName,
    checksumAsset: release.checksumName,
    sha256Present: /^[A-F0-9]{64}$/.test(release.installerSha256),
    expectedSigner: clean(source.expected_signer),
    verification: source.verification_config || {},
    installArguments: clean(source.install_arguments),
    resolvedVerificationProductCode: clean(release.verificationProductCode),
    deploymentMode: source.deployment_mode,
  }
  await pool.query(
    `INSERT INTO rmm_tenant_vendor_releases
      (source_id,tenant_id,version,release_date,release_url,installer_url,installer_sha256,installer_type,
       trust_state,trust_evidence,source_payload,last_seen_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,now())
     ON CONFLICT (source_id,version) DO UPDATE SET
       release_date=EXCLUDED.release_date,release_url=EXCLUDED.release_url,
       installer_url=EXCLUDED.installer_url,installer_sha256=EXCLUDED.installer_sha256,
       installer_type=EXCLUDED.installer_type,trust_state=EXCLUDED.trust_state,
       trust_evidence=EXCLUDED.trust_evidence,source_payload=EXCLUDED.source_payload,last_seen_at=now()`,
    [
      source.id, source.tenant_id, release.version, release.releaseDate, release.releaseUrl,
      release.installerUrl, release.installerSha256, release.installerType, release.trustState,
      JSON.stringify(evidence),
      JSON.stringify(sourcePayload || {}),
    ],
  )
  return evidence
}

function verificationForRelease(source, release) {
  const verification = { ...(source.verification_config || {}) }
  if (clean(release.verificationProductCode)) verification.productCode = clean(release.verificationProductCode)
  return verification
}

async function verificationRecommendation(source, release) {
  const verification = verificationForRelease(source, release)
  const packageId = clean(verification.packageId || source.provider_package_id)
  const productCode = clean(verification.productCode)
  const vendorProductCode = clean(release.verificationProductCode)
  const filePath = clean(verification.filePath)
  const displayName = clean(verification.displayNameContains || source.name_pattern || source.canonical_name)
  const publisher = clean(verification.publisherContains || source.publisher_pattern || source.publisher)

  const inventory = await pool.query(
    `WITH software AS (
       SELECT item
         FROM rmm_device_inventory i
         CROSS JOIN LATERAL jsonb_array_elements(
           CASE WHEN jsonb_typeof(i.source_payload->'software'->'items')='array'
             THEN i.source_payload->'software'->'items'
             ELSE '[]'::jsonb END
         ) item
        WHERE i.tenant_id=$1 AND i.active=true
     )
     SELECT
       count(*) FILTER (
         WHERE ($2='' OR lower(item->>'name') LIKE '%' || lower($2) || '%')
           AND ($3='' OR lower(COALESCE(item->>'publisher','')) LIKE '%' || lower($3) || '%')
       )::int AS registry_matches,
       count(*) FILTER (
         WHERE $4<>'' AND lower(COALESCE(item->>'registry_key',''))=lower($4)
       )::int AS product_code_matches
       FROM software`,
    [source.tenant_id, displayName, publisher, productCode],
  )
  const inventoryEvidence = inventory.rows[0] || { registry_matches: 0, product_code_matches: 0 }

  let fileProbe = null
  if (filePath) {
    const probe = await pool.query(
      `SELECT id,status,result,error_message,completed_at
         FROM rmm_agent_jobs
        WHERE tenant_id=$1
          AND job_type='custom.command'
          AND request_metadata->>'source'='vendor_verification_probe'
          AND request_metadata->>'vendor_source_id'=$2
          AND request_metadata->>'verification_file_path'=$3
          AND status IN ('completed','failed')
        ORDER BY completed_at DESC NULLS LAST,created_at DESC
        LIMIT 1`,
      [source.tenant_id, source.id, filePath],
    )
    if (probe.rowCount) {
      const row = probe.rows[0]
      const parsed = row.result?.parsed && typeof row.result.parsed === 'object' ? row.result.parsed : {}
      const version = clean(parsed.file_version || parsed.product_version || row.result?.file_version || row.result?.product_version)
      fileProbe = {
        jobId: row.id,
        status: row.status,
        completedAt: row.completed_at,
        version,
        valid: row.status === 'completed' && Boolean(version),
        error: clean(row.error_message),
      }
    }
  }

  let wingetEvidence = 0
  if (packageId) {
    const observed = await pool.query(
      `SELECT count(*)::int AS matches
         FROM rmm_software_patch_observations
        WHERE tenant_id=$1 AND lower(provider_package_id)=lower($2)`,
      [source.tenant_id, packageId],
    )
    wingetEvidence = Number(observed.rows[0]?.matches || 0)
  }

  const candidates = []
  if (productCode) {
    const validated = Boolean(vendorProductCode) || Number(inventoryEvidence.product_code_matches || 0) > 0
    candidates.push({
      method: 'uninstall_registry',
      variant: 'exact_product_code',
      strength: 100,
      available: true,
      validated,
      validation: vendorProductCode
        ? 'vendor_release_product_code'
        : validated ? 'endpoint_product_code_match' : 'configured_product_code_needs_endpoint',
      evidence: {
        productCode,
        vendorMetadata: Boolean(vendorProductCode),
        matchingEndpoints: Number(inventoryEvidence.product_code_matches || 0),
      },
      config: {
        method: 'uninstall_registry',
        packageId,
        productCode,
        displayNameContains: displayName,
        publisherContains: publisher,
        filePath: '',
      },
    })
  }
  if (filePath) {
    candidates.push({
      method: 'file_version',
      variant: 'windows_versioninfo',
      strength: 90,
      available: true,
      validated: Boolean(fileProbe?.valid),
      validation: fileProbe?.valid ? 'endpoint_versioninfo_probe' : fileProbe ? 'probe_failed_or_unusable' : 'needs_probe',
      evidence: {
        filePath,
        probe: fileProbe,
      },
      config: {
        method: 'file_version',
        packageId,
        productCode: '',
        displayNameContains: displayName,
        publisherContains: publisher,
        filePath,
      },
    })
  }
  if (displayName) {
    const validated = Number(inventoryEvidence.registry_matches || 0) > 0
    candidates.push({
      method: 'uninstall_registry',
      variant: 'display_name_publisher',
      strength: 70,
      available: true,
      validated,
      validation: validated ? 'endpoint_uninstall_registry_match' : 'needs_matching_endpoint',
      evidence: {
        displayNameContains: displayName,
        publisherContains: publisher,
        matchingEndpoints: Number(inventoryEvidence.registry_matches || 0),
      },
      config: {
        method: 'uninstall_registry',
        packageId,
        productCode: '',
        displayNameContains: displayName,
        publisherContains: publisher,
        filePath: '',
      },
    })
  }
  if (packageId) {
    const validated = wingetEvidence > 0
    candidates.push({
      method: 'winget',
      variant: 'package_identity',
      strength: 50,
      available: true,
      validated,
      validation: validated ? 'endpoint_winget_observation' : 'package_id_configured',
      evidence: { packageId, matchingObservations: wingetEvidence },
      config: {
        method: 'winget',
        packageId,
        productCode: '',
        displayNameContains: displayName,
        publisherContains: publisher,
        filePath: '',
      },
    })
  }

  const ranked = candidates.sort((a, b) => b.strength - a.strength)
  const strongestValidated = ranked.find((candidate) => candidate.validated)
  const recommended = strongestValidated || ranked[0] || null
  const strongerUnvalidated = recommended
    ? ranked.find((candidate) => !candidate.validated && candidate.strength > recommended.strength)
    : ranked.find((candidate) => !candidate.validated)
  const fileCandidate = ranked.find((candidate) => candidate.method === 'file_version')
  return {
    recommendedMethod: recommended?.method || '',
    recommendedVariant: recommended?.variant || '',
    strength: recommended?.strength || 0,
    validated: Boolean(recommended?.validated),
    validation: recommended?.validation || 'none_available',
    config: recommended?.config || null,
    candidates: ranked,
    autoProbeRecommended: Boolean(
      fileCandidate
      && !fileCandidate.validated
      && fileCandidate.validation !== 'probe_failed_or_unusable'
      && (!strongestValidated || fileCandidate.strength > strongestValidated.strength)
    ),
    strongerMethodAwaitingValidation: strongerUnvalidated
      ? { method: strongerUnvalidated.method, variant: strongerUnvalidated.variant, strength: strongerUnvalidated.strength }
      : null,
  }
}

export async function tenantVendorVerificationRecommendation(tenantId, sourceId) {
  const source = await sourceById(tenantId, sourceId)
  if (!source) throw new Error('Vendor source not found.')
  const releaseResult = await pool.query(
    `SELECT * FROM rmm_tenant_vendor_releases
      WHERE tenant_id=$1 AND source_id=$2
      ORDER BY COALESCE(release_date,last_seen_at) DESC,last_seen_at DESC LIMIT 1`,
    [tenantId, sourceId],
  )
  const row = releaseResult.rows[0]
  if (!row) return { recommendedMethod: '', validated: false, validation: 'source_not_tested', candidates: [] }
  const release = {
    version: row.version,
    releaseDate: row.release_date,
    releaseUrl: row.release_url,
    installerUrl: row.installer_url,
    installerSha256: row.installer_sha256,
    installerType: row.installer_type,
    trustState: row.trust_state,
    verificationProductCode: clean(row.source_payload?.json?.selected?.productCode),
  }
  return verificationRecommendation(source, release)
}

async function applyCatalogue(source, release, db = pool) {
  const provider = source.deployment_mode === 'winget_preferred' ? 'winget' : 'vendor'
  const verification = verificationForRelease(source, release)
  const execution = { installArguments: clean(source.install_arguments) }
  const metadata = {
    tenantVendorSourceId: source.id,
    sourceType: source.source_type,
    repository: source.repository,
    sourceUrl: source.source_url,
    deploymentMode: source.deployment_mode,
    expectedSigner: source.expected_signer,
    trustState: release.trustState,
    releaseUrl: release.releaseUrl,
  }
  const existing = await db.query(
    `SELECT id FROM rmm_software_catalogue
      WHERE tenant_id=$1 AND catalogue_source='tenant_vendor' AND external_key=$2
        AND status<>'archived' LIMIT 1`,
    [source.tenant_id, source.id],
  )
  if (existing.rowCount) {
    await db.query(
      `UPDATE rmm_software_catalogue
          SET canonical_name=$2,publisher=$3,name_pattern=$4,publisher_pattern=$5,
              provider=$6,provider_package_id=$7,target_version=$8,release_channel=$9,
              installer_type=$10,verification=$11::jsonb,execution=$12::jsonb,source_revision=$8,source_metadata=$13::jsonb,status='active',updated_at=now()
        WHERE id=$1`,
      [
        existing.rows[0].id, source.canonical_name, source.publisher, source.name_pattern,
        source.publisher_pattern, provider, source.provider_package_id, release.version,
        source.channel, release.installerType, JSON.stringify(verification), JSON.stringify(execution), JSON.stringify(metadata),
      ],
    )
  } else {
    await db.query(
      `INSERT INTO rmm_software_catalogue
        (tenant_id,canonical_name,publisher,name_pattern,publisher_pattern,provider,provider_package_id,
         target_version,release_channel,installer_type,verification,execution,catalogue_source,external_key,source_revision,source_metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,'tenant_vendor',$13,$8,$14::jsonb)`,
      [
        source.tenant_id, source.canonical_name, source.publisher, source.name_pattern,
        source.publisher_pattern, provider, source.provider_package_id, release.version,
        source.channel, release.installerType, JSON.stringify(verification), JSON.stringify(execution), source.id, JSON.stringify(metadata),
      ],
    )
  }
}
async function syncSourceRow(source, testOnly = false) {
  await pool.query('UPDATE rmm_tenant_vendor_sources SET last_attempt_at=now(),updated_at=now() WHERE id=$1', [source.id])
  try {
    const resolved = await resolveSource(source)
    const evidence = await storeRelease(source, resolved.release, resolved.sourcePayload)
    const recommendation = await verificationRecommendation(source, resolved.release)
    const blockers = []
    if (source.deployment_mode === 'vendor_direct' && resolved.release.trustState !== 'direct_ready') {
      if (!resolved.release.installerUrl) blockers.push('No installer URL was resolved from the source.')
      if (!resolved.release.installerSha256) blockers.push('No verified SHA-256 was resolved from the source.')
      if (!resolved.release.installerType) blockers.push('Installer must be MSI or EXE.')
      if (!clean(source.expected_signer)) blockers.push('Expected signer is required.')
      if (resolved.release.installerType === 'exe' && !clean(source.install_arguments)) blockers.push('Explicit silent installer arguments are required for EXE installers.')
    }
    const result = {
      ok: blockers.length === 0,
      version: resolved.release.version,
      releaseDate: resolved.release.releaseDate,
      releaseUrl: resolved.release.releaseUrl,
      installerAsset: resolved.release.installerName,
      checksumAsset: resolved.release.checksumName,
      installerType: resolved.release.installerType,
      sha256: resolved.release.installerSha256,
      trustState: resolved.release.trustState,
      blockers,
      evidence,
      verificationRecommendation: recommendation,
    }
    let status = source.status
    if (testOnly && source.status !== 'active') status = blockers.length ? 'quarantined' : 'tested'
    if (!testOnly && source.status === 'active' && blockers.length) status = 'quarantined'
    await pool.query(
      `UPDATE rmm_tenant_vendor_sources
          SET latest_version=$2,latest_release_date=$3,latest_release_url=$4,
              latest_installer_url=$5,latest_installer_sha256=$6,last_test_result=$7::jsonb,
              last_success_at=now(),last_error='',status=$8,updated_at=now()
        WHERE id=$1`,
      [
        source.id, resolved.release.version, resolved.release.releaseDate, resolved.release.releaseUrl,
        resolved.release.installerUrl, resolved.release.installerSha256, JSON.stringify(result), status,
      ],
    )
    if (!testOnly && status === 'active') await applyCatalogue(source, resolved.release)
    return { sourceId: source.id, status, ...result }
  } catch (error) {
    const message = clean(error?.message || error).slice(0, 2000)
    await pool.query(
      `UPDATE rmm_tenant_vendor_sources
          SET last_error=$2,status=CASE WHEN status='active' THEN 'quarantined' ELSE status END,updated_at=now()
        WHERE id=$1`,
      [source.id, message],
    )
    throw error
  }
}
export async function listTenantVendorSources(tenantId) {
  const result = await pool.query(
    `SELECT s.*,
            r.version AS release_version,r.release_date,r.release_url,r.installer_url,
            r.installer_sha256,r.installer_type,r.trust_state,r.trust_evidence,r.source_payload AS release_source_payload
       FROM rmm_tenant_vendor_sources s
       LEFT JOIN LATERAL (
         SELECT version,release_date,release_url,installer_url,installer_sha256,
                installer_type,trust_state,trust_evidence,source_payload
           FROM rmm_tenant_vendor_releases
          WHERE source_id=s.id
          ORDER BY COALESCE(release_date,last_seen_at) DESC,last_seen_at DESC
          LIMIT 1
       ) r ON true
      WHERE s.tenant_id=$1 AND s.status<>'archived'
      ORDER BY s.status='quarantined' DESC,s.status='draft' DESC,lower(s.display_name)`,
    [tenantId],
  )
  return Promise.all(result.rows.map(async (source) => {
    if (!source.release_version) return { ...source, verification_recommendation: null }
    const release = {
      version: source.release_version,
      releaseDate: source.release_date,
      releaseUrl: source.release_url,
      installerUrl: source.installer_url,
      installerSha256: source.installer_sha256,
      installerType: source.installer_type,
      trustState: source.trust_state,
      verificationProductCode: clean(source.release_source_payload?.json?.selected?.productCode),
    }
    const recommendation = await verificationRecommendation(source, release)
    return { ...source, verification_recommendation: recommendation }
  }))
}

export async function createTenantVendorSource(session, body) {
  const input = normalizeInput(body)
  const result = await pool.query(
    `INSERT INTO rmm_tenant_vendor_sources
      (tenant_id,display_name,source_type,repository,source_url,parser_config,verification_config,canonical_name,publisher,expected_signer,
       provider_package_id,name_pattern,publisher_pattern,channel,architecture,deployment_mode,
       asset_pattern,checksum_asset_pattern,installer_type,install_arguments,poll_minutes,created_by_user_id,updated_by_user_id)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$22)
     RETURNING id`,
    [
      session.tenant_id, input.displayName, input.sourceType, input.repository, input.sourceUrl,
      JSON.stringify(input.parserConfig), JSON.stringify(input.verificationConfig), input.canonicalName, input.publisher, input.expectedSigner,
      input.providerPackageId, input.namePattern, input.publisherPattern, input.channel,
      input.architecture, input.deploymentMode, input.assetPattern, input.checksumAssetPattern,
      input.installerType, input.installArguments, input.pollMinutes, session.user_id,
    ],
  )
  return result.rows[0]
}

export async function updateTenantVendorSource(session, sourceId, body) {
  const input = normalizeInput(body)
  return withTransaction(async (client) => {
    const result = await client.query(
      `UPDATE rmm_tenant_vendor_sources
          SET display_name=$3,source_type=$4,repository=$5,source_url=$6,parser_config=$7::jsonb,verification_config=$8::jsonb,
              canonical_name=$9,publisher=$10,expected_signer=$11,provider_package_id=$12,
              name_pattern=$13,publisher_pattern=$14,channel=$15,architecture=$16,deployment_mode=$17,
              asset_pattern=$18,checksum_asset_pattern=$19,installer_type=$20,install_arguments=$21,poll_minutes=$22,
              status='draft',approved_at=NULL,approved_by_user_id=NULL,updated_by_user_id=$23,updated_at=now()
        WHERE id=$1 AND tenant_id=$2 AND status<>'archived' RETURNING id`,
      [
        sourceId, session.tenant_id, input.displayName, input.sourceType, input.repository, input.sourceUrl,
        JSON.stringify(input.parserConfig), JSON.stringify(input.verificationConfig), input.canonicalName, input.publisher, input.expectedSigner,
        input.providerPackageId, input.namePattern, input.publisherPattern, input.channel,
        input.architecture, input.deploymentMode, input.assetPattern, input.checksumAssetPattern,
        input.installerType, input.installArguments, input.pollMinutes, session.user_id,
      ],
    )
    if (!result.rowCount) throw new Error('Vendor source not found.')
    await client.query(
      `UPDATE rmm_software_catalogue
          SET status='disabled',updated_by_user_id=$3,updated_at=now()
        WHERE tenant_id=$1 AND catalogue_source='tenant_vendor' AND external_key=$2 AND status='active'`,
      [session.tenant_id, sourceId, session.user_id],
    )
    return result.rows[0]
  })
}

export async function testTenantVendorSource(tenantId, sourceId) {
  const source = await sourceById(tenantId, sourceId)
  if (!source) throw new Error('Vendor source not found.')
  return syncSourceRow(source, true)
}

export async function approveTenantVendorSource(session, sourceId) {
  return withTransaction(async (client) => {
    const sourceResult = await client.query(
      `SELECT * FROM rmm_tenant_vendor_sources
        WHERE tenant_id=$1 AND id=$2 AND status='tested' LIMIT 1 FOR UPDATE`,
      [session.tenant_id, sourceId],
    )
    const source = sourceResult.rows[0]
    if (!source) throw new Error('Test this vendor source successfully before approving it.')
    const releaseResult = await client.query(
      `SELECT * FROM rmm_tenant_vendor_releases
        WHERE tenant_id=$1 AND source_id=$2
        ORDER BY COALESCE(release_date,last_seen_at) DESC,last_seen_at DESC LIMIT 1`,
      [session.tenant_id, sourceId],
    )
    const releaseRow = releaseResult.rows[0]
    if (!releaseRow) throw new Error('No tested release is available for approval.')
    if (source.deployment_mode === 'vendor_direct' && releaseRow.trust_state !== 'direct_ready') {
      throw new Error('Vendor-direct approval requires a verified checksum, MSI/EXE asset and expected signer.')
    }
    if (source.deployment_mode === 'winget_preferred' && !clean(source.provider_package_id)) {
      throw new Error('WinGet-preferred approval requires a package ID.')
    }
    await client.query(
      `UPDATE rmm_tenant_vendor_sources
          SET status='active',approved_at=now(),approved_by_user_id=$3,updated_by_user_id=$3,updated_at=now()
        WHERE tenant_id=$1 AND id=$2`,
      [session.tenant_id, sourceId, session.user_id],
    )
    const activeSource = { ...source, status: 'active' }
    const release = {
      version: releaseRow.version,
      releaseDate: releaseRow.release_date,
      releaseUrl: releaseRow.release_url,
      installerUrl: releaseRow.installer_url,
      installerSha256: releaseRow.installer_sha256,
      installerType: releaseRow.installer_type,
      trustState: releaseRow.trust_state,
      verificationProductCode: clean(releaseRow.source_payload?.json?.selected?.productCode),
    }
    await applyCatalogue(activeSource, release, client)
    return { source: activeSource, release }
  })
}

export async function archiveTenantVendorSource(session, sourceId) {
  const result = await withTransaction(async (client) => {
    const archived = await client.query(
      `UPDATE rmm_tenant_vendor_sources
          SET status='archived',updated_by_user_id=$3,updated_at=now()
        WHERE tenant_id=$1 AND id=$2 AND status<>'archived'
        RETURNING id,display_name`,
      [session.tenant_id, sourceId, session.user_id],
    )
    if (!archived.rowCount) return null
    await client.query(
      `UPDATE rmm_software_catalogue
          SET status='archived',updated_by_user_id=$3,updated_at=now()
        WHERE tenant_id=$1 AND catalogue_source='tenant_vendor' AND external_key=$2 AND status<>'archived'`,
      [session.tenant_id, sourceId, session.user_id],
    )
    return archived.rows[0]
  })
  if (!result) throw new Error('Vendor source not found.')
  return result
}
export async function syncDueTenantVendorSources() {
  const due = await pool.query(
    `SELECT * FROM rmm_tenant_vendor_sources
      WHERE status='active'
        AND (last_attempt_at IS NULL OR last_attempt_at + (poll_minutes || ' minutes')::interval <= now())
      ORDER BY last_attempt_at NULLS FIRST,created_at`,
  )
  const results = []
  let changed = false
  for (const source of due.rows) {
    try {
      const previous = clean(source.latest_version)
      const result = await syncSourceRow(source, false)
      results.push(result)
      if (result.status === 'active' && clean(result.version) !== previous) changed = true
    } catch (error) {
      results.push({ sourceId: source.id, ok: false, error: clean(error?.message || error) })
    }
  }
  if (changed) {
    recalculateAllTenantVulnerabilityExposures().catch((error) => {
      console.error('RMM vulnerability exposure refresh failed after tenant vendor release change', error)
    })
  }
  return results
}

let tenantSchedulerStarted = false
export function startTenantVendorSourceScheduler() {
  if (tenantSchedulerStarted) return
  tenantSchedulerStarted = true
  const run = () => syncDueTenantVendorSources()
    .catch((error) => console.error('RMM tenant vendor source scheduler failed', error))
  setTimeout(run, 20_000).unref?.()
  setInterval(run, 5 * 60 * 1000).unref?.()
}
