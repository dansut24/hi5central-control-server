import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync } from 'node:fs'
import path from 'node:path'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { gunzipSync } from 'node:zlib'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { WebSocketServer } from 'ws'
import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { ensureRedisConnected, redis } from './redis.js'
import { recordJobCompletionActivity, recordRmmActivity } from './rmmActivity.js'
import {
  reconcileNetworkDiscoveryEnrichmentJobResult,
  reconcileNetworkDiscoveryJobResult,
} from './rmmNetworkDiscoveryCore.js'
import { bitLockerRecoveryEscrowNeeded, ingestBitLockerRecoveryEscrow } from './rmmRecoveryKeys.js'
import { recalculateTenantVulnerabilityExposures } from './rmmVulnerabilityExposure.js'
import { ingestWindowsUpdateInventory, reconcileWindowsUpdateJobResult } from './rmmWindowsUpdates.js'
import { resolveSession } from './session.js'

const AGENT_DOWNLOAD_URL = 'https://downloads.hi5central.com/agent/latest/Hi5CentralAgentSetup.exe'
const AGENT_DOWNLOAD_URL_LINUX = 'https://downloads.hi5central.com/agent/latest/Hi5CentralAgent-linux-x64.tar.gz'
const AGENT_DOWNLOAD_URL_MACOS = 'https://downloads.hi5central.com/agent/latest/Hi5CentralAgent-macOS-universal.tar.gz'
const TENANT_INSTALLER_REPO = process.env.TENANT_INSTALLER_REPO || 'dansut24/Hi5Central-Agent'
const TENANT_INSTALLER_WORKFLOW = process.env.TENANT_INSTALLER_WORKFLOW || 'tenant-installer.yml'
const TENANT_INSTALLER_REF = process.env.TENANT_INSTALLER_REF || 'main'
const TENANT_INSTALLER_API_BASE = process.env.TENANT_INSTALLER_API_BASE || 'https://api.hi5central.com'
const TENANT_INSTALLER_ARTIFACT_DIR = process.env.TENANT_INSTALLER_ARTIFACT_DIR || '/srv/tenant-installers'
const TENANT_INSTALLER_MAX_ARTIFACT_BYTES = 300 * 1024 * 1024
const TENANT_INSTALLER_GENERIC_URLS = {
  exe: 'https://downloads.hi5central.com/agent/deployment/latest/Hi5CentralAgentDeployment-Windows.exe',
  msi: 'https://downloads.hi5central.com/agent/deployment/latest/Hi5CentralAgentDeployment-Windows.msi',
  app: 'https://downloads.hi5central.com/agent/deployment/latest/Hi5CentralAgentDeployment-macOS.app.zip',
  pkg: 'https://downloads.hi5central.com/agent/deployment/latest/Hi5CentralAgentDeployment-macOS.pkg',
  dmg: 'https://downloads.hi5central.com/agent/deployment/latest/Hi5CentralAgentDeployment-macOS.dmg',
  run: 'https://downloads.hi5central.com/agent/deployment/latest/Hi5CentralAgentDeployment-Linux.run',
  deb: 'https://downloads.hi5central.com/agent/deployment/latest/hi5central-agent-deployment_amd64.deb',
  rpm: 'https://downloads.hi5central.com/agent/deployment/latest/hi5central-agent-deployment_x86_64.rpm',
}
const TENANT_INSTALLER_OIDC_AUDIENCE = 'hi5central-tenant-installer'
const TENANT_INSTALLER_OIDC_ISSUER = 'https://token.actions.githubusercontent.com'
const TENANT_INSTALLER_OIDC_JWKS = createRemoteJWKSet(
  new URL('https://token.actions.githubusercontent.com/.well-known/jwks'),
)
const TENANT_INSTALLER_ASSETS = {
  exe: {
    platform: 'windows',
    fileName: 'Hi5CentralAgentTenant-Windows.exe',
    contentType: 'application/vnd.microsoft.portable-executable',
    downloadName: (id) => `Hi5CentralAgent-${id}-Windows.exe`,
  },
  msi: {
    platform: 'windows',
    fileName: 'Hi5CentralAgentTenant-Windows.msi',
    contentType: 'application/x-msi',
    downloadName: (id) => `Hi5CentralAgent-${id}-Windows.msi`,
  },
  pkg: {
    platform: 'macos',
    fileName: 'Hi5CentralAgentTenant-macOS.pkg',
    contentType: 'application/octet-stream',
    downloadName: (id) => `Hi5CentralAgent-${id}-macOS.pkg`,
  },
  dmg: {
    platform: 'macos',
    fileName: 'Hi5CentralAgentTenant-macOS.dmg',
    contentType: 'application/x-apple-diskimage',
    downloadName: (id) => `Hi5CentralAgent-${id}-macOS.dmg`,
  },
  app: {
    platform: 'macos',
    fileName: 'Hi5CentralAgentTenant-macOS.app.zip',
    contentType: 'application/zip',
    downloadName: (id) => `Hi5CentralAgent-${id}-macOS.app.zip`,
  },
  run: {
    platform: 'linux',
    fileName: 'Hi5CentralAgentTenant-Linux.run',
    contentType: 'application/octet-stream',
    downloadName: (id) => `Hi5CentralAgent-${id}-Linux.run`,
  },
  deb: {
    platform: 'linux',
    fileName: 'hi5central-agent-tenant_amd64.deb',
    contentType: 'application/vnd.debian.binary-package',
    downloadName: (id) => `hi5central-agent-${id}_amd64.deb`,
  },
  rpm: {
    platform: 'linux',
    fileName: 'hi5central-agent-tenant_x86_64.rpm',
    contentType: 'application/x-rpm',
    downloadName: (id) => `hi5central-agent-${id}.x86_64.rpm`,
  },
}
const PORTABLE_AGENT_RELEASE_MANIFEST_URL = process.env.PORTABLE_AGENT_RELEASE_MANIFEST_URL || 'https://downloads.hi5central.com/agent/latest/portable-manifest.json'
const PORTABLE_AGENT_RELEASE_CACHE_MS = 60_000
let portableAgentReleaseSyncAt = 0
let portableAgentReleaseSyncPromise = null
const MAX_INVENTORY_BYTES = 8 * 1024 * 1024
const AGENT_BROKER_INSTANCE_ID = String(process.env.API_INSTANCE_ID || process.env.HOSTNAME || `api-${process.pid}`) + '-' + randomUUID().slice(0, 8)
const AGENT_BROKER_OWNER_HASH = 'hi5central:rmm:agent:owners'
const AGENT_BROKER_SEEN_HASH = 'hi5central:rmm:agent:owner-seen'
const AGENT_BROKER_COMMAND_CHANNEL = 'hi5central:rmm:agent:command'
const AGENT_BROKER_MESSAGE_CHANNEL = 'hi5central:rmm:agent:message'
const AGENT_BROKER_PRESENCE_CHANNEL = 'hi5central:rmm:agent:presence'
const AGENT_BROKER_HEARTBEAT_MS = 5_000
const AGENT_BROKER_STALE_MS = 20_000

function clean(value = '') { return String(value ?? '').trim() }
function shellSingleQuote(value = '') { return "'" + String(value).replaceAll("'", "'\"'\"'") + "'" }
function canonicalAgentPlatform(value = '') {
  const normalized = clean(value).toLowerCase()
  if (['macos','mac','darwin','osx'].includes(normalized)) return 'macOS'
  if (['linux','ubuntu','debian','mint','fedora','rhel','centos'].includes(normalized)) return 'Linux'
  return 'Windows'
}
function isUuid(value = '') { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clean(value)) }
function sha256(value = '') { return createHash('sha256').update(String(value)).digest('hex') }
function secret(prefix) { return `${prefix}_${randomBytes(32).toString('base64url')}` }

function tenantInstallerSelection(platformValue = '', formatValue = '') {
  const platform = clean(platformValue).toLowerCase()
  const format = clean(formatValue).toLowerCase()
  const definition = TENANT_INSTALLER_ASSETS[format]
  if (!definition || definition.platform !== platform) return null
  return { platform, format, definition }
}

function tenantInstallerHmacKey() {
  return clean(process.env.TENANT_INSTALLER_HMAC_KEY || process.env.CONNECT_CODE_HMAC_KEY)
}

function tenantInstallerDeploymentSecret(packageId) {
  const key = tenantInstallerHmacKey()
  if (!key) throw new Error('Tenant installer HMAC key is not configured.')
  return createHmac('sha256', key)
    .update('hi5central-tenant-installer:' + clean(packageId))
    .digest('base64url')
}

function constantTimeTextEqual(left = '', right = '') {
  const a = Buffer.from(String(left))
  const b = Buffer.from(String(right))
  return a.length === b.length && timingSafeEqual(a, b)
}

function tenantInstallerDirectory(packageId) {
  return path.join(TENANT_INSTALLER_ARTIFACT_DIR, clean(packageId))
}

function tenantInstallerArtifactPath(packageId, format) {
  const definition = TENANT_INSTALLER_ASSETS[format]
  if (!definition) return ''
  return path.join(tenantInstallerDirectory(packageId), definition.fileName)
}

function tenantInstallerArtifactRows(packageId, selectedFormat = '') {
  const entries = Object.entries(TENANT_INSTALLER_ASSETS)
    .filter(([format]) => !selectedFormat || format === clean(selectedFormat).toLowerCase())
  return entries.map(([format, definition]) => {
    const artifactPath = tenantInstallerArtifactPath(packageId, format)
    let sizeBytes = 0
    let ready = false
    try {
      const stats = statSync(artifactPath)
      ready = stats.isFile() && stats.size > 0
      sizeBytes = ready ? stats.size : 0
    } catch {}
    return {
      format,
      platform: definition.platform,
      fileName: definition.downloadName(packageId),
      ready,
      sizeBytes,
      downloadUrl: `/api/v1/rmm/agent/enrollment-packages/${packageId}/artifacts/${format}`,
    }
  })
}

let tenantInstallerGithubTokenCache = null
function tenantInstallerGithubToken() {
  if (tenantInstallerGithubTokenCache !== null) return tenantInstallerGithubTokenCache
  tenantInstallerGithubTokenCache = clean(process.env.GITHUB_ACTIONS_TOKEN || process.env.GITHUB_TOKEN)
  if (tenantInstallerGithubTokenCache) return tenantInstallerGithubTokenCache
  for (const candidate of ['/run/secrets/github_actions_token', '/run/secrets/github_token']) {
    try {
      tenantInstallerGithubTokenCache = clean(readFileSync(candidate, 'utf8'))
      if (tenantInstallerGithubTokenCache) return tenantInstallerGithubTokenCache
    } catch {}
  }
  tenantInstallerGithubTokenCache = ''
  return ''
}

async function requestTenantInstallerBuild(packageId, installerPlatform = '', installerFormat = '') {
  const token = tenantInstallerGithubToken()
  if (!token) throw new Error('GitHub Actions token is not configured for tenant installer builds.')
  const response = await fetch(
    `https://api.github.com/repos/${TENANT_INSTALLER_REPO}/actions/workflows/${encodeURIComponent(TENANT_INSTALLER_WORKFLOW)}/dispatches`,
    {
      method: 'POST',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      body: JSON.stringify({
        ref: TENANT_INSTALLER_REF,
        inputs: {
          deployment_id: clean(packageId),
          api_base: TENANT_INSTALLER_API_BASE,
          target_platform: clean(installerPlatform).toLowerCase(),
          target_format: clean(installerFormat).toLowerCase(),
        },
      }),
      signal: AbortSignal.timeout(10_000),
    },
  )
  if (!response.ok) {
    const detail = clean(await response.text())
    throw new Error(
      `Tenant installer build dispatch failed HTTP ${response.status}` +
      (detail ? ': ' + detail.slice(0, 300) : ''),
    )
  }
}

async function verifyTenantInstallerBuilder(c) {
  const header = clean(c.req.header('authorization'))
  if (!/^Bearer\s+/i.test(header)) return null
  const token = header.replace(/^Bearer\s+/i, '')
  try {
    const verified = await jwtVerify(token, TENANT_INSTALLER_OIDC_JWKS, {
      issuer: TENANT_INSTALLER_OIDC_ISSUER,
      audience: TENANT_INSTALLER_OIDC_AUDIENCE,
    })
    const payload = verified.payload || {}
    const expectedWorkflowRef =
      `${TENANT_INSTALLER_REPO}/.github/workflows/${TENANT_INSTALLER_WORKFLOW}@refs/heads/${TENANT_INSTALLER_REF}`
    if (payload.repository !== TENANT_INSTALLER_REPO) return null
    if (payload.ref !== `refs/heads/${TENANT_INSTALLER_REF}`) return null
    if (payload.workflow_ref !== expectedWorkflowRef) return null
    if (payload.event_name !== 'workflow_dispatch') return null
    return payload
  } catch {
    return null
  }
}

function boundedNumber(value, min, max) {
  const number = Number(value)
  if (!Number.isFinite(number)) return null
  return Math.min(max, Math.max(min, number))
}
function boundedInteger(value, min, max) {
  const number = Number(value)
  if (!Number.isFinite(number)) return null
  return Math.min(max, Math.max(min, Math.trunc(number)))
}
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function psSingleQuote(value = '') { return String(value).replaceAll("'", "''") }
function versionParts(value = '') { return String(value).match(/\d+/g)?.slice(0, 4).map(Number) || [] }
function versionCompare(left, right) {
  const a = versionParts(left)
  const b = versionParts(right)
  for (let index = 0; index < Math.max(a.length, b.length, 1); index += 1) {
    const delta = (a[index] || 0) - (b[index] || 0)
    if (delta) return delta > 0 ? 1 : -1
  }
  return 0
}
function agentReleaseVersionAtLeast(currentValue, targetValue) {
  const current = clean(currentValue)
  const target = clean(targetValue)
  if (!target) return true
  if (!current) return false
  // Legacy Windows Agents reported a hardcoded 1.0.0 before the installer build
  // version was compiled into the binary. Do not let that placeholder block a
  // real 0.1.x trusted-release upgrade; the first corrected build migrates it.
  if (current === '1.0.0' && /^0\.1\./.test(target)) return false
  return versionCompare(current, target) >= 0
}
function patchHostVersionAtLeast(currentValue, targetValue) {
  const current = clean(currentValue)
  const target = clean(targetValue)
  if (!target) return true
  return Boolean(current && versionCompare(current, target) >= 0)
}

function portableReleaseChannel(platformValue = '') {
  const platform = canonicalAgentPlatform(platformValue)
  if (platform === 'Linux') return 'portable-linux'
  if (platform === 'macOS') return 'portable-macos'
  return ''
}

function releaseMatchesPlatform(release, platformValue = '') {
  const rawPlatform = clean(platformValue)
  if (!rawPlatform) return true
  const channel = clean(release?.channel).toLowerCase()
  const portableChannel = portableReleaseChannel(rawPlatform)
  if (portableChannel) return channel === portableChannel
  return !channel.startsWith('portable-')
}

async function syncPortableAgentReleases(force = false) {
  if (!force && Date.now() - portableAgentReleaseSyncAt < PORTABLE_AGENT_RELEASE_CACHE_MS) return
  if (portableAgentReleaseSyncPromise) return portableAgentReleaseSyncPromise

  portableAgentReleaseSyncPromise = (async () => {
    try {
      const response = await fetch(PORTABLE_AGENT_RELEASE_MANIFEST_URL, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(4_000),
      })
      if (!response.ok) throw new Error('Portable Agent release manifest HTTP ' + response.status)
      const manifest = await response.json()
      const platforms = object(manifest?.platforms)

      const definitions = [
        { key: 'linux', channel: 'portable-linux', expectedUrl: AGENT_DOWNLOAD_URL_LINUX, label: 'Linux x64' },
        { key: 'macos', channel: 'portable-macos', expectedUrl: AGENT_DOWNLOAD_URL_MACOS, label: 'macOS universal' },
      ]

      for (const definition of definitions) {
        const item = object(platforms[definition.key])
        const version = clean(item.version).slice(0, 80)
        const installerUrl = clean(item.url)
        const installerSha256 = clean(item.sha256).toLowerCase()
        if (!/^0\.3\.\d+(?:[-+][0-9A-Za-z._-]+)?$/.test(version)) continue
        if (installerUrl !== definition.expectedUrl) continue
        if (!/^[a-f0-9]{64}$/.test(installerSha256)) continue

        await pool.query(
          `INSERT INTO rmm_agent_releases
            (channel,version,patch_host_version,installer_url,installer_sha256,build_commit,workflow_run,status,release_notes)
           VALUES ($1,$2,'',$3,$4,'',NULL,'test',$5)
           ON CONFLICT (channel,version) DO UPDATE
             SET installer_url=EXCLUDED.installer_url,
                 installer_sha256=EXCLUDED.installer_sha256,
                 release_notes=EXCLUDED.release_notes,
                 updated_at=now()`,
          [
            definition.channel,
            version,
            installerUrl,
            installerSha256,
            definition.label + ' portable Agent · portal/self-update capable',
          ],
        )
      }
    } finally {
      portableAgentReleaseSyncAt = Date.now()
      portableAgentReleaseSyncPromise = null
    }
  })()

  return portableAgentReleaseSyncPromise
}
async function reconcileAgentUpgradeAfterHello(agent, reportedVersion) {
  const pending = await pool.query(`SELECT id,status,request_metadata,result,initiated_by_label,queued_by_user_id,correlation_id FROM rmm_agent_jobs WHERE tenant_id=$1 AND agent_device_id=$2 AND request_metadata->>'source'='agent_upgrade' AND (status IN ('queued','claimed') OR (status='failed' AND result->>'exit_code'='143')) ORDER BY created_at DESC LIMIT 1`, [agent.tenant_id, agent.id])
  const job = pending.rows[0]
  if (!job) return
  const target = clean(object(job.request_metadata).release_version)
  if (!target) return
  if (!agentReleaseVersionAtLeast(reportedVersion, target)) {
    if (clean(object(job.result).status).toLowerCase() === 'scheduled') {
      const failed = await pool.query(
        `UPDATE rmm_agent_jobs
            SET status='failed',
                error_message=$3,
                completed_at=now(),
                updated_at=now()
          WHERE id=$1 AND tenant_id=$2 AND status IN ('queued','claimed')
          RETURNING id`,
        [job.id, agent.tenant_id, 'Agent reconnected on version ' + clean(reportedVersion || 'unknown') + ' instead of target ' + target + '; upgrade rollback/failure detected.'],
      )
      if (failed.rowCount) {
        const actor = clean(job.initiated_by_label || 'Technician')
        await recordRmmActivity({
          tenantId: agent.tenant_id,
          agentDeviceId: agent.id,
          inventoryId: agent.inventory_id,
          actorUserId: job.queued_by_user_id,
          actorType: 'technician',
          actorLabel: actor,
          eventType: 'agent.upgrade.failed',
          category: 'device',
          summary: actor + ' Agent upgrade to ' + target + ' rolled back or failed',
          detail: 'Endpoint reconnected on Agent ' + clean(reportedVersion || 'unknown') + '.',
          outcome: 'failed',
          jobId: job.id,
          correlationId: job.correlation_id,
          metadata: { targetVersion: target, reportedVersion, verification: 'agent_reconnect_version_mismatch' },
        }).catch(() => {})
      }
    }
    return
  }
  const updated = await pool.query(`UPDATE rmm_agent_jobs SET status='completed',result=jsonb_build_object('status','succeeded_after_reconnect','reportedAgentVersion',$3::text),error_message=NULL,completed_at=now(),updated_at=now() WHERE id=$1 AND tenant_id=$2 AND (status IN ('queued','claimed') OR (status='failed' AND result->>'exit_code'='143')) RETURNING id`, [job.id, agent.tenant_id, reportedVersion])
  if (!updated.rowCount) return
  const actor = clean(job.initiated_by_label || 'Technician')
  await recordRmmActivity({ tenantId: agent.tenant_id, agentDeviceId: agent.id, inventoryId: agent.inventory_id, actorUserId: job.queued_by_user_id, actorType: 'technician', actorLabel: actor, eventType: 'agent.upgrade.completed', category: 'device', summary: actor + ' upgraded Hi5Central Agent to ' + target, detail: 'Verified after Agent reconnect · reported version ' + reportedVersion, outcome: 'success', jobId: job.id, correlationId: job.correlation_id, metadata: { targetVersion: target, reportedVersion, verification: 'agent_reconnect_hello' } })
}

async function requireRmmManager(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (!hasPermission(session.access, 'rmm.devices.control') && !hasPermission(session.access, 'rmm.policies.manage')) {
    return { error: c.json({ error: 'You do not have permission to manage RMM agents.' }, 403) }
  }
  return { session }
}

async function requireRmmDeviceControl(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  if (!hasPermission(session.access, 'rmm.devices.control')) {
    return { error: c.json({ error: 'You do not have permission to upgrade RMM agents.' }, 403) }
  }
  return { session }
}

function agentUpgradeScript(release) {
  const url = psSingleQuote(release.installer_url)
  const expected = psSingleQuote(clean(release.installer_sha256).toLowerCase())
  const version = clean(release.version).replace(/[^0-9A-Za-z._-]/g, '').slice(0, 48)
  const taskName = 'Hi5CentralAgentUpgrade-' + version
  return [
    "$ErrorActionPreference = 'Stop'",
    "$url = '" + url + "'",
    "$expectedSha256 = '" + expected + "'",
    "$upgradeDir = Join-Path $env:ProgramData 'Hi5Central\\Agent\\Upgrade'",
    "New-Item -ItemType Directory -Force -Path $upgradeDir | Out-Null",
    "$now = Get-Date",
    "Get-ChildItem -LiteralPath $upgradeDir -Filter 'Hi5CentralAgentSetup-*.exe' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $now.AddHours(-6) } | Remove-Item -Force -ErrorAction SilentlyContinue",
    "Get-ChildItem -LiteralPath $upgradeDir -Filter 'run-upgrade-*.ps1' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $now.AddDays(-1) } | Remove-Item -Force -ErrorAction SilentlyContinue",
    "Get-ChildItem -LiteralPath $upgradeDir -Filter 'installer-*.log' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $now.AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue",
    "Get-ChildItem -LiteralPath $upgradeDir -Filter 'installer-*.log' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -Skip 3 | Remove-Item -Force -ErrorAction SilentlyContinue",
    "Get-ChildItem -LiteralPath $upgradeDir -Filter 'result-*.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $now.AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue",
    "Get-ChildItem -LiteralPath $upgradeDir -Filter 'result-*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -Skip 3 | Remove-Item -Force -ErrorAction SilentlyContinue",
    "$installer = Join-Path $upgradeDir 'Hi5CentralAgentSetup-" + version + ".exe'",
    "$logPath = Join-Path $upgradeDir 'installer-" + version + ".log'",
    "Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue",
    "Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $installer",
    "$actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash.ToLowerInvariant()",
    "if ($actualSha256 -ne $expectedSha256) { Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue; throw ('Installer SHA-256 mismatch. Expected ' + $expectedSha256 + ' but got ' + $actualSha256) }",
    "$taskName = '" + psSingleQuote(taskName) + "'",
    "Get-ScheduledTask -TaskName 'Hi5CentralAgentUpgrade-*' -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -ne $taskName -and [string]$_.State -ne 'Running' } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue",
    "$installerArgs = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /INSTALL_SOURCE=agent-upgrade /LOG=' + [char]34 + $logPath + [char]34",
    "$runner = Join-Path $upgradeDir 'run-upgrade-" + version + ".ps1'",
    "$resultPath = Join-Path $upgradeDir 'result-" + version + ".json'",
    "$runnerScript = '$ErrorActionPreference = ''Stop''' + [Environment]::NewLine + '$installer = ''' + $installer + '''' + [Environment]::NewLine + '$installerArgs = ''' + $installerArgs + '''' + [Environment]::NewLine + '$resultPath = ''' + $resultPath + '''' + [Environment]::NewLine + '$started = Get-Date' + [Environment]::NewLine + 'try { Stop-Service -Name Hi5CentralAgent -Force -ErrorAction SilentlyContinue; $deadline=(Get-Date).AddSeconds(30); do { $p=Get-Process Hi5CentralAgentService -ErrorAction SilentlyContinue; if (-not $p) { break }; Start-Sleep -Milliseconds 500 } while ((Get-Date) -lt $deadline); if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction Stop; Start-Sleep -Seconds 2 }; @(''Hi5CentralAppPortal'',''Hi5CentralUser'',''Hi5CentralRemoteHost'',''Hi5CentralMediaHost'',''Hi5CentralPatchHost'') | ForEach-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }; Start-Sleep -Milliseconds 750; $proc=Start-Process -FilePath $installer -ArgumentList $installerArgs -Wait -PassThru; $code=$proc.ExitCode; if ($code -ne 0) { throw (''Installer exited with code '' + $code) }; $portalPath=Join-Path $env:ProgramFiles ''Hi5Central\\Agent\\Hi5CentralAppPortal.exe''; if (-not (Test-Path -LiteralPath $portalPath)) { throw ''Hi5 Self Service executable is missing after upgrade.'' }; $portalVersion=[string](Get-Item -LiteralPath $portalPath).VersionInfo.FileVersion; if (-not $portalVersion.StartsWith(''" + version + "'',[System.StringComparison]::OrdinalIgnoreCase)) { throw (''Hi5 Self Service version verification failed. Expected " + version + " but found '' + $portalVersion) }; Start-Service -Name Hi5CentralAgent -ErrorAction Stop; [pscustomobject]@{status=''succeeded'';started=$started;completed=(Get-Date);installer_exit_code=$code;portal_version=$portalVersion} | ConvertTo-Json -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8; Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue } catch { $message=$_.Exception.Message; Start-Service -Name Hi5CentralAgent -ErrorAction SilentlyContinue; [pscustomobject]@{status=''failed'';started=$started;completed=(Get-Date);error=$message} | ConvertTo-Json -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8; Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue; exit 1 }'",
    "Set-Content -LiteralPath $runner -Value $runnerScript -Encoding UTF8",
    "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + [char]34 + $runner + [char]34)",
    "$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(35)",
    "$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest",
    "$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)",
    "Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null",
    "Start-ScheduledTask -TaskName $taskName -ErrorAction Stop",
    "$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop",
    "$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop",
    "[pscustomobject]@{ status='scheduled'; task=$taskName; installer=$installer; log=$logPath; sha256=$actualSha256; scheduled_for=$trigger.StartBoundary; task_state=[string]$task.State; task_last_result=$taskInfo.LastTaskResult } | ConvertTo-Json -Compress",
  ].join("\n")
}

export function portableAgentUpgradeScript(release, platformValue, correlationId) {
  const platform = canonicalAgentPlatform(platformValue)
  const version = clean(release.version).replace(/[^0-9A-Za-z._-]/g, '').slice(0, 48)
  const expected = clean(release.installer_sha256).toLowerCase()
  const url = clean(release.installer_url)
  const token = clean(correlationId).replace(/[^0-9A-Za-z]/g, '').slice(0, 16) || randomUUID().replaceAll('-', '').slice(0, 16)

  if (!version || !/^[a-f0-9]{64}$/.test(expected)) {
    throw new Error('Portable Agent release metadata is incomplete.')
  }

  if (platform === 'Linux') {
    const stage = '/var/lib/hi5central/agent/upgrade/' + version + '-' + token
    const runner = stage + '/run-upgrade.sh'
    const runnerLog = stage + '/upgrade.log'
    const unit = 'hi5central-agent-upgrade-' + version.replaceAll('.', '-') + '-' + token.toLowerCase()
    const runnerContent = [
      '#!/usr/bin/env bash',
      'set -u',
      'sleep 5',
      'stage=' + shellSingleQuote(stage),
      'log=' + shellSingleQuote(runnerLog),
      'exec >>"$log" 2>&1',
      'echo "Hi5Central Agent upgrade starting at $(date -u +%Y-%m-%dT%H:%M:%SZ)"',
      'if /bin/bash "$stage/installer/linux/install.sh" --api-base https://api.hi5central.com; then',
      '  echo "Hi5Central Agent upgrade completed successfully"',
      '  exit 0',
      'fi',
      'rc=$?',
      'echo "Hi5Central Agent upgrade failed with exit code $rc"',
      'exit "$rc"',
    ].join('\n')

    return [
      'set -eu',
      'url=' + shellSingleQuote(url),
      'expected=' + shellSingleQuote(expected),
      'version=' + shellSingleQuote(version),
      'stage=' + shellSingleQuote(stage),
      'archive="$stage/agent.tar.gz"',
      'runner=' + shellSingleQuote(runner),
      'rm -rf "$stage"',
      'mkdir -p "$stage"',
      '/usr/bin/curl --fail --location --silent --show-error --proto "=https" --tlsv1.2 "$url" -o "$archive"',
      'actual=$(/usr/bin/sha256sum "$archive" | /usr/bin/awk \'{print $1}\')',
      'if [ "$actual" != "$expected" ]; then rm -f "$archive"; echo "Agent archive SHA-256 mismatch" >&2; exit 42; fi',
      '/bin/tar -xzf "$archive" -C "$stage"',
      'chmod 0755 "$stage/Hi5CentralAgent" "$stage/installer/linux/install.sh"',
      'candidate=$("$stage/Hi5CentralAgent" --version)',
      'if [ "$candidate" != "$version" ]; then echo "Agent version verification failed: expected $version got $candidate" >&2; exit 43; fi',
      'printf "%s\\n" ' + shellSingleQuote(runnerContent) + ' > "$runner"',
      'chmod 0700 "$runner"',
      'if [ ! -x /usr/bin/systemd-run ] && [ ! -x /bin/systemd-run ]; then echo "systemd-run is required for an in-place Agent upgrade" >&2; exit 44; fi',
      'SYSTEMD_RUN=/usr/bin/systemd-run; [ -x "$SYSTEMD_RUN" ] || SYSTEMD_RUN=/bin/systemd-run',
      '"$SYSTEMD_RUN" --no-block --unit=' + shellSingleQuote(unit) + ' --property=Type=oneshot /bin/bash "$runner" >/dev/null',
      'printf "%s\\n" ' + shellSingleQuote(JSON.stringify({ status: 'scheduled', transport: 'systemd', target_version: version })) ,
    ].join('\n')
  }

  if (platform === 'macOS') {
    const stage = '/Library/Application Support/Hi5Central/Agent/upgrade/' + version + '-' + token
    const runner = stage + '/run-upgrade.sh'
    const runnerLog = stage + '/upgrade.log'
    const label = 'com.hi5central.agent.upgrade.' + version.replaceAll('.', '-') + '.' + token.toLowerCase()
    const plist = '/Library/LaunchDaemons/' + label + '.plist'
    const runnerContent = [
      '#!/bin/bash',
      'set -u',
      'sleep 5',
      'stage=' + shellSingleQuote(stage),
      'plist=' + shellSingleQuote(plist),
      'log=' + shellSingleQuote(runnerLog),
      'exec >>"$log" 2>&1',
      'echo "Hi5Central Agent upgrade starting at $(date -u +%Y-%m-%dT%H:%M:%SZ)"',
      'rc=0',
      '/bin/bash "$stage/installer/macos/install.sh" --api-base https://api.hi5central.com || rc=$?',
      'rm -f "$plist"',
      'if [ "$rc" -eq 0 ]; then echo "Hi5Central Agent upgrade completed successfully"; else echo "Hi5Central Agent upgrade failed with exit code $rc"; fi',
      'exit "$rc"',
    ].join('\n')
    const plistContent = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
      '<plist version="1.0">',
      '<dict>',
      '  <key>Label</key><string>' + label + '</string>',
      '  <key>ProgramArguments</key>',
      '  <array><string>/bin/bash</string><string>' + runner + '</string></array>',
      '  <key>RunAtLoad</key><true/>',
      '  <key>KeepAlive</key><false/>',
      '  <key>StandardOutPath</key><string>' + runnerLog + '</string>',
      '  <key>StandardErrorPath</key><string>' + runnerLog + '</string>',
      '  <key>ProcessType</key><string>Background</string>',
      '</dict>',
      '</plist>',
    ].join('\n')

    return [
      'set -eu',
      'url=' + shellSingleQuote(url),
      'expected=' + shellSingleQuote(expected),
      'version=' + shellSingleQuote(version),
      'stage=' + shellSingleQuote(stage),
      'archive="$stage/agent.tar.gz"',
      'runner=' + shellSingleQuote(runner),
      'plist=' + shellSingleQuote(plist),
      'rm -rf "$stage"',
      'mkdir -p "$stage"',
      '/usr/bin/curl --fail --location --silent --show-error --proto "=https" --tlsv1.2 "$url" -o "$archive"',
      'actual=$(/usr/bin/shasum -a 256 "$archive" | /usr/bin/awk \'{print $1}\')',
      'if [ "$actual" != "$expected" ]; then rm -f "$archive"; echo "Agent archive SHA-256 mismatch" >&2; exit 42; fi',
      '/usr/bin/tar -xzf "$archive" -C "$stage"',
      'chmod 0755 "$stage/Hi5CentralAgent" "$stage/installer/macos/install.sh"',
      'candidate=$("$stage/Hi5CentralAgent" --version)',
      'if [ "$candidate" != "$version" ]; then echo "Agent version verification failed: expected $version got $candidate" >&2; exit 43; fi',
      'printf "%s\\n" ' + shellSingleQuote(runnerContent) + ' > "$runner"',
      'chmod 0700 "$runner"',
      'printf "%s\\n" ' + shellSingleQuote(plistContent) + ' > "$plist"',
      '/usr/sbin/chown root:wheel "$plist"',
      'chmod 0644 "$plist"',
      '/usr/bin/plutil -lint "$plist" >/dev/null',
      '/bin/launchctl bootstrap system "$plist"',
      'printf "%s\\n" ' + shellSingleQuote(JSON.stringify({ status: 'scheduled', transport: 'launchd', target_version: version })),
    ].join('\n')
  }

  throw new Error('Portable Agent self-update is supported only on macOS and Linux.')
}

async function agentReleaseRows(platform = '') {
  await syncPortableAgentReleases().catch((error) => {
    console.error('Portable Agent release sync failed', error.message)
  })
  const result = await pool.query(
    `SELECT id,channel,version,patch_host_version,installer_url,installer_sha256,
            build_commit,workflow_run,status,release_notes,created_at,updated_at
       FROM rmm_agent_releases
      WHERE status IN ('test','active')
      ORDER BY status='active' DESC,created_at DESC,version DESC`,
  )
  return result.rows.filter((release) => releaseMatchesPlatform(release, platform))
}

export async function authenticateAgent(deviceId, deviceSecret) {
  const id = clean(deviceId)
  const rawSecret = clean(deviceSecret)
  if (!id || !rawSecret) return null
  const result = await pool.query(
    `SELECT a.id,a.tenant_id,a.inventory_id,a.agent_version,i.reference,i.name
       FROM rmm_agent_devices a
       JOIN rmm_device_inventory i ON i.id=a.inventory_id
      WHERE a.id::text=$1 AND a.secret_hash=$2 AND a.disabled_at IS NULL
      LIMIT 1`,
    [id, sha256(rawSecret)],
  )
  return result.rows[0] || null
}
function storageTotals(storage) {
  if (!Array.isArray(storage)) return { total: null, free: null }
  let total = 0
  let free = 0
  let seen = false
  for (const drive of storage) {
    const driveTotal = Number(drive?.total_bytes)
    const driveFree = Number(drive?.free_bytes)
    if (Number.isFinite(driveTotal) && driveTotal >= 0) { total += driveTotal; seen = true }
    if (Number.isFinite(driveFree) && driveFree >= 0) free += driveFree
  }
  return seen ? { total, free } : { total: null, free: null }
}


function softwareIdentity(app = {}) {
  return [
    clean(app.registry_key || app.registryKey),
    clean(app.scope),
    clean(app.name).toLowerCase(),
    clean(app.version).toLowerCase(),
  ].join('|')
}

function bitlockerVolumes(payload = {}) {
  const direct = Array.isArray(payload.security?.bitlocker) ? payload.security.bitlocker : []
  if (direct.length) return direct
  return (Array.isArray(payload.storage) ? payload.storage : []).map((drive) => ({
    drive: drive.drive || drive.mount,
    ...(drive.bitlocker && typeof drive.bitlocker === 'object' ? drive.bitlocker : {}),
    encryption_percentage: drive.encryption_percentage ?? drive.bitlocker?.encryption_percentage,
    protection_status: drive.bitlocker_status || drive.bitlocker?.protection_status,
  }))
}

function inventoryDeltaEvents(previous = {}, current = {}) {
  const events = []
  if (!previous || !Object.keys(previous).length) return events

  const previousBitlocker = new Map(bitlockerVolumes(previous).map((drive) => [clean(drive.drive || drive.mount_point), drive]))
  for (const drive of bitlockerVolumes(current)) {
    const key = clean(drive.drive || drive.mount_point)
    if (!key) continue
    const before = previousBitlocker.get(key)
    if (!before) continue

    const beforePct = Number(before.encryption_percentage)
    const afterPct = Number(drive.encryption_percentage)
    const beforeProtection = clean(before.protection_status)
    const afterProtection = clean(drive.protection_status)
    const beforeVolume = clean(before.volume_status)
    const afterVolume = clean(drive.volume_status)

    if (Number.isFinite(beforePct) && Number.isFinite(afterPct) && beforePct <= 0 && afterPct > 0 && afterPct < 100) {
      events.push({ eventType: 'bitlocker.encrypting', category: 'security', summary: 'SYSTEM: ' + key + ' started encrypting', detail: 'BitLocker encryption progressed from ' + beforePct + '% to ' + afterPct + '%.', outcome: 'info', metadata: { drive: key, before: beforePct, after: afterPct } })
    } else if (Number.isFinite(beforePct) && Number.isFinite(afterPct) && beforePct < 100 && afterPct >= 100) {
      events.push({ eventType: 'bitlocker.encrypted', category: 'security', summary: 'SYSTEM: ' + key + ' finished encrypting', detail: 'BitLocker encryption reached 100%.', outcome: 'success', metadata: { drive: key, before: beforePct, after: afterPct } })
    } else if (Number.isFinite(beforePct) && Number.isFinite(afterPct) && beforePct > 0 && afterPct < beforePct && afterPct < 100) {
      events.push({ eventType: 'bitlocker.decrypting', category: 'security', summary: 'SYSTEM: ' + key + ' started decrypting', detail: 'BitLocker encryption changed from ' + beforePct + '% to ' + afterPct + '%.', outcome: 'info', severity: 'warning', metadata: { drive: key, before: beforePct, after: afterPct } })
    }

    if (beforeProtection && afterProtection && beforeProtection !== afterProtection) {
      if (/on|protected/i.test(beforeProtection) && /off|suspended/i.test(afterProtection)) {
        events.push({ eventType: 'bitlocker.suspended', category: 'security', summary: 'SYSTEM: BitLocker was suspended on ' + key, detail: beforeProtection + ' → ' + afterProtection, outcome: 'info', severity: 'warning', metadata: { drive: key, before: beforeProtection, after: afterProtection } })
      } else if (/off|suspended/i.test(beforeProtection) && /on|protected/i.test(afterProtection)) {
        events.push({ eventType: 'bitlocker.resumed', category: 'security', summary: 'SYSTEM: BitLocker protection resumed on ' + key, detail: beforeProtection + ' → ' + afterProtection, outcome: 'success', metadata: { drive: key, before: beforeProtection, after: afterProtection } })
      }
    }

    if (beforeVolume !== afterVolume && /fullyencrypted/i.test(afterVolume) && !(Number.isFinite(afterPct) && afterPct >= 100)) {
      events.push({ eventType: 'bitlocker.encrypted', category: 'security', summary: 'SYSTEM: ' + key + ' finished encrypting', detail: 'BitLocker reports the volume as fully encrypted.', outcome: 'success', metadata: { drive: key, before: beforeVolume, after: afterVolume } })
    }
  }

  const previousSoftware = Array.isArray(previous.software?.items) ? previous.software.items : []
  const currentSoftware = Array.isArray(current.software?.items) ? current.software.items : []
  if (previousSoftware.length && currentSoftware.length) {
    const beforeMap = new Map(previousSoftware.map((app) => [softwareIdentity(app), app]))
    const afterMap = new Map(currentSoftware.map((app) => [softwareIdentity(app), app]))
    for (const [key, app] of afterMap) {
      if (!beforeMap.has(key)) {
        events.push({ eventType: 'software.detected', category: 'software', summary: 'SYSTEM: detected software installation “' + clean(app.name) + '”', detail: [app.version, app.publisher].filter(Boolean).join(' · '), outcome: 'info', metadata: { software: app } })
      }
    }
    for (const [key, app] of beforeMap) {
      if (!afterMap.has(key)) {
        events.push({ eventType: 'software.removed', category: 'software', summary: 'SYSTEM: detected software removal “' + clean(app.name) + '”', detail: [app.version, app.publisher].filter(Boolean).join(' · '), outcome: 'info', metadata: { software: app } })
      }
    }
  }

  const beforeHost = clean(previous.summary?.hostname)
  const afterHost = clean(current.summary?.hostname)
  if (beforeHost && afterHost && beforeHost !== afterHost) {
    events.push({ eventType: 'device.hostname_changed', category: 'inventory', summary: 'SYSTEM: device hostname changed to ' + afterHost, detail: beforeHost + ' → ' + afterHost, outcome: 'info', metadata: { before: beforeHost, after: afterHost } })
  }

  const beforeOs = clean(previous.summary?.os_version || previous.os?.version)
  const afterOs = clean(current.summary?.os_version || current.os?.version)
  const beforeBuild = clean(previous.summary?.os_build || previous.os?.build)
  const afterBuild = clean(current.summary?.os_build || current.os?.build)
  if (beforeOs && afterOs && (beforeOs !== afterOs || (beforeBuild && afterBuild && beforeBuild !== afterBuild))) {
    events.push({ eventType: 'os.updated', category: 'inventory', summary: 'SYSTEM: Windows version changed to ' + afterOs, detail: [beforeOs + (beforeBuild ? ' (' + beforeBuild + ')' : ''), afterOs + (afterBuild ? ' (' + afterBuild + ')' : '')].join(' → '), outcome: 'success', metadata: { beforeVersion: beforeOs, afterVersion: afterOs, beforeBuild, afterBuild } })
  }

  const beforeMemory = Number(previous.summary?.total_memory_bytes ?? previous.memory?.total_bytes)
  const afterMemory = Number(current.summary?.total_memory_bytes ?? current.memory?.total_bytes)
  if (Number.isFinite(beforeMemory) && Number.isFinite(afterMemory) && beforeMemory > 0 && afterMemory > 0 && beforeMemory !== afterMemory) {
    events.push({ eventType: 'hardware.memory_changed', category: 'inventory', summary: 'SYSTEM: installed memory changed', detail: Math.round(beforeMemory / 1073741824) + ' GB → ' + Math.round(afterMemory / 1073741824) + ' GB', outcome: 'info', metadata: { beforeBytes: beforeMemory, afterBytes: afterMemory } })
  }

  const beforeUser = clean(previous.summary?.logged_in_user || previous.sessions?.active_console_user || previous.sessions?.current_user)
  const afterUser = clean(current.summary?.logged_in_user || current.sessions?.active_console_user || current.sessions?.current_user)
  if (beforeUser && afterUser && beforeUser !== afterUser) {
    events.push({ eventType: 'session.console_user_changed', category: 'session', summary: 'SYSTEM: active console user changed to ' + afterUser, detail: beforeUser + ' → ' + afterUser, outcome: 'info', metadata: { before: beforeUser, after: afterUser } })
  }

  const securityFields = [
    ['firewall_enabled', 'Windows Firewall', 'security.firewall_changed'],
    ['defender_enabled', 'Microsoft Defender', 'security.defender_changed'],
    ['defender_realtime_enabled', 'Defender real-time protection', 'security.defender_realtime_changed'],
    ['secure_boot_enabled', 'Secure Boot', 'security.secure_boot_changed'],
  ]
  for (const [field, label, eventType] of securityFields) {
    const before = previous.security?.[field]
    const after = current.security?.[field]
    if (typeof before === 'boolean' && typeof after === 'boolean' && before !== after) {
      events.push({ eventType, category: 'security', summary: 'SYSTEM: ' + label + ' was ' + (after ? 'enabled' : 'disabled'), detail: String(before) + ' → ' + String(after), outcome: after ? 'success' : 'info', severity: after ? 'info' : 'warning', metadata: { before, after } })
    }
  }

  const beforeAdmins = Number(previous.security?.local_admin_count)
  const afterAdmins = Number(current.security?.local_admin_count)
  if (Number.isFinite(beforeAdmins) && Number.isFinite(afterAdmins) && beforeAdmins !== afterAdmins) {
    events.push({ eventType: 'security.local_admins_changed', category: 'security', summary: 'SYSTEM: local administrator membership changed', detail: beforeAdmins + ' → ' + afterAdmins + ' members', outcome: 'info', severity: afterAdmins > beforeAdmins ? 'warning' : 'info', metadata: { before: beforeAdmins, after: afterAdmins } })
  }

  const beforePending = Number(previous.windows_updates?.pending_count)
  const afterPending = Number(current.windows_updates?.pending_count)
  if (Number.isFinite(beforePending) && Number.isFinite(afterPending) && beforePending !== afterPending) {
    events.push({ eventType: 'windows_updates.pending_changed', category: 'updates', summary: 'SYSTEM: Windows Update pending count changed to ' + afterPending, detail: beforePending + ' → ' + afterPending + ' pending update' + (afterPending === 1 ? '' : 's'), outcome: afterPending < beforePending ? 'success' : 'info', metadata: { before: beforePending, after: afterPending } })
  }

  return events.slice(0, 50)
}


const RETAINED_DEEP_INVENTORY_FIELDS = [
  'memory_modules','motherboard','physical_disks','monitors','drivers','problem_devices',
  'installed_hotfixes','windows_licensing','reboot_state','startup_items','scheduled_tasks',
  'local_groups','printers','usb_devices','optional_features','power_plan','network_profiles',
  'network_configurations','wifi_interfaces','default_routes','directory_join',
  'machine_certificates','virtualization','deep_inventory_collected_at',
]

const DEEP_SECTION_FIELDS = {
  core_hardware: ['memory_modules','motherboard'],
  storage: ['physical_disks'],
  monitors: ['monitors'],
  drivers: ['drivers'],
  problem_devices: ['problem_devices'],
  windows_state: ['installed_hotfixes','windows_licensing','reboot_state','startup_items'],
  scheduled_tasks: ['scheduled_tasks'],
  local_groups: ['local_groups'],
  peripherals: ['printers','usb_devices'],
  features_power: ['optional_features','power_plan'],
  network: ['network_profiles','network_configurations','wifi_interfaces','default_routes'],
  directory_join: ['directory_join'],
  certificates: ['machine_certificates'],
  virtualization: ['virtualization'],
}

function mergeRetainedDeepInventory(previousPayload, incomingPayload) {
  const previous = previousPayload && typeof previousPayload === 'object' ? previousPayload : {}
  const incoming = incomingPayload && typeof incomingPayload === 'object' ? incomingPayload : {}
  const merged = { ...incoming }
  const retainAllMissingDeep = incomingPayload?.deep_inventory_included === false

  const sectionStatuses = incoming.deep_inventory_sections && typeof incoming.deep_inventory_sections === 'object'
    ? incoming.deep_inventory_sections
    : {}
  const failedSections = new Set(
    Object.entries(sectionStatuses)
      .filter(([, value]) => value && typeof value === 'object' && value.status === 'failed')
      .map(([name]) => name),
  )

  if (retainAllMissingDeep) {
    for (const key of RETAINED_DEEP_INVENTORY_FIELDS) {
      if (merged[key] === undefined && previous[key] !== undefined) merged[key] = previous[key]
    }
  }

  for (const section of failedSections) {
    for (const key of DEEP_SECTION_FIELDS[section] || []) {
      if (previous[key] !== undefined) merged[key] = previous[key]
      else delete merged[key]
    }
  }

  const previousNetwork = previous.network && typeof previous.network === 'object' ? previous.network : {}
  const incomingNetwork = incoming.network && typeof incoming.network === 'object' ? incoming.network : {}
  const network = { ...incomingNetwork }
  for (const key of ['configurations','wifi_interfaces','default_routes']) {
    if (retainAllMissingDeep && network[key] === undefined && previousNetwork[key] !== undefined) network[key] = previousNetwork[key]
  }
  if (failedSections.has('network')) {
    for (const key of ['configurations','wifi_interfaces','default_routes']) {
      if (previousNetwork[key] !== undefined) network[key] = previousNetwork[key]
      else delete network[key]
    }
  }
  if (Object.keys(network).length) merged.network = network

  const previousSecurity = previous.security && typeof previous.security === 'object' ? previous.security : {}
  const incomingSecurity = incoming.security && typeof incoming.security === 'object' ? incoming.security : {}
  const security = { ...incomingSecurity }
  for (const key of ['defender','firewall_profiles']) {
    if (retainAllMissingDeep && security[key] === undefined && previousSecurity[key] !== undefined) security[key] = previousSecurity[key]
  }
  if (failedSections.has('security')) {
    for (const key of ['defender','firewall_profiles']) {
      if (previousSecurity[key] !== undefined) security[key] = previousSecurity[key]
      else delete security[key]
    }
  }
  if (Object.keys(security).length) merged.security = security

  const previousBattery = previous.battery && typeof previous.battery === 'object' ? previous.battery : {}
  const incomingBattery = incoming.battery && typeof incoming.battery === 'object' ? incoming.battery : {}
  const battery = { ...incomingBattery }
  const retainedBatteryKeys = [
    'name','manufacturer','chemistry','design_capacity_mwh','full_charge_capacity_mwh',
    'health_percent','wear_percent','cycle_count','voltage_mv','rate_mw',
    'remaining_capacity_mwh','power_online','discharging',
  ]
  for (const key of retainedBatteryKeys) {
    if (retainAllMissingDeep && battery[key] === undefined && previousBattery[key] !== undefined) battery[key] = previousBattery[key]
  }
  if (failedSections.has('battery')) {
    for (const key of retainedBatteryKeys) {
      if (previousBattery[key] !== undefined) battery[key] = previousBattery[key]
      else delete battery[key]
    }
  }
  if (Object.keys(battery).length) merged.battery = battery

  return merged
}

async function ingestInventory(agent, payload) {
  const summary = payload?.summary && typeof payload.summary === 'object' ? payload.summary : {}
  const hardware = payload?.hardware && typeof payload.hardware === 'object' ? payload.hardware : {}
  const os = payload?.os && typeof payload.os === 'object' ? payload.os : {}
  const memory = payload?.memory && typeof payload.memory === 'object' ? payload.memory : {}
  const agentInfo = payload?.agent && typeof payload.agent === 'object' ? payload.agent : {}
  const storage = storageTotals(payload?.storage)
  const collectedAt = clean(payload?.collected_at) || new Date().toISOString()
  const platform = canonicalAgentPlatform(summary.platform || payload?.platform || os.platform || os.name)
  const operatingSystem = clean(summary.operating_system || summary.os_name || os.name || platform)
  const hostname = clean(summary.hostname) || agent.name || (platform + ' device')
  await withTransaction(async (client) => {
    const previousResult = await client.query(
      'SELECT source_payload FROM rmm_device_inventory WHERE id=$1 FOR UPDATE',
      [agent.inventory_id],
    )
    const previousPayload = previousResult.rows[0]?.source_payload && typeof previousResult.rows[0].source_payload === 'object'
      ? previousResult.rows[0].source_payload      : {}
    const effectivePayload = mergeRetainedDeepInventory(previousPayload, payload)

    await client.query(
      `UPDATE rmm_device_inventory SET
         name=$2,
         platform=$3,
         operating_system=$4,
         os_version=$5,
         manufacturer=$6,
         model=$7,
         serial_number=$8,
         memory_bytes=$9,
         storage_total_bytes=$10,
         storage_free_bytes=$11,
         management_state='managed',
         management_agent='Hi5Central Agent',
         source_last_sync_at=$12::timestamptz,
         last_imported_at=now(),
         active=true,
         source_payload=$13::jsonb,
         updated_at=now()
       WHERE id=$1`,
      [agent.inventory_id, hostname, platform, operatingSystem, clean(summary.os_version || os.version), clean(hardware.manufacturer || summary.manufacturer), clean(hardware.model || summary.model), clean(hardware.serial_number || summary.serial_number), boundedInteger(memory.total_bytes ?? summary.total_memory_bytes, 0, Number.MAX_SAFE_INTEGER), storage.total, storage.free, collectedAt, JSON.stringify(effectivePayload)],
    )
    await client.query(
      `UPDATE rmm_agent_devices SET
         agent_version=COALESCE(NULLIF($2,''),agent_version),
         last_inventory_at=$3::timestamptz,
         last_authenticated_at=now(),
         updated_at=now()
       WHERE id=$1`,
      [agent.id, clean(agentInfo.version), collectedAt],
    )

    if (platform === 'Windows') {
      await ingestWindowsUpdateInventory(agent, effectivePayload, client)
    }

    for (const event of inventoryDeltaEvents(previousPayload, effectivePayload)) {
      await recordRmmActivity({
        tenantId: agent.tenant_id,
        agentDeviceId: agent.id,
        inventoryId: agent.inventory_id,
        actorType: 'system',
        actorLabel: 'SYSTEM',
        ...event,
      }, client)
    }
  })
  recalculateTenantVulnerabilityExposures(agent.tenant_id, [agent.inventory_id]).catch((error) => {
    console.error('RMM vulnerability exposure recalculation failed', agent.inventory_id, error.message)
  })
}

async function packageRows(tenantId) {
  const result = await pool.query(
    `SELECT p.id,p.label,p.token_hint,p.expires_at,p.max_uses,
            CASE WHEN p.persistent
              THEN p.use_count + COALESCE(children.child_use_count,0)
              ELSE p.use_count
            END AS use_count,
            COALESCE(
              GREATEST(p.last_used_at,children.child_last_used_at),
              p.last_used_at,
              children.child_last_used_at
            ) AS last_used_at,
            p.revoked_at,p.created_at,p.persistent,p.installer_platform,p.installer_format,
            p.artifact_build_requested_at,p.artifact_build_completed_at,p.artifact_build_error
       FROM rmm_agent_enrollment_packages p
       LEFT JOIN LATERAL (
         SELECT COALESCE(SUM(child.use_count),0)::integer AS child_use_count,
                MAX(child.last_used_at) AS child_last_used_at
           FROM rmm_agent_enrollment_packages child
          WHERE child.parent_deployment_id=p.id
       ) children ON true
      WHERE p.tenant_id=$1
        AND p.parent_deployment_id IS NULL
      ORDER BY p.created_at DESC
      LIMIT 25`,
    [tenantId],
  )
  return result.rows
}
export function registerRmmAgentRoutes(app) {
  app.get('/api/v1/rmm/agent/enrollment-packages', async (c) => {
    const auth = await requireRmmManager(c)
    if (auth.error) return auth.error
    const packages = (await packageRows(auth.session.tenant_id)).map((pkg) => ({
      ...pkg,
      installer_url: pkg.persistent && pkg.installer_format
        ? TENANT_INSTALLER_GENERIC_URLS[pkg.installer_format] || null
        : null,
      deployment_config_url: pkg.persistent
        ? `/api/v1/rmm/agent/enrollment-packages/${pkg.id}/deployment-config`
        : null,
    }))
    return c.json({
      packages,
      downloadUrl: AGENT_DOWNLOAD_URL,
      downloads: {
        windows: { label: 'Windows x64', url: AGENT_DOWNLOAD_URL },
        macos: { label: 'macOS universal', url: AGENT_DOWNLOAD_URL_MACOS, version: '0.3.175' },
        linux: { label: 'Linux x64', url: AGENT_DOWNLOAD_URL_LINUX, version: '0.3.175' },
      },
    })
  })

  app.post('/api/v1/rmm/agent/enrollment-packages', async (c) => {
    const auth = await requireRmmManager(c)
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const persistent = body.persistent !== false
    const ttlMinutes = boundedInteger(body.ttlMinutes ?? 60, 5, 1440) || 60
    const maxUses = boundedInteger(body.maxUses ?? 1, 1, 100) || 1
    const selection = persistent
      ? tenantInstallerSelection(body.installerPlatform || body.platform, body.installerFormat || body.format)
      : null
    if (persistent && !selection) {
      return c.json({ error: 'Select a supported operating system and installer type.' }, 400)
    }
    const token = secret('h5e')
    const label = clean(body.label).slice(0, 120) || (persistent
      ? `${selection.platform === 'macos' ? 'macOS' : selection.platform[0].toUpperCase() + selection.platform.slice(1)} ${selection.format.toUpperCase()} Agent installer`
      : 'One-time Agent enrollment')
    const result = await pool.query(
      `INSERT INTO rmm_agent_enrollment_packages
         (tenant_id,label,token_hash,token_hint,expires_at,max_uses,created_by_user_id,persistent,installer_platform,installer_format)
       VALUES ($1,$2,$3,$4,
               CASE WHEN $8 THEN now()+interval '100 years' ELSE now()+make_interval(mins=>$5) END,
               $6,$7,$8,$9,$10)
       RETURNING id,label,token_hint,expires_at,max_uses,use_count,created_at,persistent,installer_platform,installer_format`,
      [auth.session.tenant_id, label, sha256(token), token.slice(-6), ttlMinutes, maxUses, auth.session.user_id, persistent,
        selection?.platform || null, selection?.format || null],
    )
    const pkg = result.rows[0]
    const deploymentSecret = persistent ? tenantInstallerDeploymentSecret(pkg.id) : ''
    const deploymentConfig = persistent ? {
      schemaVersion: 1,
      apiBase: TENANT_INSTALLER_API_BASE,
      deploymentId: pkg.id,
      deploymentSecret,
      installerPlatform: pkg.installer_platform,
      installerFormat: pkg.installer_format,
    } : null

    const installCommand = persistent
      ? pkg.installer_format === 'msi'
        ? 'msiexec /i "Hi5CentralAgentDeployment-Windows.msi" /qn HI5DEPLOYMENTCONFIG="%CD%\\Hi5CentralDeployment.json"'
        : pkg.installer_format === 'exe'
          ? '.\\Hi5CentralAgentDeployment-Windows.exe --quiet --config ".\\Hi5CentralDeployment.json"'
          : pkg.installer_format === 'run'
            ? 'sudo ./Hi5CentralAgentDeployment-Linux.run --config ./Hi5CentralDeployment.json'
            : pkg.installer_format === 'deb'
              ? 'sudo install -d -m 700 /etc/hi5central && sudo install -m 600 ./Hi5CentralDeployment.json /etc/hi5central/deployment.json && sudo dpkg -i ./hi5central-agent-deployment_amd64.deb'
              : pkg.installer_format === 'rpm'
                ? 'sudo install -d -m 700 /etc/hi5central && sudo install -m 600 ./Hi5CentralDeployment.json /etc/hi5central/deployment.json && sudo rpm -U ./hi5central-agent-deployment_x86_64.rpm'
                : ''
      : `.\\Hi5CentralAgentSetup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ENROLLMENT_TOKEN="${token}" /TENANT_ID="${auth.session.tenant_id}" /PACKAGE_ID="${pkg.id}" /INSTALL_SOURCE="rmm-portal"`

    return c.json({
      package: pkg,
      deploymentId: persistent ? pkg.id : null,
      enrollmentToken: persistent ? null : token,
      deploymentConfig,
      deploymentConfigUrl: persistent
        ? `/api/v1/rmm/agent/enrollment-packages/${pkg.id}/deployment-config`
        : null,
      installer: persistent ? {
        platform: pkg.installer_platform,
        format: pkg.installer_format,
        url: TENANT_INSTALLER_GENERIC_URLS[pkg.installer_format] || null,
      } : null,
      downloadUrl: persistent ? TENANT_INSTALLER_GENERIC_URLS[pkg.installer_format] : AGENT_DOWNLOAD_URL,
      installCommand,
      downloads: {
        windows: { label: 'Windows x64', url: AGENT_DOWNLOAD_URL },
        macos: { label: 'macOS universal', url: AGENT_DOWNLOAD_URL_MACOS, version: '0.3.175' },
        linux: { label: 'Linux x64', url: AGENT_DOWNLOAD_URL_LINUX, version: '0.3.175' },
      },
    }, 201)
  })

  app.get('/api/v1/rmm/agent/enrollment-packages/:packageId/deployment-config', async (c) => {
    const auth = await requireRmmManager(c)
    if (auth.error) return auth.error
    const packageId = clean(c.req.param('packageId'))
    if (!isUuid(packageId)) return c.json({ error: 'A valid deployment ID is required.' }, 400)

    const result = await pool.query(
      `SELECT id,persistent,revoked_at,installer_platform,installer_format
         FROM rmm_agent_enrollment_packages
        WHERE id=$1 AND tenant_id=$2
        LIMIT 1`,
      [packageId, auth.session.tenant_id],
    )
    const pkg = result.rows[0]
    if (!pkg || !pkg.persistent) return c.json({ error: 'Agent installer record not found.' }, 404)
    if (pkg.revoked_at) return c.json({ error: 'This Agent installer has been revoked.' }, 410)

    c.header('Content-Disposition', 'attachment; filename="Hi5CentralDeployment.json"')
    c.header('Cache-Control', 'private, no-store')
    return c.json({
      schemaVersion: 1,
      apiBase: TENANT_INSTALLER_API_BASE,
      deploymentId: pkg.id,
      deploymentSecret: tenantInstallerDeploymentSecret(pkg.id),
      installerPlatform: pkg.installer_platform,
      installerFormat: pkg.installer_format,
    })
  })

  app.get('/api/v1/rmm/agent/enrollment-packages/:packageId/artifacts', async (c) => {
    const auth = await requireRmmManager(c)
    if (auth.error) return auth.error
    const packageId = clean(c.req.param('packageId'))
    if (!isUuid(packageId)) return c.json({ error: 'A valid deployment ID is required.' }, 400)

    const result = await pool.query(
      `SELECT id,persistent,revoked_at,installer_platform,installer_format,artifact_build_requested_at,
              artifact_build_completed_at,artifact_build_error
         FROM rmm_agent_enrollment_packages
        WHERE id=$1 AND tenant_id=$2
        LIMIT 1`,
      [packageId, auth.session.tenant_id],
    )
    const pkg = result.rows[0]
    if (!pkg) return c.json({ error: 'Agent deployment not found.' }, 404)
    if (!pkg.persistent) return c.json({ error: 'Native artifacts are available for persistent deployments only.' }, 409)
    if (pkg.revoked_at) return c.json({ error: 'This Agent deployment has been revoked.' }, 410)

    const artifacts = tenantInstallerArtifactRows(packageId, pkg.installer_format)
    const readyCount = artifacts.filter((artifact) => artifact.ready).length
    return c.json({
      deploymentId: packageId,
      installerPlatform: pkg.installer_platform || null,
      installerFormat: pkg.installer_format || null,
      status: readyCount === artifacts.length ? 'ready' : (readyCount ? 'partial' : 'building'),
      readyCount,
      totalCount: artifacts.length,
      artifacts,
      buildRequestedAt: pkg.artifact_build_requested_at,
      buildCompletedAt: pkg.artifact_build_completed_at,
      buildError: pkg.artifact_build_error || null,
    })
  })

  app.post('/api/v1/rmm/agent/enrollment-packages/:packageId/build-artifacts', async (c) => {
    const auth = await requireRmmManager(c)
    if (auth.error) return auth.error
    return c.json({
      error: 'Per-tenant installer builds are retired. Hi5Central now uses shared release installers with a tenant deployment JSON.',
    }, 410)
  })

  app.get('/api/v1/rmm/agent/enrollment-packages/:packageId/artifacts/:format', async (c) => {
    const auth = await requireRmmManager(c)
    if (auth.error) return auth.error
    const packageId = clean(c.req.param('packageId'))
    const format = clean(c.req.param('format')).toLowerCase()
    const definition = TENANT_INSTALLER_ASSETS[format]
    if (!isUuid(packageId)) return c.json({ error: 'A valid deployment ID is required.' }, 400)
    if (!definition) return c.json({ error: 'Unsupported installer format.' }, 404)

    const result = await pool.query(
      `SELECT id,persistent,revoked_at,installer_platform,installer_format
         FROM rmm_agent_enrollment_packages
        WHERE id=$1 AND tenant_id=$2
        LIMIT 1`,
      [packageId, auth.session.tenant_id],
    )
    const pkg = result.rows[0]
    if (!pkg) return c.json({ error: 'Agent deployment not found.' }, 404)
    if (!pkg.persistent) return c.json({ error: 'Native artifacts are available for persistent deployments only.' }, 409)
    if (pkg.revoked_at) return c.json({ error: 'This Agent deployment has been revoked.' }, 410)
    if (pkg.installer_format && pkg.installer_format !== format) {
      return c.json({ error: 'This installer record is for ' + pkg.installer_format.toUpperCase() + '.' }, 404)
    }

    const artifactPath = tenantInstallerArtifactPath(packageId, format)
    if (!artifactPath || !existsSync(artifactPath)) {
      return c.json({ error: format.toUpperCase() + ' installer is still building.' }, 409)
    }

    let stats
    try {
      stats = statSync(artifactPath)
    } catch {
      return c.json({ error: format.toUpperCase() + ' installer is unavailable.' }, 503)
    }
    if (!stats.isFile() || stats.size <= 0) {
      return c.json({ error: format.toUpperCase() + ' installer is unavailable.' }, 503)
    }

    return new Response(Readable.toWeb(createReadStream(artifactPath)), {
      status: 200,
      headers: {
        'Content-Type': definition.contentType,
        'Content-Length': String(stats.size),
        'Content-Disposition': 'attachment; filename="' + definition.downloadName(packageId) + '"',
        'Cache-Control': 'private, no-store',
      },
    })
  })

  app.get('/api/v1/agent/installer-builds/:packageId/bootstrap', async (c) => {
    const builder = await verifyTenantInstallerBuilder(c)
    if (!builder) return c.json({ error: 'Trusted tenant installer builder authentication failed.' }, 401)

    const packageId = clean(c.req.param('packageId'))
    if (!isUuid(packageId)) return c.json({ error: 'A valid deployment ID is required.' }, 400)
    const result = await pool.query(
      `SELECT id,persistent,revoked_at,installer_platform,installer_format
         FROM rmm_agent_enrollment_packages
        WHERE id=$1
        LIMIT 1`,
      [packageId],
    )
    const pkg = result.rows[0]
    if (!pkg) return c.json({ error: 'Agent deployment not found.' }, 404)
    if (!pkg.persistent) return c.json({ error: 'Agent deployment is not persistent.' }, 409)
    if (pkg.revoked_at) return c.json({ error: 'Agent deployment has been revoked.' }, 410)

    return c.json({
      deploymentId: packageId,
      deploymentSecret: tenantInstallerDeploymentSecret(packageId),
      installerPlatform: pkg.installer_platform || null,
      installerFormat: pkg.installer_format || null,
      apiBase: TENANT_INSTALLER_API_BASE,
    })
  })

  app.put('/api/v1/agent/installer-builds/:packageId/artifacts/:format', async (c) => {
    const builder = await verifyTenantInstallerBuilder(c)
    if (!builder) return c.json({ error: 'Trusted tenant installer builder authentication failed.' }, 401)

    const packageId = clean(c.req.param('packageId'))
    const format = clean(c.req.param('format')).toLowerCase()
    const definition = TENANT_INSTALLER_ASSETS[format]
    if (!isUuid(packageId)) return c.json({ error: 'A valid deployment ID is required.' }, 400)
    if (!definition) return c.json({ error: 'Unsupported installer format.' }, 404)

    const packageResult = await pool.query(
      `SELECT id,persistent,revoked_at,installer_platform,installer_format
         FROM rmm_agent_enrollment_packages
        WHERE id=$1
        LIMIT 1`,
      [packageId],
    )
    const pkg = packageResult.rows[0]
    if (!pkg) return c.json({ error: 'Agent deployment not found.' }, 404)
    if (!pkg.persistent) return c.json({ error: 'Agent deployment is not persistent.' }, 409)
    if (pkg.revoked_at) return c.json({ error: 'Agent deployment has been revoked.' }, 410)
    if (pkg.installer_format && pkg.installer_format !== format) {
      return c.json({ error: 'Unexpected installer format for this build.' }, 409)
    }
    if (pkg.installer_platform && definition.platform !== pkg.installer_platform) {
      return c.json({ error: 'Unexpected installer platform for this build.' }, 409)
    }

    const declaredLength = Number(c.req.header('content-length') || 0)
    if (declaredLength > TENANT_INSTALLER_MAX_ARTIFACT_BYTES) {
      return c.json({ error: 'Installer artifact exceeds the upload size limit.' }, 413)
    }

    const body = c.req.raw.body
    if (!body) return c.json({ error: 'Installer artifact is empty.' }, 400)

    const directory = tenantInstallerDirectory(packageId)
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    const artifactPath = tenantInstallerArtifactPath(packageId, format)
    const tempPath = artifactPath + '.' + randomUUID() + '.tmp'
    const hash = createHash('sha256')
    let sizeBytes = 0

    try {
      const limiter = new Transform({
        transform(chunk, encoding, callback) {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding)
          sizeBytes += bytes.length
          if (sizeBytes > TENANT_INSTALLER_MAX_ARTIFACT_BYTES) {
            callback(new Error('artifact_too_large'))
            return
          }
          hash.update(bytes)
          callback(null, bytes)
        },
      })

      await pipeline(
        Readable.fromWeb(body),
        limiter,
        createWriteStream(tempPath, { flags: 'wx', mode: 0o600 }),
      )
    } catch (error) {
      try { unlinkSync(tempPath) } catch {}
      if (clean(error?.message) === 'artifact_too_large') {
        return c.json({ error: 'Installer artifact exceeds the upload size limit.' }, 413)
      }
      console.error('Tenant installer artifact upload failed', packageId, format, error)
      return c.json({ error: 'Installer artifact upload failed.' }, 500)
    }

    if (!sizeBytes) {
      try { unlinkSync(tempPath) } catch {}
      return c.json({ error: 'Installer artifact is empty.' }, 400)
    }

    const expectedSha256 = clean(c.req.header('x-hi5-sha256')).toLowerCase()
    const actualSha256 = hash.digest('hex')
    if (expectedSha256 && expectedSha256 !== actualSha256) {
      try { unlinkSync(tempPath) } catch {}
      return c.json({ error: 'Installer artifact SHA-256 did not match the upload header.' }, 400)
    }

    renameSync(tempPath, artifactPath)

    const artifacts = tenantInstallerArtifactRows(packageId, pkg.installer_format)
    const readyCount = artifacts.filter((artifact) => artifact.ready).length
    await pool.query(
      `UPDATE rmm_agent_enrollment_packages
          SET artifact_build_completed_at=CASE WHEN $2 THEN now() ELSE artifact_build_completed_at END,
              artifact_build_error=NULL,updated_at=now()
        WHERE id=$1`,
      [packageId, readyCount === artifacts.length],
    )

    return c.json({
      success: true,
      format,
      sha256: actualSha256,
      sizeBytes,
      readyCount,
      totalCount: artifacts.length,
    }, 201)
  })

  app.post('/api/v1/rmm/agent/enrollment-packages/:packageId/revoke', async (c) => {
    const auth = await requireRmmManager(c)
    if (auth.error) return auth.error
    const result = await pool.query(
      `UPDATE rmm_agent_enrollment_packages SET revoked_at=now(),updated_at=now()
        WHERE id=$1 AND tenant_id=$2 AND revoked_at IS NULL
        RETURNING id`,
      [clean(c.req.param('packageId')), auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Enrollment package not found.' }, 404)
    return c.json({ success: true })
  })

  app.get('/api/v1/rmm/agent/devices/:agentDeviceId/upgrade-info', async (c) => {
    const auth = await requireRmmDeviceControl(c)
    if (auth.error) return auth.error
    const agentDeviceId = clean(c.req.param('agentDeviceId'))
    if (!isUuid(agentDeviceId)) return c.json({ error: 'A valid managed Agent ID is required.' }, 400)
    const [deviceResult, releases, jobResult] = await Promise.all([
      pool.query(
        `SELECT a.id,a.inventory_id,a.agent_version,a.websocket_status,a.last_telemetry_at,
                a.patch_capabilities,a.patch_capabilities_at,i.name,i.reference,i.platform,i.operating_system
           FROM rmm_agent_devices a
           JOIN rmm_device_inventory i ON i.id=a.inventory_id
          WHERE a.id=$1 AND a.tenant_id=$2 AND a.disabled_at IS NULL AND i.active=true
          LIMIT 1`,
        [agentDeviceId, auth.session.tenant_id],
      ),
      agentReleaseRows(),
      pool.query(
        `SELECT id,status,error_message,result,created_at,claimed_at,completed_at,updated_at,request_metadata
           FROM rmm_agent_jobs
          WHERE tenant_id=$1 AND agent_device_id=$2
            AND request_metadata->>'source'='agent_upgrade'
          ORDER BY created_at DESC LIMIT 1`,
        [auth.session.tenant_id, agentDeviceId],
      ),
    ])
    const device = deviceResult.rows[0]
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const platform = canonicalAgentPlatform(device.platform || device.operating_system)
    const compatibleReleases = releases.filter((release) => releaseMatchesPlatform(release, platform))
    const capabilities = object(device.patch_capabilities)
    const patchHostVersion = clean(capabilities.patchHostVersion || capabilities.version)
    const online = Boolean(agentSocketForDevice(device.id)?.readyState === 1)
    return c.json({
      device: {
        agentDeviceId: device.id,
        name: device.name,
        reference: device.reference,
        agentVersion: clean(device.agent_version),
        patchHostVersion,
        online,
        websocketStatus: device.websocket_status,
        lastTelemetryAt: device.last_telemetry_at,
        patchCapabilitiesAt: device.patch_capabilities_at,
        platform,
      },
      releases: compatibleReleases.map((release) => ({
        id: release.id,
        channel: release.channel,
        version: release.version,
        patchHostVersion: release.patch_host_version,
        status: release.status,
        releaseNotes: release.release_notes,
        buildCommit: release.build_commit,
        workflowRun: release.workflow_run,
        sha256: release.installer_sha256,
        installed: agentReleaseVersionAtLeast(device.agent_version, release.version)
          && patchHostVersionAtLeast(patchHostVersion, release.patch_host_version),
      })),
      latestUpgrade: jobResult.rows[0] || null,
    })
  })

  app.get('/api/v1/rmm/agent/devices/:agentDeviceId/upgrade-diagnostics', async (c) => {
    const auth = await requireRmmDeviceControl(c)
    if (auth.error) return auth.error
    const agentDeviceId = clean(c.req.param('agentDeviceId'))
    if (!isUuid(agentDeviceId)) return c.json({ error: 'A valid managed Agent ID is required.' }, 400)
    const deviceResult = await pool.query(
      `SELECT a.id,a.agent_version,a.patch_capabilities,i.name FROM rmm_agent_devices a JOIN rmm_device_inventory i ON i.id=a.inventory_id WHERE a.id=$1 AND a.tenant_id=$2 AND a.disabled_at IS NULL LIMIT 1`,
      [agentDeviceId, auth.session.tenant_id],
    )
    const device = deviceResult.rows[0]
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    const socket = agentSocketForDevice(device.id)
    if (!socket || socket.readyState !== 1) return c.json({ error: 'This device is offline.', offline: true }, 409)
    const script = [
      "$ErrorActionPreference = 'SilentlyContinue'",
      "$dir = Join-Path $env:ProgramData 'Hi5Central\\Agent\\Upgrade'",
      "$tasks = @(Get-ScheduledTask -TaskName 'Hi5CentralAgentUpgrade-*' | ForEach-Object { $i=Get-ScheduledTaskInfo -TaskName $_.TaskName; [pscustomobject]@{name=$_.TaskName;state=[string]$_.State;last_run=$i.LastRunTime;next_run=$i.NextRunTime;last_result=$i.LastTaskResult} })",
      "$logs = @(); if (Test-Path $dir) { $logs = @(Get-ChildItem $dir -Filter 'installer-*.log' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 3 | ForEach-Object { $tail=@(Get-Content $_.FullName -Tail 80 -ErrorAction SilentlyContinue); [pscustomobject]@{name=$_.Name;last_write=$_.LastWriteTime;length=$_.Length;tail=($tail -join [Environment]::NewLine)} }) }",
      "$files = @(); if (Test-Path $dir) { $files = @(Get-ChildItem $dir -Filter 'Hi5CentralAgentSetup-*.exe' -File | ForEach-Object { [pscustomobject]@{name=$_.Name;length=$_.Length;sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();last_write=$_.LastWriteTime} }) }",
      "[pscustomobject]@{tasks=$tasks;logs=$logs;installers=$files;service=(Get-Service Hi5CentralAgent | Select-Object Name,Status,StartType)} | ConvertTo-Json -Depth 6 -Compress",
    ].join("\n")
    const correlationId = randomUUID()
    const inserted = await pool.query(
      `INSERT INTO rmm_agent_jobs (tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,correlation_id,request_metadata) VALUES ($1,$2,'custom.command',$3::jsonb,$4,'technician',$5,$6,$7::jsonb) RETURNING id,job_type,status,created_at`,
      [auth.session.tenant_id,device.id,JSON.stringify({command:script,timeout_seconds:60}),auth.session.user_id,clean(auth.session.name || auth.session.email || 'Technician').slice(0,255),correlationId,JSON.stringify({source:'agent_upgrade_diagnostics'})],
    )
    const job = inserted.rows[0]
    const claimed = await pool.query(`UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now() WHERE id=$1 AND tenant_id=$2 AND status='queued' RETURNING status,claimed_at`,[job.id,auth.session.tenant_id])
    if (!claimed.rowCount) return c.json({ error: 'Unable to claim diagnostics job.' }, 409)
    Object.assign(job, claimed.rows[0])
    if (!sendAgentMessage(device.id,{type:'job_execute',job:{id:job.id,job_type:'custom.command',payload:{command:script,timeout_seconds:60},created_at:job.created_at}})) {
      await pool.query(`UPDATE rmm_agent_jobs SET status='cancelled',completed_at=now(),error_message='Device went offline before diagnostics could run.',updated_at=now() WHERE id=$1`,[job.id])
      return c.json({ error: 'Device went offline before diagnostics could run.', offline:true },409)
    }
    return c.json({success:true,job},202)
  })

  app.post('/api/v1/rmm/agent/devices/:agentDeviceId/upgrade', async (c) => {
    const auth = await requireRmmDeviceControl(c)
    if (auth.error) return auth.error
    const agentDeviceId = clean(c.req.param('agentDeviceId'))
    const body = await c.req.json().catch(() => ({}))
    const releaseId = clean(body.releaseId)
    if (!isUuid(agentDeviceId)) return c.json({ error: 'A valid managed Agent ID is required.' }, 400)
    if (!isUuid(releaseId)) return c.json({ error: 'Select a trusted Agent release.' }, 400)

    await syncPortableAgentReleases().catch((error) => {
      console.error('Portable Agent release sync failed before upgrade', error.message)
    })

    const [deviceResult, releaseResult, pendingResult] = await Promise.all([
      pool.query(
        `SELECT a.id,a.inventory_id,a.agent_version,a.patch_capabilities,i.name,i.reference,i.platform,i.operating_system
           FROM rmm_agent_devices a
           JOIN rmm_device_inventory i ON i.id=a.inventory_id
          WHERE a.id=$1 AND a.tenant_id=$2 AND a.disabled_at IS NULL AND i.active=true
          LIMIT 1`,
        [agentDeviceId, auth.session.tenant_id],
      ),
      pool.query(
        `SELECT id,channel,version,patch_host_version,installer_url,installer_sha256,
                build_commit,workflow_run,status,release_notes
           FROM rmm_agent_releases
          WHERE id=$1 AND status IN ('test','active') LIMIT 1`,
        [releaseId],
      ),
      pool.query(
        `SELECT id,status,created_at FROM rmm_agent_jobs
          WHERE tenant_id=$1 AND agent_device_id=$2
            AND request_metadata->>'source'='agent_upgrade'
            AND status IN ('queued','claimed')
          ORDER BY created_at DESC LIMIT 1`,
        [auth.session.tenant_id, agentDeviceId],
      ),
    ])
    const device = deviceResult.rows[0]
    const release = releaseResult.rows[0]
    if (!device) return c.json({ error: 'Managed Agent not found for this device.' }, 404)
    if (!release) return c.json({ error: 'Trusted Agent release not found.' }, 404)
    const platform = canonicalAgentPlatform(device.platform || device.operating_system)
    const portable = Boolean(portableReleaseChannel(platform))
    if (!releaseMatchesPlatform(release, platform)) {
      return c.json({ error: 'This Agent release is not compatible with the endpoint platform.', platform, channel: release.channel }, 409)
    }
    if (pendingResult.rowCount) return c.json({ error: 'An Agent upgrade is already queued or running for this device.', job: pendingResult.rows[0] }, 409)

    let installer
    try { installer = new URL(release.installer_url) } catch { return c.json({ error: 'Trusted release has an invalid installer URL.' }, 409) }
    if (installer.protocol !== 'https:' || installer.hostname.toLowerCase() !== 'downloads.hi5central.com') {
      return c.json({ error: 'Trusted Agent installers must be served from downloads.hi5central.com over HTTPS.' }, 409)
    }
    if (!/^[a-f0-9]{64}$/i.test(clean(release.installer_sha256))) {
      return c.json({ error: 'Trusted release does not contain a valid SHA-256.' }, 409)
    }

    const socket = agentSocketForDevice(device.id)
    if (!socket || socket.readyState !== 1) {
      return c.json({ error: 'This device is offline. No Agent upgrade was queued.', offline: true }, 409)
    }

    const capabilities = object(device.patch_capabilities)
    const currentAgentVersion = clean(device.agent_version)
    const currentPatchHost = clean(capabilities.patchHostVersion || capabilities.version)
    const agentMeetsTarget = agentReleaseVersionAtLeast(currentAgentVersion, release.version)
    const patchHostMeetsTarget = portable ? true : patchHostVersionAtLeast(currentPatchHost, release.patch_host_version)
    if (agentMeetsTarget && patchHostMeetsTarget) {
      return c.json({
        error: portable
          ? 'This device already reports the target Agent version or newer.'
          : 'This device already reports the target Agent and PatchHost versions or newer.',
        currentAgentVersion,
        targetAgentVersion: release.version,
        currentPatchHost,
        targetPatchHost: release.patch_host_version,
      }, 409)
    }

    const correlationId = randomUUID()
    let command
    try {
      command = portable
        ? portableAgentUpgradeScript(release, platform, correlationId)
        : agentUpgradeScript(release)
    } catch (error) {
      return c.json({ error: error?.message || 'Unable to prepare the Agent upgrade.' }, 409)
    }
    const actorLabel = clean(auth.session.name || auth.session.email || 'Technician').slice(0, 255)
    const inserted = await pool.query(
      `INSERT INTO rmm_agent_jobs
        (tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,
         correlation_id,request_metadata)
       VALUES ($1,$2,'custom.command',$3::jsonb,$4,'technician',$5,$6,$7::jsonb)
       RETURNING id,job_type,status,created_at`,
      [
        auth.session.tenant_id,
        device.id,
        JSON.stringify({ command, timeout_seconds: 180, run_as: portable ? 'root' : 'system' }),
        auth.session.user_id,
        actorLabel,
        correlationId,
        JSON.stringify({
          source: 'agent_upgrade',
          release_id: release.id,
          release_version: release.version,
          target_patch_host_version: release.patch_host_version,
          installer_sha256: release.installer_sha256,
          channel: release.channel,
          device_name: device.name,
          device_reference: device.reference,
          platform,
          portable,
        }),
      ],
    )
    const job = inserted.rows[0]
    const claimed = await pool.query(
      `UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now()
        WHERE id=$1 AND tenant_id=$2 AND status='queued'
        RETURNING status,claimed_at,updated_at`,
      [job.id, auth.session.tenant_id],
    )
    if (!claimed.rowCount) return c.json({ error: 'Unable to claim Agent upgrade job.' }, 409)
    Object.assign(job, claimed.rows[0])
    const pushed = sendAgentMessage(device.id, {
      type: 'job_execute',
      job: { id: job.id, job_type: 'custom.command', payload: { command, timeout_seconds: 180, run_as: portable ? 'root' : 'system' }, created_at: job.created_at },
    })
    if (!pushed) {
      await pool.query(
        `UPDATE rmm_agent_jobs
            SET status='cancelled',claimed_at=NULL,completed_at=now(),
                error_message='Device went offline before the Agent upgrade could be dispatched.',updated_at=now()
          WHERE id=$1 AND tenant_id=$2 AND status='claimed'`,
        [job.id, auth.session.tenant_id],
      )
      return c.json({ error: 'The device went offline before the Agent upgrade could start. No job was retained.', offline: true }, 409)
    }

    recordRmmActivity({
      tenantId: auth.session.tenant_id,
      agentDeviceId: device.id,
      inventoryId: device.inventory_id,
      actorUserId: auth.session.user_id,
      actorType: 'technician',
      actorLabel,
      eventType: 'agent.upgrade.requested',
      category: 'device',
      summary: actorLabel + ' requested Hi5Central Agent ' + release.version + ' upgrade',
      detail: portable
        ? platform + ' portable Agent · verified SHA-256 · ' + release.channel
        : 'Target PatchHost ' + (release.patch_host_version || 'not specified') + ' · ' + release.channel,
      outcome: 'info',
      jobId: job.id,
      correlationId,
      metadata: { releaseId: release.id, version: release.version, patchHostVersion: release.patch_host_version, channel: release.channel },
    }).catch(() => {})

    return c.json({
      success: true,
      job,
      release: { id: release.id, version: release.version, patchHostVersion: release.patch_host_version, status: release.status, platform, portable },
    }, 202)
  })

  app.post('/api/v1/agent/deployments/:deploymentId/enrollment-token', async (c) => {
    const deploymentId = clean(c.req.param('deploymentId'))
    if (!isUuid(deploymentId)) {
      return c.json({ success: false, error: 'A valid deployment ID is required.' }, 400)
    }

    const body = await c.req.json().catch(() => ({}))
    const deploymentSecret = clean(body.deploymentSecret || body.deployment_secret)
    if (!deploymentSecret || deploymentSecret.length > 200) {
      return c.json({ success: false, error: 'A valid deployment secret is required.' }, 400)
    }

    const issued = await withTransaction(async (client) => {
      const result = await client.query(
        `SELECT id,tenant_id,persistent,revoked_at
           FROM rmm_agent_enrollment_packages
          WHERE id=$1
          FOR UPDATE`,
        [deploymentId],
      )
      const deployment = result.rows[0]
      if (!deployment || !deployment.persistent) {
        return { error: 'Agent deployment is invalid.', status: 401 }
      }
      if (deployment.revoked_at) {
        return { error: 'Agent deployment has been revoked.', status: 410 }
      }

      const expectedSecret = tenantInstallerDeploymentSecret(deployment.id)
      if (!constantTimeTextEqual(deploymentSecret, expectedSecret)) {
        return { error: 'Agent deployment credentials are invalid.', status: 401 }
      }

      const token = secret('h5e')
      const child = await client.query(
        `INSERT INTO rmm_agent_enrollment_packages
           (tenant_id,label,token_hash,token_hint,expires_at,max_uses,
            created_by_user_id,persistent,parent_deployment_id)
         VALUES ($1,'Tenant installer bootstrap',$2,$3,now()+interval '10 minutes',
                 1,NULL,false,$4)
         RETURNING id,expires_at`,
        [deployment.tenant_id, sha256(token), token.slice(-6), deployment.id],
      )

      return {
        token,
        tenantId: deployment.tenant_id,
        packageId: child.rows[0].id,
        expiresAt: child.rows[0].expires_at,
      }
    })

    if (issued.error) {
      return c.json({ success: false, error: issued.error }, issued.status || 400)
    }

    c.header('Cache-Control', 'no-store')
    const accept = clean(c.req.header('accept')).toLowerCase()
    if (accept.includes('text/plain')) return c.text(issued.token, 201)
    return c.json({
      success: true,
      enrollmentToken: issued.token,
      tenantId: issued.tenantId,
      packageId: issued.packageId,
      expiresAt: issued.expiresAt,
    }, 201)
  })

  app.post('/api/v1/agent/enroll', async (c) => {
    const body = await c.req.json().catch(() => ({}))
    const enrollmentToken = clean(body.enrollmentToken || body.enrollment_token)
    const deploymentId = clean(body.deploymentId || body.deployment_id)
    const deploymentSecret = clean(body.deploymentSecret || body.deployment_secret)
    if (enrollmentToken.length > 200) return c.json({ success: false, error: 'Enrollment token is too long.' }, 400)
    if (deploymentSecret.length > 200) return c.json({ success: false, error: 'Deployment secret is too long.' }, 400)
    if (deploymentId && !isUuid(deploymentId)) return c.json({ success: false, error: 'A valid deployment ID is required.' }, 400)
    if (!enrollmentToken && !deploymentId) {
      return c.json({ success: false, error: 'An enrollment token or persistent deployment ID is required.' }, 400)
    }
    const platform = canonicalAgentPlatform(clean(body.platform).slice(0, 50) || 'windows')
    const hostname = clean(body.hostname).slice(0, 255) || (platform + ' device')
    const architecture = clean(body.architecture).slice(0, 50)
    const agentVersion = clean(body.agentVersion || body.agent_version).slice(0, 80)
    const fingerprint = clean(body.fingerprint || body.device_fingerprint).slice(0, 255)
    const tokenHash = sha256(enrollmentToken)

    const enrolled = await withTransaction(async (client) => {
      const packageResult = await client.query(
        `SELECT p.id,p.tenant_id,p.max_uses,p.use_count,p.expires_at,p.revoked_at,
                p.persistent,p.parent_deployment_id,parent.revoked_at AS parent_revoked_at
           FROM rmm_agent_enrollment_packages p
           LEFT JOIN rmm_agent_enrollment_packages parent ON parent.id=p.parent_deployment_id
          WHERE (p.token_hash=$1 AND NULLIF($2,'') IS NULL)
             OR (p.id=NULLIF($2,'')::uuid AND p.persistent=true)
          FOR UPDATE OF p`,
        [tokenHash, deploymentId],
      )
      const pkg = packageResult.rows[0]
      if (!pkg) return { error: deploymentId ? 'Agent deployment is invalid.' : 'Enrollment token is invalid.', status: 401 }
      if (pkg.revoked_at || pkg.parent_revoked_at) {
        return { error: pkg.persistent || pkg.parent_deployment_id ? 'Agent deployment has been revoked.' : 'Enrollment token has been revoked.', status: 410 }
      }
      if (pkg.persistent) {
        const expectedSecret = tenantInstallerDeploymentSecret(pkg.id)
        if (!deploymentSecret || !constantTimeTextEqual(deploymentSecret, expectedSecret)) {
          return { error: 'Agent deployment credentials are invalid.', status: 401 }
        }
      }
      if (!pkg.persistent && new Date(pkg.expires_at).getTime() <= Date.now()) {
        return { error: 'Enrollment token has expired.', status: 410 }
      }
      if (!pkg.persistent && Number(pkg.use_count) >= Number(pkg.max_uses)) {
        return { error: 'Enrollment token has already been used.', status: 410 }
      }
      const deviceId = randomUUID()
      const deviceKey = secret('h5d')
      const reference = `RMM-${deviceId.slice(0, 8).toUpperCase()}`
      const inventoryResult = await client.query(
        `INSERT INTO rmm_device_inventory
           (tenant_id,source,source_device_id,reference,name,platform,operating_system,
            management_state,management_agent,enrolled_at,source_last_sync_at,active,source_payload)
         VALUES ($1,'hi5central_agent',$2,$3,$4,$5,$6,'managed','Hi5Central Agent',now(),now(),true,$7::jsonb)
         RETURNING id`,
        [pkg.tenant_id, deviceId, reference, hostname, platform, platform, JSON.stringify({ enrollment: { architecture, agentVersion, fingerprint, platform } })],
      )
      await client.query(
        `INSERT INTO rmm_agent_devices
           (id,tenant_id,inventory_id,secret_hash,fingerprint,architecture,agent_version,enrollment_package_id,last_authenticated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())`,
        [deviceId, pkg.tenant_id, inventoryResult.rows[0].id, sha256(deviceKey), fingerprint, architecture, agentVersion, pkg.id],
      )
      await client.query(
        `UPDATE rmm_agent_enrollment_packages
            SET use_count=use_count+1,last_used_at=now(),updated_at=now()
          WHERE id=$1`,
        [pkg.id],
      )
      return { deviceId, deviceKey, tenantId: pkg.tenant_id, packageId: pkg.id, reference }
    })
    if (enrolled.error) return c.json({ success: false, error: enrolled.error }, enrolled.status)
    recordRmmActivity({
      tenantId: enrolled.tenantId,
      agentDeviceId: enrolled.deviceId,
      actorType: 'agent',
      actorLabel: 'SYSTEM',
      eventType: 'device.enrolled',
      category: 'device',
      summary: 'SYSTEM: Hi5Central Agent enrolled ' + hostname,
      detail: 'Device reference ' + enrolled.reference,
      outcome: 'success',
      metadata: { hostname, architecture, agentVersion, reference: enrolled.reference },
    }).catch(() => {})
    return c.json({
      success: true,
      device_id: enrolled.deviceId,
      device_key: enrolled.deviceKey,
      tenant_id: enrolled.tenantId,
      enrollment_package_id: enrolled.packageId,
      reference: enrolled.reference,
    }, 201)
  })

  app.post('/api/v1/agent/devices/telemetry', async (c) => {
    const agent = await authenticateAgent(c.req.header('x-hi5-device-id'), c.req.header('x-hi5-agent-secret'))
    if (!agent) return c.json({ success: false, error: 'Agent authentication failed.' }, 401)
    const body = await c.req.json().catch(() => ({}))
    await pool.query(
      `UPDATE rmm_agent_devices SET
         cpu_percent=$2,memory_used_percent=$3,memory_total_bytes=$4,memory_used_bytes=$5,
         disk_used_percent=$6,uptime_seconds=$7,active_user=$8,service_status=$9,websocket_status=$10,
         last_authenticated_at=now(),last_telemetry_at=now(),updated_at=now()
       WHERE id=$1`,
      [agent.id, boundedNumber(body.cpuPercent, 0, 100), boundedNumber(body.memoryUsedPercent, 0, 100), boundedInteger(body.memoryTotalBytes, 0, Number.MAX_SAFE_INTEGER), boundedInteger(body.memoryUsedBytes, 0, Number.MAX_SAFE_INTEGER), boundedNumber(body.diskUsedPercent, 0, 100), boundedInteger(body.uptimeSeconds, 0, Number.MAX_SAFE_INTEGER), clean(body.activeUser).slice(0, 255), clean(body.serviceStatus).slice(0, 80), clean(body.websocketStatus).slice(0, 80)],
    )
    await pool.query(`UPDATE rmm_device_inventory SET source_last_sync_at=now(),last_imported_at=now(),updated_at=now() WHERE id=$1`, [agent.inventory_id])
    return c.json({ success: true })
  })

  app.post('/api/v1/agent/devices/inventory', async (c) => {
    const agent = await authenticateAgent(c.req.header('x-hi5-device-id'), c.req.header('x-hi5-agent-secret'))
    if (!agent) return c.json({ success: false, error: 'Agent authentication failed.' }, 401)
    const body = await c.req.json().catch(() => ({}))
    if (!body || typeof body !== 'object') return c.json({ success: false, error: 'Inventory payload is required.' }, 400)
    if (clean(body.device_id) && clean(body.device_id) !== String(agent.id)) {      return c.json({ success: false, error: 'Inventory device identity does not match authentication.' }, 409)
    }
    await ingestInventory(agent, body)
    return c.json({ success: true })
  })

  app.get('/api/v1/agent/devices/jobs', async (c) => {
    const agent = await authenticateAgent(c.req.header('x-hi5-device-id'), c.req.header('x-hi5-agent-secret'))
    if (!agent) return c.json({ success: false, error: 'Agent authentication failed.' }, 401)
    const jobs = await withTransaction(async (client) => {
      const staleDiscovery = await client.query(
        `UPDATE rmm_agent_jobs
            SET status='failed',
                error_message='Network discovery scan did not complete before the probe lease expired.',
                completed_at=now(),
                updated_at=now()
          WHERE agent_device_id=$1
            AND status='claimed'
            AND job_type='network.discovery.scan'
            AND claimed_at < now() - interval '30 minutes'
        RETURNING id,tenant_id,request_metadata`,
        [agent.id],
      )
      for (const stale of staleDiscovery.rows) {
        const runId = clean(stale.request_metadata?.network_discovery_run_id)
        if (!runId) continue
        await client.query(
          `UPDATE rmm_network_discovery_runs
              SET status='failed',
                  error_message='Network discovery scan did not complete before the probe lease expired.',
                  completed_at=now(),
                  updated_at=now()
            WHERE id=$1 AND tenant_id=$2 AND status IN ('queued','running')`,
          [runId, stale.tenant_id],
        ).catch(() => null)
      }

      await client.query(
        `UPDATE rmm_agent_jobs
            SET status='queued',claimed_at=NULL,updated_at=now()
          WHERE agent_device_id=$1 AND status='claimed'
            AND job_type<>'network.discovery.scan'
            AND claimed_at < now() - CASE
              WHEN job_type='patch.software.bulk' THEN interval '6 hours'
              WHEN job_type='windows_update.install' THEN interval '3 hours'
              WHEN job_type='windows_update.scan' THEN interval '45 minutes'
              WHEN job_type='patch.software' THEN interval '35 minutes'
              WHEN job_type='custom.command' THEN interval '15 minutes'
              ELSE interval '5 minutes'
            END`,
        [agent.id],
      )
      const result = await client.query(
        `WITH picked AS (
           SELECT id FROM rmm_agent_jobs
            WHERE agent_device_id=$1 AND status='queued'
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT 10
         )
         UPDATE rmm_agent_jobs j
            SET status='claimed',claimed_at=now(),updated_at=now()
           FROM picked
          WHERE j.id=picked.id
          RETURNING j.id,j.job_type,j.payload,j.created_at`,
        [agent.id],
      )
      return result.rows
    })
    await pool.query(`UPDATE rmm_agent_devices SET last_authenticated_at=now(),updated_at=now() WHERE id=$1`, [agent.id])
    return c.json({ success: true, jobs })
  })

  app.post('/api/v1/agent/devices/jobs/:jobId/result', async (c) => {
    const agent = await authenticateAgent(c.req.header('x-hi5-device-id'), c.req.header('x-hi5-agent-secret'))
    if (!agent) return c.json({ success: false, error: 'Agent authentication failed.' }, 401)
    const body = await c.req.json().catch(() => ({}))
    const success = Boolean(body.success)
    const resultPayload = body.result && typeof body.result === 'object' ? body.result : {}
    const errorMessage = clean(body.error).slice(0, 2000) || null

    if (success && clean(resultPayload.status).toLowerCase() === 'scheduled') {
      const staged = await pool.query(
        `UPDATE rmm_agent_jobs
            SET result=$4::jsonb,error_message=NULL,updated_at=now()
          WHERE id=$1 AND agent_device_id=$2 AND tenant_id=$3
            AND status IN ('claimed','queued')
            AND request_metadata->>'source'='agent_upgrade'
          RETURNING id,tenant_id,agent_device_id,queued_by_user_id,initiated_by_label,
                    correlation_id,request_metadata,result`,
        [clean(c.req.param('jobId')), agent.id, agent.tenant_id, JSON.stringify(resultPayload)],
      )
      if (staged.rowCount) {
        const stagedJob = staged.rows[0]
        const actorLabel = clean(stagedJob.initiated_by_label || 'Technician')
        await recordRmmActivity({
          tenantId: stagedJob.tenant_id,
          agentDeviceId: stagedJob.agent_device_id,
          inventoryId: agent.inventory_id,
          actorUserId: stagedJob.queued_by_user_id,
          actorType: 'technician',
          actorLabel,
          eventType: 'agent.upgrade.staged',
          category: 'device',
          summary: actorLabel + ' staged Hi5Central Agent ' + clean(stagedJob.request_metadata?.release_version) + ' upgrade',
          detail: 'Waiting for the Agent service to restart and report the target version.',
          outcome: 'info',
          jobId: stagedJob.id,
          correlationId: stagedJob.correlation_id,
          metadata: { ...object(stagedJob.request_metadata), preparation: resultPayload },
        }).catch(() => {})
        await pool.query(`UPDATE rmm_agent_devices SET last_authenticated_at=now(),updated_at=now() WHERE id=$1`, [agent.id])
        return c.json({ success: true, staged: true })
      }
    }

    const result = await pool.query(
      `UPDATE rmm_agent_jobs
          SET status=$4,result=$5::jsonb,error_message=$6,completed_at=now(),updated_at=now()
        WHERE id=$1 AND agent_device_id=$2 AND tenant_id=$3 AND status IN ('claimed','queued')
        RETURNING id,tenant_id,agent_device_id,job_type,payload,status,result,error_message,
                  queued_by_user_id,initiated_by,initiated_by_label,correlation_id,request_metadata,created_at,claimed_at,completed_at`,
      [clean(c.req.param('jobId')), agent.id, agent.tenant_id, success ? 'completed' : 'failed', JSON.stringify(resultPayload), errorMessage],
    )
    if (!result.rowCount) return c.json({ success: false, error: 'Job not found or already completed.' }, 404)
    const completedJob = { ...result.rows[0], inventory_id: agent.inventory_id }
    await reconcileWindowsUpdateJobResult(completedJob, resultPayload, success).catch((error) => {
      console.error('Windows Update job reconciliation failed', completedJob.id, error.message)
    })
    await reconcileNetworkDiscoveryJobResult(completedJob, resultPayload, success).catch((error) => {
      console.error('Network discovery job reconciliation failed', completedJob.id, error.message)
    })
    await reconcileNetworkDiscoveryEnrichmentJobResult(completedJob, resultPayload, success).catch((error) => {
      console.error('Network discovery enrichment reconciliation failed', completedJob.id, error.message)
    })
    const bulkSucceededCount = Number(resultPayload.succeededCount || 0)
    const bulkFailedCount = Number(resultPayload.failedCount || 0)
    const bulkPartialSuccess = completedJob.job_type === 'patch.software.bulk'
      && !success
      && bulkSucceededCount > 0
      && bulkFailedCount > 0
    if (bulkPartialSuccess) {
      await pool.query(
        `UPDATE rmm_agent_jobs
            SET status='completed',error_message=NULL,updated_at=now()
          WHERE id=$1 AND tenant_id=$2`,
        [completedJob.id, completedJob.tenant_id],
      )
      completedJob.status = 'completed'
      completedJob.error_message = null
    }

    if (
      ['patch.software', 'patch.software.bulk', 'patch.vendor_artifact.inspect'].includes(completedJob.job_type)
      && resultPayload.capabilities
      && typeof resultPayload.capabilities === 'object'
      && !Array.isArray(resultPayload.capabilities)
      && clean(resultPayload.capabilities.patchHostVersion)
    ) {
      await pool.query(
        `UPDATE rmm_agent_devices
            SET patch_capabilities=$2::jsonb,
                patch_capabilities_at=now(),
                last_authenticated_at=now(),
                updated_at=now()
          WHERE id=$1`,
        [agent.id, JSON.stringify(resultPayload.capabilities)],
      )
    }

    if (clean(completedJob.request_metadata?.source) === 'app_portal') {
      await pool.query(
        `UPDATE rmm_app_portal_installations
            SET status=$3,result=$4::jsonb,completed_at=now(),updated_at=now()
          WHERE tenant_id=$1 AND agent_job_id=$2`,
        [agent.tenant_id, completedJob.id, success ? 'succeeded' : 'failed', JSON.stringify({
          ...resultPayload,
          ...(errorMessage ? { error: errorMessage } : {}),
        })],
      ).catch((error) => console.error('App Portal installation reconciliation failed', completedJob.id, error.message))
    }

    if (completedJob.job_type === 'patch.software') {
      const rebootRequired = Boolean(resultPayload.rebootRequired || resultPayload.reboot_required)
      const verificationFailed = Boolean(resultPayload.verificationFailed || resultPayload.verification_failed)
      const installerOutput = clean(resultPayload.installerOutput || resultPayload.installer_output).toLowerCase()
      const providerNoUpgrade = verificationFailed
        && clean(resultPayload.provider).toLowerCase() === 'winget'
        && (
          clean(resultPayload.error).toLowerCase() === 'provider_no_upgrade'
          || installerOutput.includes('no available upgrade found')
          || installerOutput.includes('no newer package versions are available')
        )
      const deploymentStatus = success
        ? (rebootRequired ? 'reboot_required' : 'succeeded')
        : (verificationFailed ? 'verification_failed' : 'failed')
      await withTransaction(async (client) => {
        const deployment = await client.query(
          `UPDATE rmm_patch_deployments
              SET status=$4,result=$5::jsonb,completed_at=now(),updated_at=now()
            WHERE tenant_id=$1 AND agent_job_id=$2 AND inventory_id=$3
            RETURNING catalogue_id`,
          [agent.tenant_id, completedJob.id, agent.inventory_id, deploymentStatus, JSON.stringify(resultPayload)],
        )
        if (!success && deployment.rowCount && deployment.rows[0].catalogue_id) {
          await client.query(
            `UPDATE rmm_vulnerability_exposures
                SET remediation_state='available',last_seen_at=now()
              WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id=$3
                AND status='open' AND remediation_state='in_progress'`,
            [agent.tenant_id, agent.inventory_id, deployment.rows[0].catalogue_id],
          )
        }

        if (providerNoUpgrade) {
          const packageId = clean(resultPayload.packageId || completedJob.payload?.packageId)
          if (packageId) {
            await client.query(
              `UPDATE rmm_software_patch_observations
                  SET patch_status='provider_blocked',
                      evidence=evidence || jsonb_build_object(
                        'providerBlockedReason','winget_no_available_upgrade',
                        'providerBlockedAt',now(),
                        'providerBlockedJobId',$4,
                        'providerBlockedDetail','WinGet reports no available upgrade while exact-package verification still finds an instance below target.'
                      ),
                      updated_at=now()
                WHERE tenant_id=$1 AND inventory_id=$2
                  AND lower(provider_package_id)=lower($3)`,
              [agent.tenant_id, agent.inventory_id, packageId, completedJob.id],
            )
          }
        }
      }).catch((error) => console.error('RMM patch deployment result update failed', completedJob.id, error.message))
    }

    let activityResultPayload = resultPayload
    if (completedJob.job_type === 'patch.software.bulk') {
      const itemResults = Array.isArray(resultPayload.items) ? resultPayload.items : []
      const serverItems = []
      const serverSummary = { succeeded: 0, rebootRequired: 0, remediationRequired: 0, failed: 0 }
      await withTransaction(async (client) => {
        for (const item of itemResults) {
          const catalogueId = clean(item.catalogueId)
          const packageId = clean(item.packageId)
          const itemSuccess = item.success === true
          const verificationFailed = Boolean(item.verificationFailed || item.verification_failed)
          const rebootRequired = Boolean(item.rebootRequired || item.reboot_required)
          const targetVersion = clean(item.targetVersion || item.target_version)
          const verificationVersions = Array.isArray(item?.verification?.installedVersions)
            ? item.verification.installedVersions.map((value) => clean(value)).filter(Boolean)
            : []
          const targetObserved = Boolean(targetVersion)
            && verificationVersions.some((version) => versionCompare(version, targetVersion) >= 0)
          const supersededVersions = targetVersion
            ? verificationVersions.filter((version) => versionCompare(version, targetVersion) < 0)
            : []
          const remediationRequired = !itemSuccess && verificationFailed && targetObserved && supersededVersions.length > 0
          const lateVerified = !itemSuccess && verificationFailed && targetObserved && supersededVersions.length === 0
          const deploymentStatus = remediationRequired
            ? 'remediation_required'
            : lateVerified
              ? 'succeeded'
              : itemSuccess
                ? (rebootRequired ? 'reboot_required' : 'succeeded')
                : (verificationFailed ? 'verification_failed' : 'failed')
          if (deploymentStatus === 'succeeded') serverSummary.succeeded += 1
          else if (deploymentStatus === 'reboot_required') serverSummary.rebootRequired += 1
          else if (deploymentStatus === 'remediation_required') serverSummary.remediationRequired += 1
          else serverSummary.failed += 1
          const serverItem = {
            ...item,
            serverStatus: deploymentStatus,
            patchApplied: itemSuccess || targetObserved,
            targetObserved,
            remediationRequired,
            supersededVersions,
          }
          serverItems.push(serverItem)
          const params = [agent.tenant_id, completedJob.id, agent.inventory_id, deploymentStatus, JSON.stringify(serverItem)]
          let identityClause = ''
          if (catalogueId) {
            params.push(catalogueId)
            identityClause = ' AND catalogue_id=$6::uuid'
          } else if (packageId) {
            params.push(packageId)
            identityClause = ' AND lower(provider_package_id)=lower($6)'
          } else {
            continue
          }
          const deployment = await client.query(
            `UPDATE rmm_patch_deployments
                SET status=$4,result=$5::jsonb,completed_at=now(),updated_at=now()
              WHERE tenant_id=$1 AND agent_job_id=$2 AND inventory_id=$3${identityClause}
              RETURNING catalogue_id`,
            params,
          )
          const affectedCatalogueId = deployment.rows[0]?.catalogue_id
          if (['failed','verification_failed'].includes(deploymentStatus) && affectedCatalogueId) {
            await client.query(
              `UPDATE rmm_vulnerability_exposures
                  SET remediation_state='available',last_seen_at=now()
                WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id=$3
                  AND status='open' AND remediation_state='in_progress'`,
              [agent.tenant_id, agent.inventory_id, affectedCatalogueId],
            )
          }
        }
        activityResultPayload = { ...resultPayload, items: serverItems, serverSummary }
        await client.query(
          `UPDATE rmm_agent_jobs
              SET result=$3::jsonb,
                  status=CASE WHEN ($5::int+$6::int+$7::int)>0 THEN 'completed' ELSE status END,
                  error_message=CASE WHEN ($5::int+$6::int+$7::int)>0 THEN NULL ELSE error_message END,
                  updated_at=now()
            WHERE id=$1 AND tenant_id=$2`,
          [
            completedJob.id,
            completedJob.tenant_id,
            JSON.stringify(activityResultPayload),
            serverSummary.failed,
            serverSummary.succeeded,
            serverSummary.rebootRequired,
            serverSummary.remediationRequired,
          ],
        )
      }).catch((error) => console.error('RMM bulk patch deployment result update failed', completedJob.id, error.message))
      completedJob.result = activityResultPayload
    }

    await recordJobCompletionActivity(completedJob, success || bulkPartialSuccess, activityResultPayload, bulkPartialSuccess ? null : errorMessage).catch((error) => {
      console.error('RMM activity job logging failed', completedJob.id, error.message)
    })
    await pool.query(`UPDATE rmm_agent_devices SET last_authenticated_at=now(),updated_at=now() WHERE id=$1`, [agent.id])
    return c.json({ success: true })
  })
}

const liveAgentSockets = new Map()
const agentMessageSubscribers = new Map()
const agentConnectionSubscribers = new Set()
const brokerAgentPresence = new Map()
const brokerProxySockets = new Map()
let agentBrokerPublisher = null
let agentBrokerSubscriber = null
let agentBrokerHeartbeatTimer = null
let agentBrokerPruneTimer = null
let agentBrokerStarted = false

function notifyAgentConnectionSubscribers(event) {
  for (const handler of [...agentConnectionSubscribers]) {
    try { handler(event) } catch {}
  }
}

function notifyAgentMessageSubscribers(deviceId, payload) {
  const subscribers = agentMessageSubscribers.get(String(deviceId))
  if (!subscribers?.size) return
  for (const handler of [...subscribers]) {
    try { handler(payload) } catch {}
  }
}

function brokerPresenceForDevice(deviceId) {
  const key = String(deviceId)
  const entry = brokerAgentPresence.get(key)
  if (!entry) return null
  if (!entry.seenAt || Date.now() - entry.seenAt > AGENT_BROKER_STALE_MS) {
    brokerAgentPresence.delete(key)
    return null
  }
  return entry
}

function brokerProxyForDevice(deviceId) {
  const key = String(deviceId)
  if (brokerProxySockets.has(key)) return brokerProxySockets.get(key)
  const listenerUnsubscribes = new Map()
  const proxy = {
    hi5BrokerProxy: true,
    deviceId: key,
    get readyState() {
      const presence = brokerPresenceForDevice(key)
      return presence && presence.instanceId !== AGENT_BROKER_INSTANCE_ID ? 1 : 3
    },
    send(data) {
      const presence = brokerPresenceForDevice(key)
      if (!presence || presence.instanceId === AGENT_BROKER_INSTANCE_ID || !agentBrokerPublisher?.isOpen) {
        throw new Error('Remote Agent broker owner is unavailable.')
      }
      const payloadText = typeof data === 'string' ? data : Buffer.isBuffer(data) ? data.toString('utf8') : String(data)
      const envelope = JSON.stringify({
        sourceInstanceId: AGENT_BROKER_INSTANCE_ID,
        deviceId: key,
        payload: payloadText,
        createdAt: Date.now(),
      })
      agentBrokerPublisher.publish(AGENT_BROKER_COMMAND_CHANNEL, envelope)
        .catch((error) => console.error('RMM Agent broker command publish failed', key, error.message))
    },
    on(event, handler) {
      if (event !== 'message' || typeof handler !== 'function' || listenerUnsubscribes.has(handler)) return proxy
      const unsubscribe = subscribeAgentMessages(key, (payload) => {
        try { handler(JSON.stringify(payload)) } catch {}
      })
      listenerUnsubscribes.set(handler, unsubscribe)
      return proxy
    },
    off(event, handler) {
      if (event !== 'message' || typeof handler !== 'function') return proxy
      const unsubscribe = listenerUnsubscribes.get(handler)
      if (unsubscribe) {
        listenerUnsubscribes.delete(handler)
        try { unsubscribe() } catch {}
      }
      return proxy
    },
  }
  brokerProxySockets.set(key, proxy)
  return proxy
}

async function publishAgentBrokerPresence(type, agentOrDeviceId) {
  if (!agentBrokerPublisher?.isOpen) return false
  const deviceId = String(agentOrDeviceId?.id || agentOrDeviceId || '')
  if (!deviceId) return false
  const now = Date.now()
  if (type === 'connected' || type === 'heartbeat') {
    brokerAgentPresence.set(deviceId, { instanceId: AGENT_BROKER_INSTANCE_ID, seenAt: now })
    await agentBrokerPublisher.multi()
      .hSet(AGENT_BROKER_OWNER_HASH, deviceId, AGENT_BROKER_INSTANCE_ID)
      .hSet(AGENT_BROKER_SEEN_HASH, deviceId, String(now))
      .exec()
    await agentBrokerPublisher.publish(AGENT_BROKER_PRESENCE_CHANNEL, JSON.stringify({
      type,
      sourceInstanceId: AGENT_BROKER_INSTANCE_ID,
      deviceId,
      seenAt: now,
    }))
    return true
  }

  if (type === 'disconnected') {
    const owner = await agentBrokerPublisher.hGet(AGENT_BROKER_OWNER_HASH, deviceId)
    if (owner && owner !== AGENT_BROKER_INSTANCE_ID) return false
    brokerAgentPresence.delete(deviceId)
    await agentBrokerPublisher.multi()
      .hDel(AGENT_BROKER_OWNER_HASH, deviceId)
      .hDel(AGENT_BROKER_SEEN_HASH, deviceId)
      .exec()
    await agentBrokerPublisher.publish(AGENT_BROKER_PRESENCE_CHANNEL, JSON.stringify({
      type,
      sourceInstanceId: AGENT_BROKER_INSTANCE_ID,
      deviceId,
      seenAt: now,
    }))
    return true
  }

  return false
}

function shouldBrokerAgentPayload(payload) {
  const type = clean(payload?.type)
  return Boolean(type) && ![
    'inventory_snapshot',
    'inventory_snapshot_compressed',
    'bitlocker_recovery_escrow',
    'hello',
  ].includes(type)
}

function publishAgentBrokerMessage(deviceId, payload) {
  if (!agentBrokerPublisher?.isOpen || !shouldBrokerAgentPayload(payload)) return
  agentBrokerPublisher.publish(AGENT_BROKER_MESSAGE_CHANNEL, JSON.stringify({
    sourceInstanceId: AGENT_BROKER_INSTANCE_ID,
    deviceId: String(deviceId),
    payload,
    createdAt: Date.now(),
  })).catch((error) => console.error('RMM Agent broker message publish failed', deviceId, error.message))
}

export async function initializeAgentBroker() {
  if (agentBrokerStarted) return
  await ensureRedisConnected()
  agentBrokerPublisher = redis.duplicate()
  agentBrokerSubscriber = redis.duplicate()
  agentBrokerPublisher.on('error', (error) => console.error('RMM Agent broker publisher error', error))
  agentBrokerSubscriber.on('error', (error) => console.error('RMM Agent broker subscriber error', error))
  await Promise.all([agentBrokerPublisher.connect(), agentBrokerSubscriber.connect()])

  const [owners, seen] = await Promise.all([
    redis.hGetAll(AGENT_BROKER_OWNER_HASH),
    redis.hGetAll(AGENT_BROKER_SEEN_HASH),
  ])
  const now = Date.now()
  for (const [deviceId, instanceId] of Object.entries(owners || {})) {
    const seenAt = Number(seen?.[deviceId] || 0)
    if (instanceId && seenAt && now - seenAt <= AGENT_BROKER_STALE_MS) {
      brokerAgentPresence.set(String(deviceId), { instanceId: String(instanceId), seenAt })
    }
  }

  await agentBrokerSubscriber.subscribe(AGENT_BROKER_COMMAND_CHANNEL, (message) => {
    let envelope
    try { envelope = JSON.parse(message) } catch { return }
    const deviceId = String(envelope?.deviceId || '')
    if (!deviceId) return
    const presence = brokerPresenceForDevice(deviceId)
    if (!presence || presence.instanceId !== AGENT_BROKER_INSTANCE_ID) return
    const socket = liveAgentSockets.get(deviceId)
    if (!socket || socket.readyState !== 1) return
    try { socket.send(String(envelope.payload || '')) } catch {}
  })

  await agentBrokerSubscriber.subscribe(AGENT_BROKER_MESSAGE_CHANNEL, (message) => {
    let envelope
    try { envelope = JSON.parse(message) } catch { return }
    if (!envelope || envelope.sourceInstanceId === AGENT_BROKER_INSTANCE_ID) return
    const deviceId = String(envelope.deviceId || '')
    if (!deviceId || !envelope.payload || typeof envelope.payload !== 'object') return
    notifyAgentMessageSubscribers(deviceId, envelope.payload)
  })

  await agentBrokerSubscriber.subscribe(AGENT_BROKER_PRESENCE_CHANNEL, (message) => {
    let event
    try { event = JSON.parse(message) } catch { return }
    if (!event || event.sourceInstanceId === AGENT_BROKER_INSTANCE_ID) return
    const deviceId = String(event.deviceId || '')
    if (!deviceId) return
    const prior = brokerPresenceForDevice(deviceId)
    if (event.type === 'connected' || event.type === 'heartbeat') {
      const next = { instanceId: String(event.sourceInstanceId || ''), seenAt: Number(event.seenAt || Date.now()) }
      brokerAgentPresence.set(deviceId, next)
      if (event.type === 'connected' && prior?.instanceId !== next.instanceId) {
        notifyAgentConnectionSubscribers({ type: 'connected', agent: { id: deviceId }, ws: brokerProxyForDevice(deviceId), brokered: true })
      }
      return
    }
    if (event.type === 'disconnected') {
      if (prior?.instanceId && prior.instanceId !== event.sourceInstanceId) return
      brokerAgentPresence.delete(deviceId)
      notifyAgentConnectionSubscribers({ type: 'disconnected', agent: { id: deviceId }, ws: brokerProxyForDevice(deviceId), brokered: true })
    }
  })

  agentBrokerHeartbeatTimer = setInterval(() => {
    for (const [deviceId, socket] of liveAgentSockets) {
      if (socket?.readyState !== 1) continue
      publishAgentBrokerPresence('heartbeat', deviceId).catch((error) => console.error('RMM Agent broker heartbeat failed', deviceId, error.message))
    }
  }, AGENT_BROKER_HEARTBEAT_MS)
  agentBrokerHeartbeatTimer.unref?.()

  agentBrokerPruneTimer = setInterval(() => {
    const cutoff = Date.now() - AGENT_BROKER_STALE_MS
    for (const [deviceId, entry] of brokerAgentPresence) {
      if (entry.seenAt >= cutoff) continue
      brokerAgentPresence.delete(deviceId)
      if (entry.instanceId !== AGENT_BROKER_INSTANCE_ID) {
        notifyAgentConnectionSubscribers({ type: 'disconnected', agent: { id: deviceId }, ws: brokerProxyForDevice(deviceId), brokered: true })
      }
    }
  }, AGENT_BROKER_HEARTBEAT_MS)
  agentBrokerPruneTimer.unref?.()

  agentBrokerStarted = true
  console.log('RMM Agent broker ready', AGENT_BROKER_INSTANCE_ID)
}

export async function shutdownAgentBroker() {
  if (agentBrokerHeartbeatTimer) clearInterval(agentBrokerHeartbeatTimer)
  if (agentBrokerPruneTimer) clearInterval(agentBrokerPruneTimer)
  agentBrokerHeartbeatTimer = null
  agentBrokerPruneTimer = null
  const disconnects = []
  for (const deviceId of liveAgentSockets.keys()) disconnects.push(publishAgentBrokerPresence('disconnected', deviceId))
  await Promise.allSettled(disconnects)
  if (agentBrokerSubscriber?.isOpen) await agentBrokerSubscriber.quit().catch(() => {})
  if (agentBrokerPublisher?.isOpen) await agentBrokerPublisher.quit().catch(() => {})
  agentBrokerSubscriber = null
  agentBrokerPublisher = null
  agentBrokerStarted = false
}

export function agentSocketForDevice(deviceId) {
  const key = String(deviceId)
  const local = liveAgentSockets.get(key)
  if (local?.readyState === 1) return local
  const presence = brokerPresenceForDevice(key)
  if (!presence || presence.instanceId === AGENT_BROKER_INSTANCE_ID) return null
  const proxy = brokerProxyForDevice(key)
  return proxy.readyState === 1 ? proxy : null
}

export function sendAgentMessage(deviceId, payload) {
  const socket = agentSocketForDevice(deviceId)
  if (!socket || socket.readyState !== 1) return false
  try {
    socket.send(typeof payload === 'string' ? payload : JSON.stringify(payload))
    return true
  } catch {
    return false
  }
}

export function subscribeAgentConnections(handler) {
  if (typeof handler !== 'function') return () => {}
  agentConnectionSubscribers.add(handler)
  return () => agentConnectionSubscribers.delete(handler)
}

export function subscribeAgentMessages(deviceId, handler) {
  const key = String(deviceId)
  if (!agentMessageSubscribers.has(key)) agentMessageSubscribers.set(key, new Set())
  const subscribers = agentMessageSubscribers.get(key)
  subscribers.add(handler)
  return () => {
    subscribers.delete(handler)
    if (!subscribers.size) agentMessageSubscribers.delete(key)
  }
}

export function attachRmmAgentWebSocket(server) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_INVENTORY_BYTES })
  server.on('upgrade', async (request, socket, head) => {
    let url
    try { url = new URL(request.url || '/', 'http://localhost') } catch { return }
    if (url.pathname !== '/agent/ws') return

    const deviceId = clean(url.searchParams.get('device_id'))
    const deviceKey = clean(url.searchParams.get('device_key'))
    const agent = await authenticateAgent(deviceId, deviceKey).catch(() => null)
    if (!agent) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.hi5Agent = agent
      wss.emit('connection', ws, request)
    })
  })

  wss.on('connection', async (ws) => {
    const agent = ws.hi5Agent
    liveAgentSockets.set(String(agent.id), ws)
    await publishAgentBrokerPresence('connected', agent).catch((error) => console.error('RMM Agent broker connect publish failed', agent.id, error.message))
    notifyAgentConnectionSubscribers({ type: 'connected', agent, ws })
    await pool.query(
      `UPDATE rmm_agent_devices SET websocket_status='Connected',websocket_connected_at=now(),last_authenticated_at=now(),updated_at=now() WHERE id=$1`,
      [agent.id],
    ).catch(() => {})
    recordRmmActivity({
      tenantId: agent.tenant_id,
      agentDeviceId: agent.id,
      inventoryId: agent.inventory_id,
      actorType: 'agent',
      actorLabel: 'SYSTEM',
      eventType: 'agent.connected',
      category: 'device',
      summary: 'SYSTEM: Hi5Central Agent connected',
      detail: agent.name || agent.reference || '',
      outcome: 'success',
      metadata: { reference: agent.reference || '', deviceName: agent.name || '' },
    }).catch(() => {})
    ws.on('message', (buffer) => {
      const text = Buffer.isBuffer(buffer) ? buffer.toString('utf8') : String(buffer)
      let payload
      try { payload = JSON.parse(text) } catch { return }
      if (!payload || typeof payload !== 'object') return

      if (payload.type === 'inventory_snapshot_compressed') {
        try {
          if (payload.encoding !== 'gzip+base64') throw new Error('unsupported inventory compression encoding')
          const declaredUncompressed = Number(payload.uncompressed_bytes)
          const declaredCompressed = Number(payload.compressed_bytes)
          if (!Number.isInteger(declaredUncompressed) || declaredUncompressed < 1 || declaredUncompressed > MAX_INVENTORY_BYTES) {
            throw new Error('invalid uncompressed inventory size metadata')
          }
          if (!Number.isInteger(declaredCompressed) || declaredCompressed < 1 || declaredCompressed > MAX_INVENTORY_BYTES) {
            throw new Error('invalid compressed inventory size metadata')
          }
          const compressed = Buffer.from(String(payload.payload || ''), 'base64')
          if (!compressed.length || compressed.length !== declaredCompressed) throw new Error('compressed inventory length mismatch')
          const inflated = gunzipSync(compressed, { maxOutputLength: MAX_INVENTORY_BYTES })
          if (inflated.length !== declaredUncompressed || inflated.length > MAX_INVENTORY_BYTES) {
            throw new Error('decompressed inventory length mismatch')
          }
          payload = JSON.parse(inflated.toString('utf8'))
          if (!payload || payload.type !== 'inventory_snapshot') throw new Error('compressed payload is not an inventory snapshot')
        } catch (error) {
          console.error('RMM compressed inventory decode failed', agent.id, error.message)
          return
        }
      }

      publishAgentBrokerMessage(agent.id, payload)

      if (payload.type === 'bitlocker_recovery_escrow') {
        if (clean(payload.device_id) && clean(payload.device_id) !== String(agent.id)) return
        ingestBitLockerRecoveryEscrow(agent, payload).catch((error) => console.error('RMM BitLocker recovery escrow ingest failed', agent.id, error.message))
        return
      }

      const subscribers = agentMessageSubscribers.get(String(agent.id))
      if (subscribers?.size) {
        for (const handler of [...subscribers]) {
          try { handler(payload) } catch {}
        }
      }

      if (payload.type === 'hello') {
        const reportedVersion = clean(payload.agent_version || payload.agentVersion).slice(0, 48)
        if (/^[0-9A-Za-z._-]+$/.test(reportedVersion)) {
          pool.query(
            `UPDATE rmm_agent_devices
                SET agent_version=$2,last_authenticated_at=now(),updated_at=now()
              WHERE id=$1`,
            [agent.id, reportedVersion],
          ).catch(() => {})
          reconcileAgentUpgradeAfterHello(agent, reportedVersion).catch((error) => console.error('Agent upgrade reconnect reconciliation failed', agent.id, error.message))
        }
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'hello_ack' }))
        return
      }
      if (payload.type === 'inventory_snapshot') {
        if (clean(payload.device_id) && clean(payload.device_id) !== String(agent.id)) return
        ingestInventory(agent, payload)
          .then(() => {
            if (versionCompare(agent.agent_version, '0.1.171') < 0) return
            bitLockerRecoveryEscrowNeeded(agent, payload)
              .then((needed) => {
                if (!needed || ws.readyState !== 1) return
                ws.send(JSON.stringify({ type: 'bitlocker_recovery_escrow_request', request_id: randomUUID() }))
              })
              .catch((error) => console.error('RMM BitLocker recovery escrow check failed', agent.id, error.message))
          })
          .catch((error) => console.error('RMM inventory ingest failed', agent.id, error.message))
        return
      }
    })

    ws.on('close', async () => {
      const wasCurrentSocket = liveAgentSockets.get(String(agent.id)) === ws
      if (!wasCurrentSocket) {
        // A replacement Agent socket is already authoritative on this instance.
        return
      }

      liveAgentSockets.delete(String(agent.id))
      const clusterWasCurrentOwner = await publishAgentBrokerPresence('disconnected', agent)
        .catch((error) => {
          console.error('RMM Agent broker disconnect publish failed', agent.id, error.message)
          return true
        })
      notifyAgentConnectionSubscribers({ type: 'disconnected', agent, ws })

      // Another API instance may already own a replacement socket. Never let a
      // superseded instance mark the shared device offline or cancel work.
      if (!clusterWasCurrentOwner) return

      pool.query(
        `UPDATE rmm_agent_devices SET websocket_status='Disconnected',websocket_disconnected_at=now(),updated_at=now() WHERE id=$1`,
        [agent.id],
      ).catch(() => {})
      pool.query(
        `UPDATE rmm_agent_jobs
            SET status='cancelled',completed_at=now(),updated_at=now(),
                error_message=COALESCE(error_message,'Device went offline before the job started. The job was not retained for reconnect.')
          WHERE agent_device_id=$1 AND tenant_id=$2 AND status='queued'
          RETURNING id,job_type,initiated_by_label,queued_by_user_id,correlation_id`,
        [agent.id, agent.tenant_id],
      ).then((cancelled) => Promise.all(cancelled.rows.map((job) => recordRmmActivity({
        tenantId: agent.tenant_id,
        agentDeviceId: agent.id,
        inventoryId: agent.inventory_id,
        actorUserId: job.queued_by_user_id,
        actorType: 'system',
        actorLabel: 'SYSTEM',
        eventType: 'job.cancelled_offline',
        category: 'job',
        summary: 'SYSTEM: cancelled queued ' + job.job_type + ' because the device went offline',
        detail: job.initiated_by_label ? 'Originally requested by ' + job.initiated_by_label + '.' : 'The job had not started.',
        outcome: 'cancelled',
        severity: 'warning',
        jobId: job.id,
        correlationId: job.correlation_id,
        metadata: { reason: 'device_offline_before_start', requestedBy: job.initiated_by_label || '' },
      })))).catch(() => {})
      recordRmmActivity({
        tenantId: agent.tenant_id,
        agentDeviceId: agent.id,
        inventoryId: agent.inventory_id,
        actorType: 'agent',
        actorLabel: 'SYSTEM',
        eventType: 'agent.disconnected',
        category: 'device',
        summary: 'SYSTEM: Hi5Central Agent disconnected',
        detail: agent.name || agent.reference || '',
        outcome: 'info',
        severity: 'warning',
        metadata: { reference: agent.reference || '', deviceName: agent.name || '' },
      }).catch(() => {})
    })
  })

  return wss
}