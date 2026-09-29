import { createHash } from 'node:crypto'
import { withTransaction } from './db.js'

function sha256(value = '') {
  return createHash('sha256').update(String(value)).digest('hex')
}

const DISK_ANALYSE = String.raw`$ErrorActionPreference = 'SilentlyContinue'
function Get-PathBytes([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return 0 }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  if ($item -and -not $item.PSIsContainer) { return [int64]$item.Length }
  $sum = (Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum).Sum
  if ($null -eq $sum) { return 0 }
  return [int64]$sum
}
function Add-Path([System.Collections.Generic.List[object]]$List,[string]$Name,[string]$Path) {
  $bytes = Get-PathBytes $Path
  $List.Add([pscustomobject]@{ Name=$Name; Path=$Path; Bytes=$bytes; GiB=[math]::Round($bytes/1GB,2) })
}
$drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$items = [System.Collections.Generic.List[object]]::new()
Add-Path $items 'Windows Temp' 'C:\Windows\Temp'
Add-Path $items 'Windows Update Downloads' 'C:\Windows\SoftwareDistribution\Download'
Add-Path $items 'Windows Error Reports' 'C:\ProgramData\Microsoft\Windows\WER'
Add-Path $items 'Windows Minidumps' 'C:\Windows\Minidump'
Add-Path $items 'Windows Memory Dump' 'C:\Windows\MEMORY.DMP'
Add-Path $items 'Delivery Optimization Cache' 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache'
Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
  $profile = $_.FullName
  Add-Path $items ($_.Name + ' Temp') (Join-Path $profile 'AppData\Local\Temp')
  Add-Path $items ($_.Name + ' Chrome Cache') (Join-Path $profile 'AppData\Local\Google\Chrome\User Data\Default\Cache')
  Add-Path $items ($_.Name + ' Edge Cache') (Join-Path $profile 'AppData\Local\Microsoft\Edge\User Data\Default\Cache')
  $firefoxProfiles = Join-Path $profile 'AppData\Local\Mozilla\Firefox\Profiles'
  Get-ChildItem $firefoxProfiles -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Add-Path $items ($_.Name + ' Firefox Cache') (Join-Path $_.FullName 'cache2')
  }
}
$result = [pscustomobject]@{
  ComputerName=$env:COMPUTERNAME
  Drive='C:'
  TotalGiB=[math]::Round([int64]$drive.Size/1GB,2)
  FreeGiB=[math]::Round([int64]$drive.FreeSpace/1GB,2)
  FreePercent=[math]::Round(([double]$drive.FreeSpace/[double]$drive.Size)*100,2)
  CleanupCandidatesGiB=[math]::Round((($items | Measure-Object Bytes -Sum).Sum)/1GB,2)
  Candidates=$items | Sort-Object Bytes -Descending
}
$result | ConvertTo-Json -Depth 5 -Compress
`

const SAFE_DISK_CLEANUP = String.raw`$ErrorActionPreference = 'SilentlyContinue'
$before = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$beforeFree = [int64]$before.FreeSpace
$results = [System.Collections.Generic.List[object]]::new()
function Clean-Stale([string]$Name,[string]$Path,[int]$Days) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $cutoff = (Get-Date).AddDays(-$Days)
  $beforeBytes = (Get-ChildItem $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
    Measure-Object Length -Sum).Sum
  if ($null -eq $beforeBytes) { $beforeBytes = 0 }
  Get-ChildItem $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -lt $cutoff |
    Remove-Item -Force -ErrorAction SilentlyContinue
  $afterBytes = (Get-ChildItem $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
    Measure-Object Length -Sum).Sum
  if ($null -eq $afterBytes) { $afterBytes = 0 }
  $results.Add([pscustomobject]@{
    Name=$Name
    FreedGiB=[math]::Round(([math]::Max(0,[int64]$beforeBytes-[int64]$afterBytes))/1GB,3)
  })
}
Clean-Stale 'Windows Temp' 'C:\Windows\Temp' 2
Clean-Stale 'System Temp' 'C:\Windows\System32\config\systemprofile\AppData\Local\Temp' 2
Clean-Stale 'Windows Error Reports' 'C:\ProgramData\Microsoft\Windows\WER' 2
Clean-Stale 'Windows Update Downloads' 'C:\Windows\SoftwareDistribution\Download' 7
Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
  Clean-Stale ($_.Name + ' Temp') (Join-Path $_.FullName 'AppData\Local\Temp') 2
}
if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
  Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue
}
$after = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$afterFree = [int64]$after.FreeSpace
[pscustomobject]@{
  ComputerName=$env:COMPUTERNAME
  BeforeFreeGiB=[math]::Round($beforeFree/1GB,2)
  AfterFreeGiB=[math]::Round($afterFree/1GB,2)
  ReclaimedGiB=[math]::Round(($afterFree-$beforeFree)/1GB,2)
  FreePercent=[math]::Round(([double]$afterFree/[double]$after.Size)*100,2)
  Categories=$results | Where-Object FreedGiB -gt 0 | Sort-Object FreedGiB -Descending
} | ConvertTo-Json -Depth 4 -Compress
`

const BROWSER_CACHE_CLEANUP = String.raw`$ErrorActionPreference = 'SilentlyContinue'
$before = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$beforeFree = [int64]$before.FreeSpace
$cutoff = (Get-Date).AddDays(-2)
$results = [System.Collections.Generic.List[object]]::new()
function Clean-Cache([string]$Name,[string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $beforeBytes = (Get-ChildItem $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
    Measure-Object Length -Sum).Sum
  if ($null -eq $beforeBytes) { $beforeBytes = 0 }
  Get-ChildItem $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -lt $cutoff |
    Remove-Item -Force -ErrorAction SilentlyContinue
  $afterBytes = (Get-ChildItem $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
    Measure-Object Length -Sum).Sum
  if ($null -eq $afterBytes) { $afterBytes = 0 }
  $freed = [math]::Max(0,[int64]$beforeBytes-[int64]$afterBytes)
  if ($freed -gt 0) { $results.Add([pscustomobject]@{Name=$Name;FreedGiB=[math]::Round($freed/1GB,3)}) }
}
Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
  $user = $_.Name
  $local = Join-Path $_.FullName 'AppData\Local'
  foreach ($browser in @(
    @{Name='Chrome';Root=(Join-Path $local 'Google\Chrome\User Data')},
    @{Name='Edge';Root=(Join-Path $local 'Microsoft\Edge\User Data')}
  )) {
    Get-ChildItem $browser.Root -Directory -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } |
      ForEach-Object {
        Clean-Cache ($user+' '+$browser.Name+' '+$_.Name) (Join-Path $_.FullName 'Cache')
        Clean-Cache ($user+' '+$browser.Name+' Code '+$_.Name) (Join-Path $_.FullName 'Code Cache')
      }
  }
  $ff = Join-Path $local 'Mozilla\Firefox\Profiles'
  Get-ChildItem $ff -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Clean-Cache ($user+' Firefox '+$_.Name) (Join-Path $_.FullName 'cache2')
  }
}
$after = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$afterFree = [int64]$after.FreeSpace
[pscustomobject]@{
  ComputerName=$env:COMPUTERNAME
  BeforeFreeGiB=[math]::Round($beforeFree/1GB,2)
  AfterFreeGiB=[math]::Round($afterFree/1GB,2)
  ReclaimedGiB=[math]::Round(($afterFree-$beforeFree)/1GB,2)
  FreePercent=[math]::Round(([double]$afterFree/[double]$after.Size)*100,2)
  Categories=$results | Sort-Object FreedGiB -Descending
} | ConvertTo-Json -Depth 4 -Compress
`

const COMPONENT_CLEANUP = String.raw`$ErrorActionPreference = 'Stop'
$before = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$beforeFree = [int64]$before.FreeSpace
$analysis = & dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1
$cleanup = & dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart 2>&1
$exitCode = $LASTEXITCODE
$after = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$afterFree = [int64]$after.FreeSpace
[pscustomobject]@{
  ComputerName=$env:COMPUTERNAME
  ExitCode=$exitCode
  BeforeFreeGiB=[math]::Round($beforeFree/1GB,2)
  AfterFreeGiB=[math]::Round($afterFree/1GB,2)
  ReclaimedGiB=[math]::Round(($afterFree-$beforeFree)/1GB,2)
  Analysis=($analysis -join "\n")
  Cleanup=($cleanup -join "\n")
} | ConvertTo-Json -Depth 4 -Compress
if ($exitCode -ne 0) { exit $exitCode }
`
export const BUILTIN_AUTOMATIONS = [
  {
    key: 'disk-space-analyse',
    name: 'Disk Space - Analyse',
    description: 'Read-only disk pressure analysis for known Windows temporary, cache and crash-report locations. Deletes nothing.',
    category: 'Maintenance',
    timeoutSeconds: 600,
    scriptText: DISK_ANALYSE,
  },
  {
    key: 'disk-cleanup-safe',
    name: 'Disk Cleanup - Safe',
    description: 'Removes stale Windows/user temporary files, Windows error/update caches and Delivery Optimization cache. Does not touch Documents, Downloads, Recycle Bin or installed applications.',
    category: 'Maintenance',
    timeoutSeconds: 900,
    scriptText: SAFE_DISK_CLEANUP,
  },
  {
    key: 'browser-cache-cleanup-safe',
    name: 'Browser Cache Cleanup - Safe',
    description: 'Removes browser cache files older than two days from Chrome, Edge and Firefox profiles without deleting history, cookies, passwords or bookmarks.',
    category: 'Maintenance',
    timeoutSeconds: 900,
    scriptText: BROWSER_CACHE_CLEANUP,
  },
  {
    key: 'windows-component-cleanup',
    name: 'Windows Component Cleanup',
    description: 'Runs DISM StartComponentCleanup without ResetBase. Removes superseded component-store payload while preserving update uninstall capability.',
    category: 'Maintenance',
    timeoutSeconds: 3600,
    scriptText: COMPONENT_CLEANUP,
  },
]

export async function ensureBuiltinAutomations(tenantId) {
  if (!tenantId) return { created: 0, updated: 0, existing: 0 }
  return withTransaction(async (client) => {
    let created = 0
    let updated = 0
    let existing = 0
    for (const item of BUILTIN_AUTOMATIONS) {
      const desiredHash = sha256(item.scriptText)
      const found = await client.query(
        `SELECT a.id,a.published_version_id,pv.version_number,pv.content_sha256,pv.release_notes,
                EXISTS(
                  SELECT 1 FROM rmm_automation_versions d
                   WHERE d.automation_id=a.id AND d.state='draft'
                ) AS has_draft
           FROM rmm_automations a
           LEFT JOIN rmm_automation_versions pv ON pv.id=a.published_version_id
          WHERE a.tenant_id=$1 AND lower(a.name)=lower($2) AND a.status<>'archived'
          LIMIT 1`,
        [tenantId, item.name],
      )
      if (found.rowCount) {
        const current = found.rows[0]
        const systemManaged = String(current.release_notes || '').startsWith('Built-in Hi5Central maintenance automation.')
        if (systemManaged && !current.has_draft && current.content_sha256 !== desiredHash) {
          const nextVersion = Number(current.version_number || 0) + 1
          await client.query(
            `UPDATE rmm_automation_versions SET state='superseded'
              WHERE automation_id=$1 AND state='published'`,
            [current.id],
          )
          const version = await client.query(
            `INSERT INTO rmm_automation_versions
              (tenant_id,automation_id,version_number,state,script_text,content_sha256,timeout_seconds,run_as,release_notes,published_at)
             VALUES ($1,$2,$3,'published',$4,$5,$6,'system',$7,now())
             RETURNING id`,
            [tenantId,current.id,nextVersion,item.scriptText,desiredHash,item.timeoutSeconds,
             'Built-in Hi5Central maintenance automation. Updated published version.'],
          )
          await client.query(
            `UPDATE rmm_automations
                SET description=$2,category=$3,status='published',published_version_id=$4,updated_at=now()
              WHERE id=$1`,
            [current.id,item.description,item.category,version.rows[0].id],
          )
          updated += 1
        } else {
          existing += 1
        }
        continue
      }
      const automation = await client.query(
        `INSERT INTO rmm_automations
          (tenant_id,name,description,category,platform,language,status)
         VALUES ($1,$2,$3,$4,'windows','powershell','draft')
         RETURNING id`,
        [tenantId, item.name, item.description, item.category],
      )
      const automationId = automation.rows[0].id
      const version = await client.query(
        `INSERT INTO rmm_automation_versions
          (tenant_id,automation_id,version_number,state,script_text,content_sha256,timeout_seconds,run_as,release_notes,published_at)
         VALUES ($1,$2,1,'published',$3,$4,$5,'system',$6,now())
         RETURNING id`,
        [tenantId,automationId,item.scriptText,desiredHash,item.timeoutSeconds,
         'Built-in Hi5Central maintenance automation. Initial published version.'],
      )
      await client.query(
        `UPDATE rmm_automations
            SET status='published',published_version_id=$2,updated_at=now()
          WHERE id=$1`,
        [automationId, version.rows[0].id],
      )
      created += 1
    }
    return { created, updated, existing }
  })
}
