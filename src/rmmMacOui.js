import { randomUUID } from 'node:crypto'
import { pool, withTransaction } from './db.js'

const SOURCES = [
  ['MA-L', 'https://standards-oui.ieee.org/oui/oui.csv'],
  ['MA-M', 'https://standards-oui.ieee.org/oui28/mam.csv'],
  ['MA-S', 'https://standards-oui.ieee.org/oui36/oui36.csv'],
]

let vendorByAssignment = new Map()
let schedulerStarted = false

function clean(value = '', max = 1024) {
  return String(value ?? '').trim().slice(0, max)
}

function normalizeAssignment(value = '') {
  return clean(value, 32).replace(/[^0-9a-f]/gi, '').toUpperCase()
}

function normalizeMac(value = '') {
  return clean(value, 64).replace(/[^0-9a-f]/gi, '').toUpperCase()
}

function parseCsvLine(line) {
  const values = []
  let current = ''
  let quoted = false
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index]
    if (char === '"') {
      if (quoted && line[index + 1] === '"') {
        current += '"'
        index += 1
      } else {
        quoted = !quoted
      }
      continue
    }
    if (char === ',' && !quoted) {
      values.push(current)
      current = ''
      continue
    }
    current += char
  }
  values.push(current)
  return values
}

function parseRegistryCsv(text, expectedRegistry) {
  const rows = []
  const lines = String(text || '').split(/\r?\n/)
  for (let index = 1; index < lines.length; index += 1) {
    const line = lines[index]
    if (!line) continue
    const fields = parseCsvLine(line)
    const registry = clean(fields[0], 16)
    const assignment = normalizeAssignment(fields[1])
    const organizationName = clean(fields[2], 512)
    if (!assignment || !organizationName) continue
    if (expectedRegistry && registry && registry !== expectedRegistry) continue
    if (![6, 7, 9].includes(assignment.length)) continue
    rows.push({ registry: registry || expectedRegistry, assignment, organizationName })
  }
  return rows
}

async function fetchText(url) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 30_000)
  timer.unref?.()
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'user-agent': 'Hi5Central-RMM/1.0',
        accept: 'text/csv,*/*;q=0.8',
      },
    })
    if (!response.ok) throw new Error('IEEE OUI fetch failed with HTTP ' + response.status)
    const text = await response.text()
    if (!text || text.length > 25 * 1024 * 1024) {
      throw new Error('IEEE OUI response was empty or unexpectedly large.')
    }
    return text
  } finally {
    clearTimeout(timer)
  }
}

async function refreshCache() {
  const result = await pool.query(
    `SELECT assignment,organization_name
       FROM rmm_mac_oui_registry`,
  )
  vendorByAssignment = new Map(
    result.rows.map((row) => [normalizeAssignment(row.assignment), clean(row.organization_name, 512)]),
  )
  return vendorByAssignment.size
}

async function writeBatch(client, rows, syncId) {
  if (!rows.length) return
  const assignments = rows.map((row) => row.assignment)
  const registries = rows.map((row) => row.registry)
  const organizations = rows.map((row) => row.organizationName)
  await client.query(
    `INSERT INTO rmm_mac_oui_registry
      (assignment,registry,organization_name,last_seen_sync,updated_at)
     SELECT assignment,registry,organization_name,$4::uuid,now()
       FROM unnest($1::text[],$2::text[],$3::text[])
         AS source(assignment,registry,organization_name)
     ON CONFLICT (assignment)
     DO UPDATE SET
       registry=EXCLUDED.registry,
       organization_name=EXCLUDED.organization_name,
       last_seen_sync=EXCLUDED.last_seen_sync,
       updated_at=now()`,
    [assignments, registries, organizations, syncId],
  )
}

export function lookupMacVendor(macAddress = '') {
  const mac = normalizeMac(macAddress)
  if (mac.length < 6) return ''
  for (const length of [9, 7, 6]) {
    if (mac.length < length) continue
    const vendor = vendorByAssignment.get(mac.slice(0, length))
    if (vendor) return vendor
  }
  return ''
}

export async function syncMacOuiRegistry({ force = false } = {}) {
  if (!force) {
    const state = await pool.query(
      `SELECT status,last_completed_at
         FROM rmm_mac_oui_sync_state
        WHERE singleton=true`,
    )
    const lastCompleted = state.rows[0]?.last_completed_at
    if (lastCompleted && Date.now() - new Date(lastCompleted).getTime() < 23 * 60 * 60 * 1000) {
      await refreshCache()
      return { skipped: true, rows: vendorByAssignment.size }
    }
  }

  await pool.query(
    `UPDATE rmm_mac_oui_sync_state
        SET status='running',last_started_at=now(),last_error='',updated_at=now()
      WHERE singleton=true`,
  )

  const syncId = randomUUID()
  try {
    const allRows = []
    for (const [registry, url] of SOURCES) {
      const text = await fetchText(url)
      allRows.push(...parseRegistryCsv(text, registry))
    }

    const deduped = new Map()
    for (const row of allRows) deduped.set(row.assignment, row)
    const rows = [...deduped.values()]

    await withTransaction(async (client) => {
      for (let index = 0; index < rows.length; index += 2000) {
        await writeBatch(client, rows.slice(index, index + 2000), syncId)
      }
      await client.query(
        `DELETE FROM rmm_mac_oui_registry
          WHERE last_seen_sync<>$1::uuid`,
        [syncId],
      )
      await client.query(
        `UPDATE rmm_mac_oui_sync_state
            SET status='ok',last_completed_at=now(),last_error='',row_count=$1,updated_at=now()
          WHERE singleton=true`,
        [rows.length],
      )
    })

    await refreshCache()
    return { skipped: false, rows: vendorByAssignment.size }
  } catch (error) {
    await pool.query(
      `UPDATE rmm_mac_oui_sync_state
          SET status='failed',last_error=$1,updated_at=now()
        WHERE singleton=true`,
      [clean(error?.message || error, 2000)],
    ).catch(() => null)
    throw error
  }
}

export async function startRmmMacOuiScheduler() {
  if (schedulerStarted) return
  schedulerStarted = true

  await refreshCache().catch((error) => {
    console.error('RMM MAC OUI cache load failed', error?.message || error)
  })

  const run = () => syncMacOuiRegistry()
    .then((result) => {
      if (!result.skipped) console.log('RMM MAC OUI registry synced', result.rows)
    })
    .catch((error) => console.error('RMM MAC OUI sync failed', error?.message || error))

  setTimeout(run, 45_000).unref?.()
  setInterval(run, 24 * 60 * 60 * 1000).unref?.()
}
