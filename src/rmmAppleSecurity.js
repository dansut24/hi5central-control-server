import { pool, withTransaction } from './db.js'

const APPLE_SECURITY_RELEASES_URL = 'https://support.apple.com/en-us/100100'

function clean(value = '') { return String(value ?? '').trim() }

function macReleaseLinks(html = '', limit = 48) {
  const releases = []
  const seen = new Set()
  const pattern = /<a[^>]+href="(https:\/\/support\.apple\.com\/en-us\/\d+)"[^>]*>(macOS\s+[^<]*?(\d+(?:\.\d+)*))<\/a>/gi
  for (const match of html.matchAll(pattern)) {
    const url = clean(match[1])
    const name = clean(match[2]).replace(/\s+/g, ' ')
    const version = clean(match[3])
    if (!url || !version || seen.has(url)) continue
    seen.add(url)
    releases.push({ url, name, version, major: Number(version.split('.')[0] || 0) })
    if (releases.length >= limit) break
  }
  return releases
}

function appleCves(html = '') {
  return [...new Set((html.match(/CVE-\d{4}-\d{4,}/gi) || []).map((value) => value.toUpperCase()))]
}

function appleReleaseDate(html = '') {
  const match = html.match(/Released\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})/i)
  if (!match) return ''
  const parsed = new Date(match[1] + ' UTC')
  return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString()
}

async function fetchAppleHtml(url) {
  const response = await fetch(url, {
    headers: {
      Accept: 'text/html',
      'User-Agent': 'Hi5Central-Vulnerability-Intel/1.0',
    },
    signal: AbortSignal.timeout(45_000),
  })
  if (!response.ok) throw new Error('Apple security HTTP ' + response.status + ' from ' + url)
  return response.text()
}

export async function syncAppleSecurityReleases({ limit = 48 } = {}) {
  const source = 'apple_security'
  await pool.query(
    `INSERT INTO rmm_vulnerability_sync_state (source,enabled,last_attempt_at,updated_at)
     VALUES ($1,true,now(),now())
     ON CONFLICT (source) DO UPDATE SET last_attempt_at=now(),updated_at=now()`,
    [source],
  )

  try {
    const indexHtml = await fetchAppleHtml(APPLE_SECURITY_RELEASES_URL)
    const releases = macReleaseLinks(indexHtml, Math.max(1, Math.min(100, Number(limit) || 48)))
    let pages = 0
    let records = 0
    let products = 0
    let newestVersion = ''

    for (const release of releases) {
      if (!release.major) continue
      const detailHtml = await fetchAppleHtml(release.url)
      const cveIds = appleCves(detailHtml)
      const releasedAt = appleReleaseDate(detailHtml)
      pages += 1
      if (!newestVersion) newestVersion = release.version
      if (!cveIds.length) continue

      await withTransaction(async (client) => {
        for (const cveId of cveIds) {
          await client.query(
            `INSERT INTO rmm_vulnerabilities
              (cve_id,source,published_at,modified_at,summary,references_json,source_payload,updated_at)
             VALUES ($1,'apple_security',NULLIF($2,'')::timestamptz,NULLIF($2,'')::timestamptz,$3,$4::jsonb,$5::jsonb,now())
             ON CONFLICT (cve_id) DO UPDATE SET
               source=CASE WHEN rmm_vulnerabilities.source IN ('cisa_kev','nvd','msrc') THEN rmm_vulnerabilities.source ELSE 'apple_security' END,
               published_at=COALESCE(rmm_vulnerabilities.published_at,EXCLUDED.published_at),
               modified_at=GREATEST(rmm_vulnerabilities.modified_at,EXCLUDED.modified_at),
               summary=CASE WHEN rmm_vulnerabilities.summary='' THEN EXCLUDED.summary ELSE rmm_vulnerabilities.summary END,
               references_json=CASE WHEN rmm_vulnerabilities.references_json='[]'::jsonb THEN EXCLUDED.references_json ELSE rmm_vulnerabilities.references_json END,
               source_payload=rmm_vulnerabilities.source_payload || EXCLUDED.source_payload,
               updated_at=now()`,
            [
              cveId,
              releasedAt,
              'Apple security update ' + release.name,
              JSON.stringify([{ type: 'ADVISORY', url: release.url }]),
              JSON.stringify({
                appleSecurity: {
                  release: release.name,
                  version: release.version,
                  major: release.major,
                  url: release.url,
                  releasedAt,
                },
              }),
            ],
          )

          await client.query(
            `DELETE FROM rmm_vulnerability_products
              WHERE cve_id=$1 AND source='apple_security'
                AND lower(vendor)='apple' AND lower(product)='macos'
                AND version_constraints->>'fixedVersion'=$2`,
            [cveId, release.version],
          )
          await client.query(
            `INSERT INTO rmm_vulnerability_products
              (cve_id,source,vendor,product,cpe,ecosystem,package_name,version_constraints,fixed_versions,confidence,updated_at)
             VALUES ($1,'apple_security','apple','macos','','macOS','macos',$2::jsonb,$3::jsonb,'vendor',now())`,
            [
              cveId,
              JSON.stringify({
                affectedMajor: release.major,
                versionStartIncluding: String(release.major) + '.0',
                versionEndExcluding: release.version,
                fixedVersion: release.version,
                advisoryUrl: release.url,
              }),
              JSON.stringify([release.version]),
            ],
          )
          records += 1
          products += 1
        }
      })
    }

    await pool.query(
      `UPDATE rmm_vulnerability_sync_state
          SET cursor_value=$2,last_success_at=now(),last_error='',records_seen=$3,
              metadata=$4::jsonb,updated_at=now()
        WHERE source=$1`,
      [
        source,
        newestVersion,
        records,
        JSON.stringify({
          provider: 'Apple Security Releases',
          indexUrl: APPLE_SECURITY_RELEASES_URL,
          pages,
          releases: releases.length,
          products,
        }),
      ],
    )

    return { ok: true, source, releases: releases.length, pages, records, products, newestVersion }
  } catch (error) {
    await pool.query(
      `UPDATE rmm_vulnerability_sync_state SET last_error=$2,updated_at=now() WHERE source=$1`,
      [source, clean(error?.message || error).slice(0, 2000)],
    ).catch(() => {})
    throw error
  }
}
