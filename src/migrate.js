import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { pool } from './db.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const migrationsDir = path.resolve(here, '../migrations')
const lockId = 48554321

async function migrationFiles(directory = migrationsDir) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []

  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name)
    if (entry.isDirectory()) {
      files.push(...await migrationFiles(fullPath))
      continue
    }
    if (!entry.isFile() || !entry.name.endsWith('.sql')) continue
    files.push({
      version: entry.name,
      path: fullPath,
      relativePath: path.relative(migrationsDir, fullPath),
    })
  }

  return files
}

async function migrate() {
  const client = await pool.connect()

  try {
    await client.query('SELECT pg_advisory_lock($1)', [lockId])
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version text PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `)

    const appliedResult = await client.query('SELECT version FROM schema_migrations')
    const applied = new Set(appliedResult.rows.map((row) => row.version))

    const files = await migrationFiles()
    const seenVersions = new Map()
    for (const file of files) {
      if (seenVersions.has(file.version)) {
        throw new Error(
          `Duplicate migration filename ${file.version}: ${seenVersions.get(file.version)} and ${file.relativePath}. ` +
          'Migration filenames are global identities even when organised into domain folders.',
        )
      }
      seenVersions.set(file.version, file.relativePath)
    }

    files.sort((left, right) => left.version.localeCompare(right.version))

    for (const file of files) {
      if (applied.has(file.version)) continue

      const sql = await readFile(file.path, 'utf8')
      console.log(`Applying migration ${file.version} [${file.relativePath}]`)

      await client.query('BEGIN')
      try {
        await client.query(sql)
        // Preserve the historical basename identity so reorganising a migration
        // between domain folders never causes an already-applied migration to rerun.
        await client.query('INSERT INTO schema_migrations(version) VALUES ($1)', [file.version])
        await client.query('COMMIT')
      } catch (error) {
        await client.query('ROLLBACK')
        throw error
      }
    }

    console.log('Database migrations are current')
  } finally {
    try {
      await client.query('SELECT pg_advisory_unlock($1)', [lockId])
    } catch {
      // Connection teardown will release the lock if PostgreSQL has already closed it.
    }
    client.release()
    await pool.end()
  }
}

migrate().catch((error) => {
  console.error('Migration failed', error)
  process.exitCode = 1
})
