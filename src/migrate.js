import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { pool } from './db.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const migrationsDir = path.resolve(here, '../migrations')
const lockId = 48554321

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
    const files = (await readdir(migrationsDir))
      .filter((file) => file.endsWith('.sql'))
      .sort()

    for (const file of files) {
      if (applied.has(file)) continue

      const sql = await readFile(path.join(migrationsDir, file), 'utf8')
      console.log(`Applying migration ${file}`)

      await client.query('BEGIN')
      try {
        await client.query(sql)
        await client.query('INSERT INTO schema_migrations(version) VALUES ($1)', [file])
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
