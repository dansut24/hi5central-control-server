import { pool, withTransaction } from './db.js'
import { originMatchesPortalTenant, originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'

function text(value, max = 10000) {
  return String(value ?? '').trim().slice(0, max)
}

function array(value) {
  return Array.isArray(value) ? value.map((item) => text(item, 80)).filter(Boolean).slice(0, 30) : []
}

function slugify(value = '') {
  return text(value, 160).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120) || 'article'
}

function workspaceOrigin(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

function portalOrigin(c, session) {
  return originMatchesPortalTenant(c.req.header('origin'), c.req.header('referer'), session.slug)
}

async function requireWorkspace(c, write = false) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!workspaceOrigin(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (session.tenant_role === 'requester') return { error: c.json({ error: 'Technician workspace access is required.' }, 403) }
  if (write && !['owner', 'admin', 'analyst'].includes(session.tenant_role)) {
    return { error: c.json({ error: 'Knowledge editor access is required.' }, 403) }
  }
  return { session }
}

async function requirePortal(c) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!portalOrigin(c, session)) return { error: c.json({ error: 'Portal session mismatch.' }, 403) }
  if (session.tenant_role !== 'requester') return { error: c.json({ error: 'Requester Portal access is required.' }, 403) }
  return { session }
}

function articleJson(row) {
  return {
    id: row.id,
    reference: row.reference,
    slug: row.slug,
    title: row.title,
    summary: row.summary,
    bodyText: row.body_text,
    category: row.category,
    tags: Array.isArray(row.tags) ? row.tags : [],
    status: row.status,
    visibility: row.visibility,
    ownerUserId: row.owner_user_id,
    version: row.version,
    reviewAt: row.review_at,
    publishedAt: row.published_at,
    archivedAt: row.archived_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    helpfulCount: Number(row.helpful_count || 0),
    notHelpfulCount: Number(row.not_helpful_count || 0),
    links: Array.isArray(row.links) ? row.links : [],
  }
}

const ARTICLE_SELECT = `
  SELECT a.*,
    (SELECT count(*) FROM knowledge_article_feedback f WHERE f.article_id = a.id AND f.helpful = true) AS helpful_count,
    (SELECT count(*) FROM knowledge_article_feedback f WHERE f.article_id = a.id AND f.helpful = false) AS not_helpful_count,
    COALESCE((SELECT jsonb_agg(jsonb_build_object('id', l.id, 'recordType', l.record_type, 'recordReference', l.record_reference) ORDER BY l.created_at)
      FROM knowledge_record_links l WHERE l.article_id = a.id), '[]'::jsonb) AS links
  FROM knowledge_articles a`

async function uniqueSlug(client, tenantId, requested, articleId = null) {
  const base = slugify(requested)
  let candidate = base
  for (let i = 1; i <= 50; i += 1) {
    const existing = await client.query(
      'SELECT 1 FROM knowledge_articles WHERE tenant_id = $1 AND slug = $2 AND ($3::uuid IS NULL OR id <> $3) LIMIT 1',
      [tenantId, candidate, articleId],
    )
    if (!existing.rowCount) return candidate
    candidate = `${base}-${i + 1}`.slice(0, 140)
  }
  return `${base}-${Date.now().toString(36)}`.slice(0, 140)
}

async function nextReference(client, tenantId) {
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`knowledge:${tenantId}`])
  const result = await client.query(
    `SELECT COALESCE(MAX(NULLIF(regexp_replace(reference, '\\D', '', 'g'), '')::integer), 0) + 1 AS next
     FROM knowledge_articles WHERE tenant_id = $1`,
    [tenantId],
  )
  return `KB-${String(Number(result.rows[0]?.next || 1)).padStart(5, '0')}`
}

async function snapshotVersion(client, articleId, userId, note = '') {
  await client.query(
    `INSERT INTO knowledge_article_versions (
       tenant_id, article_id, version, title, summary, body_text, category, tags,
       status, visibility, changed_by_user_id, change_note
     )
     SELECT tenant_id, id, version, title, summary, body_text, category, tags,
            status, visibility, $2, $3
     FROM knowledge_articles WHERE id = $1
     ON CONFLICT (article_id, version) DO NOTHING`,
    [articleId, userId, text(note, 500)],
  )
}

export function registerKnowledgeRoutes(app) {
  app.get('/api/v1/knowledge', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const q = text(c.req.query('q'), 200).toLowerCase()
    const status = text(c.req.query('status'), 30)
    const category = text(c.req.query('category'), 120)
    const values = [auth.session.tenant_id]
    const where = ['a.tenant_id = $1']
    if (status && ['Draft', 'Published', 'Archived'].includes(status)) {
      values.push(status); where.push(`a.status = $${values.length}`)
    }
    if (category) { values.push(category); where.push(`a.category = $${values.length}`) }
    if (q) {
      values.push(`%${q}%`)
      where.push(`(lower(a.title) LIKE $${values.length} OR lower(a.summary) LIKE $${values.length} OR lower(a.body_text) LIKE $${values.length} OR lower(a.category) LIKE $${values.length})`)
    }
    const result = await pool.query(`${ARTICLE_SELECT} WHERE ${where.join(' AND ')} ORDER BY CASE a.status WHEN 'Published' THEN 0 WHEN 'Draft' THEN 1 ELSE 2 END, a.updated_at DESC LIMIT 500`, values)
    return c.json({ items: result.rows.map(articleJson) })
  })

  app.get('/api/v1/knowledge/:key', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const key = text(c.req.param('key'), 160)
    const result = await pool.query(`${ARTICLE_SELECT} WHERE a.tenant_id = $1 AND (a.reference = $2 OR a.slug = $2) LIMIT 1`, [auth.session.tenant_id, key])
    if (!result.rowCount) return c.json({ error: 'Knowledge article not found.' }, 404)
    return c.json(articleJson(result.rows[0]))
  })

  app.post('/api/v1/knowledge', async (c) => {
    const auth = await requireWorkspace(c, true)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const title = text(body?.title, 240)
    if (title.length < 3) return c.json({ error: 'Article title must be at least 3 characters.' }, 400)
    const created = await withTransaction(async (client) => {
      const reference = await nextReference(client, auth.session.tenant_id)
      const slug = await uniqueSlug(client, auth.session.tenant_id, body?.slug || title)
      const visibility = ['internal', 'portal', 'both'].includes(body?.visibility) ? body.visibility : 'internal'
      const status = body?.status === 'Published' ? 'Published' : 'Draft'
      const result = await client.query(
        `INSERT INTO knowledge_articles (
           tenant_id, reference, slug, title, summary, body_text, category, tags,
           status, visibility, owner_user_id, created_by_user_id, published_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$11,CASE WHEN $9='Published' THEN now() ELSE NULL END)
         RETURNING id`,
        [auth.session.tenant_id, reference, slug, title, text(body?.summary, 1000), text(body?.bodyText, 100000), text(body?.category || 'General', 120), JSON.stringify(array(body?.tags)), status, visibility, auth.session.user_id],
      )
      await snapshotVersion(client, result.rows[0].id, auth.session.user_id, 'Article created')
      return result.rows[0].id
    })
    const result = await pool.query(`${ARTICLE_SELECT} WHERE a.id = $1`, [created])
    return c.json(articleJson(result.rows[0]), 201)
  })

  app.patch('/api/v1/knowledge/:key', async (c) => {
    const auth = await requireWorkspace(c, true)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const key = text(c.req.param('key'), 160)
    const updatedId = await withTransaction(async (client) => {
      const current = await client.query('SELECT * FROM knowledge_articles WHERE tenant_id = $1 AND (reference = $2 OR slug = $2) FOR UPDATE', [auth.session.tenant_id, key])
      if (!current.rowCount) return null
      const row = current.rows[0]
      const title = body?.title === undefined ? row.title : text(body.title, 240)
      if (title.length < 3) throw Object.assign(new Error('Article title must be at least 3 characters.'), { status: 400 })
      const slug = body?.slug === undefined ? row.slug : await uniqueSlug(client, auth.session.tenant_id, body.slug || title, row.id)
      const status = ['Draft', 'Published', 'Archived'].includes(body?.status) ? body.status : row.status
      const visibility = ['internal', 'portal', 'both'].includes(body?.visibility) ? body.visibility : row.visibility
      await client.query(
        `UPDATE knowledge_articles SET
           slug=$2, title=$3, summary=$4, body_text=$5, category=$6, tags=$7::jsonb,
           status=$8, visibility=$9, version=version+1,
           review_at=$10,
           published_at=CASE WHEN $8='Published' THEN COALESCE(published_at, now()) ELSE published_at END,
           archived_at=CASE WHEN $8='Archived' THEN COALESCE(archived_at, now()) ELSE NULL END,
           updated_at=now()
         WHERE id=$1`,
        [row.id, slug, title, body?.summary === undefined ? row.summary : text(body.summary, 1000), body?.bodyText === undefined ? row.body_text : text(body.bodyText, 100000), body?.category === undefined ? row.category : text(body.category || 'General', 120), JSON.stringify(body?.tags === undefined ? row.tags : array(body.tags)), status, visibility, body?.reviewAt || row.review_at],
      )
      await snapshotVersion(client, row.id, auth.session.user_id, body?.changeNote || 'Article updated')
      return row.id
    }).catch((error) => {
      if (error?.status === 400) return { error }
      throw error
    })
    if (updatedId?.error) return c.json({ error: updatedId.error.message }, 400)
    if (!updatedId) return c.json({ error: 'Knowledge article not found.' }, 404)
    const result = await pool.query(`${ARTICLE_SELECT} WHERE a.id = $1`, [updatedId])
    return c.json(articleJson(result.rows[0]))
  })

  app.get('/api/v1/knowledge/:key/versions', async (c) => {
    const auth = await requireWorkspace(c)
    if (auth.error) return auth.error
    const key = text(c.req.param('key'), 160)
    const result = await pool.query(
      `SELECT v.* FROM knowledge_article_versions v
       JOIN knowledge_articles a ON a.id = v.article_id
       WHERE a.tenant_id = $1 AND (a.reference = $2 OR a.slug = $2)
       ORDER BY v.version DESC`,
      [auth.session.tenant_id, key],
    )
    return c.json({ items: result.rows.map((row) => ({ version: row.version, title: row.title, summary: row.summary, bodyText: row.body_text, category: row.category, tags: row.tags, status: row.status, visibility: row.visibility, changeNote: row.change_note, createdAt: row.created_at })) })
  })

  app.post('/api/v1/knowledge/:key/links', async (c) => {
    const auth = await requireWorkspace(c, true)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    const recordReference = text(body?.recordReference, 120).toUpperCase()
    const recordType = text(body?.recordType, 80)
    if (!recordReference || !recordType) return c.json({ error: 'Record type and reference are required.' }, 400)
    const key = text(c.req.param('key'), 160)
    const article = await pool.query('SELECT id FROM knowledge_articles WHERE tenant_id=$1 AND (reference=$2 OR slug=$2)', [auth.session.tenant_id, key])
    if (!article.rowCount) return c.json({ error: 'Knowledge article not found.' }, 404)
    await pool.query(
      `INSERT INTO knowledge_record_links (tenant_id, article_id, record_type, record_reference, created_by_user_id)
       VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id, article_id, record_reference) DO NOTHING`,
      [auth.session.tenant_id, article.rows[0].id, recordType, recordReference, auth.session.user_id],
    )
    return c.json({ linked: true, recordType, recordReference })
  })

  app.get('/api/v1/portal/knowledge', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const q = text(c.req.query('q'), 200).toLowerCase()
    const values = [auth.session.tenant_id]
    let search = ''
    if (q) { values.push(`%${q}%`); search = ` AND (lower(a.title) LIKE $2 OR lower(a.summary) LIKE $2 OR lower(a.body_text) LIKE $2 OR lower(a.category) LIKE $2)` }
    const result = await pool.query(`${ARTICLE_SELECT} WHERE a.tenant_id=$1 AND a.status='Published' AND a.visibility IN ('portal','both')${search} ORDER BY a.published_at DESC NULLS LAST, a.title LIMIT 250`, values)
    return c.json({ items: result.rows.map(articleJson) })
  })

  app.get('/api/v1/portal/knowledge/:key', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    const key = text(c.req.param('key'), 160)
    const result = await pool.query(`${ARTICLE_SELECT} WHERE a.tenant_id=$1 AND (a.reference=$2 OR a.slug=$2) AND a.status='Published' AND a.visibility IN ('portal','both') LIMIT 1`, [auth.session.tenant_id, key])
    if (!result.rowCount) return c.json({ error: 'Knowledge article not found.' }, 404)
    return c.json(articleJson(result.rows[0]))
  })

  app.post('/api/v1/portal/knowledge/:key/feedback', async (c) => {
    const auth = await requirePortal(c)
    if (auth.error) return auth.error
    let body
    try { body = await c.req.json() } catch { return c.json({ error: 'A valid JSON request body is required.' }, 400) }
    if (typeof body?.helpful !== 'boolean') return c.json({ error: 'Choose whether this article was helpful.' }, 400)
    const key = text(c.req.param('key'), 160)
    const article = await pool.query(`SELECT id FROM knowledge_articles WHERE tenant_id=$1 AND (reference=$2 OR slug=$2) AND status='Published' AND visibility IN ('portal','both')`, [auth.session.tenant_id, key])
    if (!article.rowCount) return c.json({ error: 'Knowledge article not found.' }, 404)
    await pool.query(
      `INSERT INTO knowledge_article_feedback (tenant_id, article_id, user_id, helpful, comment)
       VALUES ($1,$2,$3,$4,$5)`,
      [auth.session.tenant_id, article.rows[0].id, auth.session.user_id, body.helpful, text(body?.comment, 1000)],
    )
    return c.json({ saved: true }, 201)
  })
}
