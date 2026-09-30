CREATE TABLE IF NOT EXISTS knowledge_articles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  reference text NOT NULL,
  slug text NOT NULL,
  title text NOT NULL,
  summary text NOT NULL DEFAULT '',
  body_text text NOT NULL DEFAULT '',
  category text NOT NULL DEFAULT 'General',
  tags jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft','Published','Archived')),
  visibility text NOT NULL DEFAULT 'internal' CHECK (visibility IN ('internal','portal','both')),
  owner_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  review_at timestamptz,
  published_at timestamptz,
  archived_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, reference),
  UNIQUE (tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS knowledge_articles_tenant_status_idx
  ON knowledge_articles(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS knowledge_articles_portal_idx
  ON knowledge_articles(tenant_id, visibility, published_at DESC)
  WHERE status = 'Published';

CREATE TABLE IF NOT EXISTS knowledge_article_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  article_id uuid NOT NULL REFERENCES knowledge_articles(id) ON DELETE CASCADE,
  version integer NOT NULL,
  title text NOT NULL,
  summary text NOT NULL DEFAULT '',
  body_text text NOT NULL DEFAULT '',
  category text NOT NULL DEFAULT 'General',
  tags jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL,
  visibility text NOT NULL,
  changed_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  change_note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (article_id, version)
);

CREATE INDEX IF NOT EXISTS knowledge_article_versions_article_idx
  ON knowledge_article_versions(article_id, version DESC);

CREATE TABLE IF NOT EXISTS knowledge_article_feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  article_id uuid NOT NULL REFERENCES knowledge_articles(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  helpful boolean NOT NULL,
  comment text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS knowledge_article_feedback_article_idx
  ON knowledge_article_feedback(article_id, created_at DESC);

CREATE TABLE IF NOT EXISTS knowledge_record_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  article_id uuid NOT NULL REFERENCES knowledge_articles(id) ON DELETE CASCADE,
  record_type text NOT NULL,
  record_reference text NOT NULL,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, article_id, record_reference)
);

CREATE INDEX IF NOT EXISTS knowledge_record_links_record_idx
  ON knowledge_record_links(tenant_id, record_reference, created_at DESC);
