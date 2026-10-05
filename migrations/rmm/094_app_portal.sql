CREATE TABLE IF NOT EXISTS rmm_app_portal_apps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  catalogue_id uuid REFERENCES rmm_software_catalogue(id) ON DELETE SET NULL,
  source_type text NOT NULL CHECK (source_type IN ('catalogue','custom')),
  name text NOT NULL,
  publisher text NOT NULL DEFAULT '',
  description text NOT NULL DEFAULT '',
  category text NOT NULL DEFAULT 'Company software',
  icon_url text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','archived')),
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS rmm_app_portal_apps_tenant_name_idx
  ON rmm_app_portal_apps(tenant_id, lower(name))
  WHERE status <> 'archived';
CREATE INDEX IF NOT EXISTS rmm_app_portal_apps_catalogue_idx
  ON rmm_app_portal_apps(tenant_id, catalogue_id)
  WHERE catalogue_id IS NOT NULL AND status <> 'archived';

CREATE TABLE IF NOT EXISTS rmm_app_portal_revisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  app_id uuid NOT NULL REFERENCES rmm_app_portal_apps(id) ON DELETE CASCADE,
  revision integer NOT NULL CHECK (revision > 0),
  version text NOT NULL DEFAULT '',
  source_kind text NOT NULL CHECK (source_kind IN ('catalogue','direct_url','upload')),
  source_config jsonb NOT NULL DEFAULT '{}'::jsonb,
  sha256 text NOT NULL DEFAULT '',
  expected_signer text NOT NULL DEFAULT '',
  installer_type text NOT NULL DEFAULT '' CHECK (installer_type IN ('','msi','exe')),
  execution jsonb NOT NULL DEFAULT '{}'::jsonb,
  verification jsonb NOT NULL DEFAULT '{}'::jsonb,
  validation jsonb NOT NULL DEFAULT '{}'::jsonb,
  publish_state text NOT NULL DEFAULT 'draft'
    CHECK (publish_state IN ('draft','validated','published','retired')),
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  UNIQUE (app_id, revision)
);

CREATE INDEX IF NOT EXISTS rmm_app_portal_revisions_app_idx
  ON rmm_app_portal_revisions(tenant_id, app_id, revision DESC);

ALTER TABLE rmm_app_portal_apps
  ADD COLUMN IF NOT EXISTS current_revision_id uuid REFERENCES rmm_app_portal_revisions(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS rmm_app_portal_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  app_id uuid NOT NULL REFERENCES rmm_app_portal_apps(id) ON DELETE CASCADE,
  scope_type text NOT NULL CHECK (scope_type IN ('Estate','Site','Group','User','Device')),
  scope_id text NOT NULL,
  scope_name text NOT NULL DEFAULT '',
  intent text NOT NULL DEFAULT 'available'
    CHECK (intent IN ('available','required','uninstall','hidden','approval_required')),
  priority integer NOT NULL DEFAULT 0,
  enabled boolean NOT NULL DEFAULT true,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, app_id, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS rmm_app_portal_assignments_scope_idx
  ON rmm_app_portal_assignments(tenant_id, scope_type, scope_id, priority DESC)
  WHERE enabled=true;

CREATE TABLE IF NOT EXISTS rmm_app_portal_end_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  sid text NOT NULL DEFAULT '',
  username text NOT NULL DEFAULT '',
  upn text NOT NULL DEFAULT '',
  display_name text NOT NULL DEFAULT '',
  session_id text NOT NULL DEFAULT '',
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  source_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS rmm_app_portal_end_users_device_sid_idx
  ON rmm_app_portal_end_users(tenant_id, agent_device_id, sid)
  WHERE sid <> '';
CREATE INDEX IF NOT EXISTS rmm_app_portal_end_users_upn_idx
  ON rmm_app_portal_end_users(tenant_id, lower(upn), last_seen_at DESC)
  WHERE upn <> '';

CREATE TABLE IF NOT EXISTS rmm_app_portal_installations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  app_id uuid NOT NULL REFERENCES rmm_app_portal_apps(id) ON DELETE CASCADE,
  revision_id uuid NOT NULL REFERENCES rmm_app_portal_revisions(id) ON DELETE RESTRICT,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  agent_job_id uuid REFERENCES rmm_agent_jobs(id) ON DELETE SET NULL,
  requested_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  requested_by_sid text NOT NULL DEFAULT '',
  requested_by_upn text NOT NULL DEFAULT '',
  request_source text NOT NULL DEFAULT 'self_service'
    CHECK (request_source IN ('self_service','admin','required_assignment','approval')),
  status text NOT NULL DEFAULT 'requested'
    CHECK (status IN ('requested','queued','running','succeeded','failed','cancelled')),
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rmm_app_portal_installations_device_idx
  ON rmm_app_portal_installations(tenant_id, agent_device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_app_portal_installations_job_idx
  ON rmm_app_portal_installations(agent_job_id)
  WHERE agent_job_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS rmm_app_portal_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  app_id uuid NOT NULL REFERENCES rmm_app_portal_apps(id) ON DELETE CASCADE,
  revision_id uuid REFERENCES rmm_app_portal_revisions(id) ON DELETE SET NULL,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  requested_by_sid text NOT NULL DEFAULT '',
  requested_by_upn text NOT NULL DEFAULT '',
  reason text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','rejected','fulfilled','cancelled')),
  decided_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  decision_note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_app_portal_requests_pending_idx
  ON rmm_app_portal_requests(tenant_id, status, created_at DESC);
CREATE TABLE IF NOT EXISTS rmm_app_portal_package_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  revision_id uuid NOT NULL REFERENCES rmm_app_portal_revisions(id) ON DELETE CASCADE,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_app_portal_package_tokens_expiry_idx
  ON rmm_app_portal_package_tokens(expires_at)
  WHERE used_at IS NULL;
