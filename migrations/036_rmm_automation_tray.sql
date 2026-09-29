CREATE TABLE IF NOT EXISTS rmm_automations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  category text NOT NULL DEFAULT 'General',
  platform text NOT NULL DEFAULT 'windows' CHECK (platform IN ('windows')),
  language text NOT NULL DEFAULT 'powershell' CHECK (language IN ('powershell','cmd')),
  status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','archived')),
  published_version_id uuid,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS rmm_automations_tenant_name_idx
  ON rmm_automations(tenant_id, lower(name)) WHERE status <> 'archived';
CREATE INDEX IF NOT EXISTS rmm_automations_tenant_updated_idx
  ON rmm_automations(tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS rmm_automation_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  automation_id uuid NOT NULL REFERENCES rmm_automations(id) ON DELETE CASCADE,
  version_number integer NOT NULL CHECK (version_number > 0),
  state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft','published','superseded')),
  script_text text NOT NULL,
  content_sha256 text NOT NULL,
  timeout_seconds integer NOT NULL DEFAULT 120 CHECK (timeout_seconds BETWEEN 5 AND 3600),
  run_as text NOT NULL DEFAULT 'system' CHECK (run_as IN ('system','current_user')),
  parameters jsonb NOT NULL DEFAULT '[]'::jsonb,
  release_notes text NOT NULL DEFAULT '',
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  published_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  UNIQUE (automation_id, version_number)
);

CREATE INDEX IF NOT EXISTS rmm_automation_versions_lookup_idx
  ON rmm_automation_versions(automation_id, version_number DESC);

ALTER TABLE rmm_automations
  ADD CONSTRAINT rmm_automations_published_version_fk
  FOREIGN KEY (published_version_id) REFERENCES rmm_automation_versions(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS rmm_tray_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL DEFAULT 'Default tray policy',
  enabled boolean NOT NULL DEFAULT false,
  scope_type text NOT NULL DEFAULT 'tenant' CHECK (scope_type IN ('tenant','site','group','device')),
  scope_id text NOT NULL DEFAULT '',
  priority integer NOT NULL DEFAULT 0,
  branding jsonb NOT NULL DEFAULT '{}'::jsonb,
  support jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS rmm_tray_policies_scope_idx
  ON rmm_tray_policies(tenant_id, scope_type, scope_id);

CREATE TABLE IF NOT EXISTS rmm_tray_policy_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  policy_id uuid NOT NULL REFERENCES rmm_tray_policies(id) ON DELETE CASCADE,
  automation_id uuid NOT NULL REFERENCES rmm_automations(id) ON DELETE CASCADE,
  automation_version_id uuid NOT NULL REFERENCES rmm_automation_versions(id) ON DELETE RESTRICT,
  label text NOT NULL,
  description text NOT NULL DEFAULT '',
  enabled boolean NOT NULL DEFAULT true,
  confirmation_required boolean NOT NULL DEFAULT false,
  sort_order integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (policy_id, automation_id)
);

CREATE INDEX IF NOT EXISTS rmm_tray_policy_actions_policy_idx
  ON rmm_tray_policy_actions(policy_id, sort_order, created_at);

ALTER TABLE rmm_agent_jobs ADD COLUMN IF NOT EXISTS automation_id uuid REFERENCES rmm_automations(id) ON DELETE SET NULL;
ALTER TABLE rmm_agent_jobs ADD COLUMN IF NOT EXISTS automation_version_id uuid REFERENCES rmm_automation_versions(id) ON DELETE SET NULL;
ALTER TABLE rmm_agent_jobs ADD COLUMN IF NOT EXISTS initiated_by text NOT NULL DEFAULT 'system';
ALTER TABLE rmm_agent_jobs ADD COLUMN IF NOT EXISTS initiated_by_label text NOT NULL DEFAULT '';
ALTER TABLE rmm_agent_jobs ADD COLUMN IF NOT EXISTS correlation_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE rmm_agent_jobs ADD COLUMN IF NOT EXISTS request_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE rmm_agent_jobs ADD CONSTRAINT rmm_agent_jobs_initiated_by_check
  CHECK (initiated_by IN ('technician','schedule','alert','tray','system'));

CREATE INDEX IF NOT EXISTS rmm_agent_jobs_automation_idx
  ON rmm_agent_jobs(tenant_id, automation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_agent_jobs_correlation_idx
  ON rmm_agent_jobs(tenant_id, correlation_id);

UPDATE access_roles
SET permissions = permissions || ARRAY['rmm.automation.view','rmm.automation.run','rmm.jobs.view','rmm.tray.view']::text[],
    updated_at = now()
WHERE role_key='rmm-operator'
  AND NOT permissions @> ARRAY['rmm.automation.view','rmm.automation.run','rmm.jobs.view','rmm.tray.view']::text[];
