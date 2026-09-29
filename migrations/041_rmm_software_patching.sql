CREATE TABLE IF NOT EXISTS rmm_software_catalogue (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
  canonical_name text NOT NULL,
  publisher text NOT NULL DEFAULT '',
  name_pattern text NOT NULL,
  publisher_pattern text NOT NULL DEFAULT '',
  platform text NOT NULL DEFAULT 'windows' CHECK (platform IN ('windows')),
  provider text NOT NULL DEFAULT 'winget' CHECK (provider IN ('winget','managed','vendor')),
  provider_package_id text NOT NULL DEFAULT '',
  target_version text NOT NULL DEFAULT '',
  release_channel text NOT NULL DEFAULT 'stable',
  installer_type text NOT NULL DEFAULT '',
  detection jsonb NOT NULL DEFAULT '{}'::jsonb,
  execution jsonb NOT NULL DEFAULT '{}'::jsonb,
  verification jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','archived')),
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_software_catalogue_tenant_status_idx
  ON rmm_software_catalogue(tenant_id, status, lower(canonical_name));
CREATE UNIQUE INDEX IF NOT EXISTS rmm_software_catalogue_tenant_name_provider_idx
  ON rmm_software_catalogue(tenant_id, lower(canonical_name), provider, lower(provider_package_id))
  WHERE tenant_id IS NOT NULL AND status <> 'archived';

CREATE TABLE IF NOT EXISTS rmm_software_patch_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  catalogue_id uuid REFERENCES rmm_software_catalogue(id) ON DELETE SET NULL,
  application_key text NOT NULL,
  application_name text NOT NULL,
  publisher text NOT NULL DEFAULT '',
  installed_version text NOT NULL DEFAULT '',
  provider text NOT NULL DEFAULT '',
  provider_package_id text NOT NULL DEFAULT '',
  available_version text NOT NULL DEFAULT '',
  patch_status text NOT NULL DEFAULT 'detection_pending'
    CHECK (patch_status IN ('unmapped','detection_pending','current','update_available','unsupported')),
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  observed_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, inventory_id, application_key)
);

CREATE INDEX IF NOT EXISTS rmm_software_patch_observations_status_idx
  ON rmm_software_patch_observations(tenant_id, patch_status, observed_at DESC);
CREATE TABLE IF NOT EXISTS rmm_patch_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  software_enabled boolean NOT NULL DEFAULT true,
  windows_enabled boolean NOT NULL DEFAULT false,
  approval_mode text NOT NULL DEFAULT 'manual'
    CHECK (approval_mode IN ('automatic','manual','pilot','blocked')),
  deployment_delay_days integer NOT NULL DEFAULT 0 CHECK (deployment_delay_days BETWEEN 0 AND 365),
  maintenance_window jsonb NOT NULL DEFAULT '{}'::jsonb,
  reboot_policy text NOT NULL DEFAULT 'never'
    CHECK (reboot_policy IN ('never','maintenance_window','notify_user')),
  max_retries integer NOT NULL DEFAULT 2 CHECK (max_retries BETWEEN 0 AND 10),
  software_rules jsonb NOT NULL DEFAULT '{}'::jsonb,
  windows_rules jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','archived')),
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS rmm_patch_policies_tenant_name_idx
  ON rmm_patch_policies(tenant_id, lower(name)) WHERE status <> 'archived';
CREATE TABLE IF NOT EXISTS rmm_patch_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  policy_id uuid NOT NULL REFERENCES rmm_patch_policies(id) ON DELETE CASCADE,
  scope_type text NOT NULL CHECK (scope_type IN ('Estate','Site','Group','Device')),
  scope_id text NOT NULL,
  scope_name text NOT NULL DEFAULT '',
  priority integer NOT NULL DEFAULT 0,
  enabled boolean NOT NULL DEFAULT true,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, policy_id, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS rmm_patch_assignments_scope_idx
  ON rmm_patch_assignments(tenant_id, scope_type, scope_id, priority DESC)
  WHERE enabled=true;

CREATE TABLE IF NOT EXISTS rmm_patch_deployments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  catalogue_id uuid REFERENCES rmm_software_catalogue(id) ON DELETE SET NULL,
  policy_id uuid REFERENCES rmm_patch_policies(id) ON DELETE SET NULL,
  agent_job_id uuid REFERENCES rmm_agent_jobs(id) ON DELETE SET NULL,
  application_name text NOT NULL,
  provider text NOT NULL DEFAULT '',
  provider_package_id text NOT NULL DEFAULT '',
  installed_version text NOT NULL DEFAULT '',
  target_version text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'planned'
    CHECK (status IN ('planned','eligible','running','succeeded','failed','cancelled','verification_failed','reboot_required')),
  requested_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_patch_deployments_device_idx
  ON rmm_patch_deployments(tenant_id, inventory_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_patch_deployments_status_idx
  ON rmm_patch_deployments(tenant_id, status, created_at DESC);
CREATE TABLE IF NOT EXISTS rmm_vulnerabilities (
  cve_id text PRIMARY KEY,
  source text NOT NULL DEFAULT 'nvd',
  published_at timestamptz,
  modified_at timestamptz,
  summary text NOT NULL DEFAULT '',
  cvss_score numeric(4,1),
  cvss_version text NOT NULL DEFAULT '',
  cvss_vector text NOT NULL DEFAULT '',
  severity text NOT NULL DEFAULT '',
  cwe_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  references_json jsonb NOT NULL DEFAULT '[]'::jsonb,
  kev boolean NOT NULL DEFAULT false,
  kev_added_at date,
  kev_due_at date,
  known_ransomware_use text NOT NULL DEFAULT '',
  required_action text NOT NULL DEFAULT '',
  source_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_vulnerabilities_priority_idx
  ON rmm_vulnerabilities(kev DESC, cvss_score DESC, modified_at DESC);
CREATE TABLE IF NOT EXISTS rmm_vulnerability_products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id text NOT NULL REFERENCES rmm_vulnerabilities(cve_id) ON DELETE CASCADE,
  source text NOT NULL DEFAULT 'nvd',
  vendor text NOT NULL DEFAULT '',
  product text NOT NULL DEFAULT '',
  cpe text NOT NULL DEFAULT '',
  ecosystem text NOT NULL DEFAULT '',
  package_name text NOT NULL DEFAULT '',
  version_constraints jsonb NOT NULL DEFAULT '{}'::jsonb,
  fixed_versions jsonb NOT NULL DEFAULT '[]'::jsonb,
  confidence text NOT NULL DEFAULT 'source'
    CHECK (confidence IN ('source','vendor','curated','heuristic')),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_vulnerability_products_lookup_idx
  ON rmm_vulnerability_products(lower(vendor), lower(product), cve_id);
CREATE INDEX IF NOT EXISTS rmm_vulnerability_products_package_idx
  ON rmm_vulnerability_products(lower(ecosystem), lower(package_name), cve_id);
CREATE TABLE IF NOT EXISTS rmm_vulnerability_exposures (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  catalogue_id uuid REFERENCES rmm_software_catalogue(id) ON DELETE SET NULL,
  cve_id text NOT NULL REFERENCES rmm_vulnerabilities(cve_id) ON DELETE CASCADE,
  application_key text NOT NULL,
  application_name text NOT NULL,
  installed_version text NOT NULL DEFAULT '',
  fixed_version text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'open'
    CHECK (status IN ('open','remediated','accepted','not_affected','review')),
  match_source text NOT NULL DEFAULT '',
  match_confidence text NOT NULL DEFAULT 'source',
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  remediated_at timestamptz,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, inventory_id, cve_id, application_key)
);

CREATE INDEX IF NOT EXISTS rmm_vulnerability_exposures_open_idx
  ON rmm_vulnerability_exposures(tenant_id, status, last_seen_at DESC);
CREATE TABLE IF NOT EXISTS rmm_vulnerability_sync_state (
  source text PRIMARY KEY,
  enabled boolean NOT NULL DEFAULT true,
  cursor_value text NOT NULL DEFAULT '',
  last_attempt_at timestamptz,
  last_success_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  records_seen bigint NOT NULL DEFAULT 0,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO rmm_vulnerability_sync_state (source, enabled)
VALUES ('cisa_kev', true), ('nvd', true), ('msrc', true), ('osv', true)
ON CONFLICT (source) DO NOTHING;
ALTER TABLE rmm_software_catalogue
  ADD COLUMN IF NOT EXISTS cpe_vendor text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS cpe_product text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS osv_ecosystem text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS osv_package_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS catalogue_source text NOT NULL DEFAULT 'tenant',
  ADD COLUMN IF NOT EXISTS external_key text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS source_revision text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS source_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE UNIQUE INDEX IF NOT EXISTS rmm_software_catalogue_global_external_idx
  ON rmm_software_catalogue(catalogue_source, external_key)
  WHERE tenant_id IS NULL AND external_key <> '' AND status <> 'archived';
