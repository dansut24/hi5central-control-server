CREATE TABLE IF NOT EXISTS rmm_tenant_vendor_sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  display_name text NOT NULL,
  source_type text NOT NULL DEFAULT 'github_releases'
    CHECK (source_type IN ('github_releases')),
  repository text NOT NULL DEFAULT '',
  canonical_name text NOT NULL,
  publisher text NOT NULL DEFAULT '',
  expected_signer text NOT NULL DEFAULT '',
  provider_package_id text NOT NULL DEFAULT '',
  name_pattern text NOT NULL,
  publisher_pattern text NOT NULL DEFAULT '',
  channel text NOT NULL DEFAULT 'stable',
  platform text NOT NULL DEFAULT 'windows' CHECK (platform IN ('windows')),
  architecture text NOT NULL DEFAULT 'x64',
  deployment_mode text NOT NULL DEFAULT 'winget_preferred'
    CHECK (deployment_mode IN ('winget_preferred','vendor_direct','intelligence_only')),
  asset_pattern text NOT NULL DEFAULT '',
  checksum_asset_pattern text NOT NULL DEFAULT '',
  installer_type text NOT NULL DEFAULT '',
  poll_minutes integer NOT NULL DEFAULT 60 CHECK (poll_minutes BETWEEN 15 AND 10080),
  status text NOT NULL DEFAULT 'draft'
    CHECK (status IN ('draft','tested','active','quarantined','disabled','archived')),
  latest_version text NOT NULL DEFAULT '',
  latest_release_date timestamptz,
  latest_release_url text NOT NULL DEFAULT '',
  latest_installer_url text NOT NULL DEFAULT '',
  latest_installer_sha256 text NOT NULL DEFAULT '',
  last_test_result jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_attempt_at timestamptz,
  last_success_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  approved_at timestamptz,
  approved_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS rmm_tenant_vendor_sources_name_idx
  ON rmm_tenant_vendor_sources(tenant_id,lower(display_name))
  WHERE status<>'archived';

CREATE INDEX IF NOT EXISTS rmm_tenant_vendor_sources_due_idx
  ON rmm_tenant_vendor_sources(status,last_attempt_at,poll_minutes)
  WHERE status='active';

CREATE TABLE IF NOT EXISTS rmm_tenant_vendor_releases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id uuid NOT NULL REFERENCES rmm_tenant_vendor_sources(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  version text NOT NULL,
  release_date timestamptz,
  release_url text NOT NULL DEFAULT '',
  installer_url text NOT NULL DEFAULT '',
  installer_sha256 text NOT NULL DEFAULT '',
  installer_type text NOT NULL DEFAULT '',
  trust_state text NOT NULL DEFAULT 'version_only'
    CHECK (trust_state IN ('version_only','winget_ready','direct_ready','quarantined')),
  trust_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  source_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_id,version)
);

CREATE INDEX IF NOT EXISTS rmm_tenant_vendor_releases_latest_idx
  ON rmm_tenant_vendor_releases(tenant_id,source_id,release_date DESC,last_seen_at DESC);
