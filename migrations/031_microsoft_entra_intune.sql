CREATE TABLE IF NOT EXISTS tenant_microsoft_connections (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  directory_tenant_id text,
  status text NOT NULL DEFAULT 'disconnected'
    CHECK (status IN ('disconnected','pending','connected','error')),
  sso_enabled boolean NOT NULL DEFAULT false,
  intune_enabled boolean NOT NULL DEFAULT false,
  intune_sync_enabled boolean NOT NULL DEFAULT false,
  intune_sync_interval_minutes integer NOT NULL DEFAULT 60
    CHECK (intune_sync_interval_minutes BETWEEN 15 AND 1440),
  intune_status text NOT NULL DEFAULT 'not_configured'
    CHECK (intune_status IN ('not_configured','ready','unavailable','error')),
  device_count integer NOT NULL DEFAULT 0 CHECK (device_count >= 0),
  last_validated_at timestamptz,
  last_sync_started_at timestamptz,
  last_sync_completed_at timestamptz,
  last_sync_status text,
  last_sync_error text,
  connected_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  admin_consent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS tenant_microsoft_directory_tenant_unique
  ON tenant_microsoft_connections(directory_tenant_id)
  WHERE directory_tenant_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS user_external_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('microsoft_entra')),
  issuer_tenant_id text NOT NULL,
  subject text NOT NULL,
  object_id text,
  principal_name text NOT NULL DEFAULT '',
  last_login_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, provider, issuer_tenant_id, subject),
  UNIQUE (tenant_id, provider, issuer_tenant_id, object_id)
);

CREATE INDEX IF NOT EXISTS user_external_identities_user_idx
  ON user_external_identities(tenant_id, user_id);

CREATE TABLE IF NOT EXISTS microsoft_sync_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  sync_type text NOT NULL CHECK (sync_type IN ('intune_devices')),
  status text NOT NULL DEFAULT 'running'
    CHECK (status IN ('running','completed','failed')),
  started_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  discovered_count integer NOT NULL DEFAULT 0 CHECK (discovered_count >= 0),
  imported_count integer NOT NULL DEFAULT 0 CHECK (imported_count >= 0),
  updated_count integer NOT NULL DEFAULT 0 CHECK (updated_count >= 0),
  deactivated_count integer NOT NULL DEFAULT 0 CHECK (deactivated_count >= 0),
  error_message text,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE INDEX IF NOT EXISTS microsoft_sync_runs_tenant_idx
  ON microsoft_sync_runs(tenant_id, started_at DESC);

CREATE TABLE IF NOT EXISTS rmm_device_inventory (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source text NOT NULL CHECK (source IN ('intune','hi5central_agent')),
  source_device_id text NOT NULL,
  reference text NOT NULL,
  directory_device_id text,
  name text NOT NULL,
  platform text NOT NULL DEFAULT 'Unknown',
  operating_system text NOT NULL DEFAULT '',
  os_version text NOT NULL DEFAULT '',
  manufacturer text NOT NULL DEFAULT '',
  model text NOT NULL DEFAULT '',
  serial_number text NOT NULL DEFAULT '',
  user_id_external text,
  assigned_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  user_display_name text NOT NULL DEFAULT '',
  user_principal_name text NOT NULL DEFAULT '',
  owner_type text NOT NULL DEFAULT 'unknown',
  compliance_state text NOT NULL DEFAULT 'unknown',
  management_state text NOT NULL DEFAULT 'managed',
  management_agent text NOT NULL DEFAULT '',
  enrollment_type text NOT NULL DEFAULT '',
  registration_state text NOT NULL DEFAULT '',
  category_name text NOT NULL DEFAULT '',
  is_encrypted boolean,
  memory_bytes bigint,
  storage_total_bytes bigint,
  storage_free_bytes bigint,
  ethernet_mac text NOT NULL DEFAULT '',
  wifi_mac text NOT NULL DEFAULT '',
  enrolled_at timestamptz,
  source_last_sync_at timestamptz,
  last_imported_at timestamptz NOT NULL DEFAULT now(),
  last_seen_sync_run_id uuid REFERENCES microsoft_sync_runs(id) ON DELETE SET NULL,
  active boolean NOT NULL DEFAULT true,
  source_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, source, source_device_id),
  UNIQUE (tenant_id, reference)
);

CREATE INDEX IF NOT EXISTS rmm_device_inventory_tenant_active_idx
  ON rmm_device_inventory(tenant_id, active, name);
CREATE INDEX IF NOT EXISTS rmm_device_inventory_directory_device_idx
  ON rmm_device_inventory(tenant_id, directory_device_id)
  WHERE directory_device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS rmm_device_inventory_person_idx
  ON rmm_device_inventory(tenant_id, assigned_person_id, active);
