CREATE TABLE IF NOT EXISTS rmm_network_discovery_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  snmp_version text NOT NULL DEFAULT 'v2c'
    CHECK (snmp_version IN ('v1','v2c','v3')),
  community_encrypted text NOT NULL DEFAULT '',
  username text NOT NULL DEFAULT '',
  security_level text NOT NULL DEFAULT 'noAuthNoPriv'
    CHECK (security_level IN ('noAuthNoPriv','authNoPriv','authPriv')),
  auth_protocol text NOT NULL DEFAULT ''
    CHECK (auth_protocol IN ('','MD5','SHA','SHA224','SHA256','SHA384','SHA512')),
  auth_secret_encrypted text NOT NULL DEFAULT '',
  privacy_protocol text NOT NULL DEFAULT ''
    CHECK (privacy_protocol IN ('','DES','AES','AES192','AES256')),
  privacy_secret_encrypted text NOT NULL DEFAULT '',
  context_name text NOT NULL DEFAULT '',
  enabled boolean NOT NULL DEFAULT true,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS rmm_network_discovery_credentials_name_idx
  ON rmm_network_discovery_credentials(tenant_id, lower(name))
  WHERE enabled=true;

CREATE TABLE IF NOT EXISTS rmm_network_discovery_profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  cidr cidr NOT NULL,
  site_id uuid REFERENCES organisation_sites(id) ON DELETE SET NULL,
  probe_agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  credential_id uuid NOT NULL REFERENCES rmm_network_discovery_credentials(id) ON DELETE RESTRICT,
  snmp_port integer NOT NULL DEFAULT 161 CHECK (snmp_port BETWEEN 1 AND 65535),
  timeout_ms integer NOT NULL DEFAULT 800 CHECK (timeout_ms BETWEEN 100 AND 10000),
  retries integer NOT NULL DEFAULT 1 CHECK (retries BETWEEN 0 AND 5),
  concurrency integer NOT NULL DEFAULT 32 CHECK (concurrency BETWEEN 1 AND 128),
  scan_interval_minutes integer NOT NULL DEFAULT 60
    CHECK (scan_interval_minutes BETWEEN 5 AND 10080),
  enabled boolean NOT NULL DEFAULT true,
  last_scan_at timestamptz,
  next_scan_at timestamptz,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS rmm_network_discovery_profiles_probe_idx
  ON rmm_network_discovery_profiles(tenant_id, probe_agent_device_id)
  WHERE enabled=true;
CREATE INDEX IF NOT EXISTS rmm_network_discovery_profiles_next_scan_idx
  ON rmm_network_discovery_profiles(next_scan_at)
  WHERE enabled=true AND next_scan_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS rmm_network_discovery_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  profile_id uuid NOT NULL REFERENCES rmm_network_discovery_profiles(id) ON DELETE CASCADE,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  agent_job_id uuid REFERENCES rmm_agent_jobs(id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued','running','completed','failed','cancelled')),
  addresses_total integer NOT NULL DEFAULT 0,
  addresses_responded integer NOT NULL DEFAULT 0,
  snmp_devices integer NOT NULL DEFAULT 0,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  error_message text NOT NULL DEFAULT '',
  initiated_by text NOT NULL DEFAULT 'technician'
    CHECK (initiated_by IN ('technician','scheduler','system')),
  initiated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_network_discovery_runs_profile_idx
  ON rmm_network_discovery_runs(tenant_id, profile_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_network_discovery_runs_job_idx
  ON rmm_network_discovery_runs(agent_job_id)
  WHERE agent_job_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS rmm_network_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  profile_id uuid NOT NULL REFERENCES rmm_network_discovery_profiles(id) ON DELETE CASCADE,
  site_id uuid REFERENCES organisation_sites(id) ON DELETE SET NULL,
  source_agent_device_id uuid REFERENCES rmm_agent_devices(id) ON DELETE SET NULL,
  ip_address inet NOT NULL,
  mac_address text NOT NULL DEFAULT '',
  hostname text NOT NULL DEFAULT '',
  snmp_version text NOT NULL DEFAULT '',
  sys_name text NOT NULL DEFAULT '',
  sys_descr text NOT NULL DEFAULT '',
  sys_object_id text NOT NULL DEFAULT '',
  sys_location text NOT NULL DEFAULT '',
  sys_contact text NOT NULL DEFAULT '',
  uptime_ticks bigint,
  interface_count integer,
  vendor text NOT NULL DEFAULT '',
  model text NOT NULL DEFAULT '',
  device_type text NOT NULL DEFAULT 'network_device',
  status text NOT NULL DEFAULT 'online'
    CHECK (status IN ('online','offline','unknown')),
  interfaces jsonb NOT NULL DEFAULT '[]'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  last_snmp_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (profile_id, ip_address)
);

CREATE INDEX IF NOT EXISTS rmm_network_devices_tenant_status_idx
  ON rmm_network_devices(tenant_id, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS rmm_network_devices_site_idx
  ON rmm_network_devices(tenant_id, site_id, last_seen_at DESC)
  WHERE site_id IS NOT NULL;
