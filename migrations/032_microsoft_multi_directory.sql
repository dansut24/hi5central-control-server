ALTER TABLE tenant_microsoft_connections
  ADD COLUMN IF NOT EXISTS id uuid DEFAULT gen_random_uuid(),
  ADD COLUMN IF NOT EXISTS connection_name text NOT NULL DEFAULT 'Microsoft 365';

UPDATE tenant_microsoft_connections
SET id = gen_random_uuid()
WHERE id IS NULL;

ALTER TABLE tenant_microsoft_connections
  ALTER COLUMN id SET NOT NULL;

ALTER TABLE tenant_microsoft_connections
  DROP CONSTRAINT IF EXISTS tenant_microsoft_connections_pkey;

ALTER TABLE tenant_microsoft_connections
  ADD CONSTRAINT tenant_microsoft_connections_pkey PRIMARY KEY (id);

DROP INDEX IF EXISTS tenant_microsoft_directory_tenant_unique;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_microsoft_connection_directory_unique
  ON tenant_microsoft_connections(tenant_id, directory_tenant_id)
  WHERE directory_tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tenant_microsoft_connections_tenant_idx
  ON tenant_microsoft_connections(tenant_id, status, created_at);
ALTER TABLE microsoft_sync_runs
  ADD COLUMN IF NOT EXISTS microsoft_connection_id uuid REFERENCES tenant_microsoft_connections(id) ON DELETE CASCADE;

UPDATE microsoft_sync_runs r
SET microsoft_connection_id = c.id
FROM tenant_microsoft_connections c
WHERE r.microsoft_connection_id IS NULL
  AND r.tenant_id = c.tenant_id;

CREATE INDEX IF NOT EXISTS microsoft_sync_runs_connection_idx
  ON microsoft_sync_runs(microsoft_connection_id, started_at DESC);

ALTER TABLE rmm_device_inventory
  ADD COLUMN IF NOT EXISTS microsoft_connection_id uuid REFERENCES tenant_microsoft_connections(id) ON DELETE SET NULL;

UPDATE rmm_device_inventory d
SET microsoft_connection_id = c.id
FROM tenant_microsoft_connections c
WHERE d.microsoft_connection_id IS NULL
  AND d.source = 'intune'
  AND d.tenant_id = c.tenant_id;

ALTER TABLE rmm_device_inventory
  DROP CONSTRAINT IF EXISTS rmm_device_inventory_tenant_id_source_source_device_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS rmm_device_inventory_intune_source_unique
  ON rmm_device_inventory(tenant_id, microsoft_connection_id, source_device_id)
  WHERE source = 'intune';

CREATE UNIQUE INDEX IF NOT EXISTS rmm_device_inventory_agent_source_unique
  ON rmm_device_inventory(tenant_id, source, source_device_id)
  WHERE source <> 'intune';

CREATE TABLE IF NOT EXISTS organisation_person_external_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  person_id uuid NOT NULL REFERENCES organisation_people(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('microsoft_entra')),
  microsoft_connection_id uuid REFERENCES tenant_microsoft_connections(id) ON DELETE CASCADE,
  issuer_tenant_id text NOT NULL,
  object_id text NOT NULL,
  principal_name text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, provider, issuer_tenant_id, object_id)
);

CREATE INDEX IF NOT EXISTS organisation_person_external_identity_person_idx
  ON organisation_person_external_identities(tenant_id, person_id);
