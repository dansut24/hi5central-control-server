ALTER TABLE rmm_network_discovery_profiles
  ALTER COLUMN credential_id DROP NOT NULL;

ALTER TABLE rmm_network_discovery_profiles
  ADD COLUMN IF NOT EXISTS presence_enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS snmp_enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS presence_timeout_ms integer NOT NULL DEFAULT 350
    CHECK (presence_timeout_ms BETWEEN 50 AND 5000);

ALTER TABLE rmm_network_discovery_runs
  ADD COLUMN IF NOT EXISTS presence_devices integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS snmp_enriched_devices integer NOT NULL DEFAULT 0;

ALTER TABLE rmm_network_devices
  ADD COLUMN IF NOT EXISTS discovery_methods jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS icmp_reachable boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS latency_ms integer,
  ADD COLUMN IF NOT EXISTS last_presence_at timestamptz;

UPDATE rmm_network_discovery_profiles
   SET presence_enabled=true,
       snmp_enabled=true
 WHERE presence_enabled IS DISTINCT FROM true
    OR snmp_enabled IS DISTINCT FROM true;

UPDATE rmm_network_devices
   SET discovery_methods = CASE
     WHEN snmp_version<>'' THEN '["snmp"]'::jsonb
     ELSE '[]'::jsonb
   END
 WHERE discovery_methods='[]'::jsonb;
