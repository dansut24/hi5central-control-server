ALTER TABLE rmm_agent_devices
  ADD COLUMN IF NOT EXISTS patch_capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS patch_capabilities_at timestamptz,
  ADD COLUMN IF NOT EXISTS patch_discovery_at timestamptz;

ALTER TABLE rmm_software_patch_observations
  ADD COLUMN IF NOT EXISTS display_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS source_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS discovery_method text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS match_confidence text NOT NULL DEFAULT 'source'
    CHECK (match_confidence IN ('source','exact','curated','heuristic'));

CREATE INDEX IF NOT EXISTS rmm_software_patch_observations_package_idx
  ON rmm_software_patch_observations(tenant_id, lower(provider), lower(provider_package_id))
  WHERE provider_package_id <> '';
CREATE TABLE IF NOT EXISTS rmm_patch_catalogue_candidates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider text NOT NULL,
  provider_package_id text NOT NULL,
  display_name text NOT NULL DEFAULT '',
  publisher text NOT NULL DEFAULT '',
  latest_observed_version text NOT NULL DEFAULT '',
  devices_seen integer NOT NULL DEFAULT 0,
  updates_seen integer NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  state text NOT NULL DEFAULT 'observed'
    CHECK (state IN ('observed','mapped','ignored','review')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, provider, provider_package_id)
);

CREATE INDEX IF NOT EXISTS rmm_patch_catalogue_candidates_state_idx
  ON rmm_patch_catalogue_candidates(tenant_id, state, updates_seen DESC, last_seen_at DESC);
