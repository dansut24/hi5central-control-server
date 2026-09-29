ALTER TABLE rmm_software_vendor_releases
  ADD COLUMN IF NOT EXISTS asset_health_state text NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS asset_last_checked_at timestamptz,
  ADD COLUMN IF NOT EXISTS asset_http_status integer,
  ADD COLUMN IF NOT EXISTS asset_failure_count integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS asset_final_url text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS asset_content_type text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS asset_content_length bigint,
  ADD COLUMN IF NOT EXISTS asset_etag text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS asset_last_modified text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS asset_health_error text NOT NULL DEFAULT '';

ALTER TABLE rmm_software_vendor_releases
  DROP CONSTRAINT IF EXISTS rmm_software_vendor_releases_asset_health_state_check;
ALTER TABLE rmm_software_vendor_releases
  ADD CONSTRAINT rmm_software_vendor_releases_asset_health_state_check
  CHECK (asset_health_state = ANY (ARRAY['unknown'::text,'healthy'::text,'degraded'::text,'dead'::text]));

CREATE INDEX IF NOT EXISTS rmm_software_vendor_releases_asset_health_idx
  ON rmm_software_vendor_releases(asset_health_state, asset_last_checked_at)
  WHERE installer_url <> '';
