ALTER TABLE rmm_tenant_vendor_sources
  ADD COLUMN IF NOT EXISTS source_url text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS parser_config jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE rmm_tenant_vendor_sources
  DROP CONSTRAINT IF EXISTS rmm_tenant_vendor_sources_source_type_check;

ALTER TABLE rmm_tenant_vendor_sources
  ADD CONSTRAINT rmm_tenant_vendor_sources_source_type_check
  CHECK (source_type IN ('github_releases','vendor_json'));
