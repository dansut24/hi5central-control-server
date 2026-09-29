ALTER TABLE rmm_tenant_vendor_sources
  DROP CONSTRAINT IF EXISTS rmm_tenant_vendor_sources_source_type_check;

ALTER TABLE rmm_tenant_vendor_sources
  ADD CONSTRAINT rmm_tenant_vendor_sources_source_type_check
  CHECK (source_type IN ('github_releases','vendor_json','static_release'));
