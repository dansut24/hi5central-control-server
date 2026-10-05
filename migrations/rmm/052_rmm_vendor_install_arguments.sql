ALTER TABLE rmm_tenant_vendor_sources
  ADD COLUMN IF NOT EXISTS install_arguments text NOT NULL DEFAULT '';
