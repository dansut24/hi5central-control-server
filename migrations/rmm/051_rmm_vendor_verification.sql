ALTER TABLE rmm_tenant_vendor_sources
  ADD COLUMN IF NOT EXISTS verification_config jsonb NOT NULL DEFAULT '{}'::jsonb;
