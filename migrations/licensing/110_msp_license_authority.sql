ALTER TABLE installation_licensing
  ADD COLUMN IF NOT EXISTS refresh_token text;

CREATE TABLE IF NOT EXISTS msp_licenses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_key_hash text NOT NULL UNIQUE,
  display_key_suffix text NOT NULL DEFAULT '',
  customer_name text NOT NULL,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','suspended','cancelled')),
  products jsonb NOT NULL DEFAULT '["itsm","rmm"]'::jsonb,
  features jsonb NOT NULL DEFAULT '{"multiTenant":true,"whiteLabel":true,"platformAdmin":true,"customerPortals":true,"customDomains":true}'::jsonb,
  tenant_limit integer CHECK (tenant_limit IS NULL OR tenant_limit >= 1),
  user_limit integer CHECK (user_limit IS NULL OR user_limit >= 1),
  device_limit integer CHECK (device_limit IS NULL OR device_limit >= 1),
  starts_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  grace_days integer NOT NULL DEFAULT 30 CHECK (grace_days BETWEEN 0 AND 90),
  bound_installation_id uuid,
  bound_at timestamptz,
  refresh_token_hash text,
  last_activated_at timestamptz,
  last_refreshed_at timestamptz,
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS msp_licenses_status_expiry_idx
  ON msp_licenses(status, expires_at);

CREATE UNIQUE INDEX IF NOT EXISTS msp_licenses_bound_installation_idx
  ON msp_licenses(bound_installation_id)
  WHERE bound_installation_id IS NOT NULL;
