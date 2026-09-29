CREATE TABLE IF NOT EXISTS service_catalogue_categories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  name text NOT NULL,
  sort_order integer NOT NULL DEFAULT 0,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, external_key),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS service_catalogue_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  category_id uuid REFERENCES service_catalogue_categories(id) ON DELETE SET NULL,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  kind text NOT NULL DEFAULT 'product' CHECK (kind IN ('product', 'request-form')),
  request_type text NOT NULL DEFAULT 'Service Request',
  service text NOT NULL DEFAULT 'Service Catalogue',
  fulfilment_team_id uuid REFERENCES organisation_teams(id) ON DELETE SET NULL,
  fulfilment_team_name text NOT NULL DEFAULT '',
  approval_mode text NOT NULL DEFAULT 'none',
  approval_threshold numeric(12,2),
  visibility text NOT NULL DEFAULT 'portal' CHECK (visibility IN ('portal', 'technicians', 'hidden')),
  vendor text NOT NULL DEFAULT '',
  sku text NOT NULL DEFAULT '',
  price_mode text NOT NULL DEFAULT 'none' CHECK (price_mode IN ('none', 'fixed', 'calculated')),
  one_off_price numeric(12,2) NOT NULL DEFAULT 0 CHECK (one_off_price >= 0),
  monthly_price numeric(12,2) NOT NULL DEFAULT 0 CHECK (monthly_price >= 0),
  currency text NOT NULL DEFAULT 'GBP',
  workflow_key text NOT NULL DEFAULT '',
  form_schema jsonb NOT NULL DEFAULT '[]'::jsonb,
  options jsonb NOT NULL DEFAULT '[]'::jsonb,
  source jsonb NOT NULL DEFAULT '{"provider":"hi5central"}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, external_key)
);

CREATE INDEX IF NOT EXISTS service_catalogue_categories_tenant_idx
  ON service_catalogue_categories(tenant_id, active, sort_order);

CREATE INDEX IF NOT EXISTS service_catalogue_items_tenant_idx
  ON service_catalogue_items(tenant_id, active);

CREATE INDEX IF NOT EXISTS service_catalogue_items_category_idx
  ON service_catalogue_items(tenant_id, category_id, active);

CREATE INDEX IF NOT EXISTS service_catalogue_items_team_idx
  ON service_catalogue_items(tenant_id, fulfilment_team_id)
  WHERE fulfilment_team_id IS NOT NULL;
