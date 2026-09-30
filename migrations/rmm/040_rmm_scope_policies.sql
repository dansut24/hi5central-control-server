CREATE TABLE IF NOT EXISTS rmm_device_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  mode text NOT NULL DEFAULT 'static' CHECK (mode IN ('static','dynamic')),
  site_id text NOT NULL DEFAULT '',
  rules jsonb NOT NULL DEFAULT '{}'::jsonb,
  monitoring_policy_id uuid,
  patch_ring text NOT NULL DEFAULT 'Inherited',
  software_profile text NOT NULL DEFAULT 'Inherited',
  automation_profile text NOT NULL DEFAULT 'Inherited',
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,name)
);

CREATE TABLE IF NOT EXISTS rmm_device_group_memberships (
  group_id uuid NOT NULL REFERENCES rmm_device_groups(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  added_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id,inventory_id)
);

CREATE INDEX IF NOT EXISTS rmm_device_group_memberships_inventory_idx
  ON rmm_device_group_memberships(tenant_id,inventory_id);

CREATE TABLE IF NOT EXISTS rmm_saved_views (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private','shared')),
  filters jsonb NOT NULL DEFAULT '{}'::jsonb,
  sort jsonb NOT NULL DEFAULT '{}'::jsonb,
  columns jsonb NOT NULL DEFAULT '[]'::jsonb,
  is_favourite boolean NOT NULL DEFAULT false,
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_saved_views_visible_idx
  ON rmm_saved_views(tenant_id,visibility,owner_user_id,updated_at DESC);

CREATE TABLE IF NOT EXISTS rmm_monitoring_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  platform text NOT NULL DEFAULT 'All',
  evaluation text NOT NULL DEFAULT 'Every 5 minutes',
  alert_delay text NOT NULL DEFAULT '5 minutes',
  auto_resolve boolean NOT NULL DEFAULT true,
  checks jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled','archived')),
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,name)
);

ALTER TABLE rmm_device_groups
  ADD CONSTRAINT rmm_device_groups_monitoring_policy_fk
  FOREIGN KEY (monitoring_policy_id) REFERENCES rmm_monitoring_policies(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS rmm_monitoring_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  policy_id uuid NOT NULL REFERENCES rmm_monitoring_policies(id) ON DELETE CASCADE,
  scope_type text NOT NULL CHECK (scope_type IN ('Estate','Site','Group','Device')),
  scope_id text NOT NULL DEFAULT '',
  scope_name text NOT NULL DEFAULT '',
  priority integer NOT NULL DEFAULT 100,
  enabled boolean NOT NULL DEFAULT true,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_monitoring_assignments_scope_idx
  ON rmm_monitoring_assignments(tenant_id,scope_type,scope_id,priority DESC);

CREATE TABLE IF NOT EXISTS rmm_monitoring_device_overrides (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  policy_id uuid NOT NULL REFERENCES rmm_monitoring_policies(id) ON DELETE CASCADE,
  check_overrides jsonb NOT NULL DEFAULT '{}'::jsonb,
  reason text NOT NULL DEFAULT '',
  enabled boolean NOT NULL DEFAULT true,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,inventory_id)
);

CREATE INDEX IF NOT EXISTS rmm_monitoring_device_overrides_policy_idx
  ON rmm_monitoring_device_overrides(tenant_id,policy_id)
;

CREATE UNIQUE INDEX IF NOT EXISTS rmm_saved_views_one_default_per_user_idx
  ON rmm_saved_views(owner_user_id)
  WHERE is_default=true;
