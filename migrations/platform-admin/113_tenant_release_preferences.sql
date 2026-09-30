CREATE TABLE IF NOT EXISTS tenant_release_preferences (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  update_mode text NOT NULL DEFAULT 'admin_controlled'
    CHECK (update_mode IN ('admin_controlled','hi5_managed')),
  test_auto_sync boolean NOT NULL DEFAULT true,
  uat_auto_stage boolean NOT NULL DEFAULT false,
  live_auto_promote boolean NOT NULL DEFAULT false,
  live_delay_hours integer NOT NULL DEFAULT 24
    CHECK (live_delay_hours BETWEEN 0 AND 720),
  allow_emergency_security_updates boolean NOT NULL DEFAULT true,
  maintenance_window jsonb NOT NULL DEFAULT '{"timezone":"Europe/London","days":[],"start":"02:00","end":"05:00"}'::jsonb,
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_environment_state (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  environment text NOT NULL
    CHECK (environment IN ('test','uat','live')),
  status text NOT NULL DEFAULT 'available'
    CHECK (status IN ('available','provisioning','ready','resetting','error')),
  active_release_ref text NOT NULL DEFAULT '',
  last_reset_at timestamptz,
  last_deployed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,environment)
);

CREATE TABLE IF NOT EXISTS tenant_environment_feature_overrides (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  environment text NOT NULL
    CHECK (environment IN ('uat','live')),
  feature_key text NOT NULL REFERENCES platform_feature_definitions(feature_key) ON DELETE CASCADE,
  enabled boolean NOT NULL,
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,environment,feature_key)
);

CREATE INDEX IF NOT EXISTS tenant_release_preferences_mode_idx
  ON tenant_release_preferences(update_mode);

CREATE OR REPLACE FUNCTION initialise_tenant_release_environments()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO tenant_release_preferences (tenant_id)
  VALUES (NEW.id)
  ON CONFLICT (tenant_id) DO NOTHING;

  INSERT INTO tenant_environment_state (tenant_id,environment,status)
  VALUES
    (NEW.id,'test','available'),
    (NEW.id,'uat','available'),
    (NEW.id,'live','ready')
  ON CONFLICT (tenant_id,environment) DO NOTHING;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS tenants_release_environment_init ON tenants;
CREATE TRIGGER tenants_release_environment_init
AFTER INSERT ON tenants
FOR EACH ROW
EXECUTE FUNCTION initialise_tenant_release_environments();

INSERT INTO tenant_release_preferences (tenant_id)
SELECT id FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO tenant_environment_state (tenant_id,environment,status)
SELECT t.id,e.environment,e.status
FROM tenants t
CROSS JOIN (
  VALUES ('test','available'),('uat','available'),('live','ready')
) AS e(environment,status)
ON CONFLICT (tenant_id,environment) DO NOTHING;
