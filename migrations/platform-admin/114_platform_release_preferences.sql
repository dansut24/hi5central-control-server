CREATE TABLE IF NOT EXISTS platform_release_preferences (
  preference_key text PRIMARY KEY DEFAULT 'deployment'
    CHECK (preference_key='deployment'),
  update_mode text NOT NULL DEFAULT 'admin_controlled'
    CHECK (update_mode IN ('admin_controlled','hi5_managed')),
  release_channel text NOT NULL DEFAULT 'stable'
    CHECK (release_channel IN ('stable','preview')),
  test_auto_sync boolean NOT NULL DEFAULT true,
  uat_auto_stage boolean NOT NULL DEFAULT false,
  live_auto_promote boolean NOT NULL DEFAULT false,
  live_delay_hours integer NOT NULL DEFAULT 24
    CHECK (live_delay_hours BETWEEN 0 AND 720),
  allow_emergency_security_updates boolean NOT NULL DEFAULT true,
  maintenance_window jsonb NOT NULL DEFAULT '{"timezone":"Europe/London","days":[],"start":"02:00","end":"05:00"}'::jsonb,
  last_feed_sync_at timestamptz,
  last_release_seen text NOT NULL DEFAULT '',
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO platform_release_preferences (preference_key)
VALUES ('deployment')
ON CONFLICT (preference_key) DO NOTHING;
