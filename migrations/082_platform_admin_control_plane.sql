CREATE TABLE IF NOT EXISTS platform_admin_members (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'read_only'
    CHECK (role IN ('owner','admin','support','catalogue','billing','read_only')),
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','suspended')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS platform_admin_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS platform_admin_sessions_lookup_idx
  ON platform_admin_sessions(token_hash,expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS platform_admin_audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  session_id uuid REFERENCES platform_admin_sessions(id) ON DELETE SET NULL,
  action text NOT NULL,
  target_type text NOT NULL DEFAULT '',
  target_id text NOT NULL DEFAULT '',
  ip_address text NOT NULL DEFAULT '',
  user_agent text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS platform_admin_audit_created_idx
  ON platform_admin_audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS tenant_commercial_settings (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  plan_key text NOT NULL DEFAULT 'custom',
  billing_status text NOT NULL DEFAULT 'trial'
    CHECK (billing_status IN ('trial','active','past_due','suspended','cancelled')),
  billing_cycle text NOT NULL DEFAULT 'monthly'
    CHECK (billing_cycle IN ('monthly','annual','custom')),
  currency text NOT NULL DEFAULT 'GBP',
  monthly_price_pence integer CHECK (monthly_price_pence IS NULL OR monthly_price_pence >= 0),
  trial_ends_at timestamptz,
  renewal_at timestamptz,
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO tenant_commercial_settings (tenant_id)
SELECT id FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;
