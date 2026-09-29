CREATE TABLE IF NOT EXISTS installation_licensing (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  installation_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  license_status text NOT NULL DEFAULT 'evaluation'
    CHECK (license_status IN ('evaluation', 'active', 'grace', 'expired', 'suspended')),
  license_key_hash text,
  entitlement_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  entitlement_signature text,
  evaluation_started_at timestamptz NOT NULL DEFAULT now(),
  evaluation_ends_at timestamptz NOT NULL DEFAULT (now() + interval '30 days'),
  issued_at timestamptz,
  expires_at timestamptz,
  last_contact_at timestamptz,
  last_validated_at timestamptz,
  grace_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO installation_licensing (singleton)
VALUES (true)
ON CONFLICT (singleton) DO NOTHING;
