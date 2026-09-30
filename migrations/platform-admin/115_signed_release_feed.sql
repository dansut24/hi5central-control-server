ALTER TABLE platform_environment_actions
  ADD COLUMN IF NOT EXISTS not_before timestamptz NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS platform_environment_actions_ready_idx
  ON platform_environment_actions(status,not_before,requested_at)
  WHERE status='requested';

CREATE TABLE IF NOT EXISTS platform_release_feed_receipts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  release_ref text NOT NULL,
  channel text NOT NULL CHECK (channel IN ('stable','preview')),
  envelope jsonb NOT NULL,
  signature text NOT NULL,
  source_url text NOT NULL DEFAULT '',
  verified_at timestamptz NOT NULL DEFAULT now(),
  imported_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (release_ref,channel)
);

CREATE INDEX IF NOT EXISTS platform_release_feed_receipts_imported_idx
  ON platform_release_feed_receipts(imported_at DESC);
