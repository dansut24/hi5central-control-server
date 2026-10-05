CREATE TABLE IF NOT EXISTS platform_environment_state (
  environment text PRIMARY KEY
    CHECK (environment IN ('dev','test','uat','live')),
  feature_mode text NOT NULL DEFAULT 'controlled'
    CHECK (feature_mode IN ('all_enabled','controlled')),
  disposable boolean NOT NULL DEFAULT false,
  active_release_ref text NOT NULL DEFAULT '',
  last_reset_at timestamptz,
  last_deployed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO platform_environment_state (environment,feature_mode,disposable)
VALUES
  ('dev','all_enabled',true),
  ('test','all_enabled',true),
  ('uat','controlled',false),
  ('live','controlled',false)
ON CONFLICT (environment) DO UPDATE
SET feature_mode=EXCLUDED.feature_mode,
    disposable=EXCLUDED.disposable,
    updated_at=now();

CREATE TABLE IF NOT EXISTS platform_feature_definitions (
  feature_key text PRIMARY KEY,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  component text NOT NULL DEFAULT 'platform',
  default_enabled boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','retired')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (feature_key ~ '^[a-z0-9][a-z0-9._-]{1,119}$')
);

CREATE TABLE IF NOT EXISTS platform_environment_feature_flags (
  environment text NOT NULL REFERENCES platform_environment_state(environment) ON DELETE CASCADE,
  feature_key text NOT NULL REFERENCES platform_feature_definitions(feature_key) ON DELETE CASCADE,
  enabled boolean NOT NULL,
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (environment,feature_key)
);

CREATE TABLE IF NOT EXISTS platform_release_changes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  change_key text NOT NULL UNIQUE,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  component text NOT NULL DEFAULT 'platform',
  feature_key text REFERENCES platform_feature_definitions(feature_key) ON DELETE SET NULL,
  source_ref text NOT NULL DEFAULT '',
  version text NOT NULL DEFAULT '',
  risk text NOT NULL DEFAULT 'medium'
    CHECK (risk IN ('low','medium','high')),
  state text NOT NULL DEFAULT 'draft'
    CHECK (state IN (
      'draft','ready_for_test','testing','ready_for_uat','uat_testing',
      'uat_passed','uat_failed','selected_for_live','promoted','withdrawn'
    )),
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  promoted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS platform_release_changes_state_idx
  ON platform_release_changes(state,created_at DESC);

CREATE TABLE IF NOT EXISTS platform_release_test_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  change_id uuid NOT NULL REFERENCES platform_release_changes(id) ON DELETE CASCADE,
  environment text NOT NULL
    CHECK (environment IN ('test','uat')),
  result text NOT NULL
    CHECK (result IN ('passed','failed','blocked')),
  notes text NOT NULL DEFAULT '',
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  tested_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS platform_release_test_results_change_idx
  ON platform_release_test_results(change_id,environment,created_at DESC);

CREATE TABLE IF NOT EXISTS platform_release_promotions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_environment text NOT NULL
    CHECK (from_environment IN ('test','uat')),
  to_environment text NOT NULL
    CHECK (to_environment IN ('uat','live')),
  status text NOT NULL DEFAULT 'requested'
    CHECK (status IN ('requested','running','succeeded','failed','cancelled')),
  release_ref text NOT NULL DEFAULT '',
  requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  error_message text NOT NULL DEFAULT '',
  CHECK (
    (from_environment='test' AND to_environment='uat')
    OR (from_environment='uat' AND to_environment='live')
  )
);

CREATE TABLE IF NOT EXISTS platform_release_promotion_items (
  promotion_id uuid NOT NULL REFERENCES platform_release_promotions(id) ON DELETE CASCADE,
  change_id uuid NOT NULL REFERENCES platform_release_changes(id) ON DELETE RESTRICT,
  PRIMARY KEY (promotion_id,change_id)
);

CREATE TABLE IF NOT EXISTS platform_environment_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  environment text NOT NULL REFERENCES platform_environment_state(environment) ON DELETE CASCADE,
  action text NOT NULL
    CHECK (action IN ('reset','deploy','promote')),
  status text NOT NULL DEFAULT 'requested'
    CHECK (status IN ('requested','running','succeeded','failed','cancelled')),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
  requested_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  error_message text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS platform_environment_actions_queue_idx
  ON platform_environment_actions(status,requested_at)
  WHERE status IN ('requested','running');
