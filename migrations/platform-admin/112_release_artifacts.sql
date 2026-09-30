ALTER TABLE platform_release_promotions
  ADD COLUMN IF NOT EXISTS artifact_manifest jsonb NOT NULL DEFAULT '{}'::jsonb;
