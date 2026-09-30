ALTER TABLE tenant_settings
  ADD COLUMN IF NOT EXISTS configuration jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE tenant_settings
SET configuration = onboarding_data
WHERE onboarding_completed_at IS NOT NULL
  AND configuration = '{}'::jsonb
  AND onboarding_data <> '{}'::jsonb;
