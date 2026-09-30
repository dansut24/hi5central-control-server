-- Permanently retire the historical frontend demo organisation directory.
-- Migration 019 removed these rows once, but an already-open stale client was
-- able to write the old snapshot back afterwards. Repair existing tenants again
-- and reserve those exact legacy keys so they can never be reintroduced.

DELETE FROM organisation_people
WHERE external_key = ANY (ARRAY[
  'AGT-DANA',
  'AGT-SOFIA',
  'AGT-LEWIS',
  'AGT-EMILY',
  'AGT-PRIYA',
  'AGT-NOAH',
  'AGT-MAYA',
  'AGT-AISHA',
  'AGT-JAMES',
  'AGT-OLIVIA',
  'USR-ELEANOR',
  'USR-MARCUS',
  'USR-HELEN',
  'USR-AMELIA',
  'USR-SAM'
]::text[]);

DELETE FROM organisation_teams
WHERE external_key = ANY (ARRAY[
  'TEAM-SD',
  'TEAM-INFRA',
  'TEAM-EUC',
  'TEAM-CHANGE',
  'TEAM-LEADERSHIP',
  'TEAM-FINANCE',
  'TEAM-BIZOPS',
  'TEAM-PEOPLE'
]::text[]);

DELETE FROM organisation_departments
WHERE external_key = ANY (ARRAY[
  'DEPT-TECH',
  'DEPT-FIN',
  'DEPT-OPS',
  'DEPT-PEOPLE'
]::text[]);

-- Restore real account-backed People if a stale browser snapshot deactivated
-- them. Tenant membership is the authoritative signal for these identities.
UPDATE organisation_people p
SET active = true,
    updated_at = now()
FROM tenant_memberships m
WHERE p.tenant_id = m.tenant_id
  AND p.user_id = m.user_id
  AND m.status = 'active'
  AND p.active = false;

UPDATE organisation_departments
SET active = true,
    updated_at = now()
WHERE external_key = 'DEPT-DEFAULT'
  AND active = false;

UPDATE organisation_teams
SET active = true,
    updated_at = now()
WHERE external_key = 'TEAM-SERVICE-DESK'
  AND active = false;

UPDATE organisation_sites
SET active = true,
    updated_at = now()
WHERE external_key = 'SITE-DEFAULT'
  AND active = false;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'organisation_people_no_legacy_demo_keys'
      AND conrelid = 'organisation_people'::regclass
  ) THEN
    ALTER TABLE organisation_people
      ADD CONSTRAINT organisation_people_no_legacy_demo_keys
      CHECK (external_key NOT IN (
        'AGT-DANA',
        'AGT-SOFIA',
        'AGT-LEWIS',
        'AGT-EMILY',
        'AGT-PRIYA',
        'AGT-NOAH',
        'AGT-MAYA',
        'AGT-AISHA',
        'AGT-JAMES',
        'AGT-OLIVIA',
        'USR-ELEANOR',
        'USR-MARCUS',
        'USR-HELEN',
        'USR-AMELIA',
        'USR-SAM'
      ));
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'organisation_teams_no_legacy_demo_keys'
      AND conrelid = 'organisation_teams'::regclass
  ) THEN
    ALTER TABLE organisation_teams
      ADD CONSTRAINT organisation_teams_no_legacy_demo_keys
      CHECK (external_key NOT IN (
        'TEAM-SD',
        'TEAM-INFRA',
        'TEAM-EUC',
        'TEAM-CHANGE',
        'TEAM-LEADERSHIP',
        'TEAM-FINANCE',
        'TEAM-BIZOPS',
        'TEAM-PEOPLE'
      ));
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'organisation_departments_no_legacy_demo_keys'
      AND conrelid = 'organisation_departments'::regclass
  ) THEN
    ALTER TABLE organisation_departments
      ADD CONSTRAINT organisation_departments_no_legacy_demo_keys
      CHECK (external_key NOT IN (
        'DEPT-TECH',
        'DEPT-FIN',
        'DEPT-OPS',
        'DEPT-PEOPLE'
      ));
  END IF;
END $$;
