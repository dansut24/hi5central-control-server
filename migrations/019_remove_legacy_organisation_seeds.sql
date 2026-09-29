-- Remove the historical frontend organisation demo directory from real tenants.
-- Real People are preserved: the legacy frontend records never carried user_id.
-- Foreign keys referencing People/Teams/Departments use ON DELETE SET NULL/CASCADE,
-- so historical ITSM snapshots remain intact while fake directory entities disappear.

DELETE FROM organisation_people
WHERE user_id IS NULL
  AND external_key = ANY (ARRAY[
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

-- The former browser mirror could mark legitimate account-backed People and the
-- onboarding-created baseline organisation records inactive when it uploaded the
-- demo snapshot. Restore only entities whose identity is authoritative.
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
