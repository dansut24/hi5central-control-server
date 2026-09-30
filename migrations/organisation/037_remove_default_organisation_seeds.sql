-- Remove onboarding-created placeholder organisation scopes so production RMM/ITSM surfaces show only real data.
-- Account-backed People are preserved; generated site/team/department links clear through ON DELETE SET NULL.

DELETE FROM organisation_team_memberships m
USING organisation_teams t
WHERE m.team_id=t.id AND t.external_key='TEAM-SERVICE-DESK';

DELETE FROM organisation_sites
WHERE external_key='SITE-DEFAULT';

DELETE FROM organisation_teams
WHERE external_key='TEAM-SERVICE-DESK';

DELETE FROM organisation_departments
WHERE external_key='DEPT-DEFAULT';

-- Do not reserve these historical identifiers with database constraints.
-- Older integrations and test harnesses may legitimately reuse an identifier;
-- the important production rule is that Hi5Central no longer creates them automatically.
