CREATE TABLE IF NOT EXISTS access_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  role_key text NOT NULL,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  permissions text[] NOT NULL DEFAULT ARRAY[]::text[],
  system_key text,
  is_default boolean NOT NULL DEFAULT false,
  is_protected boolean NOT NULL DEFAULT false,
  active boolean NOT NULL DEFAULT true,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, role_key),
  UNIQUE (tenant_id, id),
  CHECK (role_key ~ '^[a-z0-9][a-z0-9-]{1,79}$')
);

CREATE TABLE IF NOT EXISTS access_user_roles (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL,
  assigned_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id, role_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES tenant_memberships(tenant_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, role_id) REFERENCES access_roles(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS access_roles_tenant_active_idx ON access_roles(tenant_id, active, name);
CREATE UNIQUE INDEX IF NOT EXISTS access_roles_tenant_system_key_uidx ON access_roles(tenant_id, system_key) WHERE system_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS access_user_roles_user_idx ON access_user_roles(tenant_id, user_id);

INSERT INTO access_roles (tenant_id, role_key, name, description, permissions, system_key, is_default, is_protected)
SELECT t.id, seed.role_key, seed.name, seed.description, seed.permissions, seed.system_key, true, seed.is_protected
FROM tenants t
CROSS JOIN (
  VALUES
    ('owner', 'Owner', 'Protected tenant owner with unrestricted access.', ARRAY['*']::text[], 'owner', true),
    ('administrator', 'Administrator', 'Broad tenant administration without ownership transfer.', ARRAY['workspace.access','dashboard.view','access.roles.view','access.roles.manage','access.roles.assign','settings.*','organisation.*','itsm.*','catalogue.*','knowledge.*','live_chat.*','projects.*','calendar.*','rota.*','notifications.*','cmdb.*','reports.*','integrations.*','rmm.*','audit.view','billing.view']::text[], 'administrator', false),
    ('analyst', 'Analyst', 'General ITSM analyst access for day-to-day service desk work.', ARRAY['workspace.access','dashboard.view','itsm.records.view_all','itsm.records.create_all','itsm.incidents.*','itsm.requests.*','itsm.problems.*','itsm.changes.view','itsm.changes.create','itsm.changes.edit','itsm.tasks.*','itsm.comments.internal','itsm.export','catalogue.view','knowledge.view_internal','live_chat.view','live_chat.claim','live_chat.reply','live_chat.close','live_chat.transfer','organisation.people.view','organisation.teams.view','organisation.departments.view','organisation.sites.view','projects.view','calendar.view','rota.view','cmdb.view','reports.view','notifications.view']::text[], 'analyst', false),
    ('requester', 'Requester', 'Portal-only requester access.', ARRAY['portal.access','portal.requests.create','portal.requests.view_own','portal.requests.comment','portal.knowledge.view','portal.live_chat.use']::text[], 'requester', false),
    ('approver', 'Approver', 'Portal approval capability. Stack with Requester for normal approvers.', ARRAY['portal.access','portal.approvals.view','portal.approvals.decide']::text[], 'approver', false),
    ('management', 'Management', 'Management visibility across operational work and people.', ARRAY['workspace.access','dashboard.view','itsm.incidents.view','itsm.requests.view','itsm.problems.view','itsm.changes.view','organisation.people.view','organisation.teams.view','organisation.departments.view','projects.view','calendar.view','rota.view','reports.view','notifications.view']::text[], 'management', false),
    ('change-board', 'Change Board / CAB', 'Focused Change Advisory Board access.', ARRAY['workspace.access','itsm.changes.view','itsm.changes.cab','itsm.changes.approve','notifications.view']::text[], 'change-board', false),
    ('knowledge-publisher', 'Knowledge Publisher', 'Create, edit and publish internal and portal knowledge.', ARRAY['workspace.access','knowledge.view_internal','knowledge.create','knowledge.edit','knowledge.publish','knowledge.archive','knowledge.link']::text[], 'knowledge-publisher', false),
    ('live-chat-analyst', 'Live Chat Analyst', 'Operate Live Chat without granting wider ITSM administration.', ARRAY['workspace.access','live_chat.view','live_chat.claim','live_chat.reply','live_chat.transfer','live_chat.close','notifications.view']::text[], 'live-chat-analyst', false),
    ('rmm-operator', 'RMM Operator', 'Operate endpoint monitoring and remote management.', ARRAY['workspace.access','rmm.access','rmm.devices.view','rmm.devices.control','rmm.devices.files','rmm.devices.terminal','rmm.devices.remote','rmm.alerts.manage','rmm.sites.view','rmm.groups.view','notifications.view']::text[], 'rmm-operator', false)
) AS seed(role_key, name, description, permissions, system_key, is_protected)
ON CONFLICT (tenant_id, role_key) DO NOTHING;

INSERT INTO access_user_roles (tenant_id, user_id, role_id)
SELECT m.tenant_id, m.user_id, r.id
FROM tenant_memberships m
JOIN access_roles r
  ON r.tenant_id = m.tenant_id
 AND r.system_key = CASE m.role
   WHEN 'owner' THEN 'owner'
   WHEN 'admin' THEN 'administrator'
   WHEN 'analyst' THEN 'analyst'
   WHEN 'requester' THEN 'requester'
   ELSE 'requester'
 END
ON CONFLICT DO NOTHING;
