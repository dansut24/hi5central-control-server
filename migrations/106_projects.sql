-- Production project-management persistence.
CREATE TABLE IF NOT EXISTS project_reference_sequences (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  next_value integer NOT NULL DEFAULT 1 CHECK (next_value > 0)
);

CREATE TABLE IF NOT EXISTS projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  reference text NOT NULL,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  summary text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'Planned' CHECK (status IN ('Planned','In Progress','On Hold','Complete','Cancelled')),
  health text NOT NULL DEFAULT 'On Track' CHECK (health IN ('On Track','At Risk','Blocked','Complete')),
  priority text NOT NULL DEFAULT 'Medium' CHECK (priority IN ('Low','Medium','High','Critical')),
  owner_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  owner_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  sponsor_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  sponsor_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  team_id uuid REFERENCES organisation_teams(id) ON DELETE SET NULL,
  team_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  start_date date,
  target_date date,
  completed_at timestamptz,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_by_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, reference)
);

CREATE INDEX IF NOT EXISTS projects_tenant_status_idx ON projects(tenant_id,status,updated_at DESC);
CREATE INDEX IF NOT EXISTS projects_tenant_target_idx ON projects(tenant_id,target_date) WHERE status NOT IN ('Complete','Cancelled');

CREATE TABLE IF NOT EXISTS project_members (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  person_id uuid NOT NULL REFERENCES organisation_people(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'Member',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_id,person_id)
);

CREATE TABLE IF NOT EXISTS project_milestones (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  title text NOT NULL,
  due_date date,
  status text NOT NULL DEFAULT 'Planned' CHECK (status IN ('Planned','In Progress','Complete')),
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,external_key)
);

CREATE INDEX IF NOT EXISTS project_milestones_project_idx ON project_milestones(project_id,due_date);

CREATE TABLE IF NOT EXISTS project_tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'To Do' CHECK (status IN ('Backlog','To Do','In Progress','Blocked','Done')),
  priority text NOT NULL DEFAULT 'Medium' CHECK (priority IN ('Low','Medium','High','Critical')),
  assignee_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  assignee_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  start_date date,
  due_date date,
  planned_hours numeric(8,2) NOT NULL DEFAULT 0 CHECK (planned_hours >= 0),
  milestone_id uuid REFERENCES project_milestones(id) ON DELETE SET NULL,
  dependencies text[] NOT NULL DEFAULT ARRAY[]::text[],
  linked_record text NOT NULL DEFAULT '',
  completed_at timestamptz,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,external_key)
);

CREATE INDEX IF NOT EXISTS project_tasks_project_status_idx ON project_tasks(project_id,status,due_date);
CREATE INDEX IF NOT EXISTS project_tasks_assignee_idx ON project_tasks(tenant_id,assignee_person_id,status);

CREATE TABLE IF NOT EXISTS project_risks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  kind text NOT NULL DEFAULT 'Risk' CHECK (kind IN ('Risk','Issue')),
  title text NOT NULL,
  severity text NOT NULL DEFAULT 'Medium' CHECK (severity IN ('Low','Medium','High','Critical')),
  status text NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','Mitigating','Closed')),
  response text NOT NULL DEFAULT '',
  owner_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  owner_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  closed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,external_key)
);

CREATE INDEX IF NOT EXISTS project_risks_project_idx ON project_risks(project_id,status,severity);

CREATE TABLE IF NOT EXISTS project_activities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind text NOT NULL DEFAULT 'update',
  body_text text NOT NULL,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  actor_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  actor_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS project_activities_project_idx ON project_activities(project_id,created_at DESC);
