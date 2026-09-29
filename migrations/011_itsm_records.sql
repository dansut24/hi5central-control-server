CREATE TABLE IF NOT EXISTS itsm_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  reference text NOT NULL,
  record_type text NOT NULL CHECK (record_type IN ('Incident', 'Problem', 'Change')),
  requester_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  requester_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  service text NOT NULL DEFAULT '',
  category text NOT NULL DEFAULT '',
  priority text NOT NULL DEFAULT 'Medium',
  status text NOT NULL DEFAULT 'New',
  source text NOT NULL DEFAULT 'technician',
  assignment_team_id uuid REFERENCES organisation_teams(id) ON DELETE SET NULL,
  assignment_team_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  assigned_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  assignee_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  record_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  closed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, reference)
);

CREATE TABLE IF NOT EXISTS itsm_record_activities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  record_id uuid NOT NULL REFERENCES itsm_records(id) ON DELETE CASCADE,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  actor_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  actor_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  kind text NOT NULL DEFAULT 'system',
  visibility text NOT NULL DEFAULT 'internal',
  body_text text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS itsm_records_tenant_type_updated_idx
  ON itsm_records(tenant_id, record_type, updated_at DESC);

CREATE INDEX IF NOT EXISTS itsm_records_tenant_status_idx
  ON itsm_records(tenant_id, record_type, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS itsm_records_assignment_idx
  ON itsm_records(tenant_id, assignment_team_id, assigned_person_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS itsm_record_activities_record_idx
  ON itsm_record_activities(record_id, created_at DESC);
