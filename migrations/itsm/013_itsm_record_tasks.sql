CREATE TABLE IF NOT EXISTS itsm_record_tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  record_id uuid NOT NULL REFERENCES itsm_records(id) ON DELETE CASCADE,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'Open',
  team_id uuid REFERENCES organisation_teams(id) ON DELETE SET NULL,
  team_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  assignee_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  assignee_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  instructions text NOT NULL DEFAULT '',
  due_at timestamptz,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_by_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS itsm_record_tasks_record_idx
  ON itsm_record_tasks(record_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS itsm_record_tasks_tenant_assignee_idx
  ON itsm_record_tasks(tenant_id, assignee_person_id, status, due_at)
  WHERE assignee_person_id IS NOT NULL;
