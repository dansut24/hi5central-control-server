CREATE TABLE IF NOT EXISTS tenant_record_counters (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  record_type text NOT NULL,
  next_value bigint NOT NULL DEFAULT 1 CHECK (next_value > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, record_type)
);

CREATE TABLE IF NOT EXISTS service_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  reference text NOT NULL,
  catalogue_item_id uuid REFERENCES service_catalogue_items(id) ON DELETE SET NULL,
  catalogue_item_key_snapshot text NOT NULL DEFAULT '',
  catalogue_item_title_snapshot text NOT NULL DEFAULT '',
  requester_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  requester_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  requester_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  description_html text NOT NULL DEFAULT '',
  request_type text NOT NULL DEFAULT 'Service Request',
  service text NOT NULL DEFAULT 'Service Catalogue',
  priority text NOT NULL DEFAULT 'Medium',
  status text NOT NULL DEFAULT 'New',
  source text NOT NULL DEFAULT 'technician',
  fulfilment_team_id uuid REFERENCES organisation_teams(id) ON DELETE SET NULL,
  fulfilment_team_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  assigned_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  submitted_fields jsonb NOT NULL DEFAULT '{}'::jsonb,
  request_information jsonb NOT NULL DEFAULT '[]'::jsonb,
  approval_mode_snapshot text NOT NULL DEFAULT 'none',
  approval_threshold_snapshot numeric(12,2),
  workflow_key_snapshot text NOT NULL DEFAULT '',
  one_off_cost numeric(12,2) NOT NULL DEFAULT 0 CHECK (one_off_cost >= 0),
  monthly_cost numeric(12,2) NOT NULL DEFAULT 0 CHECK (monthly_cost >= 0),
  currency text NOT NULL DEFAULT 'GBP',
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  closed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, reference)
);

CREATE TABLE IF NOT EXISTS service_request_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  request_id uuid NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
  catalogue_item_id uuid REFERENCES service_catalogue_items(id) ON DELETE SET NULL,
  catalogue_item_key_snapshot text NOT NULL DEFAULT '',
  name_snapshot text NOT NULL,
  category_snapshot text NOT NULL DEFAULT '',
  quantity integer NOT NULL DEFAULT 1 CHECK (quantity > 0),
  unit_one_off_cost numeric(12,2) NOT NULL DEFAULT 0 CHECK (unit_one_off_cost >= 0),
  unit_monthly_cost numeric(12,2) NOT NULL DEFAULT 0 CHECK (unit_monthly_cost >= 0),
  currency text NOT NULL DEFAULT 'GBP',
  selected_via text NOT NULL DEFAULT '',
  options_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
  product_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS service_request_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  request_id uuid NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
  sequence integer NOT NULL DEFAULT 1 CHECK (sequence > 0),
  label text NOT NULL,
  status text NOT NULL DEFAULT 'Pending',
  approver_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  approver_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  approver_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  decision_note text NOT NULL DEFAULT '',
  decided_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS service_request_tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  request_id uuid NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'Waiting',
  team_id uuid REFERENCES organisation_teams(id) ON DELETE SET NULL,
  team_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  assignee_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  assignee_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  instructions text NOT NULL DEFAULT '',
  dependencies jsonb NOT NULL DEFAULT '[]'::jsonb,
  due_at timestamptz,
  completion_notes text NOT NULL DEFAULT '',
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (request_id, external_key)
);

CREATE TABLE IF NOT EXISTS service_request_activities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  request_id uuid NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  actor_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  actor_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  kind text NOT NULL DEFAULT 'system',
  visibility text NOT NULL DEFAULT 'customer',
  body_text text NOT NULL DEFAULT '',
  body_html text NOT NULL DEFAULT '',
  attachments jsonb NOT NULL DEFAULT '[]'::jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS service_requests_tenant_status_idx
  ON service_requests(tenant_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS service_requests_requester_idx
  ON service_requests(tenant_id, requester_user_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS service_requests_team_idx
  ON service_requests(tenant_id, fulfilment_team_id, updated_at DESC)
  WHERE fulfilment_team_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS service_request_items_request_idx
  ON service_request_items(request_id);

CREATE INDEX IF NOT EXISTS service_request_approvals_request_idx
  ON service_request_approvals(request_id, sequence);

CREATE INDEX IF NOT EXISTS service_request_tasks_request_idx
  ON service_request_tasks(request_id, status);

CREATE INDEX IF NOT EXISTS service_request_activities_request_idx
  ON service_request_activities(request_id, created_at DESC);
