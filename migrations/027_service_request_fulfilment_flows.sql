CREATE TABLE IF NOT EXISTS service_catalogue_fulfilment_flows (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  catalogue_item_key text NOT NULL,
  tasks jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, catalogue_item_key),
  CHECK (jsonb_typeof(tasks) = 'array')
);

CREATE INDEX IF NOT EXISTS service_catalogue_fulfilment_flows_tenant_idx
  ON service_catalogue_fulfilment_flows(tenant_id, updated_at DESC);

ALTER TABLE service_requests
  ADD COLUMN IF NOT EXISTS workflow_tasks_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON TABLE service_catalogue_fulfilment_flows IS
  'Simple per-catalogue-item fulfilment task flows. Dependencies are configured by task key and snapshotted onto each request.';

COMMENT ON COLUMN service_requests.workflow_tasks_snapshot IS
  'Immutable fulfilment flow snapshot captured when the Service Request is submitted.';
