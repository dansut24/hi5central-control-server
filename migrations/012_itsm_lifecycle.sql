ALTER TABLE itsm_records
  ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS impact text NOT NULL DEFAULT 'Medium',
  ADD COLUMN IF NOT EXISTS urgency text NOT NULL DEFAULT 'Medium',
  ADD COLUMN IF NOT EXISTS first_response_at timestamptz,
  ADD COLUMN IF NOT EXISTS response_due_at timestamptz,
  ADD COLUMN IF NOT EXISTS resolution_due_at timestamptz,
  ADD COLUMN IF NOT EXISTS sla_paused_at timestamptz,
  ADD COLUMN IF NOT EXISTS sla_paused_seconds bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS resolved_at timestamptz,
  ADD COLUMN IF NOT EXISTS resolution_code text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS resolution_summary text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS itsm_record_relationships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source_record_id uuid NOT NULL REFERENCES itsm_records(id) ON DELETE CASCADE,
  target_reference text NOT NULL,
  target_type text NOT NULL,
  relationship_type text NOT NULL DEFAULT 'related',
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_record_id, target_reference, relationship_type)
);

CREATE TABLE IF NOT EXISTS itsm_record_attachments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  record_id uuid NOT NULL REFERENCES itsm_records(id) ON DELETE CASCADE,
  file_name text NOT NULL,
  mime_type text NOT NULL DEFAULT 'application/octet-stream',
  byte_size bigint NOT NULL CHECK (byte_size > 0),
  sha256 text NOT NULL,
  content bytea NOT NULL,
  uploaded_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  uploaded_by_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS itsm_record_relationships_source_idx
  ON itsm_record_relationships(source_record_id, created_at DESC);

CREATE INDEX IF NOT EXISTS itsm_record_relationships_target_idx
  ON itsm_record_relationships(tenant_id, target_reference, created_at DESC);

CREATE INDEX IF NOT EXISTS itsm_record_attachments_record_idx
  ON itsm_record_attachments(record_id, created_at DESC);

CREATE INDEX IF NOT EXISTS itsm_records_sla_idx
  ON itsm_records(tenant_id, record_type, status, resolution_due_at)
  WHERE record_type = 'Incident' AND closed_at IS NULL;
