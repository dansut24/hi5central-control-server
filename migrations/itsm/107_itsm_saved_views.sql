-- Persist ITSM queue views so technicians keep their working views across devices.
CREATE TABLE IF NOT EXISTS itsm_saved_views (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  record_type text NOT NULL CHECK (record_type IN ('Incident','Service Request','Problem','Change')),
  name text NOT NULL,
  visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private','shared')),
  query text NOT NULL DEFAULT '',
  filters jsonb NOT NULL DEFAULT '{}'::jsonb,
  view_style text NOT NULL DEFAULT 'table' CHECK (view_style IN ('table','compact','cards')),
  columns jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS itsm_saved_views_owner_name_idx
  ON itsm_saved_views(tenant_id, owner_user_id, record_type, lower(name));

CREATE INDEX IF NOT EXISTS itsm_saved_views_tenant_type_idx
  ON itsm_saved_views(tenant_id, record_type, visibility, updated_at DESC);