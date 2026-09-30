CREATE TABLE IF NOT EXISTS person_feature_entitlements (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  person_id uuid NOT NULL REFERENCES organisation_people(id) ON DELETE CASCADE,
  live_chat_enabled boolean NOT NULL DEFAULT false,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, person_id)
);

CREATE TABLE IF NOT EXISTS live_chat_conversations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  reference text NOT NULL,
  requester_person_id uuid NOT NULL REFERENCES organisation_people(id) ON DELETE CASCADE,
  requester_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  assigned_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  assigned_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  subject text NOT NULL,
  status text NOT NULL DEFAULT 'Waiting' CHECK (status IN ('Waiting','Open','Closed')),
  requester_read_at timestamptz,
  agent_read_at timestamptz,
  closed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, reference)
);

CREATE INDEX IF NOT EXISTS live_chat_conversations_tenant_status_idx
  ON live_chat_conversations(tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS live_chat_conversations_requester_idx
  ON live_chat_conversations(tenant_id, requester_person_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS live_chat_conversations_assignee_idx
  ON live_chat_conversations(tenant_id, assigned_person_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS live_chat_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  conversation_id uuid NOT NULL REFERENCES live_chat_conversations(id) ON DELETE CASCADE,
  sender_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  sender_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  sender_role text NOT NULL CHECK (sender_role IN ('requester','agent','system')),
  sender_name text NOT NULL DEFAULT '',
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS live_chat_messages_conversation_idx
  ON live_chat_messages(conversation_id, created_at ASC);
