-- Live Chat production operations: routing, read state, typing, attachments,
-- canned replies, record linking, service hours and queue metrics support.

ALTER TABLE live_chat_conversations
  ADD COLUMN IF NOT EXISTS linked_record_type text,
  ADD COLUMN IF NOT EXISTS linked_record_reference text,
  ADD COLUMN IF NOT EXISTS agent_typing_until timestamptz,
  ADD COLUMN IF NOT EXISTS requester_typing_until timestamptz,
  ADD COLUMN IF NOT EXISTS first_agent_response_at timestamptz,
  ADD COLUMN IF NOT EXISTS transferred_at timestamptz;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'live_chat_conversations_linked_record_type_check'
  ) THEN
    ALTER TABLE live_chat_conversations
      ADD CONSTRAINT live_chat_conversations_linked_record_type_check
      CHECK (
        linked_record_type IS NULL
        OR linked_record_type IN ('Incident','Problem','Change','Service Request')
      );
  END IF;
END
$$;

ALTER TABLE live_chat_messages
  ADD COLUMN IF NOT EXISTS delivered_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS read_at timestamptz;

CREATE TABLE IF NOT EXISTS live_chat_attachments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  conversation_id uuid NOT NULL REFERENCES live_chat_conversations(id) ON DELETE CASCADE,
  sender_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  sender_person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  sender_role text NOT NULL CHECK (sender_role IN ('requester','agent')),
  sender_name text NOT NULL DEFAULT '',
  file_name text NOT NULL,
  mime_type text NOT NULL,
  size_bytes integer NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 5242880),
  content bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS live_chat_attachments_conversation_idx
  ON live_chat_attachments(conversation_id, created_at ASC);

CREATE TABLE IF NOT EXISTS live_chat_canned_responses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  shortcut text NOT NULL,
  title text NOT NULL,
  body text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, shortcut),
  CHECK (shortcut = lower(shortcut)),
  CHECK (shortcut ~ '^[a-z0-9][a-z0-9_-]{0,39}$')
);

CREATE INDEX IF NOT EXISTS live_chat_canned_responses_active_idx
  ON live_chat_canned_responses(tenant_id, active, title);

CREATE TABLE IF NOT EXISTS live_chat_service_settings (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  service_hours_enabled boolean NOT NULL DEFAULT false,
  timezone text NOT NULL DEFAULT 'Europe/London',
  schedule jsonb NOT NULL DEFAULT '{
    "1":[["09:00","17:00"]],
    "2":[["09:00","17:00"]],
    "3":[["09:00","17:00"]],
    "4":[["09:00","17:00"]],
    "5":[["09:00","17:00"]]
  }'::jsonb,
  updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION hi5_live_chat_message_maintenance()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE live_chat_conversations
  SET first_agent_response_at = CASE
        WHEN NEW.sender_role = 'agent'
          THEN COALESCE(first_agent_response_at, NEW.created_at)
        ELSE first_agent_response_at
      END,
      updated_at = GREATEST(updated_at, NEW.created_at)
  WHERE id = NEW.conversation_id;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS live_chat_message_maintenance ON live_chat_messages;

CREATE TRIGGER live_chat_message_maintenance
AFTER INSERT ON live_chat_messages
FOR EACH ROW
EXECUTE FUNCTION hi5_live_chat_message_maintenance();

CREATE OR REPLACE FUNCTION hi5_live_chat_read_receipts()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.agent_read_at IS DISTINCT FROM OLD.agent_read_at
     AND NEW.agent_read_at IS NOT NULL THEN
    UPDATE live_chat_messages
    SET read_at = COALESCE(read_at, NEW.agent_read_at)
    WHERE conversation_id = NEW.id
      AND sender_role = 'requester'
      AND created_at <= NEW.agent_read_at;
  END IF;

  IF NEW.requester_read_at IS DISTINCT FROM OLD.requester_read_at
     AND NEW.requester_read_at IS NOT NULL THEN
    UPDATE live_chat_messages
    SET read_at = COALESCE(read_at, NEW.requester_read_at)
    WHERE conversation_id = NEW.id
      AND sender_role = 'agent'
      AND created_at <= NEW.requester_read_at;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS live_chat_read_receipts ON live_chat_conversations;

CREATE TRIGGER live_chat_read_receipts
AFTER UPDATE OF agent_read_at, requester_read_at ON live_chat_conversations
FOR EACH ROW
EXECUTE FUNCTION hi5_live_chat_read_receipts();

UPDATE live_chat_conversations c
SET first_agent_response_at = first_response.first_agent_response_at
FROM (
  SELECT conversation_id, min(created_at) AS first_agent_response_at
  FROM live_chat_messages
  WHERE sender_role = 'agent'
  GROUP BY conversation_id
) first_response
WHERE c.id = first_response.conversation_id
  AND c.first_agent_response_at IS NULL;

UPDATE live_chat_messages m
SET read_at = c.agent_read_at
FROM live_chat_conversations c
WHERE m.conversation_id = c.id
  AND m.sender_role = 'requester'
  AND c.agent_read_at IS NOT NULL
  AND m.created_at <= c.agent_read_at
  AND m.read_at IS NULL;

UPDATE live_chat_messages m
SET read_at = c.requester_read_at
FROM live_chat_conversations c
WHERE m.conversation_id = c.id
  AND m.sender_role = 'agent'
  AND c.requester_read_at IS NOT NULL
  AND m.created_at <= c.requester_read_at
  AND m.read_at IS NULL;
