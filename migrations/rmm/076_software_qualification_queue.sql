CREATE TABLE IF NOT EXISTS rmm_software_qualification_queue (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  catalogue_id uuid NOT NULL REFERENCES rmm_software_catalogue(id) ON DELETE CASCADE,
  test_type text NOT NULL DEFAULT 'clean_install' CHECK (test_type IN ('clean_install','upgrade')),
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','cleanup_pending','cleanup_running','passed','review_required','cancelled')),
  priority integer NOT NULL DEFAULT 100,
  attempt_count integer NOT NULL DEFAULT 0,
  runner_agent_device_id uuid REFERENCES rmm_agent_devices(id) ON DELETE SET NULL,
  agent_job_id uuid REFERENCES rmm_agent_jobs(id) ON DELETE SET NULL,
  deployment_id uuid REFERENCES rmm_patch_deployments(id) ON DELETE SET NULL,
  cleanup_job_id uuid REFERENCES rmm_agent_jobs(id) ON DELETE SET NULL,
  last_error text NOT NULL DEFAULT '',
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (catalogue_id,test_type)
);

CREATE INDEX IF NOT EXISTS rmm_software_qualification_queue_state_idx
  ON rmm_software_qualification_queue (state,priority DESC,created_at);

CREATE INDEX IF NOT EXISTS rmm_software_qualification_queue_runner_idx
  ON rmm_software_qualification_queue (runner_agent_device_id,state);
