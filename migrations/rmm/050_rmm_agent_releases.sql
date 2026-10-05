CREATE TABLE IF NOT EXISTS rmm_agent_releases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  channel text NOT NULL,
  version text NOT NULL,
  patch_host_version text NOT NULL DEFAULT '',
  installer_url text NOT NULL,
  installer_sha256 text NOT NULL,
  build_commit text NOT NULL DEFAULT '',
  workflow_run bigint,
  status text NOT NULL DEFAULT 'test'
    CHECK (status IN ('test','active','retired')),
  release_notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (channel,version)
);

CREATE INDEX IF NOT EXISTS rmm_agent_releases_status_idx
  ON rmm_agent_releases(status,channel,created_at DESC);

INSERT INTO rmm_agent_releases
  (id,channel,version,patch_host_version,installer_url,installer_sha256,
   build_commit,workflow_run,status,release_notes)
VALUES
  ('a1720000-0000-4000-8000-000000000001','agent-hardening-v2','0.1.72','0.2.3',
   'https://downloads.hi5central.com/agent/hardening-v2/0.1.72/Hi5CentralAgentSetup.exe',
   '388e19c76d8050e6b3b2445e8dd4bcf90fcd9a5c5cafe3238d8ca65fd210a333',
   '7ae12d020f1b742cba3497db941e4e9ac5b4f4f5',35495454266,'test',
   'PatchHost 0.2.3 serializes and isolates software installs for controlled concurrency testing.')
ON CONFLICT (channel,version) DO UPDATE SET
  patch_host_version=EXCLUDED.patch_host_version,
  installer_url=EXCLUDED.installer_url,
  installer_sha256=EXCLUDED.installer_sha256,
  build_commit=EXCLUDED.build_commit,
  workflow_run=EXCLUDED.workflow_run,
  release_notes=EXCLUDED.release_notes,
  updated_at=now();
