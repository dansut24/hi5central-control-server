-- Distinguish application vulnerabilities from native OS/package exposures so
-- remediation is routed through the correct patching domain.
ALTER TABLE rmm_vulnerability_exposures
  ADD COLUMN IF NOT EXISTS exposure_class text NOT NULL DEFAULT 'application',
  ADD COLUMN IF NOT EXISTS remediation_domain text NOT NULL DEFAULT 'software',
  ADD COLUMN IF NOT EXISTS platform text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS package_manager text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS package_name text NOT NULL DEFAULT '';

UPDATE rmm_vulnerability_exposures
   SET exposure_class='application',
       remediation_domain='software'
 WHERE exposure_class='' OR remediation_domain='';

ALTER TABLE rmm_vulnerability_exposures
  DROP CONSTRAINT IF EXISTS rmm_vulnerability_exposures_class_check;

ALTER TABLE rmm_vulnerability_exposures
  ADD CONSTRAINT rmm_vulnerability_exposures_class_check
  CHECK (exposure_class IN ('application','os_package','os'));

ALTER TABLE rmm_vulnerability_exposures
  DROP CONSTRAINT IF EXISTS rmm_vulnerability_exposures_domain_check;

ALTER TABLE rmm_vulnerability_exposures
  ADD CONSTRAINT rmm_vulnerability_exposures_domain_check
  CHECK (remediation_domain IN ('software','os'));

CREATE INDEX IF NOT EXISTS rmm_vulnerability_exposures_domain_idx
  ON rmm_vulnerability_exposures(tenant_id,remediation_domain,exposure_class,status,last_seen_at DESC);

CREATE TABLE IF NOT EXISTS rmm_native_package_vulnerability_cache (
  ecosystem text NOT NULL,
  package_name text NOT NULL,
  version text NOT NULL,
  cve_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  checked_at timestamptz NOT NULL DEFAULT now(),
  last_error text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (ecosystem,package_name,version)
);

CREATE INDEX IF NOT EXISTS rmm_native_package_vulnerability_cache_checked_idx
  ON rmm_native_package_vulnerability_cache(checked_at);

INSERT INTO rmm_vulnerability_sync_state (source,enabled,metadata)
VALUES (
  'apple_security',
  true,
  '{"provider":"Apple Security Releases","scope":"macOS native OS CVEs"}'::jsonb
)
ON CONFLICT (source) DO NOTHING;
