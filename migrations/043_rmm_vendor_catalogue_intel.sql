CREATE TABLE IF NOT EXISTS rmm_software_vendor_sources (
  source_key text PRIMARY KEY,
  display_name text NOT NULL,
  source_type text NOT NULL,
  source_url text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 100,
  poll_minutes integer NOT NULL DEFAULT 60 CHECK (poll_minutes BETWEEN 5 AND 10080),
  cursor_value text NOT NULL DEFAULT '',
  last_attempt_at timestamptz,
  last_success_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  records_seen bigint NOT NULL DEFAULT 0,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rmm_software_vendor_bindings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_key text NOT NULL REFERENCES rmm_software_vendor_sources(source_key) ON DELETE CASCADE,
  provider_package_id text NOT NULL,
  canonical_name text NOT NULL,
  publisher text NOT NULL DEFAULT '',
  channel text NOT NULL DEFAULT 'stable',
  platform text NOT NULL DEFAULT 'windows',
  architecture text NOT NULL DEFAULT 'x64',
  enabled boolean NOT NULL DEFAULT true,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (source_key, provider_package_id, channel, platform, architecture)
);
CREATE TABLE IF NOT EXISTS rmm_software_vendor_releases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_key text NOT NULL REFERENCES rmm_software_vendor_sources(source_key) ON DELETE CASCADE,
  provider_package_id text NOT NULL,
  canonical_name text NOT NULL,
  publisher text NOT NULL DEFAULT '',
  channel text NOT NULL DEFAULT 'stable',
  platform text NOT NULL DEFAULT 'windows',
  architecture text NOT NULL DEFAULT 'x64',
  version text NOT NULL,
  release_date timestamptz,
  installer_url text NOT NULL DEFAULT '',
  installer_sha256 text NOT NULL DEFAULT '',
  installer_type text NOT NULL DEFAULT '',
  source_priority integer NOT NULL DEFAULT 100,
  source_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_key, provider_package_id, channel, platform, architecture, version)
);

CREATE INDEX IF NOT EXISTS rmm_software_vendor_releases_latest_idx
  ON rmm_software_vendor_releases(provider_package_id, channel, platform, architecture, release_date DESC, last_seen_at DESC);
INSERT INTO rmm_software_vendor_sources (source_key,display_name,source_type,source_url,priority,poll_minutes)
VALUES
  ('google_chrome','Google Chrome','vendor_api','https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions',500,15),
  ('microsoft_edge','Microsoft Edge','vendor_api','https://edgeupdates.microsoft.com/api/products?view=enterprise',500,15),
  ('mozilla_firefox','Mozilla Firefox','vendor_json','https://product-details.mozilla.org/1.0/firefox_versions.json',500,30),
  ('mozilla_thunderbird','Mozilla Thunderbird','vendor_json','https://product-details.mozilla.org/1.0/thunderbird_versions.json',500,30),
  ('microsoft_vscode','Visual Studio Code','vendor_api','https://update.code.visualstudio.com/api/releases/stable',500,30),
  ('sevenzip','7-Zip','vendor_release','https://www.7-zip.org/download.html',450,60),
  ('adobe_acrobat_reader','Adobe Acrobat Reader','vendor_release','https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html',450,30)
ON CONFLICT (source_key) DO NOTHING;
INSERT INTO rmm_software_vendor_bindings
  (source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,metadata)
VALUES
  ('google_chrome','Google.Chrome','Google Chrome','Google LLC','stable','windows','x64','{"winget_provider":true}'::jsonb),
  ('microsoft_edge','Microsoft.Edge','Microsoft Edge','Microsoft Corporation','stable','windows','x64','{"winget_provider":true}'::jsonb),
  ('mozilla_firefox','Mozilla.Firefox','Mozilla Firefox','Mozilla','stable','windows','x64','{"winget_provider":true}'::jsonb),
  ('mozilla_thunderbird','Mozilla.Thunderbird','Mozilla Thunderbird','Mozilla','stable','windows','x64','{"winget_provider":true}'::jsonb),
  ('microsoft_vscode','Microsoft.VisualStudioCode','Visual Studio Code','Microsoft Corporation','stable','windows','x64','{"winget_provider":true}'::jsonb),
  ('sevenzip','7zip.7zip','7-Zip','Igor Pavlov','stable','windows','x64','{"winget_provider":true}'::jsonb),
  ('adobe_acrobat_reader','Adobe.Acrobat.Reader.64-bit','Adobe Acrobat Reader','Adobe','continuous','windows','x64','{"winget_provider":true}'::jsonb)
ON CONFLICT (source_key,provider_package_id,channel,platform,architecture) DO NOTHING;
