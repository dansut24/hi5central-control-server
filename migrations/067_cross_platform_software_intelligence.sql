-- Round 3 includes authoritative package/store intelligence for macOS, Linux and
-- cross-platform ecosystems. Hi5Central still executes software deployments only on
-- Windows, so these platform values are intelligence-only at the application layer.
ALTER TABLE rmm_software_catalogue
  DROP CONSTRAINT IF EXISTS rmm_software_catalogue_platform_check;
ALTER TABLE rmm_software_catalogue
  ADD CONSTRAINT rmm_software_catalogue_platform_check
  CHECK (platform IN ('windows','macos','linux','cross_platform'));
