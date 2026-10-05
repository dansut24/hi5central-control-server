INSERT INTO rmm_software_vendor_sources
  (source_key,display_name,source_type,source_url,enabled,priority,poll_minutes,metadata,updated_at)
VALUES
  (
    'microsoft_365_apps_current',
    'Microsoft 365 Apps - Current Channel',
    'microsoft_365_apps',
    'https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date',
    true,
    980,
    60,
    '{
      "vendorDirect": true,
      "businessEssential": true,
      "odtDownloadPage": "https://www.microsoft.com/en-us/download/details.aspx?id=49117",
      "channel": "Current",
      "releaseAuthority": "Microsoft 365 Apps update history",
      "deploymentAuthority": "Microsoft Office Deployment Tool"
    }'::jsonb,
    now()
  )
ON CONFLICT (source_key) DO UPDATE SET
  display_name=EXCLUDED.display_name,
  source_type=EXCLUDED.source_type,
  source_url=EXCLUDED.source_url,
  enabled=true,
  priority=EXCLUDED.priority,
  poll_minutes=EXCLUDED.poll_minutes,
  metadata=rmm_software_vendor_sources.metadata || EXCLUDED.metadata,
  updated_at=now();

INSERT INTO rmm_software_vendor_bindings
  (source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,enabled,metadata)
VALUES
  (
    'microsoft_365_apps_current',
    'vendor:microsoft_365_apps_enterprise_current',
    'Microsoft 365 Apps for enterprise',
    'Microsoft Corporation',
    'current',
    'windows',
    'x64',
    true,
    '{
      "businessEssential": true,
      "deploymentMode": "vendor_direct",
      "expectedSigner": "Microsoft Corporation",
      "signerBaseline": "Microsoft Corporation",
      "installerType": "exe",
      "installerTechnology": "office_odt_sfx",
      "officeProductId": "O365ProPlusRetail",
      "namePattern": "Microsoft 365 Apps for enterprise",
      "publisherPattern": "Microsoft Corporation",
      "odtDownloadPage": "https://www.microsoft.com/en-us/download/details.aspx?id=49117",
      "installArguments": "/configure {HI5_RESPONSE_FILE}",
      "responseFile": {
        "fileName": "microsoft-365-current.xml",
        "content": "<Configuration>\n  <Add OfficeClientEdition=\"64\" Channel=\"Current\" Version=\"{HI5_TARGET_VERSION}\" AllowCdnFallback=\"TRUE\">\n    <Product ID=\"O365ProPlusRetail\">\n      <Language ID=\"MatchOS\" Fallback=\"en-us\" />\n    </Product>\n  </Add>\n  <Updates Enabled=\"TRUE\" Channel=\"Current\" />\n  <Display Level=\"None\" AcceptEULA=\"TRUE\" />\n</Configuration>\n"
      },
      "verificationConfig": {
        "method": "office_c2r_registry",
        "productId": "O365ProPlusRetail",
        "displayNameContains": "Microsoft 365 Apps for enterprise",
        "publisherContains": "Microsoft Corporation"
      },
      "nvdVendor": "microsoft",
      "nvdProduct": "office",
      "qualificationNotes": "Microsoft Current Channel is authoritative for version discovery. Deployment uses Microsoft-signed ODT and Office CDN with Click-to-Run registry verification."
    }'::jsonb
  )
ON CONFLICT (source_key,provider_package_id,channel,platform,architecture) DO UPDATE SET
  canonical_name=EXCLUDED.canonical_name,
  publisher=EXCLUDED.publisher,
  enabled=true,
  metadata=rmm_software_vendor_bindings.metadata || EXCLUDED.metadata;

-- Keep the legacy Homebrew record explicitly scoped to macOS and prevent it from
-- becoming the Windows Office deployment source.
UPDATE rmm_software_catalogue
   SET source_metadata=source_metadata || jsonb_build_object(
         'platformScope','macos',
         'windowsDeploymentSource',false
       ),
       updated_at=now()
 WHERE tenant_id IS NULL
   AND platform='macos'
   AND lower(canonical_name)='microsoft office'
   AND source_metadata->>'latestSource'='registry_homebrew_microsoft_office';
