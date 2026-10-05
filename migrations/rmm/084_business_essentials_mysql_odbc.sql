INSERT INTO rmm_software_vendor_sources
  (source_key,display_name,source_type,source_url,enabled,priority,poll_minutes,metadata,updated_at)
VALUES
  (
    'mysql_connector_odbc',
    'MySQL Connector/ODBC',
    'vendor_api',
    'https://dev.mysql.com/downloads/connector/odbc/',
    true,
    900,
    180,
    '{"businessEssential":true,"vendorDirect":true,"archiveUrl":"https://downloads.mysql.com/archives/c-odbc/"}'::jsonb,
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
    'mysql_connector_odbc',
    'vendor:mysql_connector_odbc',
    'MySQL Connector/ODBC',
    'Oracle Corporation',
    'stable',
    'windows',
    'x64',
    true,
    '{
      "businessEssential": true,
      "deploymentMode": "vendor_direct",
      "namePattern": "MySQL Connector/ODBC",
      "publisherPattern": "Oracle",
      "installerType": "msi",
      "verificationConfig": {
        "method": "uninstall_registry",
        "packageId": "",
        "productCode": "",
        "displayNameContains": "MySQL Connector/ODBC",
        "publisherContains": "Oracle",
        "filePath": ""
      }
    }'::jsonb
  )
ON CONFLICT (source_key,provider_package_id,channel,platform,architecture) DO UPDATE SET
  canonical_name=EXCLUDED.canonical_name,
  publisher=EXCLUDED.publisher,
  enabled=true,
  metadata=rmm_software_vendor_bindings.metadata || EXCLUDED.metadata;

-- Correct the PuTTY CPE identity to the NVD vendor/product actually used in the CPE dictionary.
UPDATE rmm_software_vulnerability_identities vi
   SET enabled=false,updated_at=now()
  FROM rmm_software_catalogue c
 WHERE vi.catalogue_id=c.id
   AND c.tenant_id IS NULL
   AND lower(c.canonical_name)='putty'
   AND vi.source='nvd'
   AND lower(vi.vendor)='putty'
   AND lower(vi.product)='putty';

UPDATE rmm_software_catalogue
   SET cpe_vendor='simon_tatham',
       cpe_product='putty',
       source_metadata=source_metadata || '{"nvdVendor":"simon_tatham","nvdProduct":"putty"}'::jsonb,
       updated_at=now()
 WHERE tenant_id IS NULL
   AND status='active'
   AND lower(canonical_name)='putty';

INSERT INTO rmm_software_vulnerability_identities
  (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
SELECT c.id,'nvd','simon_tatham','putty',
       'cpe:2.3:a:simon_tatham:putty:*:*:*:*:*:*:*:*','','','curated',true,
       '{"origin":"business_essentials_cpe_correction","verifiedAgainstNvd":true}'::jsonb
  FROM rmm_software_catalogue c
 WHERE c.tenant_id IS NULL
   AND c.status='active'
   AND lower(c.canonical_name)='putty'
ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now();
