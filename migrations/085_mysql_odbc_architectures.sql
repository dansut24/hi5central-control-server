-- Add explicit MySQL Connector/ODBC compatibility variants for Windows.
-- 8.0 x86 supports 32-bit applications; 9.x x64 supports the requested 64-bit v9 line.

INSERT INTO rmm_software_vendor_sources
  (source_key,display_name,source_type,source_url,enabled,priority,poll_minutes,metadata,updated_at)
VALUES
  (
    'mysql_connector_odbc_8_x86',
    'MySQL Connector/ODBC 8.0 x86',
    'vendor_api',
    'https://downloads.mysql.com/archives/c-odbc/',
    true, 930, 1440,
    '{"businessEssential":true,"vendorDirect":true,"compatibilitySeries":"8.0","architecture":"x86","pinnedArchive":true}'::jsonb,
    now()
  ),
  (
    'mysql_connector_odbc_9_x64',
    'MySQL Connector/ODBC 9 x64',
    'vendor_api',
    'https://downloads.mysql.com/archives/c-odbc/',
    true, 935, 1440,
    '{"businessEssential":true,"vendorDirect":true,"compatibilitySeries":"9","architecture":"x64","pinnedArchive":true}'::jsonb,
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
    'mysql_connector_odbc_8_x86',
    'vendor:mysql_connector_odbc_8_x86',
    'MySQL Connector/ODBC 8.0 x86',
    'Oracle Corporation',
    'stable','windows','x86',true,
    '{
      "businessEssential":true,
      "deploymentMode":"vendor_direct",
      "namePattern":"MySQL Connector/ODBC 8.0",
      "publisherPattern":"Oracle",
      "installerType":"msi",
      "architecture":"x86",
      "verificationConfig":{
        "method":"uninstall_registry",
        "packageId":"",
        "productCode":"",
        "displayNameContains":"MySQL Connector/ODBC 8.0",
        "publisherContains":"Oracle",
        "filePath":""
      }
    }'::jsonb
  ),
  (
    'mysql_connector_odbc_9_x64',
    'vendor:mysql_connector_odbc_9_x64',
    'MySQL Connector/ODBC 9 x64',
    'Oracle Corporation',
    'stable','windows','x64',true,
    '{
      "businessEssential":true,
      "deploymentMode":"vendor_direct",
      "namePattern":"MySQL Connector/ODBC 9.7",
      "publisherPattern":"Oracle",
      "installerType":"msi",
      "architecture":"x64",
      "verificationConfig":{
        "method":"uninstall_registry",
        "packageId":"",
        "productCode":"",
        "displayNameContains":"MySQL Connector/ODBC 9.7",
        "publisherContains":"Oracle",
        "filePath":""
      }
    }'::jsonb
  )
ON CONFLICT (source_key,provider_package_id,channel,platform,architecture) DO UPDATE SET
  canonical_name=EXCLUDED.canonical_name,
  publisher=EXCLUDED.publisher,
  enabled=true,
  metadata=rmm_software_vendor_bindings.metadata || EXCLUDED.metadata;
