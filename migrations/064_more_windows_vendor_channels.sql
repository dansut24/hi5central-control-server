UPDATE rmm_software_vendor_sources
   SET source_type='vendor_text',
       source_url='https://download.nextcloud.com/desktop/releases/Windows/',
       metadata=metadata || jsonb_build_object(
         'adapter','nextcloud_windows_index',
         'staticReleaseUrl','https://download.nextcloud.com/desktop/releases/Windows/'
       ),
       updated_at=now()
 WHERE source_key='gh_nextcloud_desktop';

UPDATE rmm_software_vendor_bindings
   SET metadata=metadata || jsonb_build_object(
         'adapter','nextcloud_windows_index',
         'repository','',
         'staticReleaseUrl','https://download.nextcloud.com/desktop/releases/Windows/'
       )
 WHERE source_key='gh_nextcloud_desktop';

UPDATE rmm_software_vendor_sources
   SET source_type='vendor_text',
       source_url='https://qgis.org/download/',
       metadata=metadata || jsonb_build_object(
         'adapter','qgis_windows_download',
         'staticReleaseUrl','https://qgis.org/download/'
       ),
       updated_at=now()
 WHERE source_key='gh_qgis_qgis';

UPDATE rmm_software_vendor_bindings
   SET metadata=metadata || jsonb_build_object(
         'adapter','qgis_windows_download',
         'repository','',
         'staticReleaseUrl','https://qgis.org/download/'
       )
 WHERE source_key='gh_qgis_qgis';
