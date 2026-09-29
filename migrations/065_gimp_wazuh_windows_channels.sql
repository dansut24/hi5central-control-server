UPDATE rmm_software_vendor_sources
   SET source_type='vendor_text',
       source_url='https://download.gimp.org/gimp/v3.2/windows/',
       metadata=metadata || jsonb_build_object(
         'adapter','gimp_windows_index',
         'staticReleaseUrl','https://download.gimp.org/gimp/v3.2/windows/'
       ),
       updated_at=now()
 WHERE source_key='gitlab_gimp';

UPDATE rmm_software_vendor_bindings
   SET metadata=metadata || jsonb_build_object(
         'adapter','gimp_windows_index',
         'repository','',
         'staticReleaseUrl','https://download.gimp.org/gimp/v3.2/windows/'
       )
 WHERE source_key='gitlab_gimp';

UPDATE rmm_software_vendor_sources
   SET source_type='vendor_text',
       source_url='https://documentation.wazuh.com/current/installation-guide/packages-list.html',
       metadata=metadata || jsonb_build_object(
         'adapter','wazuh_windows_packages',
         'staticReleaseUrl','https://documentation.wazuh.com/current/installation-guide/packages-list.html'
       ),
       updated_at=now()
 WHERE source_key='gh_wazuh_wazuh';

UPDATE rmm_software_vendor_bindings
   SET metadata=metadata || jsonb_build_object(
         'adapter','wazuh_windows_packages',
         'repository','',
         'staticReleaseUrl','https://documentation.wazuh.com/current/installation-guide/packages-list.html'
       )
 WHERE source_key='gh_wazuh_wazuh';
