UPDATE rmm_software_vendor_sources
   SET source_type='vendor_text',
       source_url='https://packages.element.io/desktop/install/win32/x64/index.html',
       metadata=metadata || jsonb_build_object(
         'adapter','element_windows_index',
         'staticReleaseUrl','https://packages.element.io/desktop/install/win32/x64/index.html'
       ),
       updated_at=now()
 WHERE source_key='gh_element_hq_element_desktop';

UPDATE rmm_software_vendor_bindings
   SET metadata=metadata || jsonb_build_object(
         'adapter','element_windows_index',
         'repository','',
         'staticReleaseUrl','https://packages.element.io/desktop/install/win32/x64/index.html'
       )
 WHERE source_key='gh_element_hq_element_desktop';

UPDATE rmm_software_vendor_sources
   SET source_type='vendor_text',
       source_url='https://grafana.com/grafana/download?edition=oss&platform=windows',
       metadata=metadata || jsonb_build_object(
         'adapter','grafana_windows_download',
         'staticReleaseUrl','https://grafana.com/grafana/download?edition=oss&platform=windows'
       ),
       updated_at=now()
 WHERE source_key='gh_grafana_grafana';

UPDATE rmm_software_vendor_bindings
   SET metadata=metadata || jsonb_build_object(
         'adapter','grafana_windows_download',
         'repository','',
         'staticReleaseUrl','https://grafana.com/grafana/download?edition=oss&platform=windows'
       )
 WHERE source_key='gh_grafana_grafana';
