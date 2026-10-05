ALTER TABLE rmm_software_catalogue
  ADD COLUMN IF NOT EXISTS icon_url text NOT NULL DEFAULT '';

COMMENT ON COLUMN rmm_software_catalogue.icon_url IS
  'Curated application icon URL used by Self Service and other catalogue surfaces.';