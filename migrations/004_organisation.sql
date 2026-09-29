CREATE TABLE IF NOT EXISTS organisation_departments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  lead_person_id uuid,
  source jsonb NOT NULL DEFAULT '{"provider":"hi5central","managedFields":[]}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, external_key),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS organisation_teams (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  department_id uuid REFERENCES organisation_departments(id) ON DELETE SET NULL,
  name text NOT NULL,
  description text NOT NULL DEFAULT '',
  colour text NOT NULL DEFAULT 'blue',
  lead_person_id uuid,
  source jsonb NOT NULL DEFAULT '{"provider":"hi5central","managedFields":[]}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, external_key),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS organisation_sites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  code text NOT NULL,
  name text NOT NULL,
  type text NOT NULL DEFAULT 'Office',
  address_line1 text NOT NULL DEFAULT '',
  city text NOT NULL DEFAULT '',
  postcode text NOT NULL DEFAULT '',
  country text NOT NULL DEFAULT 'United Kingdom',
  timezone text NOT NULL DEFAULT 'Europe/London',
  primary_contact_id uuid,
  support_team_id uuid,
  rmm_site_key text NOT NULL DEFAULT '',
  rmm_link_status text NOT NULL DEFAULT 'not_linked' CHECK (rmm_link_status IN ('not_linked', 'linked_demo', 'linked')),
  notes text NOT NULL DEFAULT '',
  source jsonb NOT NULL DEFAULT '{"provider":"hi5central","managedFields":[]}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, external_key),
  UNIQUE (tenant_id, code),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS organisation_people (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  external_key text NOT NULL,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  primary_team_id uuid REFERENCES organisation_teams(id) ON DELETE SET NULL,
  department_id uuid REFERENCES organisation_departments(id) ON DELETE SET NULL,
  site_id uuid REFERENCES organisation_sites(id) ON DELETE SET NULL,
  manager_id uuid,
  name text NOT NULL,
  email text NOT NULL DEFAULT '',
  phone text NOT NULL DEFAULT '',
  job_title text NOT NULL DEFAULT '',
  availability text NOT NULL DEFAULT 'Available',
  capacity_hours numeric(5,2) NOT NULL DEFAULT 35,
  skills jsonb NOT NULL DEFAULT '[]'::jsonb,
  working_pattern jsonb NOT NULL DEFAULT '{}'::jsonb,
  access_profile text NOT NULL DEFAULT 'employee',
  directory_source jsonb NOT NULL DEFAULT '{"provider":"local","label":"Hi5Central","managedFields":[]}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, external_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS organisation_people_tenant_email_unique
  ON organisation_people (tenant_id, lower(email))
  WHERE email <> '';

CREATE TABLE IF NOT EXISTS organisation_team_memberships (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  person_id uuid NOT NULL REFERENCES organisation_people(id) ON DELETE CASCADE,
  team_id uuid NOT NULL REFERENCES organisation_teams(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'lead')),
  is_primary boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (person_id, team_id)
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organisation_people_manager_fk') THEN
    ALTER TABLE organisation_people
      ADD CONSTRAINT organisation_people_manager_fk
      FOREIGN KEY (manager_id) REFERENCES organisation_people(id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organisation_departments_lead_fk') THEN
    ALTER TABLE organisation_departments
      ADD CONSTRAINT organisation_departments_lead_fk
      FOREIGN KEY (lead_person_id) REFERENCES organisation_people(id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organisation_teams_lead_fk') THEN
    ALTER TABLE organisation_teams
      ADD CONSTRAINT organisation_teams_lead_fk
      FOREIGN KEY (lead_person_id) REFERENCES organisation_people(id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organisation_sites_primary_contact_fk') THEN
    ALTER TABLE organisation_sites
      ADD CONSTRAINT organisation_sites_primary_contact_fk
      FOREIGN KEY (primary_contact_id) REFERENCES organisation_people(id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organisation_sites_support_team_fk') THEN
    ALTER TABLE organisation_sites
      ADD CONSTRAINT organisation_sites_support_team_fk
      FOREIGN KEY (support_team_id) REFERENCES organisation_teams(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS organisation_departments_tenant_idx ON organisation_departments(tenant_id);
CREATE INDEX IF NOT EXISTS organisation_teams_tenant_idx ON organisation_teams(tenant_id);
CREATE INDEX IF NOT EXISTS organisation_teams_department_idx ON organisation_teams(tenant_id, department_id);
CREATE INDEX IF NOT EXISTS organisation_sites_tenant_idx ON organisation_sites(tenant_id);
CREATE INDEX IF NOT EXISTS organisation_people_tenant_idx ON organisation_people(tenant_id);
CREATE INDEX IF NOT EXISTS organisation_people_team_idx ON organisation_people(tenant_id, primary_team_id);
CREATE INDEX IF NOT EXISTS organisation_people_department_idx ON organisation_people(tenant_id, department_id);
CREATE INDEX IF NOT EXISTS organisation_people_site_idx ON organisation_people(tenant_id, site_id);
CREATE INDEX IF NOT EXISTS organisation_memberships_team_idx ON organisation_team_memberships(tenant_id, team_id);
