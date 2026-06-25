ALTER TABLE domains ADD COLUMN project_subdomain TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_project_subdomain ON domains(project_subdomain) WHERE project_subdomain IS NOT NULL;
