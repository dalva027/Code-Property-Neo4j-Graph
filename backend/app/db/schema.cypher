// Uniqueness
CREATE CONSTRAINT project_id IF NOT EXISTS FOR (p:Project) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT file_id IF NOT EXISTS FOR (f:File) REQUIRE f.id IS UNIQUE;
CREATE CONSTRAINT symbol_id IF NOT EXISTS FOR (s:Symbol) REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE;

// Lookups: everything is scoped by project_id
CREATE INDEX file_project IF NOT EXISTS FOR (f:File) ON (f.project_id);
CREATE INDEX symbol_project IF NOT EXISTS FOR (s:Symbol) ON (s.project_id);
CREATE INDEX symbol_name IF NOT EXISTS FOR (s:Symbol) ON (s.name);
CREATE INDEX finding_project IF NOT EXISTS FOR (f:Finding) ON (f.project_id);
