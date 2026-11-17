// Uniqueness
CREATE CONSTRAINT project_id IF NOT EXISTS FOR (p:Project) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT file_id IF NOT EXISTS FOR (f:File) REQUIRE f.id IS UNIQUE;
CREATE CONSTRAINT symbol_id IF NOT EXISTS FOR (s:Symbol) REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE;
// Advisories are global: one node per RustSec id, shared by every project that is affected.
CREATE CONSTRAINT advisory_id IF NOT EXISTS FOR (a:Advisory) REQUIRE a.id IS UNIQUE;

// Lookups: everything else is scoped by project_id
CREATE INDEX file_project IF NOT EXISTS FOR (f:File) ON (f.project_id);
CREATE INDEX symbol_project IF NOT EXISTS FOR (s:Symbol) ON (s.project_id);
CREATE INDEX symbol_name IF NOT EXISTS FOR (s:Symbol) ON (s.name);
CREATE INDEX finding_project IF NOT EXISTS FOR (f:Finding) ON (f.project_id);
CREATE INDEX project_status IF NOT EXISTS FOR (p:Project) ON (p.status);

// Schema v2 (docs/build-plan.md section 5)
CREATE INDEX external_path IF NOT EXISTS FOR (e:External) ON (e.project_id, e.path);
CREATE INDEX function_entry_kind IF NOT EXISTS FOR (f:Function) ON (f.project_id, f.entry_kind);
CREATE INDEX crate_name IF NOT EXISTS FOR (c:Crate) ON (c.project_id, c.name);
CREATE INDEX finding_category IF NOT EXISTS FOR (f:Finding) ON (f.project_id, f.category);

// Security facts (phase 2): unsafe spans, call sites of interest, redacted secret literals
CREATE CONSTRAINT unsafe_id IF NOT EXISTS FOR (u:Unsafe) REQUIRE u.id IS UNIQUE;
CREATE CONSTRAINT call_id IF NOT EXISTS FOR (c:Call) REQUIRE c.id IS UNIQUE;
CREATE CONSTRAINT literal_id IF NOT EXISTS FOR (l:Literal) REQUIRE l.id IS UNIQUE;
CREATE INDEX unsafe_project IF NOT EXISTS FOR (u:Unsafe) ON (u.project_id);
CREATE INDEX call_project IF NOT EXISTS FOR (c:Call) ON (c.project_id, c.callee_path);
CREATE INDEX literal_project IF NOT EXISTS FOR (l:Literal) ON (l.project_id);
CREATE INDEX function_entry_distance IF NOT EXISTS FOR (f:Function) ON (f.project_id, f.entry_distance);

// Data flow (phase 3): parameters, locals and return values, connected by FLOWS_TO / PASSES / RETURNS_TO
CREATE CONSTRAINT var_id IF NOT EXISTS FOR (v:Var) REQUIRE v.id IS UNIQUE;
CREATE INDEX var_project IF NOT EXISTS FOR (v:Var) ON (v.project_id, v.subkind);
CREATE INDEX var_param_type IF NOT EXISTS FOR (v:Var) ON (v.project_id, v.param_type);
