//! The walk over every workspace source file: symbols, resolved call sites and data flow.
//!
//! Two passes. The first lists the items of each file and registers every function with its
//! parameter and return variables, so the second can connect a call site to its callee's
//! parameters whatever order the files come in. The second walks each function body once and
//! records call sites (resolved to a workspace function or to an external path), macro
//! invocations and the calls their expansions make, index and integer arithmetic operations, and
//! a flow-insensitive, field-insensitive def-use graph over locals and call sites (see
//! docs/build-plan.md section 5.4).
//!
//! Data-flow conventions:
//! - a call to something outside the workspace is a summary: receiver and arguments flow into the
//!   site, the site flows to whatever the result is bound to;
//! - a call to a workspace function passes each argument to the matching parameter variable and
//!   the callee's return variable flows to the site, so paths run through the callee's body;
//! - `x.push(y)` on a `&mut self` method taints `x`; `f(&mut x)` taints `x` with the call;
//! - a closure passed to a call receives what flows into the call's receiver and other arguments;
//! - checks are flow-insensitive: a comparison or a bool-returning call anywhere in the function
//!   is recorded as a guard on the variables involved.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use ra_ap_hir::{
    self as hir, AsAssocItem, AssocItemContainer, ModuleDef, PathResolution, Semantics,
};
use ra_ap_ide_db::RootDatabase;
use ra_ap_syntax::ast::{self, BinaryOp, HasArgList, HasName};
use ra_ap_syntax::{AstNode, SyntaxKind, SyntaxNode, TextRange, TextSize};
use ra_ap_vfs::{FileId, Vfs};

use super::names::{crate_name, truncate, ty_kind, Namer};
use crate::facts::{
    CodeFacts, CrateInfo, FileFact, FlowFact, FnFact, ParamFact, RefFact, SiteFact, SymbolFact,
    VarFact,
};

const MAX_MACRO_DEPTH: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Atom {
    Var(u32),
    Site(u32),
}

impl Atom {
    fn key(self) -> String {
        match self {
            Atom::Var(id) => format!("v{id}"),
            Atom::Site(id) => format!("s{id}"),
        }
    }
}

type Atoms = Vec<Atom>;

fn merge(into: &mut Atoms, more: &[Atom]) {
    for atom in more {
        if !into.contains(atom) {
            into.push(*atom);
        }
    }
}

struct FileInfo {
    id: u32,
    line_starts: Vec<u32>,
}

/// What a function body is analyzed relative to.
#[derive(Clone, Copy)]
struct Scope {
    fn_id: u32,
    file: FileId,
    /// The crate root, where public paths are searched from.
    from: hir::Module,
    krate: hir::Crate,
}

struct FnEntry {
    scope: Scope,
    node: ast::Fn,
    def: Option<hir::Function>,
    /// Variable ids per parameter index (a pattern parameter binds several).
    params: Vec<Vec<u32>>,
    /// (rust-analyzer binding id, variable id) of the parameters.
    param_locals: Vec<(u32, u32)>,
    ret_var: Option<u32>,
}

#[derive(Clone)]
struct ClosureInfo {
    params: Vec<Vec<u32>>,
    ret: Atoms,
}

#[derive(Clone)]
struct MacroCtx {
    /// Where the outermost macro invocation starts.
    pos: (u32, u32),
    range: TextRange,
    /// Keep call sites that come from a macro's definition, not only from the invocation's tokens.
    keep_all: bool,
}

pub struct Walker<'db> {
    db: &'db RootDatabase,
    sema: &'db Semantics<'db, RootDatabase>,
    vfs: &'db Vfs,
    root: PathBuf,
    namer: Namer<'db>,
    files: HashMap<FileId, FileInfo>,
    fn_by_pos: HashMap<(FileId, TextSize), u32>,
    fn_ids: HashMap<hir::Function, Option<u32>>,
    fns: Vec<FnEntry>,
    flow_seen: HashSet<(Atom, Atom, &'static str)>,
    pub facts: CodeFacts,

    // State of the function being walked.
    scope: Option<Scope>,
    unsafe_depth: u32,
    locals: HashMap<u32, u32>,
    names: HashMap<String, u32>,
    closures: HashMap<u32, ClosureInfo>,
    last_closure: Option<ClosureInfo>,
    guards: HashMap<u32, BTreeSet<String>>,
    seq: HashMap<(u32, u32), u32>,
    mapped_sites: HashMap<(u32, u32, &'static str), u32>,
    macro_ctx: Option<MacroCtx>,
    macro_depth: u32,
    /// Sites of the macro invocations being expanded, outermost first.
    macro_sites: Vec<u32>,
    via: Vec<String>,
}

fn last_segment(path: &ast::Path) -> String {
    path.segment()
        .and_then(|segment| segment.name_ref())
        .map(|name| name.text().to_string())
        .unwrap_or_else(|| path.syntax().text().to_string())
}

fn string_value(text: &str) -> String {
    match (text.find('"'), text.rfind('"')) {
        (Some(start), Some(end)) if start < end => text[start + 1..end].to_owned(),
        _ => String::new(),
    }
}

/// (kind, text) of an argument that is a literal, as the tree-sitter parser reports them.
fn literal(expr: &ast::Expr) -> Option<(&'static str, String)> {
    let text = expr.syntax().text().to_string();
    match expr {
        ast::Expr::Literal(lit) => Some(match lit.kind() {
            ast::LiteralKind::String(_)
            | ast::LiteralKind::ByteString(_)
            | ast::LiteralKind::CString(_) => ("str", truncate(&string_value(&text), 24)),
            ast::LiteralKind::IntNumber(_) => ("int", truncate(&text, 24)),
            ast::LiteralKind::FloatNumber(_) => ("float", truncate(&text, 24)),
            ast::LiteralKind::Char(_) | ast::LiteralKind::Byte(_) => ("char", truncate(&text, 24)),
            ast::LiteralKind::Bool(_) => ("bool", text),
        }),
        ast::Expr::PrefixExpr(prefix) => match prefix.expr()? {
            ast::Expr::Literal(inner) => match inner.kind() {
                ast::LiteralKind::IntNumber(_) => Some(("int", truncate(&text, 24))),
                ast::LiteralKind::FloatNumber(_) => Some(("float", truncate(&text, 24))),
                _ => None,
            },
            _ => None,
        },
        ast::Expr::ArrayExpr(_) => Some(("array", truncate(&text, 24))),
        // A constant passed by name (`header::LOCATION`): not a literal, but as fixed as one, and
        // a rule may need to know which constant it is.
        ast::Expr::PathExpr(path) => {
            let name = last_segment(&path.path()?);
            let constant = name.len() > 1
                && name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            constant.then(|| ("path", truncate(&text, 48)))
        }
        _ => None,
    }
}

/// Does an index expression mention a name, so it is not a constant such as `v[0]` or `v[..]`?
fn mentions_name(expr: &ast::Expr) -> bool {
    expr.syntax().descendants().any(|node| {
        matches!(
            node.kind(),
            SyntaxKind::PATH_EXPR
                | SyntaxKind::FIELD_EXPR
                | SyntaxKind::CALL_EXPR
                | SyntaxKind::METHOD_CALL_EXPR
        )
    })
}

/// Names written as `{name}` or `{name:?}` in a format string.
fn inline_format_names(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if bytes.get(i + 1) == Some(&b'{') {
                i += 2;
                continue;
            }
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            let closes = matches!(bytes.get(end), Some(b'}') | Some(b':'));
            if end > start && closes && !bytes[start].is_ascii_digit() {
                names.push(template[start..end].to_owned());
            }
            i = end;
        }
        i += 1;
    }
    names
}

impl<'db> Walker<'db> {
    pub fn new(
        db: &'db RootDatabase,
        sema: &'db Semantics<'db, RootDatabase>,
        vfs: &'db Vfs,
        root: &Path,
    ) -> Self {
        Walker {
            db,
            sema,
            vfs,
            root: root.to_path_buf(),
            namer: Namer::new(db),
            files: HashMap::new(),
            fn_by_pos: HashMap::new(),
            fn_ids: HashMap::new(),
            fns: Vec::new(),
            flow_seen: HashSet::new(),
            facts: CodeFacts::default(),
            scope: None,
            unsafe_depth: 0,
            locals: HashMap::new(),
            names: HashMap::new(),
            closures: HashMap::new(),
            last_closure: None,
            guards: HashMap::new(),
            seq: HashMap::new(),
            mapped_sites: HashMap::new(),
            macro_ctx: None,
            macro_depth: 0,
            macro_sites: Vec::new(),
            via: Vec::new(),
        }
    }

    pub fn run(&mut self) {
        self.collect();
        self.link_dispatch();
        for index in 0..self.fns.len() {
            if self.fns[index].def.is_none() || self.fns[index].node.body().is_none() {
                continue;
            }
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| self.walk_fn(index)));
            if outcome.is_err() {
                self.facts.stats.panicked_functions += 1;
                let fact = &self.facts.fns[index];
                let file = &self.facts.files[fact.file as usize].path;
                if self.facts.warnings.len() < 50 {
                    self.facts.warnings.push(format!(
                        "analysis of {} ({}:{}) stopped early: rust-analyzer panicked",
                        fact.name, file, fact.line
                    ));
                }
            }
        }
        self.facts.stats.files = self.facts.files.len() as u32;
        self.facts.stats.functions = self.facts.fns.len() as u32;
        self.facts.stats.analyzed_functions =
            self.facts.fns.iter().filter(|f| f.analyzed).count() as u32;
    }

    // -- pass 1: files, symbols, functions ---------------------------------------------------
    fn rel_path(&self, file: FileId) -> Option<String> {
        let path: &Path = self.vfs.file_path(file).as_path()?.as_ref();
        let rel = path.strip_prefix(&self.root).ok()?;
        Some(rel.to_string_lossy().replace('\\', "/"))
    }

    fn collect(&mut self) {
        let db = self.db;
        let mut sources = Vec::new();
        for krate in hir::Crate::all(db) {
            if !krate.origin(db).is_local() {
                continue;
            }
            let name = crate_name(db, krate).unwrap_or_else(|| "?".to_owned());
            let mut listed = false;
            for module in krate.modules(db) {
                let Some(source) = module.as_source_file_id(db) else {
                    continue;
                };
                let file = source.file_id(db);
                if self.files.contains_key(&file) {
                    continue;
                }
                let Some(path) = self.rel_path(file) else {
                    continue;
                };
                if !listed {
                    listed = true;
                    let root_file = self.rel_path(krate.root_file(db)).unwrap_or_default();
                    self.facts.crates.push(CrateInfo {
                        name: name.clone(),
                        root_file,
                    });
                }
                let id = self.facts.files.len() as u32;
                self.files.insert(
                    file,
                    FileInfo {
                        id,
                        line_starts: Vec::new(),
                    },
                );
                self.facts.files.push(FileFact {
                    id,
                    path,
                    crate_name: name.clone(),
                    symbols: Vec::new(),
                });
                sources.push((file, source, krate));
            }
        }

        for (file, source, krate) in sources {
            let tree = self.sema.parse(source);
            let text = tree.syntax().text().to_string();
            let mut starts = vec![0u32];
            starts.extend(
                text.bytes()
                    .enumerate()
                    .filter(|(_, b)| *b == b'\n')
                    .map(|(i, _)| i as u32 + 1),
            );
            let file_id = {
                let info = self.files.get_mut(&file).expect("registered above");
                info.line_starts = starts;
                info.id
            };
            let from = krate.root_module(db);
            for node in tree.syntax().descendants() {
                let (kind, name) = match node.kind() {
                    SyntaxKind::FN => ("fn", ast::Fn::cast(node.clone()).and_then(|it| it.name())),
                    SyntaxKind::STRUCT => (
                        "struct",
                        ast::Struct::cast(node.clone()).and_then(|it| it.name()),
                    ),
                    SyntaxKind::ENUM => (
                        "enum",
                        ast::Enum::cast(node.clone()).and_then(|it| it.name()),
                    ),
                    SyntaxKind::UNION => (
                        "union",
                        ast::Union::cast(node.clone()).and_then(|it| it.name()),
                    ),
                    SyntaxKind::TRAIT => (
                        "trait",
                        ast::Trait::cast(node.clone()).and_then(|it| it.name()),
                    ),
                    _ => continue,
                };
                let Some(name) = name else { continue };
                let offset = name.syntax().text_range().start();
                let (line, col) = self.line_col(file, offset);
                let text = name.text().to_string();
                self.facts.files[file_id as usize].symbols.push(SymbolFact {
                    kind,
                    name: text.clone(),
                    line,
                    col,
                });
                if kind == "fn" {
                    let func = ast::Fn::cast(node).expect("kind checked");
                    let id = self.fns.len() as u32;
                    self.fn_by_pos.insert((file, offset), id);
                    let scope = Scope {
                        fn_id: id,
                        file,
                        from,
                        krate,
                    };
                    self.register_fn(scope, func, file_id, text, line, col);
                }
            }
        }
    }

    fn register_fn(
        &mut self,
        scope: Scope,
        node: ast::Fn,
        file_id: u32,
        name: String,
        line: u32,
        col: u32,
    ) {
        let db = self.db;
        let def = self.sema.to_def(&node);
        let mut entry = FnEntry {
            scope,
            node: node.clone(),
            def,
            params: Vec::new(),
            param_locals: Vec::new(),
            ret_var: None,
        };
        let mut fact = FnFact {
            id: scope.fn_id,
            file: file_id,
            name,
            line,
            col,
            analyzed: def.is_some(),
            has_body: node.body().is_some(),
            params: Vec::new(),
            ret_kind: "unknown",
            ret_type: None,
            self_access: None,
        };
        if let Some(def) = def {
            let ret = def.ret_type(db);
            fact.ret_kind = ty_kind(db, &ret);
            fact.ret_type = self.namer.display(&ret, scope.krate);
            fact.self_access = def.self_param(db).map(|param| match param.access(db) {
                hir::Access::Shared => "shared",
                hir::Access::Exclusive => "exclusive",
                hir::Access::Owned => "owned",
            });
            if let Some(list) = node.param_list() {
                let mut index = 0u32;
                if let Some(self_param) = list.self_param() {
                    let mut vars = Vec::new();
                    if let Some(local) = self.sema.to_def(&self_param) {
                        let pos =
                            self.line_col(scope.file, self_param.syntax().text_range().start());
                        let ty = local.ty(db);
                        let var = self.new_var(
                            scope,
                            "self".to_owned(),
                            "param",
                            Some(0),
                            pos,
                            Some(&ty),
                            Vec::new(),
                        );
                        entry.param_locals.push((local.as_id(), var));
                        vars.push(var);
                    }
                    fact.params.push(ParamFact {
                        index: 0,
                        name: "self".to_owned(),
                        ty: Some(self_param.syntax().text().to_string()),
                        type_paths: Vec::new(),
                    });
                    entry.params.push(vars);
                    index = 1;
                }
                for param in list.params() {
                    let declared = param.ty().and_then(|ty| self.sema.resolve_type(&ty));
                    let declared_paths = declared
                        .as_ref()
                        .map(|ty| self.namer.type_paths(scope.from, ty))
                        .unwrap_or_default();
                    let mut vars = Vec::new();
                    if let Some(pat) = param.pat() {
                        for ident in pat.syntax().descendants().filter_map(ast::IdentPat::cast) {
                            let Some(local) = self.sema.to_def(&ident) else {
                                continue;
                            };
                            let Some(name) = ident.name() else { continue };
                            let pos = self.line_col(scope.file, name.syntax().text_range().start());
                            let ty = local.ty(db);
                            let var = self.new_var(
                                scope,
                                name.text().to_string(),
                                "param",
                                Some(index),
                                pos,
                                Some(&ty),
                                declared_paths.clone(),
                            );
                            entry.param_locals.push((local.as_id(), var));
                            vars.push(var);
                        }
                    }
                    fact.params.push(ParamFact {
                        index,
                        name: param
                            .pat()
                            .map(|pat| truncate(&pat.syntax().text().to_string(), 40))
                            .unwrap_or_else(|| "_".to_owned()),
                        ty: param
                            .ty()
                            .map(|ty| truncate(&ty.syntax().text().to_string(), 80)),
                        type_paths: declared_paths,
                    });
                    entry.params.push(vars);
                    index += 1;
                }
            }
            if !matches!(fact.ret_kind, "unit" | "never") {
                let var = self.new_var(
                    scope,
                    "<return>".to_owned(),
                    "ret",
                    None,
                    (line, col),
                    Some(&ret),
                    Vec::new(),
                );
                entry.ret_var = Some(var);
            }
        }
        self.facts.fns.push(fact);
        self.fns.push(entry);
    }

    /// A call that resolves to a trait method may run any implementation in the workspace:
    /// parameters flow from the trait method to each impl, return values flow back.
    fn link_dispatch(&mut self) {
        let db = self.db;
        for index in 0..self.fns.len() {
            let Some(def) = self.fns[index].def else {
                continue;
            };
            let Some(AssocItemContainer::Impl(imp)) =
                def.as_assoc_item(db).map(|it| it.container(db))
            else {
                continue;
            };
            let Some(trait_) = imp.trait_(db) else {
                continue;
            };
            let Some(declared) = trait_.function(db, def.name(db)) else {
                continue;
            };
            let Some(trait_fn) = self.local_fn_id(declared) else {
                continue;
            };
            let impl_fn = index as u32;
            if trait_fn == impl_fn {
                continue;
            }
            self.facts.dispatch.push((trait_fn, impl_fn));
            let pairs: Vec<(Vec<u32>, Vec<u32>)> = self.fns[trait_fn as usize]
                .params
                .iter()
                .cloned()
                .zip(self.fns[index].params.iter().cloned())
                .collect();
            for (from, to) in pairs {
                let from: Atoms = from.into_iter().map(Atom::Var).collect();
                for var in to {
                    self.flow(&from, Atom::Var(var), "flow", "dispatch");
                }
            }
            if let (Some(from), Some(to)) =
                (self.fns[index].ret_var, self.fns[trait_fn as usize].ret_var)
            {
                self.flow(&[Atom::Var(from)], Atom::Var(to), "flow", "dispatch");
            }
        }
    }

    // -- helpers ---------------------------------------------------------------------------
    fn line_col(&self, file: FileId, offset: TextSize) -> (u32, u32) {
        let starts = &self.files[&file].line_starts;
        let offset: u32 = offset.into();
        let line = starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        (line as u32 + 1, offset - starts[line])
    }

    fn scope(&self) -> Scope {
        self.scope.expect("inside a function")
    }

    fn local_fn_id(&mut self, func: hir::Function) -> Option<u32> {
        if let Some(known) = self.fn_ids.get(&func) {
            return *known;
        }
        let db = self.db;
        let found = (|| {
            if !func.module(db).krate(db).origin(db).is_local() {
                return None;
            }
            let source = self.sema.source(func)?;
            let file = source.file_id.file_id()?.file_id(db);
            let name = source.value.name()?;
            self.fn_by_pos
                .get(&(file, name.syntax().text_range().start()))
                .copied()
        })();
        self.fn_ids.insert(func, found);
        found
    }

    #[allow(clippy::too_many_arguments)]
    fn new_var(
        &mut self,
        scope: Scope,
        name: String,
        kind: &'static str,
        index: Option<u32>,
        pos: (u32, u32),
        ty: Option<&hir::Type<'db>>,
        param_type_paths: Vec<String>,
    ) -> u32 {
        let id = self.facts.vars.len() as u32;
        let (text, ty_class, type_paths) = match ty {
            Some(ty) => (
                self.namer.display(ty, scope.krate),
                ty_kind(self.db, ty),
                self.namer.type_paths(scope.from, ty),
            ),
            None => (None, "unknown", Vec::new()),
        };
        self.facts.vars.push(VarFact {
            id,
            func: scope.fn_id,
            name,
            kind,
            index,
            line: pos.0,
            col: pos.1,
            ty: text,
            ty_kind: ty_class,
            type_paths,
            param_type_paths,
            guards: Vec::new(),
        });
        id
    }

    fn var_for_local(&mut self, local: hir::Local<'db>) -> u32 {
        let key = local.as_id();
        if let Some(&var) = self.locals.get(&key) {
            return var;
        }
        let db = self.db;
        let scope = self.scope();
        let name = local.name(db).as_str().to_owned();
        let source = local.primary_source(db);
        let written = source.name().and_then(|name| {
            let file = name.file_id.file_id()?.file_id(db);
            (file == scope.file)
                .then(|| self.line_col(file, name.value.syntax().text_range().start()))
        });
        let pos = written
            .or_else(|| self.macro_ctx.as_ref().map(|ctx| ctx.pos))
            .unwrap_or_else(|| {
                let fact = &self.facts.fns[scope.fn_id as usize];
                (fact.line, fact.col)
            });
        let ty = local.ty(db);
        let var = self.new_var(
            scope,
            name.clone(),
            "local",
            None,
            pos,
            Some(&ty),
            Vec::new(),
        );
        self.locals.insert(key, var);
        self.names.insert(name, var);
        var
    }

    fn flow(&mut self, from: &[Atom], to: Atom, kind: &'static str, via: &str) {
        for &source in from {
            if source == to || !self.flow_seen.insert((source, to, kind)) {
                continue;
            }
            self.facts.flows.push(FlowFact {
                from: source.key(),
                to: to.key(),
                kind,
                via: via.to_owned(),
            });
        }
    }

    fn pass(&mut self, atoms: &[Atom], callee: u32, index: usize) {
        let Some(vars) = self.fns[callee as usize].params.get(index).cloned() else {
            return;
        };
        for var in vars {
            self.flow(atoms, Atom::Var(var), "pass", &format!("arg:{index}"));
        }
    }

    /// (line, col, came from a macro expansion); None when the node was produced by the definition
    /// of a macro whose internals are not kept.
    fn site_pos(&self, anchor: &SyntaxNode) -> Option<(u32, u32, bool)> {
        let scope = self.scope();
        let Some(ctx) = &self.macro_ctx else {
            let (line, col) = self.line_col(scope.file, anchor.text_range().start());
            return Some((line, col, false));
        };
        let mapped = self.sema.original_range_opt(anchor).filter(|range| {
            range.file_id.file_id(self.db) == scope.file && ctx.range.contains_range(range.range)
        });
        match mapped {
            Some(range) => {
                let (line, col) = self.line_col(scope.file, range.range.start());
                Some((line, col, false))
            }
            None if ctx.keep_all => Some((ctx.pos.0, ctx.pos.1, true)),
            None => None,
        }
    }

    fn new_site(&mut self, kind: &'static str, name: String, anchor: &SyntaxNode) -> Option<u32> {
        let (line, col, synthesized) = self.site_pos(anchor)?;
        let in_macro = self.macro_ctx.is_some();
        let seq = if in_macro && !synthesized {
            // The same invocation tokens can be expanded more than once (`$x` used twice).
            if let Some(&known) = self.mapped_sites.get(&(line, col, kind)) {
                return Some(known);
            }
            0
        } else {
            let counter = self.seq.entry((line, col)).or_insert(0);
            let seq = *counter;
            *counter += 1;
            seq
        };
        let id = self.facts.sites.len() as u32;
        if in_macro && !synthesized {
            self.mapped_sites.insert((line, col, kind), id);
        }
        self.facts.sites.push(SiteFact {
            id,
            func: self.scope().fn_id,
            kind,
            name,
            line,
            col,
            seq,
            in_unsafe: self.unsafe_depth > 0,
            in_macro,
            ret_kind: "unknown",
            ..SiteFact::default()
        });
        Some(id)
    }

    fn expr_kind(&self, expr: &ast::Expr) -> &'static str {
        match self.sema.type_of_expr(expr) {
            Some(info) => ty_kind(self.db, &info.original),
            None => "unknown",
        }
    }

    /// The local an expression reads from or writes to: `x`, `x.f`, `&mut x`, `x.as_str()`, `x[i]`.
    fn root_local(&mut self, expr: &ast::Expr) -> Option<u32> {
        match expr {
            ast::Expr::PathExpr(path) => match self.sema.resolve_path(&path.path()?)? {
                PathResolution::Local(local) => Some(self.var_for_local(local)),
                _ => None,
            },
            ast::Expr::FieldExpr(it) => self.root_local(&it.expr()?),
            ast::Expr::RefExpr(it) => self.root_local(&it.expr()?),
            ast::Expr::ParenExpr(it) => self.root_local(&it.expr()?),
            ast::Expr::PrefixExpr(it) => self.root_local(&it.expr()?),
            ast::Expr::TryExpr(it) => self.root_local(&it.expr()?),
            ast::Expr::AwaitExpr(it) => self.root_local(&it.expr()?),
            ast::Expr::CastExpr(it) => self.root_local(&it.expr()?),
            ast::Expr::MethodCallExpr(it) => self.root_local(&it.receiver()?),
            ast::Expr::IndexExpr(it) => self.root_local(&it.base()?),
            _ => None,
        }
    }

    /// Record that `expr`'s root local went through the check `name`, along with the methods
    /// called on it on the way (`url.host_str() == ..` guards `url` with `host_str` and `eq`).
    fn guard(&mut self, expr: &ast::Expr, name: &str) {
        let Some(var) = self.root_local(expr) else {
            return;
        };
        let set = self.guards.entry(var).or_default();
        set.insert(name.to_owned());
        let mut current = expr.clone();
        loop {
            let next = match &current {
                ast::Expr::MethodCallExpr(it) => {
                    if let Some(method) = it.name_ref() {
                        set.insert(method.text().to_string());
                    }
                    it.receiver()
                }
                ast::Expr::FieldExpr(it) => it.expr(),
                ast::Expr::RefExpr(it) => it.expr(),
                ast::Expr::ParenExpr(it) => it.expr(),
                ast::Expr::PrefixExpr(it) => it.expr(),
                ast::Expr::TryExpr(it) => it.expr(),
                ast::Expr::AwaitExpr(it) => it.expr(),
                ast::Expr::CastExpr(it) => it.expr(),
                ast::Expr::IndexExpr(it) => it.base(),
                _ => None,
            };
            match next {
                Some(inner) => current = inner,
                None => break,
            }
        }
    }

    // -- pass 2: one function body -------------------------------------------------------------
    fn walk_fn(&mut self, index: usize) {
        let entry = &self.fns[index];
        let (scope, node, ret_var) = (entry.scope, entry.node.clone(), entry.ret_var);
        self.scope = Some(scope);
        self.unsafe_depth = u32::from(node.unsafe_token().is_some());
        self.locals = entry.param_locals.iter().copied().collect();
        self.names.clear();
        for (_, var) in &entry.param_locals {
            self.names
                .insert(self.facts.vars[*var as usize].name.clone(), *var);
        }
        self.closures.clear();
        self.last_closure = None;
        self.guards.clear();
        self.seq.clear();
        self.mapped_sites.clear();
        self.macro_ctx = None;
        self.macro_depth = 0;
        self.macro_sites.clear();
        self.via.clear();

        if let Some(body) = node.body() {
            let value = self.block(&body);
            if let Some(ret) = ret_var {
                self.flow(&value, Atom::Var(ret), "flow", "return");
            }
        }
        for (var, set) in std::mem::take(&mut self.guards) {
            self.facts.vars[var as usize].guards = set.into_iter().collect();
        }
        self.scope = None;
    }

    fn block(&mut self, block: &ast::BlockExpr) -> Atoms {
        let is_unsafe = block.unsafe_token().is_some();
        self.unsafe_depth += u32::from(is_unsafe);
        for stmt in block.statements() {
            self.stmt(&stmt);
        }
        let value = block
            .tail_expr()
            .map(|tail| self.eval(&tail))
            .unwrap_or_default();
        self.unsafe_depth -= u32::from(is_unsafe);
        value
    }

    fn stmt(&mut self, stmt: &ast::Stmt) {
        match stmt {
            ast::Stmt::LetStmt(let_stmt) => {
                let init = let_stmt.initializer();
                self.last_closure = None;
                let value = init
                    .as_ref()
                    .map(|expr| self.eval(expr))
                    .unwrap_or_default();
                let closure = self.last_closure.take();
                if let Some(pat) = let_stmt.pat() {
                    let vars = self.bind_pat(&pat, &value, "assign");
                    if let (Some(ast::Expr::ClosureExpr(_)), [var], Some(info)) =
                        (&init, vars.as_slice(), closure)
                    {
                        self.closures.insert(*var, info);
                    }
                }
                if let Some(block) = let_stmt.let_else().and_then(|it| it.block_expr()) {
                    self.block(&block);
                }
            }
            ast::Stmt::ExprStmt(expr) => {
                if let Some(expr) = expr.expr() {
                    self.eval(&expr);
                }
            }
            ast::Stmt::Item(ast::Item::MacroCall(call)) => {
                self.macro_call(call);
            }
            ast::Stmt::Item(_) => {}
        }
    }

    /// Bind every name in a pattern to `value`; returns the variables bound.
    fn bind_pat(&mut self, pat: &ast::Pat, value: &[Atom], via: &str) -> Vec<u32> {
        let mut vars = Vec::new();
        for ident in pat.syntax().descendants().filter_map(ast::IdentPat::cast) {
            let Some(local) = self.sema.to_def(&ident) else {
                continue;
            };
            let var = self.var_for_local(local);
            self.names
                .insert(self.facts.vars[var as usize].name.clone(), var);
            self.flow(value, Atom::Var(var), "flow", via);
            vars.push(var);
        }
        vars
    }

    fn children(&mut self, node: &SyntaxNode) -> Atoms {
        let mut out = Atoms::new();
        for expr in node.children().filter_map(ast::Expr::cast) {
            let value = self.eval(&expr);
            merge(&mut out, &value);
        }
        out
    }

    fn eval_all(&mut self, exprs: &[ast::Expr]) -> Atoms {
        let mut out = Atoms::new();
        for expr in exprs {
            let value = self.eval(expr);
            merge(&mut out, &value);
        }
        out
    }

    /// The variables and call sites whose values flow into the value of `expr`.
    fn eval(&mut self, expr: &ast::Expr) -> Atoms {
        match expr {
            ast::Expr::Literal(_) => Atoms::new(),
            ast::Expr::PathExpr(path) => self.path_expr(path),
            ast::Expr::CallExpr(call) => self.call(call),
            ast::Expr::MethodCallExpr(call) => self.method_call(call),
            ast::Expr::MacroExpr(mac) => mac
                .macro_call()
                .map(|call| self.macro_call(&call))
                .unwrap_or_default(),
            ast::Expr::IndexExpr(index) => self.index(index),
            ast::Expr::BinExpr(bin) => self.bin(bin),
            ast::Expr::ClosureExpr(closure) => self.closure(closure, &[]),
            ast::Expr::BlockExpr(block) => self.block(block),
            ast::Expr::LetExpr(let_expr) => {
                let value = let_expr.expr().map(|it| self.eval(&it)).unwrap_or_default();
                if let Some(pat) = let_expr.pat() {
                    self.bind_pat(&pat, &value, "match");
                }
                Atoms::new()
            }
            ast::Expr::IfExpr(if_expr) => {
                if let Some(condition) = if_expr.condition() {
                    self.eval(&condition);
                }
                let mut out = if_expr
                    .then_branch()
                    .map(|it| self.block(&it))
                    .unwrap_or_default();
                match if_expr.else_branch() {
                    Some(ast::ElseBranch::Block(block)) => {
                        let value = self.block(&block);
                        merge(&mut out, &value);
                    }
                    Some(ast::ElseBranch::IfExpr(nested)) => {
                        let value = self.eval(&ast::Expr::IfExpr(nested));
                        merge(&mut out, &value);
                    }
                    None => {}
                }
                out
            }
            ast::Expr::MatchExpr(match_expr) => {
                let scrutinee = match_expr.expr();
                let value = scrutinee
                    .as_ref()
                    .map(|it| self.eval(it))
                    .unwrap_or_default();
                let arms: Vec<ast::MatchArm> = match_expr
                    .match_arm_list()
                    .map(|list| list.arms().collect())
                    .unwrap_or_default();
                let allow_list = arms.iter().any(|arm| {
                    arm.pat().is_some_and(|pat| {
                        pat.syntax()
                            .descendants()
                            .any(|node| node.kind() == SyntaxKind::LITERAL_PAT)
                    })
                });
                if let (true, Some(scrutinee)) = (allow_list, &scrutinee) {
                    self.guard(scrutinee, "match");
                }
                let mut out = Atoms::new();
                for arm in arms {
                    if let Some(pat) = arm.pat() {
                        self.bind_pat(&pat, &value, "match");
                    }
                    if let Some(guard) = arm.guard() {
                        self.children(guard.syntax());
                    }
                    if let Some(body) = arm.expr() {
                        let value = self.eval(&body);
                        merge(&mut out, &value);
                    }
                }
                out
            }
            ast::Expr::ForExpr(for_expr) => {
                let mut parts = for_expr.syntax().children().filter_map(ast::Expr::cast);
                let iterable = parts.next();
                let body = parts.next();
                let value = iterable.map(|it| self.eval(&it)).unwrap_or_default();
                if let Some(pat) = for_expr.pat() {
                    self.bind_pat(&pat, &value, "for");
                }
                if let Some(body) = body {
                    self.eval(&body);
                }
                Atoms::new()
            }
            ast::Expr::ReturnExpr(ret) => {
                let value = ret.expr().map(|it| self.eval(&it)).unwrap_or_default();
                if let Some(var) = self.fns[self.scope().fn_id as usize].ret_var {
                    self.flow(&value, Atom::Var(var), "flow", "return");
                }
                Atoms::new()
            }
            ast::Expr::RecordExpr(record) => {
                // A struct literal is a site of its own, so a rule can tell "this value was put
                // into a field" from "this value is the struct": the analysis is field-insensitive,
                // and a tainted string field must not make an integer field of the same struct
                // look tainted to the rules about numbers.
                let name = record
                    .path()
                    .map(|path| last_segment(&path))
                    .unwrap_or_default();
                let site = self.new_site("struct", name.clone(), record.syntax());
                let mut out = Atoms::new();
                if let Some(list) = record.record_expr_field_list() {
                    for field in list.fields() {
                        if let Some(value) = field.expr() {
                            let value = self.eval(&value);
                            let label = field
                                .name_ref()
                                .map(|it| format!("field:{}", it.text()))
                                .unwrap_or_else(|| "field".to_owned());
                            match site {
                                Some(site) => self.flow(&value, Atom::Site(site), "flow", &label),
                                None => merge(&mut out, &value),
                            }
                        }
                    }
                    if let Some(spread) = list.spread() {
                        let value = self.eval(&spread);
                        match site {
                            Some(site) => self.flow(&value, Atom::Site(site), "flow", "spread"),
                            None => merge(&mut out, &value),
                        }
                    }
                }
                match site {
                    Some(site) => {
                        let fact = &mut self.facts.sites[site as usize];
                        fact.resolved = true;
                        fact.detail = Some(name);
                        fact.ret_kind = "other";
                        vec![Atom::Site(site)]
                    }
                    None => out,
                }
            }
            ast::Expr::FormatArgsExpr(format) => {
                let mut out = Atoms::new();
                if let Some(template) = format.template() {
                    let text = template.syntax().text().to_string();
                    // The format string belongs to the macro the user wrote (`write!`, `format!`):
                    // rules about hand-built protocol lines read it there.
                    if let Some(&site) = self.macro_sites.last() {
                        let fact = &mut self.facts.sites[site as usize];
                        if fact.detail.is_none() {
                            fact.detail = Some(truncate(&text, 240));
                        }
                    }
                    for name in inline_format_names(&text) {
                        if let Some(&var) = self.names.get(&name) {
                            merge(&mut out, &[Atom::Var(var)]);
                        }
                    }
                }
                for arg in format.args() {
                    if let Some(value) = arg.expr() {
                        let value = self.eval(&value);
                        merge(&mut out, &value);
                    }
                }
                out
            }
            other => self.children(other.syntax()),
        }
    }

    fn path_expr(&mut self, expr: &ast::PathExpr) -> Atoms {
        let Some(path) = expr.path() else {
            return Atoms::new();
        };
        match self.sema.resolve_path(&path) {
            Some(PathResolution::Local(local)) => vec![Atom::Var(self.var_for_local(local))],
            Some(PathResolution::Def(ModuleDef::Function(func))) => {
                self.record_ref(expr.syntax(), func);
                Atoms::new()
            }
            _ => Atoms::new(),
        }
    }

    fn record_ref(&mut self, anchor: &SyntaxNode, func: hir::Function) {
        let Some((line, col, _)) = self.site_pos(anchor) else {
            return;
        };
        let scope = self.scope();
        let target = self.local_fn_id(func);
        let paths = match target {
            Some(_) => Vec::new(),
            None => self.namer.fn_paths(scope.from, func, None).paths,
        };
        self.facts.refs.push(RefFact {
            func: scope.fn_id,
            line,
            col,
            target,
            paths,
            via: self.via.last().cloned().unwrap_or_default(),
        });
    }

    fn call(&mut self, call: &ast::CallExpr) -> Atoms {
        let args: Vec<ast::Expr> = call
            .arg_list()
            .map(|list| list.args().collect())
            .unwrap_or_default();
        let Some(callee) = call.expr() else {
            return self.eval_all(&args);
        };
        let whole = ast::Expr::CallExpr(call.clone());
        if let ast::Expr::PathExpr(path_expr) = &callee {
            if let Some(path) = path_expr.path() {
                let name = last_segment(&path);
                return match self.sema.resolve_path(&path) {
                    Some(PathResolution::Def(ModuleDef::Function(func))) => {
                        self.facts.stats.path_calls += 1;
                        self.facts.stats.resolved_path_calls += 1;
                        self.fn_call("call", name, func, callee.syntax(), None, &args, &whole)
                    }
                    Some(PathResolution::Local(local)) => self.closure_call(local, &args),
                    // Tuple struct and enum variant constructors wrap their arguments.
                    Some(_) => self.eval_all(&args),
                    None => {
                        self.facts.stats.path_calls += 1;
                        self.unresolved_call("call", name, callee.syntax(), None, &args, &whole)
                    }
                };
            }
        }
        let mut out = self.eval(&callee);
        let value = self.eval_all(&args);
        merge(&mut out, &value);
        out
    }

    fn method_call(&mut self, call: &ast::MethodCallExpr) -> Atoms {
        let args: Vec<ast::Expr> = call
            .arg_list()
            .map(|list| list.args().collect())
            .unwrap_or_default();
        let receiver = call.receiver();
        let Some(name_ref) = call.name_ref() else {
            let mut out = receiver.map(|it| self.eval(&it)).unwrap_or_default();
            let value = self.eval_all(&args);
            merge(&mut out, &value);
            return out;
        };
        let name = name_ref.text().to_string();
        let whole = ast::Expr::MethodCallExpr(call.clone());
        self.facts.stats.method_calls += 1;
        match self.sema.resolve_method_call(call) {
            Some(func) => {
                self.facts.stats.resolved_method_calls += 1;
                self.fn_call(
                    "method",
                    name,
                    func,
                    name_ref.syntax(),
                    receiver.as_ref(),
                    &args,
                    &whole,
                )
            }
            None => self.unresolved_call(
                "method",
                name,
                name_ref.syntax(),
                receiver.as_ref(),
                &args,
                &whole,
            ),
        }
    }

    /// Evaluate receiver and arguments. Closures go last and receive what the others carry, so
    /// `items.iter().map(|item| ..)` taints `item` with `items`.
    fn eval_operands(
        &mut self,
        via: &str,
        receiver: Option<&ast::Expr>,
        args: &[ast::Expr],
    ) -> (Atoms, Vec<Atoms>) {
        self.via.push(via.to_owned());
        let recv = receiver.map(|it| self.eval(it)).unwrap_or_default();
        let mut feed = recv.clone();
        let mut values: Vec<Atoms> = Vec::with_capacity(args.len());
        for arg in args {
            if matches!(arg, ast::Expr::ClosureExpr(_)) {
                values.push(Atoms::new());
            } else {
                let value = self.eval(arg);
                merge(&mut feed, &value);
                values.push(value);
            }
        }
        for (i, arg) in args.iter().enumerate() {
            if let ast::Expr::ClosureExpr(closure) = arg {
                values[i] = self.closure(closure, &feed);
            }
        }
        self.via.pop();
        (recv, values)
    }

    fn fill_site(&mut self, site: u32, args: &[ast::Expr], whole: &ast::Expr) {
        let ret_kind = self.expr_kind(whole);
        let fact = &mut self.facts.sites[site as usize];
        fact.ret_kind = ret_kind;
        fact.arg_count = args.len() as u32;
        fact.literal_args = args
            .iter()
            .enumerate()
            .filter_map(|(i, arg)| literal(arg).map(|(kind, text)| (i as u32, kind, text)))
            .collect();
    }

    #[allow(clippy::too_many_arguments)]
    fn unresolved_call(
        &mut self,
        kind: &'static str,
        name: String,
        anchor: &SyntaxNode,
        receiver: Option<&ast::Expr>,
        args: &[ast::Expr],
        whole: &ast::Expr,
    ) -> Atoms {
        let site = self.new_site(kind, name.clone(), anchor);
        let (recv, values) = self.eval_operands(&name, receiver, args);
        let Some(site) = site else {
            let mut out = recv;
            for value in &values {
                merge(&mut out, value);
            }
            return out;
        };
        self.fill_site(site, args, whole);
        if let Some(receiver) = receiver {
            if let Some(info) = self.sema.type_of_expr(receiver) {
                let scope = self.scope();
                self.facts.sites[site as usize].recv_type =
                    self.namer.type_paths(scope.from, &info.original);
            }
        }
        let target = Atom::Site(site);
        self.flow(&recv, target, "flow", "recv");
        for (i, value) in values.iter().enumerate() {
            self.flow(value, target, "flow", &format!("arg:{i}"));
        }
        vec![target]
    }

    #[allow(clippy::too_many_arguments)]
    fn fn_call(
        &mut self,
        kind: &'static str,
        name: String,
        func: hir::Function,
        anchor: &SyntaxNode,
        receiver: Option<&ast::Expr>,
        args: &[ast::Expr],
        whole: &ast::Expr,
    ) -> Atoms {
        let db = self.db;
        let scope = self.scope();
        let site = self.new_site(kind, name.clone(), anchor);
        let (mut recv, mut values) = self.eval_operands(&name, receiver, args);
        let Some(site) = site else {
            for value in &values {
                merge(&mut recv, value);
            }
            return recv;
        };
        self.fill_site(site, args, whole);

        // `Type::method(recv, a)` is `recv.method(a)`: line the arguments up the same way.
        let self_access = func.self_param(db).map(|param| param.access(db));
        let mut receiver_expr = receiver.cloned();
        let mut plain_args: &[ast::Expr] = args;
        if receiver.is_none() && self_access.is_some() && !args.is_empty() {
            receiver_expr = Some(args[0].clone());
            recv = values.remove(0);
            plain_args = &args[1..];
        }

        let receiver_ty = receiver_expr
            .as_ref()
            .and_then(|it| self.sema.type_of_expr(it))
            .map(|it| it.original);
        let target = self.local_fn_id(func);
        {
            let recv_type = receiver_ty
                .as_ref()
                .map(|ty| self.namer.type_paths(scope.from, ty))
                .unwrap_or_default();
            let (paths, def_crate) = match target {
                Some(_) => (Vec::new(), None),
                None => {
                    let found = self.namer.fn_paths(scope.from, func, receiver_ty.as_ref());
                    (found.paths, found.def_crate)
                }
            };
            let fact = &mut self.facts.sites[site as usize];
            fact.resolved = true;
            fact.target = target;
            fact.paths = paths;
            fact.def_crate = def_crate;
            fact.recv_type = recv_type;
        }

        let this = Atom::Site(site);
        let has_receiver = receiver_expr.is_some();
        match target {
            Some(callee) => {
                let shift = usize::from(has_receiver);
                if has_receiver {
                    self.pass(&recv, callee, 0);
                }
                for (i, value) in values.iter().enumerate() {
                    self.pass(value, callee, shift + i);
                }
                if let Some(ret) = self.fns[callee as usize].ret_var {
                    self.flow(&[Atom::Var(ret)], this, "ret", "return");
                }
            }
            None => {
                self.flow(&recv, this, "flow", "recv");
                for (i, value) in values.iter().enumerate() {
                    self.flow(value, this, "flow", &format!("arg:{i}"));
                }
            }
        }

        // `buf.push_str(x)`: a `&mut self` method stores its arguments in the receiver. When the
        // method is in the workspace, what its body puts into `self` comes back too.
        if matches!(self_access, Some(hir::Access::Exclusive)) {
            if let Some(root) = receiver_expr.as_ref().and_then(|it| self.root_local(it)) {
                for value in &values {
                    self.flow(value, Atom::Var(root), "flow", "mut");
                }
                if let Some(callee) = target {
                    let params: Atoms = self.fns[callee as usize]
                        .params
                        .first()
                        .into_iter()
                        .flatten()
                        .map(|var| Atom::Var(*var))
                        .collect();
                    self.flow(&params, Atom::Var(root), "ret", "mut");
                }
            }
        }
        // `reader.read_line(&mut line)`: the call writes into what it borrows mutably.
        for (i, arg) in plain_args.iter().enumerate() {
            let ast::Expr::RefExpr(reference) = arg else {
                continue;
            };
            if reference.mut_token().is_none() {
                continue;
            }
            let Some(root) = reference.expr().and_then(|it| self.root_local(&it)) else {
                continue;
            };
            self.facts.sites[site as usize].writes_out = true;
            self.flow(&[this], Atom::Var(root), "flow", "out");
            if let Some(callee) = target {
                // A workspace callee: what its body writes into the `&mut` parameter comes back.
                let index = usize::from(has_receiver) + i;
                let params: Atoms = self.fns[callee as usize]
                    .params
                    .get(index)
                    .into_iter()
                    .flatten()
                    .map(|var| Atom::Var(*var))
                    .collect();
                self.flow(&params, Atom::Var(root), "ret", "out");
                self.flow(&recv, Atom::Var(root), "flow", "out");
                for (j, value) in values.iter().enumerate() {
                    if i != j {
                        self.flow(value, Atom::Var(root), "flow", "out");
                    }
                }
            }
        }
        if self.facts.sites[site as usize].ret_kind == "bool" {
            if let Some(receiver) = &receiver_expr {
                self.guard(receiver, &name);
            }
            for arg in plain_args {
                self.guard(arg, &name);
            }
        }
        vec![this]
    }

    fn closure_call(&mut self, local: hir::Local<'db>, args: &[ast::Expr]) -> Atoms {
        let var = self.var_for_local(local);
        let values: Vec<Atoms> = args.iter().map(|arg| self.eval(arg)).collect();
        let mut out = vec![Atom::Var(var)];
        match self.closures.get(&var).cloned() {
            Some(info) => {
                for (i, value) in values.iter().enumerate() {
                    for param in info.params.get(i).into_iter().flatten() {
                        self.flow(value, Atom::Var(*param), "flow", "closure");
                    }
                }
                merge(&mut out, &info.ret);
            }
            None => {
                for value in &values {
                    merge(&mut out, value);
                }
            }
        }
        out
    }

    fn closure(&mut self, closure: &ast::ClosureExpr, feed: &[Atom]) -> Atoms {
        let mut params = Vec::new();
        if let Some(list) = closure.param_list() {
            for param in list.params() {
                params.push(match param.pat() {
                    Some(pat) => self.bind_pat(&pat, feed, "closure"),
                    None => Vec::new(),
                });
            }
        }
        let ret = closure
            .body()
            .map(|body| self.eval(&body))
            .unwrap_or_default();
        self.last_closure = Some(ClosureInfo {
            params,
            ret: ret.clone(),
        });
        ret
    }

    fn index(&mut self, index: &ast::IndexExpr) -> Atoms {
        let (Some(base), Some(position)) = (index.base(), index.index()) else {
            return self.children(index.syntax());
        };
        let mut base_value = self.eval(&base);
        let position_value = self.eval(&position);
        if !mentions_name(&position) {
            return base_value;
        }
        let Some(site) = self.new_site("index", "index".to_owned(), index.syntax()) else {
            merge(&mut base_value, &position_value);
            return base_value;
        };
        let base_kind = match self.sema.type_of_expr(&base) {
            None => "unknown",
            Some(info) => {
                let ty = info.original.strip_references();
                if ty.is_unknown() {
                    "unknown"
                } else if ty.is_slice() {
                    "slice"
                } else if ty.is_array() {
                    "array"
                } else if ty.is_str() {
                    "str"
                } else {
                    match ty
                        .as_adt()
                        .map(|adt| adt.name(self.db).as_str().to_owned())
                        .as_deref()
                    {
                        Some(
                            "Vec" | "VecDeque" | "String" | "SmallVec" | "ArrayVec" | "Bytes"
                            | "BytesMut",
                        ) => "vec",
                        Some("HashMap" | "BTreeMap" | "IndexMap" | "DashMap") => "map",
                        _ => "other",
                    }
                }
            }
        };
        let ret_kind = self.expr_kind(&ast::Expr::IndexExpr(index.clone()));
        let fact = &mut self.facts.sites[site as usize];
        fact.resolved = true;
        fact.detail = Some(truncate(&position.syntax().text().to_string(), 40));
        fact.base_kind = Some(base_kind);
        fact.ret_kind = ret_kind;
        let this = Atom::Site(site);
        self.flow(&base_value, this, "flow", "recv");
        self.flow(&position_value, this, "flow", "arg:0");
        vec![this]
    }

    fn bin(&mut self, bin: &ast::BinExpr) -> Atoms {
        let (Some(lhs), Some(rhs)) = (bin.lhs(), bin.rhs()) else {
            return self.children(bin.syntax());
        };
        let Some(op) = bin.op_kind() else {
            return self.children(bin.syntax());
        };
        let arith = |op: ast::ArithOp| {
            matches!(
                op,
                ast::ArithOp::Add | ast::ArithOp::Sub | ast::ArithOp::Mul | ast::ArithOp::Shl
            )
        };
        match op {
            BinaryOp::Assignment { op } => {
                let left = self.eval(&lhs);
                let mut value = self.eval(&rhs);
                if let Some(op) = op.filter(|op| arith(*op)) {
                    let _ = op;
                    if let Some(site) = self.arith_site(bin, &lhs, &rhs, &left, &value) {
                        value = vec![site];
                    }
                }
                if let Some(root) = self.root_local(&lhs) {
                    self.flow(&value, Atom::Var(root), "flow", "assign");
                }
                Atoms::new()
            }
            BinaryOp::CmpOp(cmp) => {
                self.eval(&lhs);
                self.eval(&rhs);
                let name = match cmp {
                    ast::CmpOp::Eq { .. } => "eq",
                    ast::CmpOp::Ord { .. } => "cmp",
                };
                self.guard(&lhs, name);
                self.guard(&rhs, name);
                Atoms::new()
            }
            BinaryOp::LogicOp(_) => {
                self.eval(&lhs);
                self.eval(&rhs);
                Atoms::new()
            }
            BinaryOp::ArithOp(op) => {
                let left = self.eval(&lhs);
                let right = self.eval(&rhs);
                if arith(op) {
                    if let Some(site) = self.arith_site(bin, &lhs, &rhs, &left, &right) {
                        return vec![site];
                    }
                }
                let mut out = left;
                merge(&mut out, &right);
                out
            }
        }
    }

    /// An `ops::arith` site for `+ - * <<` inside unsafe, or on integers with a non-constant operand.
    fn arith_site(
        &mut self,
        bin: &ast::BinExpr,
        lhs: &ast::Expr,
        rhs: &ast::Expr,
        left: &[Atom],
        right: &[Atom],
    ) -> Option<Atom> {
        let integer = self.expr_kind(lhs) == "int";
        let constant = literal(lhs).is_some() && literal(rhs).is_some();
        if !(self.unsafe_depth > 0 || (integer && !constant)) {
            return None;
        }
        let symbol = bin
            .op_token()
            .map(|token| token.text().to_owned())
            .unwrap_or_default();
        let site = self.new_site("arith", symbol.clone(), bin.syntax())?;
        let fact = &mut self.facts.sites[site as usize];
        fact.resolved = true;
        fact.detail = Some(symbol);
        fact.ret_kind = if integer { "int" } else { "unknown" };
        let this = Atom::Site(site);
        self.flow(left, this, "flow", "arg:0");
        self.flow(right, this, "flow", "arg:1");
        Some(this)
    }

    fn macro_call(&mut self, call: &ast::MacroCall) -> Atoms {
        let Some(path) = call.path() else {
            return Atoms::new();
        };
        let db = self.db;
        let scope = self.scope();
        let name = format!("{}!", last_segment(&path));
        self.facts.stats.macro_calls += 1;
        let mac = self.sema.resolve_macro_call(call);
        let site = self.new_site("macro", name.clone(), path.syntax());
        if let (Some(site), Some(mac)) = (site, mac) {
            let found = self.namer.macro_paths(scope.from, mac);
            let fact = &mut self.facts.sites[site as usize];
            fact.resolved = true;
            fact.paths = found.paths;
            fact.def_crate = found.def_crate;
        }
        let local = mac.is_some_and(|mac| mac.module(db).krate(db).origin(db).is_local());

        let mut value = Atoms::new();
        if self.macro_depth < MAX_MACRO_DEPTH {
            if let Some(expansion) = self.sema.expand_macro_call(call) {
                self.facts.stats.expanded_macro_calls += 1;
                let outer = self.macro_ctx.clone();
                self.macro_ctx = Some(match &outer {
                    Some(ctx) => MacroCtx {
                        keep_all: ctx.keep_all || local,
                        ..ctx.clone()
                    },
                    None => MacroCtx {
                        pos: self.line_col(scope.file, path.syntax().text_range().start()),
                        range: call.syntax().text_range(),
                        keep_all: local,
                    },
                });
                self.macro_depth += 1;
                self.via.push(name.clone());
                if let Some(site) = site {
                    self.macro_sites.push(site);
                }
                value = self.eval_node(&expansion.value);
                if site.is_some() {
                    self.macro_sites.pop();
                }
                self.via.pop();
                self.macro_depth -= 1;
                self.macro_ctx = outer;
            }
        }
        match site {
            Some(site) => {
                self.flow(&value, Atom::Site(site), "flow", "macro");
                vec![Atom::Site(site)]
            }
            None => value,
        }
    }

    /// Walk an expansion, whatever it parsed as: an expression, statements or items.
    fn eval_node(&mut self, node: &SyntaxNode) -> Atoms {
        if let Some(expr) = ast::Expr::cast(node.clone()) {
            return self.eval(&expr);
        }
        if let Some(stmts) = ast::MacroStmts::cast(node.clone()) {
            for stmt in stmts.statements() {
                self.stmt(&stmt);
            }
            return stmts
                .expr()
                .map(|tail| self.eval(&tail))
                .unwrap_or_default();
        }
        if let Some(call) = ast::MacroCall::cast(node.clone()) {
            return self.macro_call(&call);
        }
        if ast::Item::can_cast(node.kind()) {
            return Atoms::new();
        }
        if let Some(stmt) = ast::Stmt::cast(node.clone()) {
            self.stmt(&stmt);
            return Atoms::new();
        }
        let mut out = Atoms::new();
        for child in node.children() {
            let value = self.eval_node(&child);
            merge(&mut out, &value);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_format_arguments() {
        assert_eq!(inline_format_names(r#""ping -c 1 {host}""#), ["host"]);
        assert_eq!(
            inline_format_names(r#""{a} {b:?} {c:>8}""#),
            ["a", "b", "c"]
        );
        // Positional and escaped braces capture nothing.
        assert!(inline_format_names(r#""{} {0} {{literal}}""#).is_empty());
        assert!(inline_format_names(r#""no arguments""#).is_empty());
    }

    #[test]
    fn string_literal_values() {
        assert_eq!(string_value(r#""abc""#), "abc");
        assert_eq!(string_value(r##"br#"raw"#"##), "raw");
        assert_eq!(string_value("42"), "");
    }

    #[test]
    fn atoms_merge_without_duplicates() {
        let mut atoms = vec![Atom::Var(1)];
        merge(&mut atoms, &[Atom::Var(1), Atom::Site(1), Atom::Var(2)]);
        assert_eq!(atoms.len(), 3);
        assert_eq!(Atom::Var(7).key(), "v7");
        assert_eq!(Atom::Site(7).key(), "s7");
    }
}
