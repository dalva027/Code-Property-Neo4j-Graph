//! Turning rust-analyzer definitions and types into `::` paths the rule catalogue can match.
//!
//! One callee has several defensible names: where it is defined (`http::header::value::
//! HeaderValue::from_str`), where it is exported (`http::HeaderValue::from_str`), and for std the
//! facade path (`std::option::Option::unwrap`, defined in `core`). Every function therefore gets a
//! list of candidates, most public first; the loader keeps the first one the catalogue knows, or
//! the first one otherwise.

use std::collections::HashMap;

use ra_ap_hir::{
    self as hir, AsAssocItem, AssocItemContainer, FindPathConfig, HirDisplay, ItemInNs, ModuleDef,
    PathKind,
};
use ra_ap_ide_db::RootDatabase;

pub struct FnPaths {
    pub paths: Vec<String>,
    pub def_crate: Option<String>,
}

pub struct Namer<'db> {
    db: &'db RootDatabase,
    public: HashMap<(hir::Module, ModuleDef), Option<String>>,
}

pub fn crate_name(db: &RootDatabase, krate: hir::Crate) -> Option<String> {
    krate
        .display_name(db)
        .map(|name| name.crate_name().to_string())
}

/// `core::option::Option` and `alloc::vec::Vec` are written `std::...` in code and in the catalogue.
fn std_facade(path: &str) -> String {
    for prefix in ["core::", "alloc::"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return format!("std::{rest}");
        }
    }
    path.to_owned()
}

fn push_unique(out: &mut Vec<String>, value: Option<String>) {
    if let Some(value) = value {
        if !value.is_empty() && !out.contains(&value) {
            out.push(value);
        }
    }
}

pub fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// A coarse class of a type, for rules that only care whether a value can carry text.
pub fn ty_kind(db: &RootDatabase, ty: &hir::Type<'_>) -> &'static str {
    let ty = ty.strip_references();
    if ty.is_unknown() {
        "unknown"
    } else if ty.is_unit() {
        "unit"
    } else if ty.is_never() {
        "never"
    } else if ty.is_bool() {
        "bool"
    } else if ty.is_int_or_uint() {
        "int"
    } else if ty.is_float() {
        "float"
    } else if ty.is_char() {
        "char"
    } else if ty.is_str() {
        "str"
    } else if ty.is_raw_ptr() {
        "ptr"
    } else if let Some(adt) = ty.as_adt() {
        // Option<u32> and Result<u32, E> carry what their first argument carries.
        let name = adt.name(db);
        let wrapper =
            matches!(name.as_str(), "Option" | "Result") && adt.module(db).krate(db).is_builtin(db);
        match ty.type_arguments().next() {
            Some(inner) if wrapper => ty_kind(db, &inner),
            _ => "other",
        }
    } else {
        "other"
    }
}

impl<'db> Namer<'db> {
    pub fn new(db: &'db RootDatabase) -> Self {
        Namer {
            db,
            public: HashMap::new(),
        }
    }

    pub fn display(&self, ty: &hir::Type<'db>, krate: hir::Crate) -> Option<String> {
        if ty.is_unknown() {
            return None;
        }
        let text = ty
            .display(self.db, krate.to_display_target(self.db))
            .to_string();
        Some(truncate(&text, 80))
    }

    /// Where the item is defined: crate, modules, name.
    fn def_path(&self, def: ModuleDef) -> Option<String> {
        let module = def.module(self.db)?;
        let mut segments = vec![crate_name(self.db, module.krate(self.db))?];
        segments.extend(
            module
                .path_segments(self.db)
                .map(|name| name.as_str().to_owned()),
        );
        segments.push(def.name(self.db)?.as_str().to_owned());
        Some(segments.join("::"))
    }

    /// The shortest path the item can be imported by from `from`, as auto-import would write it.
    fn public_path(&mut self, from: hir::Module, def: ModuleDef) -> Option<String> {
        if let Some(known) = self.public.get(&(from, def)) {
            return known.clone();
        }
        let config = FindPathConfig {
            prefer_no_std: false,
            prefer_prelude: false,
            prefer_absolute: false,
            allow_unstable: true,
        };
        let home = def
            .module(self.db)
            .and_then(|module| crate_name(self.db, module.krate(self.db)));
        let found = from
            .find_path(self.db, ItemInNs::from(def), config)
            .and_then(|path| self.accept_public(&path, home.as_deref()));
        self.public.insert((from, def), found.clone());
        found
    }

    /// A found import path is a name for the item only when it starts at the crate that defines
    /// it (or at `std` for `core`/`alloc` items). An item re-exported by several dependencies
    /// would otherwise be named after whichever one the search met first: `sha2`'s `Digest` trait
    /// as `sha1::Digest`. A single segment is a prelude name (`String`), and `crate::`/`super::`
    /// paths belong to the workspace; neither is a name either.
    fn accept_public(&self, path: &hir::ModPath, home: Option<&str>) -> Option<String> {
        if path.kind != PathKind::Plain || path.segments().len() < 2 {
            return None;
        }
        let first = path.segments()[0].as_str();
        let at_home = match home {
            Some("core" | "alloc" | "std") => first == "std",
            Some(home) => first == home,
            None => false,
        };
        at_home.then(|| {
            path.segments()
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>()
                .join("::")
        })
    }

    pub fn item_paths(&mut self, from: hir::Module, def: ModuleDef) -> Vec<String> {
        let mut out = Vec::new();
        push_unique(&mut out, self.public_path(from, def));
        if let Some(defined) = self.def_path(def) {
            push_unique(&mut out, Some(std_facade(&defined)));
            // `crate::Name`, for catalogue entries that skip private modules.
            let krate = defined.split("::").next().unwrap_or_default();
            let name = defined.rsplit("::").next().unwrap_or_default();
            if defined.matches("::").count() > 1 && !matches!(krate, "std" | "core" | "alloc") {
                push_unique(&mut out, Some(format!("{krate}::{name}")));
            }
            push_unique(&mut out, Some(defined));
        }
        out
    }

    pub fn type_paths(&mut self, from: hir::Module, ty: &hir::Type<'db>) -> Vec<String> {
        let ty = ty.strip_references();
        if let Some(adt) = ty.as_adt() {
            return self.item_paths(from, ModuleDef::Adt(adt));
        }
        if let Some(builtin) = ty.as_builtin() {
            return vec![builtin.name().as_str().to_owned()];
        }
        if let Some(trait_) = ty.as_dyn_trait() {
            return self.item_paths(from, ModuleDef::Trait(trait_));
        }
        let name = if ty.as_type_param(self.db).is_some() {
            // A value of a generic type is opaque: bytes behind a reader, items of an iterator.
            "generic"
        } else if ty.is_slice() {
            "slice"
        } else if ty.is_array() {
            "array"
        } else if ty.is_raw_ptr() {
            "pointer"
        } else if ty.is_tuple() {
            "tuple"
        } else if ty.is_fn() || ty.is_closure() {
            "fn"
        } else {
            return Vec::new();
        };
        vec![name.to_owned()]
    }

    /// Candidate paths of a function that is not defined in the workspace. `receiver` is the type
    /// a method was called on, used when the method belongs to a trait.
    pub fn fn_paths(
        &mut self,
        from: hir::Module,
        func: hir::Function,
        receiver: Option<&hir::Type<'db>>,
    ) -> FnPaths {
        let db = self.db;
        let name = func.name(db).as_str().to_owned();
        let def_crate = crate_name(db, func.module(db).krate(db));
        let mut owners: Vec<String> = Vec::new();
        match func.as_assoc_item(db).map(|item| item.container(db)) {
            Some(AssocItemContainer::Impl(imp)) => {
                let self_ty = imp.self_ty(db);
                owners.extend(self.type_paths(from, &self_ty));
                if owners.is_empty() {
                    if let Some(receiver) = receiver {
                        owners.extend(self.type_paths(from, receiver));
                    }
                }
                if let Some(trait_) = imp.trait_(db) {
                    owners.extend(self.item_paths(from, ModuleDef::Trait(trait_)));
                }
            }
            Some(AssocItemContainer::Trait(trait_)) => {
                // A method the trait provides (`Iterator::map`): the trait names it best; the
                // receiver's type is a second candidate for catalogue entries written that way.
                owners.extend(self.item_paths(from, ModuleDef::Trait(trait_)));
                if let Some(receiver) = receiver {
                    owners.extend(self.type_paths(from, receiver));
                }
            }
            None => {
                let paths = self.item_paths(from, ModuleDef::Function(func));
                return FnPaths { paths, def_crate };
            }
        }
        let mut paths = Vec::new();
        for owner in owners {
            push_unique(&mut paths, Some(format!("{owner}::{name}")));
        }
        FnPaths { paths, def_crate }
    }

    pub fn macro_paths(&mut self, from: hir::Module, mac: hir::Macro) -> FnPaths {
        let def = ModuleDef::Macro(mac);
        let def_crate = crate_name(self.db, mac.module(self.db).krate(self.db));
        let name = mac.name(self.db).as_str().to_owned();
        let mut paths = Vec::new();
        let mut public = None;
        if let Some(path) = self.public.get(&(from, def)) {
            public = path.clone();
        } else {
            let config = FindPathConfig {
                prefer_no_std: false,
                prefer_prelude: false,
                prefer_absolute: false,
                allow_unstable: true,
            };
            if let Some(path) = from.find_path(self.db, ItemInNs::Macros(mac), config) {
                public = self.accept_public(&path, def_crate.as_deref());
            }
            self.public.insert((from, def), public.clone());
        }
        push_unique(&mut paths, public.map(|path| format!("{path}!")));
        // `macro_rules!` macros are exported at the crate root whatever module defines them.
        if let Some(krate) = &def_crate {
            push_unique(&mut paths, Some(std_facade(&format!("{krate}::{name}!"))));
        }
        FnPaths { paths, def_crate }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn std_facade_covers_core_and_alloc() {
        assert_eq!(
            std_facade("core::option::Option::unwrap"),
            "std::option::Option::unwrap"
        );
        assert_eq!(std_facade("alloc::vec::Vec::push"), "std::vec::Vec::push");
        assert_eq!(std_facade("corelib::x"), "corelib::x");
        assert_eq!(std_facade("http::HeaderValue"), "http::HeaderValue");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("héllo", 2), "h");
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn candidates_stay_unique_and_ordered() {
        let mut out = Vec::new();
        push_unique(&mut out, Some("a::b".to_owned()));
        push_unique(&mut out, Some("a::b".to_owned()));
        push_unique(&mut out, None);
        push_unique(&mut out, Some(String::new()));
        push_unique(&mut out, Some("c".to_owned()));
        assert_eq!(out, ["a::b", "c"]);
    }
}
