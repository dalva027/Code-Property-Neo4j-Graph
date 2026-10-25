/// Nobody calls this: expect an unused-function finding.
pub fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

pub fn legacy_export(names: &[String]) -> String {
    names.join("\n")
}
