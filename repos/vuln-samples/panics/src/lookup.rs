/// Returns the byte at `index`, or panics when out of range.
pub fn nth_byte(s: &str, index: usize) -> u8 {
    let bytes = s.as_bytes();
    bytes[index]
}

/// A literal index is not reported.
pub fn first(s: &str) -> u8 {
    s.as_bytes()[0]
}

/// Nothing calls this, but the index is still unchecked.
pub fn last(v: &[u8]) -> u8 {
    v[v.len() - 1]
}
