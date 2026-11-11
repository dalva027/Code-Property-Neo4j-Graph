//! Class P sample: panics reachable from main, unchecked indexing, and unbounded recursion.
mod lookup;
mod parser;

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let tree = parser::parse(&input);
    let n = input.len() / 2;
    println!("{} {} {}", lookup::nth_byte(&input, n), tree.depth(), config_port());
}

/// Reads the port from the environment and panics when it is missing or malformed.
fn config_port() -> u16 {
    let raw = std::env::var("PORT").unwrap();
    raw.parse::<u16>().expect("PORT must be a number")
}

#[cfg(test)]
mod tests {
    #[test]
    fn unwrap_in_tests_is_fine() {
        let v: Option<u8> = Some(1);
        assert_eq!(v.unwrap(), 1);
    }
}
