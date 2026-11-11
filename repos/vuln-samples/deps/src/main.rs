//! Dependency sample for class D: each pinned crate exercises one triage outcome.
use smallvec::SmallVec;

fn buffer(extra: &[u8]) -> SmallVec<[u8; 4]> {
    let mut v: SmallVec<[u8; 4]> = SmallVec::new();
    v.push(1);
    // Called through its full path so a syntactic scanner can see which function it is.
    SmallVec::insert_many(&mut v, 0, extra.iter().copied());
    v
}

fn timestamp() -> i64 {
    time::get_time().sec
}

fn interactive() -> bool {
    atty::is(atty::Stream::Stdout)
}

fn main() {
    let v = buffer(&[2, 3, 4, 5, 6]);
    println!("{} bytes at {} (tty: {})", v.len(), timestamp(), interactive());
}
