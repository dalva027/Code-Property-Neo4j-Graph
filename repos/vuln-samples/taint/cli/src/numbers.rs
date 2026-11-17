//! The tainted forms of the panic rules: allocation size and integer arithmetic from input.
use crate::commands::argument;

// -- P4 unbounded allocation ---------------------------------------------------------------------
pub fn table() -> usize {
    let rows: usize = argument(1).parse().unwrap_or(0);
    let cells: Vec<u64> = Vec::with_capacity(rows); // EXPECT unbounded-allocation
    cells.capacity()
}

/// Safe: the size is capped.
pub fn table_capped() -> usize {
    let rows: usize = argument(1).parse().unwrap_or(0);
    let cells: Vec<u64> = Vec::with_capacity(rows.min(4096));
    cells.capacity()
}

// -- P3 integer overflow -------------------------------------------------------------------------
pub fn frame_size() -> u32 {
    let frames: u32 = argument(1).parse().unwrap_or(0);
    frames * 4096 // EXPECT overflow-candidate
}

/// Safe: checked arithmetic.
pub fn frame_size_checked() -> u32 {
    let frames: u32 = argument(1).parse().unwrap_or(0);
    frames.checked_mul(4096).unwrap_or(u32::MAX)
}
