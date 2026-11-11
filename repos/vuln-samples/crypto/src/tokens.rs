use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

pub fn session_token() -> u64 {
    let mut rng = SmallRng::seed_from_u64(42);
    rng.gen()
}

pub fn nonce() -> u32 {
    fastrand::u32(..)
}
