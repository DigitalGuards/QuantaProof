//! Shared helpers for the integration tests.

use stark_prover::config::{FriConfig, preset};
use stark_prover::vectors::{Generated, generate, vector_name};

/// Presets exercised by the integration tests: the three main sets, a binary variant and the
/// widest-arity sweep cells (arity 16 rows), all small enough to keep the suite fast.
pub fn test_cases() -> Vec<(&'static str, FriConfig, usize)> {
    vec![
        ("c1", preset("c1").unwrap(), 10),
        ("c2", preset("c2").unwrap(), 10),
        ("c3", preset("c3").unwrap(), 10),
        ("c1-binary", preset("c1-binary").unwrap(), 10),
        ("c3-a4-f0", preset("c3-a4-f0").unwrap(), 10),
        ("c3-a4-f5", preset("c3-a4-f5").unwrap(), 11),
    ]
}

pub fn generate_case(name: &str, cfg: &FriConfig, n: usize) -> Generated {
    generate(cfg, &vector_name(name, n), n, 0, 1)
        .unwrap_or_else(|e| panic!("{name} n={n}: generation failed: {e:#}"))
}
