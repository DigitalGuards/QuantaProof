//! Proving and upstream verification with the logging challenger.

use p3_uni_stark::{PcsError, VerificationError, prove, verify};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::challenger::{RawTranscript, new_log, take_log};
use crate::config::{Config, FriConfig, Proof, Val, build_config};
use crate::fib_air::{FibonacciAir, generate_trace_rows, public_values};

/// The Goldilocks prime, for seeded start values.
const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Result of proving one Fibonacci instance.
pub struct ProveOutput {
    pub proof: Proof,
    pub public_values: [Val; 3],
    pub degree_bits: usize,
    /// Every byte the prover's challenger observed and sampled, in order.
    pub prover_transcript: RawTranscript,
}

/// Deterministic pseudo-random start values `(a, b)` for `--seed`.
pub fn seeded_start(seed: u64) -> (u64, u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    (rng.next_u64() % P, rng.next_u64() % P)
}

/// Generate the trace of `2^degree_bits` rows from `(a, b)`, prove it, and return the proof
/// together with the prover-side transcript.
pub fn prove_fibonacci(cfg: &FriConfig, degree_bits: usize, a: u64, b: u64) -> ProveOutput {
    let n = 1usize << degree_bits;
    let trace = generate_trace_rows::<Val>(a, b, n);
    let pis = public_values(&trace, a, b);
    let log = new_log();
    let config = build_config(cfg, log.clone());
    let proof = prove(&config, &FibonacciAir {}, trace, &pis);
    ProveOutput {
        proof,
        public_values: pis,
        degree_bits,
        prover_transcript: take_log(&log),
    }
}

/// The upstream verifier's error type for this configuration.
pub type UpstreamError = VerificationError<PcsError<Config>>;

/// Run the unmodified upstream `verify` and return its result together with the verifier-side
/// transcript (the ground truth for `docs/PROTOCOL.md`).
pub fn verify_upstream(
    cfg: &FriConfig,
    proof: &Proof,
    pis: &[Val; 3],
) -> (Result<(), UpstreamError>, RawTranscript) {
    let log = new_log();
    let config = build_config(cfg, log.clone());
    let result = verify(&config, &FibonacciAir {}, proof, pis);
    (result, take_log(&log))
}
