//! Concrete Plonky3 configuration mirrored by the on-chain verifier, plus the FRI presets.
//!
//! Every type alias below names the exact `0.7.0-rc.1` item; the mapping from the plan's names
//! is recorded in `docs/PROTOCOL.md` (section "Configuration").

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use p3_uni_stark::StarkConfig;
use serde::{Deserialize, Serialize};

use crate::challenger::{LoggingChallenger, TranscriptLog};

/// Base field: Goldilocks, `p = 2^64 - 2^32 + 1`.
pub type Val = Goldilocks;
/// Challenge field: the quadratic binomial extension `F[X] / (X^2 - 7)`.
pub type Challenge = BinomialExtensionField<Goldilocks, 2>;
/// Byte hasher used for leaves, compression and the transcript.
pub type ByteHash = Keccak256Hash;
/// Leaf hasher: field elements are serialised as canonical 8-byte little-endian words.
pub type FieldHash = SerializingHasher<Keccak256Hash>;
/// Merkle compression: `keccak256(left || right)`.
pub type Compress = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;
/// Binary Merkle MMCS over base-field matrices, 32-byte digests, cap height 0 (root only).
pub type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 2, 32>;
/// The same MMCS lifted to the extension field (rows are flattened to base coefficients).
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
/// The byte-level hash challenger (input buffer, keccak flush, 32-byte output buffer).
pub type InnerChallenger = HashChallenger<u8, Keccak256Hash, 32>;
/// The field challenger. The logging wrapper is byte-transparent: it forwards every byte to
/// the inner `HashChallenger` unchanged and only records what passed through.
pub type Challenger = SerializingChallenger64<Val, LoggingChallenger<InnerChallenger>>;
/// DFT backend used for the low-degree extensions.
pub type Dft = Radix2DitParallel<Val>;
/// Two-adic FRI polynomial commitment scheme.
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// The complete STARK configuration.
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
/// A uni-stark proof for this configuration.
pub type Proof = p3_uni_stark::Proof<Config>;
/// A Merkle commitment (cap of height 0: exactly one 32-byte root).
pub type Commitment = MerkleCap<Val, [u8; 32]>;

/// Version string of the pinned Plonky3 release (mirrors `../PLONKY3_VERSION`).
pub const PLONKY3_VERSION: &str = "0.7.0-rc.1";

/// Plain-data FRI parameter set (the `mmcs` field of `FriParameters` is constructed on demand).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FriConfig {
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
    pub num_queries: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
}

impl FriConfig {
    /// `blowup * final_poly_len`: the log2 of the domain size at which FRI folding stops.
    pub const fn log_final_height(&self) -> usize {
        self.log_blowup + self.log_final_poly_len
    }

    /// Number of final polynomial coefficients.
    pub const fn final_poly_len(&self) -> usize {
        1 << self.log_final_poly_len
    }

    /// Conjectured soundness bits (ethSTARK conjecture), as reported by `p3-fri`.
    pub const fn conjectured_soundness_bits(&self) -> usize {
        self.log_blowup * self.num_queries + self.query_pow_bits
    }

    /// The FRI folding schedule for a trace of `2^degree_bits` rows, exactly as
    /// `p3_fri::compute_log_arity_for_round` derives it when a single input height is present.
    pub fn arity_schedule(&self, degree_bits: usize) -> Vec<usize> {
        let mut remaining = degree_bits.saturating_sub(self.log_final_poly_len);
        let mut schedule = Vec::new();
        while remaining > 0 {
            let k = remaining.min(self.max_log_arity);
            schedule.push(k);
            remaining -= k;
        }
        schedule
    }

    /// The CLI name of a preset with these parameters, if it is one of the named presets.
    pub fn preset_name(&self) -> Option<&'static str> {
        all_presets()
            .into_iter()
            .find(|(_, cfg)| cfg == self)
            .map(|(name, _)| name)
    }
}

const C1: FriConfig = FriConfig {
    log_blowup: 1,
    log_final_poly_len: 3,
    max_log_arity: 3,
    num_queries: 100,
    commit_pow_bits: 0,
    query_pow_bits: 16,
};
const C2: FriConfig = FriConfig {
    log_blowup: 2,
    log_final_poly_len: 3,
    max_log_arity: 3,
    num_queries: 50,
    commit_pow_bits: 0,
    query_pow_bits: 16,
};
const C3: FriConfig = FriConfig {
    log_blowup: 3,
    log_final_poly_len: 3,
    max_log_arity: 3,
    num_queries: 34,
    commit_pow_bits: 0,
    query_pow_bits: 16,
};

const fn binary(cfg: FriConfig) -> FriConfig {
    FriConfig {
        max_log_arity: 1,
        ..cfg
    }
}

/// The C3 arity / final-polynomial sweep cells (`c3-a<k>-f<l>`), excluding the two cells that
/// coincide with `c3` (k = 3, l = 3) and `c3-binary` (k = 1, l = 3).
pub const SWEEP_ARITIES: [usize; 4] = [1, 2, 3, 4];
pub const SWEEP_FINAL_POLY: [usize; 3] = [0, 3, 5];

/// Every named preset, in the order the `vectors --preset all` command emits them.
pub fn all_presets() -> Vec<(&'static str, FriConfig)> {
    let mut out: Vec<(&'static str, FriConfig)> = vec![
        ("c1", C1),
        ("c2", C2),
        ("c3", C3),
        ("c1-binary", binary(C1)),
        ("c2-binary", binary(C2)),
        ("c3-binary", binary(C3)),
    ];
    for k in SWEEP_ARITIES {
        for l in SWEEP_FINAL_POLY {
            let cfg = FriConfig {
                max_log_arity: k,
                log_final_poly_len: l,
                ..C3
            };
            if out.iter().any(|(_, existing)| *existing == cfg) {
                continue;
            }
            let name: &'static str = Box::leak(format!("c3-a{k}-f{l}").into_boxed_str());
            out.push((name, cfg));
        }
    }
    out
}

/// Look up a preset by CLI name.
pub fn preset(name: &str) -> Option<FriConfig> {
    all_presets()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, cfg)| cfg)
}

/// The names accepted by `--preset` (plus `all` and `custom`, handled by the CLI).
pub fn preset_names() -> Vec<&'static str> {
    all_presets().into_iter().map(|(n, _)| n).collect()
}

/// Build the MMCS pair shared by the PCS and the FRI parameters.
pub fn build_mmcs() -> (ValMmcs, ChallengeMmcs) {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = Compress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    (val_mmcs, challenge_mmcs)
}

/// Build the `p3-fri` parameter struct for a preset.
pub fn fri_parameters(cfg: &FriConfig) -> FriParameters<ChallengeMmcs> {
    let (_, challenge_mmcs) = build_mmcs();
    FriParameters {
        log_blowup: cfg.log_blowup,
        log_final_poly_len: cfg.log_final_poly_len,
        max_log_arity: cfg.max_log_arity,
        num_queries: cfg.num_queries,
        commit_proof_of_work_bits: cfg.commit_pow_bits,
        query_proof_of_work_bits: cfg.query_pow_bits,
        mmcs: challenge_mmcs,
    }
}

/// Build a complete STARK configuration whose challenger records its byte transcript into `log`.
///
/// The challenger stored in the config is the "template" (logging depth 0). `prove` and `verify`
/// clone it once through `initialise_challenger` (depth 1, the instance that logs); clones made
/// by the proof-of-work grinder are depth 2 and stay silent.
pub fn build_config(cfg: &FriConfig, log: TranscriptLog) -> Config {
    let (val_mmcs, _) = build_mmcs();
    let fri = fri_parameters(cfg);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri);
    let inner = InnerChallenger::new(Vec::new(), ByteHash {});
    let challenger = Challenger::new(LoggingChallenger::new(inner, log));
    Config::new(pcs, challenger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_match_the_fri_prover_rule() {
        assert_eq!(C1.arity_schedule(10), vec![3, 3, 1]);
        assert_eq!(C1.arity_schedule(12), vec![3, 3, 3]);
        assert_eq!(binary(C3).arity_schedule(10), vec![1; 7]);
        let a4f0 = FriConfig {
            max_log_arity: 4,
            log_final_poly_len: 0,
            ..C3
        };
        assert_eq!(a4f0.arity_schedule(10), vec![4, 4, 2]);
    }

    #[test]
    fn preset_table_has_sixteen_unique_entries() {
        let presets = all_presets();
        assert_eq!(presets.len(), 16);
        for (i, (_, a)) in presets.iter().enumerate() {
            for (_, b) in presets.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        assert_eq!(preset("c3-a4-f5").unwrap().max_log_arity, 4);
        assert!(
            preset("c3-a3-f3").is_none(),
            "duplicate of c3 must be folded"
        );
    }
}
