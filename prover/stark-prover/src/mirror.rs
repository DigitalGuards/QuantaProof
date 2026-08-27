//! An independent re-implementation of the uni-stark verifier for the Fibonacci configuration.
//!
//! The mirror uses the Plonky3 field types for arithmetic only. The transcript, the Merkle
//! multi-opening verification, the FRI fold chain and the constraint folding are written from
//! scratch against `docs/PROTOCOL.md`, with an independent keccak (`tiny-keccak`). Every
//! intermediate value is recorded so the JS and Hyperion implementations can be checked
//! field by field, and the flattened byte transcript is asserted equal to the one recorded
//! from the unmodified upstream verifier.
//!
//! Check order (this order is part of the protocol contract because it decides which error a
//! malformed proof raises):
//!
//! 1. layout: version, header, exact length, canonical elements
//! 2. transcript: the program identifier (step 0), the instance up to `zeta`, the
//!    out-of-domain check, `zeta_next`, the opened values
//! 3. the constraint identity at `zeta` (`OodMismatch`)
//! 4. FRI transcript: `fri_alpha`, per round commit / commit PoW / `beta`, final polynomial,
//!    arities, query PoW (`PowFailed`), query indices
//! 5. input batches (trace, quotient): duplicate consistency, sibling count, Merkle root
//! 6. reduced openings (`ZeroDenominator`)
//! 7. fold chains and the final polynomial check per query (`FinalPolyMismatch`)
//! 8. per-round Merkle checks of the reconstructed rows

use std::fmt;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use serde::{Deserialize, Serialize};

use crate::challenger::RawTranscript;
use crate::config::{Challenge, FriConfig, Val, program_identifier};
use crate::keccak::{keccak256, keccak256_concat};
use crate::layout::{
    DIGEST_BYTES, GOLDILOCKS_P, Layout, LayoutError, RawProof, decode_raw, ef_bytes, ef_coeffs,
    ef_from_coeffs, f_bytes,
};

// Formatting helpers shared with the vector writer.

/// A base element as a decimal string.
pub fn f_str(v: &Val) -> String {
    v.as_canonical_u64().to_string()
}

/// An extension element as `[c0, c1]` decimal strings.
pub type EfJson = [String; 2];

pub fn ef_json(e: &Challenge) -> EfJson {
    let [a, b] = ef_coeffs(e);
    [f_str(&a), f_str(&b)]
}

/// `0x`-prefixed lowercase hex.
pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// `x.reverse_bits()` restricted to `bit_len` bits.
pub fn rev_bits(x: usize, bit_len: usize) -> usize {
    if bit_len == 0 {
        return 0;
    }
    x.reverse_bits() >> (usize::BITS as usize - bit_len)
}

// Transcript events.

/// One labelled transcript step. `observe` and `sample_u64` carry the bytes that flow through
/// the byte challenger; the other variants are annotations of what those bytes mean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TranscriptEvent {
    /// Bytes appended to the input buffer (which also discards any unread output bytes).
    Observe { label: String, bytes: String },
    /// A keccak256 of the input buffer; `input` is what was hashed, `bytes` the digest that
    /// becomes both the new input buffer and the output buffer.
    Flush {
        label: String,
        input: String,
        bytes: String,
    },
    /// Eight bytes popped from the end of the output buffer, in the order they were popped;
    /// `value` is their little-endian u64 interpretation.
    SampleU64 {
        label: String,
        bytes: String,
        value: String,
    },
    /// A base field sample: the accepted u64 and the values rejected before it (each `>= p`).
    SampleField {
        label: String,
        value: String,
        rejected: Vec<String>,
    },
    /// `sample_bits`: one full u64 group masked to its low `bits` bits.
    SampleBits {
        label: String,
        bits: usize,
        raw: String,
        value: String,
    },
    /// A proof-of-work check: with `bits == 0` nothing is observed or sampled.
    CheckPow {
        label: String,
        bits: usize,
        witness: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        ok: bool,
    },
}

/// Flatten labelled events into the byte-run form recorded by the logging challenger.
pub fn flatten_events(events: &[TranscriptEvent]) -> RawTranscript {
    let mut raw = RawTranscript::default();
    for e in events {
        match e {
            TranscriptEvent::Observe { bytes, .. } => {
                raw.push_observe(&decode_hex(bytes));
            }
            TranscriptEvent::SampleU64 { bytes, .. } => {
                raw.push_sample(&decode_hex(bytes));
            }
            _ => {}
        }
    }
    raw
}

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("mirror-produced hex")
}

/// Byte-exact model of `HashChallenger<u8, Keccak256Hash, 32>` under `SerializingChallenger64`.
#[derive(Debug, Clone)]
pub struct MirrorChallenger {
    input: Vec<u8>,
    /// Unread output bytes; samples pop from the end.
    output: Vec<u8>,
    pub events: Vec<TranscriptEvent>,
    flushes: usize,
}

impl Default for MirrorChallenger {
    fn default() -> Self {
        Self::new()
    }
}

impl MirrorChallenger {
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            output: Vec::new(),
            events: Vec::new(),
            flushes: 0,
        }
    }

    pub fn observe(&mut self, label: &str, bytes: &[u8]) {
        self.output.clear();
        self.input.extend_from_slice(bytes);
        self.events.push(TranscriptEvent::Observe {
            label: label.to_string(),
            bytes: hex0x(bytes),
        });
    }

    pub fn observe_field(&mut self, label: &str, v: &Val) {
        self.observe(label, &f_bytes(v));
    }

    pub fn observe_ef(&mut self, label: &str, e: &Challenge) {
        self.observe(label, &ef_bytes(e));
    }

    fn flush(&mut self) {
        let digest = keccak256(&self.input);
        self.events.push(TranscriptEvent::Flush {
            label: format!("flush[{}]", self.flushes),
            input: hex0x(&self.input),
            bytes: hex0x(&digest),
        });
        self.flushes += 1;
        self.input = digest.to_vec();
        self.output = digest.to_vec();
    }

    fn sample_byte(&mut self) -> u8 {
        if self.output.is_empty() {
            self.flush();
        }
        self.output.pop().expect("output buffer refilled by flush")
    }

    /// Pop eight bytes and interpret them little-endian (the `sample_array` + `from_le_bytes`
    /// pair in `SerializingChallenger64`).
    pub fn sample_u64(&mut self, label: &str) -> u64 {
        let mut bytes = [0u8; 8];
        for b in bytes.iter_mut() {
            *b = self.sample_byte();
        }
        let value = u64::from_le_bytes(bytes);
        self.events.push(TranscriptEvent::SampleU64 {
            label: label.to_string(),
            bytes: hex0x(&bytes),
            value: value.to_string(),
        });
        value
    }

    /// Rejection-sampled base field element: reject any u64 `>= p` and take the next group.
    pub fn sample_field(&mut self, label: &str) -> Val {
        let mut rejected = Vec::new();
        loop {
            let v = self.sample_u64(label);
            if v < GOLDILOCKS_P {
                self.events.push(TranscriptEvent::SampleField {
                    label: label.to_string(),
                    value: v.to_string(),
                    rejected,
                });
                return Val::from_u64(v);
            }
            rejected.push(v.to_string());
        }
    }

    pub fn sample_ef(&mut self, label: &str) -> Challenge {
        let c0 = self.sample_field(&format!("{label}.c0"));
        let c1 = self.sample_field(&format!("{label}.c1"));
        ef_from_coeffs(c0, c1)
    }

    /// One full u64 group masked to `bits` low bits.
    pub fn sample_bits(&mut self, label: &str, bits: usize) -> usize {
        assert!(bits < 64 && (1u64 << bits) < GOLDILOCKS_P);
        let raw = self.sample_u64(label);
        let value = raw & ((1u64 << bits) - 1);
        self.events.push(TranscriptEvent::SampleBits {
            label: label.to_string(),
            bits,
            raw: raw.to_string(),
            value: value.to_string(),
        });
        value as usize
    }

    /// `GrindingChallenger::check_witness`: a no-op for zero bits, otherwise observe the witness
    /// and require `sample_bits(bits) == 0`.
    pub fn check_pow(&mut self, label: &str, bits: usize, witness: &Val) -> bool {
        if bits == 0 {
            self.events.push(TranscriptEvent::CheckPow {
                label: label.to_string(),
                bits,
                witness: f_str(witness),
                value: None,
                ok: true,
            });
            return true;
        }
        self.observe_field(&format!("{label}.witness"), witness);
        let value = self.sample_bits(label, bits);
        let ok = value == 0;
        self.events.push(TranscriptEvent::CheckPow {
            label: label.to_string(),
            bits,
            witness: f_str(witness),
            value: Some(value.to_string()),
            ok,
        });
        ok
    }
}

// Errors.

/// Verification errors, named exactly like the custom errors of the on-chain verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorError {
    Layout(LayoutError),
    PowFailed {
        stage: String,
    },
    SiblingCountMismatch {
        block: String,
        expected: usize,
        got: usize,
    },
    MerkleRootMismatch {
        block: String,
    },
    DuplicateOpeningMismatch {
        block: String,
        index: usize,
    },
    FinalPolyMismatch {
        query: usize,
    },
    OodPointInDomain,
    OodMismatch,
    ZeroDenominator {
        query: usize,
    },
    /// An invariant that no proof bytes can violate was violated: a bug in this crate.
    Internal(String),
}

impl MirrorError {
    /// The bare error name (the on-chain custom error).
    pub fn name(&self) -> &'static str {
        match self {
            MirrorError::Layout(e) => e.name(),
            MirrorError::PowFailed { .. } => "PowFailed",
            MirrorError::SiblingCountMismatch { .. } => "SiblingCountMismatch",
            MirrorError::MerkleRootMismatch { .. } => "MerkleRootMismatch",
            MirrorError::DuplicateOpeningMismatch { .. } => "DuplicateOpeningMismatch",
            MirrorError::FinalPolyMismatch { .. } => "FinalPolyMismatch",
            MirrorError::OodPointInDomain => "OodPointInDomain",
            MirrorError::OodMismatch => "OodMismatch",
            MirrorError::ZeroDenominator { .. } => "ZeroDenominator",
            MirrorError::Internal(_) => "Internal",
        }
    }

    /// Every error name the on-chain verifier can raise, in check order.
    pub const ALL_NAMES: [&'static str; 12] = [
        "BadVersion",
        "BadHeader",
        "BadLength",
        "NonCanonicalElement",
        "OodPointInDomain",
        "OodMismatch",
        "PowFailed",
        "DuplicateOpeningMismatch",
        "SiblingCountMismatch",
        "MerkleRootMismatch",
        "ZeroDenominator",
        "FinalPolyMismatch",
    ];
}

impl fmt::Display for MirrorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MirrorError::Layout(e) => write!(f, "{e}"),
            MirrorError::PowFailed { stage } => write!(f, "PowFailed({stage})"),
            MirrorError::SiblingCountMismatch {
                block,
                expected,
                got,
            } => write!(
                f,
                "SiblingCountMismatch({block}: expected {expected}, got {got})"
            ),
            MirrorError::MerkleRootMismatch { block } => write!(f, "MerkleRootMismatch({block})"),
            MirrorError::DuplicateOpeningMismatch { block, index } => {
                write!(f, "DuplicateOpeningMismatch({block}, leaf {index})")
            }
            MirrorError::FinalPolyMismatch { query } => {
                write!(f, "FinalPolyMismatch(query {query})")
            }
            MirrorError::OodPointInDomain => f.write_str("OodPointInDomain"),
            MirrorError::OodMismatch => f.write_str("OodMismatch"),
            MirrorError::ZeroDenominator { query } => write!(f, "ZeroDenominator(query {query})"),
            MirrorError::Internal(s) => write!(f, "Internal({s})"),
        }
    }
}

impl std::error::Error for MirrorError {}

impl From<LayoutError> for MirrorError {
    fn from(e: LayoutError) -> Self {
        MirrorError::Layout(e)
    }
}

// Recorded intermediate values.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenges {
    pub alpha: EfJson,
    pub zeta: EfJson,
    pub zeta_next: EfJson,
    pub fri_alpha: EfJson,
    pub betas: Vec<EfJson>,
    pub indices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Constraints {
    pub z_h: EfJson,
    pub is_first: EfJson,
    pub is_last: EfJson,
    pub is_trans: EfJson,
    pub inv_van: EfJson,
    /// The five constraint values in emission order (before folding).
    pub values: Vec<EfJson>,
    pub acc: EfJson,
    pub quotient: EfJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenInput {
    pub query: usize,
    pub index: usize,
    /// `7 * g_H^rev(index, H)`.
    pub x: String,
    pub denom_zeta: EfJson,
    pub denom_zeta_next: EfJson,
    pub inv_denom_zeta: EfJson,
    pub inv_denom_zeta_next: EfJson,
    pub trace_row: [String; 2],
    pub quotient_row: [String; 2],
    pub reduced_opening: EfJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FoldStep {
    pub query: usize,
    pub round: usize,
    pub log_arity: usize,
    /// Index entering the round (in the round's input domain).
    pub index: usize,
    /// `index % arity`: the query's own slot in the row.
    pub position: usize,
    /// The reconstructed row (query value at `position`, siblings elsewhere).
    pub row: Vec<EfJson>,
    /// `index >> log_arity`: the leaf index in the round's Merkle tree and the next index.
    pub folded_index: usize,
    /// `g_{h+k}^rev(folded_index, h)` with `h` the folded height and `k` the log arity.
    pub subgroup_start: String,
    /// The folded value in the binary form (the on-chain form).
    pub folded: EfJson,
    /// The folded value from the literal barycentric `fold_row`.
    pub folded_barycentric: EfJson,
    /// `keccak256(row bytes)`.
    pub leaf_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalPolyCheck {
    pub query: usize,
    pub index: usize,
    /// `g_H^rev(index, H)` (no coset shift).
    pub x: String,
    pub value: EfJson,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleNode {
    pub index: usize,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleBlock {
    pub name: String,
    pub log_height: usize,
    pub indices: Vec<usize>,
    pub sorted_unique: Vec<usize>,
    pub sib_count: usize,
    pub leaves: Vec<MerkleNode>,
    /// Frontier digests per level, level 1 (parents of the leaves) first, root last.
    pub levels: Vec<Vec<MerkleNode>>,
    pub root: String,
}

/// Everything the mirror derived from a valid proof.
#[derive(Debug, Clone)]
pub struct MirrorOutput {
    pub layout: Layout,
    pub proof_id: [u8; DIGEST_BYTES],
    pub events: Vec<TranscriptEvent>,
    pub challenges: Challenges,
    pub constraints: Constraints,
    pub open_inputs: Vec<OpenInput>,
    pub fold: Vec<FoldStep>,
    pub final_poly_checks: Vec<FinalPolyCheck>,
    pub merkle: Vec<MerkleBlock>,
    /// Transcript flattened to byte runs.
    pub raw_transcript: RawTranscript,
}

// Merkle multi-opening verification (binary tree, cap height 0).

/// Count the boundary siblings the frontier walk consumes for `sorted_unique` leaves.
pub fn expected_sibling_count(sorted_unique: &[usize], log_height: usize) -> usize {
    let mut nodes: Vec<usize> = sorted_unique.to_vec();
    let mut count = 0;
    for _ in 0..log_height {
        let mut next = Vec::with_capacity(nodes.len());
        let mut i = 0;
        while i < nodes.len() {
            let idx = nodes[i];
            if idx & 1 == 0 && i + 1 < nodes.len() && nodes[i + 1] == idx + 1 {
                i += 2;
            } else {
                count += 1;
                i += 1;
            }
            next.push(idx >> 1);
        }
        nodes = next;
    }
    count
}

/// Verify one pruned multi-opening. `rows[q]` is the leaf preimage (row bytes) of query `q`.
pub fn verify_pruned_binary(
    name: &str,
    root: &[u8; DIGEST_BYTES],
    log_height: usize,
    indices: &[usize],
    rows: &[Vec<u8>],
    siblings: &[[u8; DIGEST_BYTES]],
) -> Result<MerkleBlock, MirrorError> {
    if rows.len() != indices.len() {
        return Err(MirrorError::Internal(format!(
            "{name}: rows/indices length"
        )));
    }
    for &i in indices {
        if i >= (1usize << log_height) {
            return Err(MirrorError::Internal(format!(
                "{name}: index {i} out of range"
            )));
        }
    }

    // Sorted-unique leaves with a representative (first query in original order) per leaf, and
    // the duplicate-consistency check.
    let mut order: Vec<usize> = (0..indices.len()).collect();
    order.sort_by_key(|&q| indices[q]);
    let mut sorted_unique: Vec<usize> = Vec::new();
    let mut reps: Vec<usize> = Vec::new();
    for q in order {
        let leaf = indices[q];
        match sorted_unique.last() {
            Some(&last) if last == leaf => {
                let rep = *reps.last().expect("rep per unique leaf");
                if rows[rep] != rows[q] {
                    return Err(MirrorError::DuplicateOpeningMismatch {
                        block: name.to_string(),
                        index: leaf,
                    });
                }
            }
            _ => {
                sorted_unique.push(leaf);
                reps.push(q);
            }
        }
    }

    let expected = expected_sibling_count(&sorted_unique, log_height);
    if expected != siblings.len() {
        return Err(MirrorError::SiblingCountMismatch {
            block: name.to_string(),
            expected,
            got: siblings.len(),
        });
    }

    let mut nodes: Vec<(usize, [u8; DIGEST_BYTES])> = sorted_unique
        .iter()
        .zip(&reps)
        .map(|(&leaf, &rep)| (leaf, keccak256(&rows[rep])))
        .collect();
    let leaves: Vec<MerkleNode> = nodes
        .iter()
        .map(|(i, d)| MerkleNode {
            index: *i,
            digest: hex0x(d),
        })
        .collect();

    let mut levels = Vec::with_capacity(log_height);
    let mut cursor = 0;
    for _ in 0..log_height {
        let mut next = Vec::with_capacity(nodes.len());
        let mut i = 0;
        while i < nodes.len() {
            let (idx, digest) = nodes[i];
            let (left, right) = if idx & 1 == 0 {
                if i + 1 < nodes.len() && nodes[i + 1].0 == idx + 1 {
                    let r = nodes[i + 1].1;
                    i += 2;
                    (digest, r)
                } else {
                    let s = siblings[cursor];
                    cursor += 1;
                    i += 1;
                    (digest, s)
                }
            } else {
                let s = siblings[cursor];
                cursor += 1;
                i += 1;
                (s, digest)
            };
            next.push((idx >> 1, keccak256_concat(&[&left, &right])));
        }
        levels.push(
            next.iter()
                .map(|(i, d)| MerkleNode {
                    index: *i,
                    digest: hex0x(d),
                })
                .collect(),
        );
        nodes = next;
    }
    if cursor != siblings.len() || nodes.len() != 1 || nodes[0].0 != 0 {
        return Err(MirrorError::Internal(format!(
            "{name}: frontier walk did not converge"
        )));
    }
    if nodes[0].1 != *root {
        return Err(MirrorError::MerkleRootMismatch {
            block: name.to_string(),
        });
    }

    Ok(MerkleBlock {
        name: name.to_string(),
        log_height,
        indices: indices.to_vec(),
        sorted_unique,
        sib_count: siblings.len(),
        leaves,
        levels,
        root: hex0x(root),
    })
}

// FRI folding.

fn ef(v: Val) -> Challenge {
    Challenge::from(v)
}

/// Literal port of `TwoAdicFriFolding::fold_row` (barycentric Lagrange interpolation at `beta`).
pub fn fold_row_barycentric(
    index: usize,
    log_height: usize,
    log_arity: usize,
    beta: Challenge,
    evals: &[Challenge],
) -> Challenge {
    let arity = 1usize << log_arity;
    assert_eq!(evals.len(), arity);
    let subgroup_start =
        Val::two_adic_generator(log_height + log_arity).exp_u64(rev_bits(index, log_height) as u64);
    let g = Val::two_adic_generator(log_arity);
    let xs_natural: Vec<Val> = (0..arity)
        .map(|i| subgroup_start * g.exp_u64(i as u64))
        .collect();
    let xs: Vec<Val> = (0..arity)
        .map(|i| xs_natural[rev_bits(i, log_arity)])
        .collect();
    lagrange_interpolate_at(&xs, evals, beta)
}

fn lagrange_interpolate_at(xs: &[Val], ys: &[Challenge], z: Challenge) -> Challenge {
    let n = xs.len();
    if n == 0 {
        return Challenge::ZERO;
    }
    for i in 0..n {
        if (z - ef(xs[i])).is_zero() {
            return ys[i];
        }
    }
    let log_n = n.trailing_zeros() as usize;
    let coset_power = xs[0].exp_power_of_2(log_n);
    let weight_scale = (Val::from_usize(n) * coset_power).inverse();
    let diffs: Vec<Challenge> = xs.iter().map(|&x| z - ef(x)).collect();
    let diff_invs: Vec<Challenge> = diffs.iter().map(|d| d.inverse()).collect();
    let l_z: Challenge = diffs.iter().copied().product();
    let mut result = Challenge::ZERO;
    for ((&x, &y), &diff_inv) in xs.iter().zip(ys).zip(diff_invs.iter()) {
        let weight = x * weight_scale;
        result += y * ef(weight) * diff_inv;
    }
    result * l_z
}

/// The same fold as `k` sequential binary folds with challenges `beta, beta^2, beta^4, ...`.
///
/// The row is in bit-reversed order over the coset `s * <g_k>` with
/// `s = g_{h+k}^rev(index, h)`. At a step with `2^m` values the pairs `(2j, 2j+1)` sit at
/// `(y, -y)` with `y = s * g_m^rev(j, m-1)` and fold to
/// `(lo + hi) / 2 + beta_step * (lo - hi) / (2y)`, the value at `y^2`; then the coset shift
/// squares (`s <- s^2`, so the next coset is `s^2 * <g_{m-1}>`) and the challenge squares.
pub fn fold_row_binary(
    index: usize,
    log_height: usize,
    log_arity: usize,
    beta: Challenge,
    evals: &[Challenge],
) -> Challenge {
    assert_eq!(evals.len(), 1usize << log_arity);
    let mut vals = evals.to_vec();
    let mut s =
        Val::two_adic_generator(log_height + log_arity).exp_u64(rev_bits(index, log_height) as u64);
    let mut b = beta;
    let mut m = log_arity;
    while m > 0 {
        let half = 1usize << (m - 1);
        let g = Val::two_adic_generator(m);
        let mut next = Vec::with_capacity(half);
        for j in 0..half {
            // rev_m(2j) == rev_{m-1}(j), so the pair sits at (y, -y).
            let y = s * g.exp_u64(rev_bits(j, m - 1) as u64);
            let inv_2y = y.double().inverse();
            let lo = vals[2 * j];
            let hi = vals[2 * j + 1];
            next.push((lo + hi).halve() + (lo - hi) * b * ef(inv_2y));
        }
        vals = next;
        s = s.square();
        b = b.square();
        m -= 1;
    }
    vals[0]
}

/// Horner evaluation of `coeffs[0] + coeffs[1] x + ...` at a base-field point.
pub fn horner(coeffs: &[Challenge], x: Val) -> Challenge {
    let mut acc = Challenge::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * ef(x) + *c;
    }
    acc
}

// Constraints.

/// Recompose the quotient from its two opened basis coefficients: `q0 + X * q1`.
pub fn recompose_quotient(qc: &[Challenge; 2]) -> Challenge {
    let [a0, a1] = ef_coeffs(&qc[0]);
    let [b0, b1] = ef_coeffs(&qc[1]);
    let w = Val::from_u64(7);
    ef_from_coeffs(a0 + w * b1, a1 + b0)
}

/// Evaluate the folded Fibonacci constraints at `zeta` and compare with the quotient.
pub fn evaluate_constraints(
    degree_bits: usize,
    zeta: Challenge,
    alpha: Challenge,
    trace_local: &[Challenge; 2],
    trace_next: &[Challenge; 2],
    quotient_chunk: &[Challenge; 2],
    public_values: &[Val; 3],
) -> (Constraints, bool) {
    let g_n = Val::two_adic_generator(degree_bits);
    let g_n_inv = ef(g_n.inverse());
    let z_h = zeta.exp_power_of_2(degree_bits) - Challenge::ONE;
    let is_first = z_h / (zeta - Challenge::ONE);
    let is_last = z_h / (zeta - g_n_inv);
    let is_trans = zeta - g_n_inv;
    let inv_van = z_h.inverse();

    let [a, b, x] = public_values;
    let (l0, l1) = (trace_local[0], trace_local[1]);
    let (n0, n1) = (trace_next[0], trace_next[1]);
    let values = [
        is_first * (l0 - ef(*a)),
        is_first * (l1 - ef(*b)),
        is_trans * (l1 - n0),
        is_trans * (l0 + l1 - n1),
        is_last * (l1 - ef(*x)),
    ];
    let mut acc = Challenge::ZERO;
    for c in values {
        acc = acc * alpha + c;
    }
    let quotient = recompose_quotient(quotient_chunk);
    let ok = acc * inv_van == quotient;
    (
        Constraints {
            z_h: ef_json(&z_h),
            is_first: ef_json(&is_first),
            is_last: ef_json(&is_last),
            is_trans: ef_json(&is_trans),
            inv_van: ef_json(&inv_van),
            values: values.iter().map(ef_json).collect(),
            acc: ef_json(&acc),
            quotient: ef_json(&quotient),
        },
        ok,
    )
}

// The verifier.

/// Verify `proof_bytes` against `public_values` under `cfg`, recording every intermediate.
pub fn mirror_verify(
    cfg: &FriConfig,
    proof_bytes: &[u8],
    public_values: &[Val; 3],
) -> Result<MirrorOutput, MirrorError> {
    let raw: RawProof = decode_raw(proof_bytes, cfg)?;
    mirror_verify_raw(cfg, &raw, public_values)
}

/// [`mirror_verify`] on an already decoded proof.
pub fn mirror_verify_raw(
    cfg: &FriConfig,
    raw: &RawProof,
    public_values: &[Val; 3],
) -> Result<MirrorOutput, MirrorError> {
    let n = raw.degree_bits;
    let h = n + cfg.log_blowup;
    let q = cfg.num_queries;
    let num_rounds = raw.rounds.len();
    let mut ch = MirrorChallenger::new();

    // Transcript step 0: domain separation. The program identifier binds the AIR, the field,
    // the hash suite, the layout and every parameter before anything is sampled.
    ch.observe("program_identifier", &program_identifier(cfg));

    // Instance and first commitment.
    ch.observe_field("degree_bits", &Val::from_usize(n));
    ch.observe_field("base_degree_bits", &Val::from_usize(n));
    ch.observe_field("preprocessed_width", &Val::ZERO);
    ch.observe("trace_root", &raw.trace_root);
    for (i, v) in public_values.iter().enumerate() {
        ch.observe_field(&format!("public_values[{i}]"), v);
    }
    let alpha = ch.sample_ef("alpha");
    ch.observe("quotient_root", &raw.quotient_root);
    let zeta = ch.sample_ef("zeta");

    // Out-of-domain point must be off the trace domain.
    if (zeta.exp_power_of_2(n) - Challenge::ONE).is_zero() {
        return Err(MirrorError::OodPointInDomain);
    }
    let zeta_next = zeta * ef(Val::two_adic_generator(n));

    // Opened values, in (round, matrix, point) order.
    ch.observe_ef("trace_local[0]", &raw.trace_local[0]);
    ch.observe_ef("trace_local[1]", &raw.trace_local[1]);
    ch.observe_ef("trace_next[0]", &raw.trace_next[0]);
    ch.observe_ef("trace_next[1]", &raw.trace_next[1]);
    ch.observe_ef("quotient_chunk[0]", &raw.quotient_chunk[0]);
    ch.observe_ef("quotient_chunk[1]", &raw.quotient_chunk[1]);

    // Constraint identity (fail fast, transcript-independent).
    let (constraints, ok) = evaluate_constraints(
        n,
        zeta,
        alpha,
        &raw.trace_local,
        &raw.trace_next,
        &raw.quotient_chunk,
        public_values,
    );
    if !ok {
        return Err(MirrorError::OodMismatch);
    }

    // FRI transcript.
    let fri_alpha = ch.sample_ef("fri_alpha");
    let mut betas = Vec::with_capacity(num_rounds);
    for (r, round) in raw.rounds.iter().enumerate() {
        ch.observe(&format!("fri_commit[{r}]"), &round.commit);
        if !ch.check_pow(
            &format!("commit_pow[{r}]"),
            cfg.commit_pow_bits,
            &round.pow_witness,
        ) {
            return Err(MirrorError::PowFailed {
                stage: format!("commit_pow[{r}]"),
            });
        }
        betas.push(ch.sample_ef(&format!("beta[{r}]")));
    }
    for (i, c) in raw.final_poly.iter().enumerate() {
        ch.observe_ef(&format!("final_poly[{i}]"), c);
    }
    for (r, round) in raw.rounds.iter().enumerate() {
        ch.observe_field(
            &format!("log_arity[{r}]"),
            &Val::from_usize(round.log_arity),
        );
    }
    if !ch.check_pow("query_pow", cfg.query_pow_bits, &raw.query_pow_witness) {
        return Err(MirrorError::PowFailed {
            stage: "query_pow".to_string(),
        });
    }
    let indices: Vec<usize> = (0..q)
        .map(|i| ch.sample_bits(&format!("index[{i}]"), h))
        .collect();

    // Input batches.
    let trace_rows: Vec<Vec<u8>> = raw
        .trace_rows
        .iter()
        .map(|r| r.iter().flat_map(f_bytes).collect())
        .collect();
    let quotient_rows: Vec<Vec<u8>> = raw
        .quotient_rows
        .iter()
        .map(|r| r.iter().flat_map(f_bytes).collect())
        .collect();
    let mut merkle = Vec::with_capacity(2 + num_rounds);
    merkle.push(verify_pruned_binary(
        "trace",
        &raw.trace_root,
        h,
        &indices,
        &trace_rows,
        &raw.trace_siblings,
    )?);
    merkle.push(verify_pruned_binary(
        "quotient",
        &raw.quotient_root,
        h,
        &indices,
        &quotient_rows,
        &raw.quotient_siblings,
    )?);

    // Reduced openings.
    let g_h = Val::two_adic_generator(h);
    let shift = Val::GENERATOR;
    let mut alpha_pows = [Challenge::ONE; 6];
    for i in 1..6 {
        alpha_pows[i] = alpha_pows[i - 1] * fri_alpha;
    }
    let mut open_inputs = Vec::with_capacity(q);
    let mut reduced = Vec::with_capacity(q);
    for (qi, &idx) in indices.iter().enumerate() {
        let x = shift * g_h.exp_u64(rev_bits(idx, h) as u64);
        let dz = zeta - ef(x);
        let dzn = zeta_next - ef(x);
        if dz.is_zero() || dzn.is_zero() {
            return Err(MirrorError::ZeroDenominator { query: qi });
        }
        let idz = dz.inverse();
        let idzn = dzn.inverse();
        let [r0, r1] = raw.trace_rows[qi];
        let [s0, s1] = raw.quotient_rows[qi];
        let ro = alpha_pows[0] * (raw.trace_local[0] - ef(r0)) * idz
            + alpha_pows[1] * (raw.trace_local[1] - ef(r1)) * idz
            + alpha_pows[2] * (raw.trace_next[0] - ef(r0)) * idzn
            + alpha_pows[3] * (raw.trace_next[1] - ef(r1)) * idzn
            + alpha_pows[4] * (raw.quotient_chunk[0] - ef(s0)) * idz
            + alpha_pows[5] * (raw.quotient_chunk[1] - ef(s1)) * idz;
        reduced.push(ro);
        open_inputs.push(OpenInput {
            query: qi,
            index: idx,
            x: f_str(&x),
            denom_zeta: ef_json(&dz),
            denom_zeta_next: ef_json(&dzn),
            inv_denom_zeta: ef_json(&idz),
            inv_denom_zeta_next: ef_json(&idzn),
            trace_row: [f_str(&r0), f_str(&r1)],
            quotient_row: [f_str(&s0), f_str(&s1)],
            reduced_opening: ef_json(&ro),
        });
    }

    // Fold chains.
    let mut fold = Vec::with_capacity(q * num_rounds);
    let mut final_poly_checks = Vec::with_capacity(q);
    let mut round_groups: Vec<Vec<usize>> = vec![Vec::with_capacity(q); num_rounds];
    let mut round_rows: Vec<Vec<Vec<u8>>> = vec![Vec::with_capacity(q); num_rounds];
    for qi in 0..q {
        let mut idx = indices[qi];
        let mut folded = reduced[qi];
        let mut height = h;
        for (r, round) in raw.rounds.iter().enumerate() {
            let k = round.log_arity;
            let arity = 1usize << k;
            let position = idx & (arity - 1);
            let mut row = vec![Challenge::ZERO; arity];
            row[position] = folded;
            let mut s = 0;
            for (j, slot) in row.iter_mut().enumerate() {
                if j != position {
                    *slot = round.sibling_values[qi][s];
                    s += 1;
                }
            }
            let folded_height = height - k;
            let folded_index = idx >> k;
            let barycentric = fold_row_barycentric(folded_index, folded_height, k, betas[r], &row);
            let binary = fold_row_binary(folded_index, folded_height, k, betas[r], &row);
            if barycentric != binary {
                return Err(MirrorError::Internal(format!(
                    "fold forms disagree at query {qi} round {r}"
                )));
            }
            let row_bytes: Vec<u8> = row.iter().flat_map(ef_bytes).collect();
            let leaf = keccak256(&row_bytes);
            let subgroup_start =
                Val::two_adic_generator(folded_height + k)
                    .exp_u64(rev_bits(folded_index, folded_height) as u64);
            fold.push(FoldStep {
                query: qi,
                round: r,
                log_arity: k,
                index: idx,
                position,
                row: row.iter().map(ef_json).collect(),
                folded_index,
                subgroup_start: f_str(&subgroup_start),
                folded: ef_json(&binary),
                folded_barycentric: ef_json(&barycentric),
                leaf_digest: hex0x(&leaf),
            });
            round_groups[r].push(folded_index);
            round_rows[r].push(row_bytes);
            idx = folded_index;
            height = folded_height;
            folded = binary;
        }
        if height != cfg.log_final_height() {
            return Err(MirrorError::Internal(
                "fold chain ended at the wrong height".into(),
            ));
        }
        let x_final = g_h.exp_u64(rev_bits(idx, h) as u64);
        let eval = horner(&raw.final_poly, x_final);
        final_poly_checks.push(FinalPolyCheck {
            query: qi,
            index: idx,
            x: f_str(&x_final),
            value: ef_json(&eval),
        });
        if eval != folded {
            return Err(MirrorError::FinalPolyMismatch { query: qi });
        }
    }

    // Per-round Merkle checks.
    let mut height = h;
    for (r, round) in raw.rounds.iter().enumerate() {
        let folded_height = height - round.log_arity;
        merkle.push(verify_pruned_binary(
            &format!("round[{r}]"),
            &round.commit,
            folded_height,
            &round_groups[r],
            &round_rows[r],
            &round.siblings,
        )?);
        height = folded_height;
    }

    let raw_transcript = flatten_events(&ch.events);
    Ok(MirrorOutput {
        layout: raw.layout.clone(),
        proof_id: raw.proof_id,
        events: ch.events,
        challenges: Challenges {
            alpha: ef_json(&alpha),
            zeta: ef_json(&zeta),
            zeta_next: ef_json(&zeta_next),
            fri_alpha: ef_json(&fri_alpha),
            betas: betas.iter().map(ef_json).collect(),
            indices,
        },
        constraints,
        open_inputs,
        fold,
        final_poly_checks,
        merkle,
        raw_transcript,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rev_bits_matches_p3() {
        for bits in 0..12 {
            for x in 0..(1usize << bits) {
                assert_eq!(rev_bits(x, bits), p3_util::reverse_bits_len(x, bits));
            }
        }
    }

    #[test]
    fn sibling_count_examples() {
        // Height-3 tree, leaves {1, 2, 5}: siblings 0, 3, 4 at level 0, F at level 1, none above.
        assert_eq!(expected_sibling_count(&[1, 2, 5], 3), 4);
        assert_eq!(expected_sibling_count(&[0, 1, 2, 3, 4, 5, 6, 7], 3), 0);
        assert_eq!(expected_sibling_count(&[5], 3), 3);
    }

    #[test]
    fn challenger_flush_serves_groups_from_the_end() {
        let mut ch = MirrorChallenger::new();
        ch.observe("x", &[1, 2, 3]);
        let digest = keccak256(&[1, 2, 3]);
        let g0 = ch.sample_u64("g0");
        let mut expect = [0u8; 8];
        for (i, b) in expect.iter_mut().enumerate() {
            *b = digest[31 - i];
        }
        assert_eq!(g0, u64::from_le_bytes(expect));
        // Three more groups exhaust the digest; the fifth re-hashes the digest itself.
        let _ = ch.sample_u64("g1");
        let _ = ch.sample_u64("g2");
        let _ = ch.sample_u64("g3");
        let d2 = keccak256(&digest);
        let g4 = ch.sample_u64("g4");
        for (i, b) in expect.iter_mut().enumerate() {
            *b = d2[31 - i];
        }
        assert_eq!(g4, u64::from_le_bytes(expect));
    }

    #[test]
    fn fold_forms_agree_on_random_rows() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut rand_ef = || {
            ef_from_coeffs(
                Val::from_u64(rng.next_u64() % GOLDILOCKS_P),
                Val::from_u64(rng.next_u64() % GOLDILOCKS_P),
            )
        };
        for log_arity in 1..=4 {
            for log_height in [3usize, 5, 9] {
                let beta = rand_ef();
                let row: Vec<Challenge> = (0..1usize << log_arity).map(|_| rand_ef()).collect();
                for index in [0usize, 1, 5, (1 << log_height) - 1] {
                    let a = fold_row_barycentric(index, log_height, log_arity, beta, &row);
                    let b = fold_row_binary(index, log_height, log_arity, beta, &row);
                    assert_eq!(
                        a, b,
                        "log_arity {log_arity} log_height {log_height} index {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn horner_constant_term_first() {
        let c = [
            ef(Val::from_u64(3)),
            ef(Val::from_u64(5)),
            ef(Val::from_u64(7)),
        ];
        let x = Val::from_u64(2);
        // 3 + 5*2 + 7*4 = 41
        assert_eq!(horner(&c, x), ef(Val::from_u64(41)));
    }
}
