//! Calldata layout v1: byte offsets, header validation, exact-length rule and raw decoding.
//!
//! The layout is a lossless, canonical encoding of `Proof<Config>` for the Fibonacci AIR.
//! `docs/PROTOCOL.md` (section "Calldata layout v1") is the normative table; this module is the
//! executable form of it. Every offset below is computable from the header bytes plus the
//! `sib_count` fields read in order, which is what lets the on-chain verifier address any block
//! without parsing the ones before it beyond their counts.

use std::fmt;

use p3_field::{BasedVectorSpace, PrimeField64};
use p3_goldilocks::Goldilocks;
use serde::{Deserialize, Serialize};

use crate::config::{Challenge, FriConfig, Val};
use crate::keccak::keccak256;

/// Layout version byte.
pub const VERSION: u8 = 1;
/// Bytes per base field element (canonical little-endian u64).
pub const F_BYTES: usize = 8;
/// Bytes per extension field element (`c0 || c1`).
pub const EF_BYTES: usize = 16;
/// Bytes per Merkle digest / root (raw keccak256 output).
pub const DIGEST_BYTES: usize = 32;
/// Width of the Fibonacci trace (and of the flattened quotient chunk).
pub const TRACE_WIDTH: usize = 2;
/// Bytes of the `sib_count` field (u16, big-endian).
pub const SIB_COUNT_BYTES: usize = 2;
/// The Goldilocks prime.
pub const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;
/// Goldilocks two-adicity: the largest supported LDE height is `2^32`.
pub const TWO_ADICITY: usize = 32;

/// Decoding errors, named exactly like the custom errors the on-chain verifier raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayoutError {
    /// `version != 1`.
    BadVersion,
    /// Header fields inconsistent with the verifier parameters (degree bits out of range, an
    /// arity outside `1..=max_log_arity`, or an arity schedule that does not sum to
    /// `degree_bits - log_final_poly_len`).
    BadHeader,
    /// The proof length differs from the length implied by the header and the `sib_count` fields
    /// (this includes proofs too short to contain the fields the check needs).
    BadLength,
    /// A field element is not in `[0, p)`.
    NonCanonicalElement,
}

impl LayoutError {
    pub fn name(&self) -> &'static str {
        match self {
            LayoutError::BadVersion => "BadVersion",
            LayoutError::BadHeader => "BadHeader",
            LayoutError::BadLength => "BadLength",
            LayoutError::NonCanonicalElement => "NonCanonicalElement",
        }
    }
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for LayoutError {}

/// Offsets of every field of the transcript prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixLayout {
    pub version: usize,
    pub degree_bits: usize,
    pub num_rounds: usize,
    pub log_arity: usize,
    pub trace_root: usize,
    pub quotient_root: usize,
    pub trace_local: usize,
    pub trace_next: usize,
    pub quotient_chunk: usize,
    pub round_commits: Vec<usize>,
    pub round_pow_witnesses: Vec<usize>,
    pub final_poly: usize,
    pub query_pow_witness: usize,
    /// End of the prefix: `proofId = keccak256(proof[0..pEnd])`.
    pub p_end: usize,
}

/// One input batch block (`trace` or `quotient`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockLayout {
    pub name: String,
    pub rows_offset: usize,
    pub rows_len: usize,
    pub sib_count_offset: usize,
    pub siblings_offset: usize,
    pub sib_count: usize,
    pub end: usize,
}

/// One FRI commit-phase round block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundLayout {
    pub log_arity: usize,
    pub sibling_values_offset: usize,
    pub sibling_values_len: usize,
    pub sib_count_offset: usize,
    pub siblings_offset: usize,
    pub sib_count: usize,
    pub end: usize,
}

/// The complete layout of one proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layout {
    pub degree_bits: usize,
    pub log_arities: Vec<usize>,
    pub num_queries: usize,
    pub p_end: usize,
    pub prefix: PrefixLayout,
    pub blocks: Vec<BlockLayout>,
    pub rounds: Vec<RoundLayout>,
    pub total_len: usize,
}

/// Validate the header against the verifier parameters.
pub fn validate_header(
    degree_bits: usize,
    log_arities: &[usize],
    cfg: &FriConfig,
) -> Result<(), LayoutError> {
    if degree_bits == 0 || degree_bits + cfg.log_blowup > TWO_ADICITY {
        return Err(LayoutError::BadHeader);
    }
    if degree_bits < cfg.log_final_poly_len {
        return Err(LayoutError::BadHeader);
    }
    if cfg.max_log_arity == 0 || cfg.num_queries == 0 {
        return Err(LayoutError::BadHeader);
    }
    let mut sum = 0usize;
    for &k in log_arities {
        if k == 0 || k > cfg.max_log_arity {
            return Err(LayoutError::BadHeader);
        }
        sum += k;
    }
    if sum != degree_bits - cfg.log_final_poly_len {
        return Err(LayoutError::BadHeader);
    }
    Ok(())
}

/// Compute the prefix layout from validated header values.
pub fn prefix_layout(num_rounds: usize, final_poly_len: usize) -> PrefixLayout {
    let log_arity = 3;
    let trace_root = log_arity + num_rounds;
    let quotient_root = trace_root + DIGEST_BYTES;
    let trace_local = quotient_root + DIGEST_BYTES;
    let trace_next = trace_local + TRACE_WIDTH * EF_BYTES;
    let quotient_chunk = trace_next + TRACE_WIDTH * EF_BYTES;
    let mut cursor = quotient_chunk + TRACE_WIDTH * EF_BYTES;
    let mut round_commits = Vec::with_capacity(num_rounds);
    let mut round_pow_witnesses = Vec::with_capacity(num_rounds);
    for _ in 0..num_rounds {
        round_commits.push(cursor);
        cursor += DIGEST_BYTES;
        round_pow_witnesses.push(cursor);
        cursor += F_BYTES;
    }
    let final_poly = cursor;
    cursor += final_poly_len * EF_BYTES;
    let query_pow_witness = cursor;
    cursor += F_BYTES;
    PrefixLayout {
        version: 0,
        degree_bits: 1,
        num_rounds: 2,
        log_arity,
        trace_root,
        quotient_root,
        trace_local,
        trace_next,
        quotient_chunk,
        round_commits,
        round_pow_witnesses,
        final_poly,
        query_pow_witness,
        p_end: cursor,
    }
}

fn read_u16_be(bytes: &[u8], off: usize) -> Result<usize, LayoutError> {
    if off + SIB_COUNT_BYTES > bytes.len() {
        return Err(LayoutError::BadLength);
    }
    Ok(u16::from_be_bytes([bytes[off], bytes[off + 1]]) as usize)
}

/// Parse the header and the `sib_count` fields, validate the header and enforce the exact-length
/// rule. No field element is decoded here.
pub fn parse_layout(bytes: &[u8], cfg: &FriConfig) -> Result<Layout, LayoutError> {
    if bytes.is_empty() {
        return Err(LayoutError::BadLength);
    }
    if bytes[0] != VERSION {
        return Err(LayoutError::BadVersion);
    }
    if bytes.len() < 3 {
        return Err(LayoutError::BadLength);
    }
    let degree_bits = bytes[1] as usize;
    let num_rounds = bytes[2] as usize;
    if bytes.len() < 3 + num_rounds {
        return Err(LayoutError::BadLength);
    }
    let log_arities: Vec<usize> = bytes[3..3 + num_rounds]
        .iter()
        .map(|&b| b as usize)
        .collect();
    validate_header(degree_bits, &log_arities, cfg)?;

    let prefix = prefix_layout(num_rounds, cfg.final_poly_len());
    let q = cfg.num_queries;
    let mut cursor = prefix.p_end;

    let mut blocks = Vec::with_capacity(2);
    for name in ["trace", "quotient"] {
        let rows_offset = cursor;
        let rows_len = q * TRACE_WIDTH * F_BYTES;
        let sib_count_offset = rows_offset + rows_len;
        let sib_count = read_u16_be(bytes, sib_count_offset)?;
        let siblings_offset = sib_count_offset + SIB_COUNT_BYTES;
        let end = siblings_offset + sib_count * DIGEST_BYTES;
        blocks.push(BlockLayout {
            name: name.to_string(),
            rows_offset,
            rows_len,
            sib_count_offset,
            siblings_offset,
            sib_count,
            end,
        });
        cursor = end;
    }

    let mut rounds = Vec::with_capacity(num_rounds);
    for &k in &log_arities {
        let sibling_values_offset = cursor;
        let sibling_values_len = q * ((1usize << k) - 1) * EF_BYTES;
        let sib_count_offset = sibling_values_offset + sibling_values_len;
        let sib_count = read_u16_be(bytes, sib_count_offset)?;
        let siblings_offset = sib_count_offset + SIB_COUNT_BYTES;
        let end = siblings_offset + sib_count * DIGEST_BYTES;
        rounds.push(RoundLayout {
            log_arity: k,
            sibling_values_offset,
            sibling_values_len,
            sib_count_offset,
            siblings_offset,
            sib_count,
            end,
        });
        cursor = end;
    }

    if cursor != bytes.len() {
        return Err(LayoutError::BadLength);
    }

    Ok(Layout {
        degree_bits,
        log_arities,
        num_queries: q,
        p_end: prefix.p_end,
        prefix,
        blocks,
        rounds,
        total_len: cursor,
    })
}

/// Read one canonical base field element.
pub fn read_f(bytes: &[u8], off: usize) -> Result<Val, LayoutError> {
    let word: [u8; F_BYTES] = bytes[off..off + F_BYTES]
        .try_into()
        .map_err(|_| LayoutError::BadLength)?;
    let v = u64::from_le_bytes(word);
    if v >= GOLDILOCKS_P {
        return Err(LayoutError::NonCanonicalElement);
    }
    Ok(Goldilocks::new(v))
}

/// Read one extension field element (`c0 || c1`).
pub fn read_ef(bytes: &[u8], off: usize) -> Result<Challenge, LayoutError> {
    let c0 = read_f(bytes, off)?;
    let c1 = read_f(bytes, off + F_BYTES)?;
    Ok(ef_from_coeffs(c0, c1))
}

/// Read a 32-byte digest.
pub fn read_digest(bytes: &[u8], off: usize) -> [u8; DIGEST_BYTES] {
    bytes[off..off + DIGEST_BYTES]
        .try_into()
        .expect("caller checked the length")
}

/// Build an extension element from its basis coefficients.
pub fn ef_from_coeffs(c0: Val, c1: Val) -> Challenge {
    Challenge::from_basis_coefficients_fn(|i| if i == 0 { c0 } else { c1 })
}

/// Basis coefficients of an extension element.
pub fn ef_coeffs(e: &Challenge) -> [Val; 2] {
    let s = e.as_basis_coefficients_slice();
    [s[0], s[1]]
}

/// Canonical little-endian bytes of a base element.
pub fn f_bytes(v: &Val) -> [u8; F_BYTES] {
    v.as_canonical_u64().to_le_bytes()
}

/// Wire bytes of an extension element (`c0 || c1`).
pub fn ef_bytes(e: &Challenge) -> [u8; EF_BYTES] {
    let [c0, c1] = ef_coeffs(e);
    let mut out = [0u8; EF_BYTES];
    out[..F_BYTES].copy_from_slice(&f_bytes(&c0));
    out[F_BYTES..].copy_from_slice(&f_bytes(&c1));
    out
}

/// Wire bytes of the public values (`a || b || x`).
pub fn public_values_bytes(pv: &[Val; 3]) -> Vec<u8> {
    pv.iter().flat_map(f_bytes).collect()
}

/// One decoded FRI round.
#[derive(Debug, Clone)]
pub struct RawRound {
    pub log_arity: usize,
    pub commit: [u8; DIGEST_BYTES],
    pub pow_witness: Val,
    /// `sibling_values[q]` holds the `arity - 1` values at the positions other than the query's own.
    pub sibling_values: Vec<Vec<Challenge>>,
    pub siblings: Vec<[u8; DIGEST_BYTES]>,
}

/// The fully decoded proof, still in wire structure.
#[derive(Debug, Clone)]
pub struct RawProof {
    pub layout: Layout,
    pub degree_bits: usize,
    pub trace_root: [u8; DIGEST_BYTES],
    pub quotient_root: [u8; DIGEST_BYTES],
    pub trace_local: [Challenge; 2],
    pub trace_next: [Challenge; 2],
    pub quotient_chunk: [Challenge; 2],
    pub rounds: Vec<RawRound>,
    pub final_poly: Vec<Challenge>,
    pub query_pow_witness: Val,
    pub trace_rows: Vec<[Val; 2]>,
    pub trace_siblings: Vec<[u8; DIGEST_BYTES]>,
    pub quotient_rows: Vec<[Val; 2]>,
    pub quotient_siblings: Vec<[u8; DIGEST_BYTES]>,
    pub proof_id: [u8; DIGEST_BYTES],
}

fn read_ef_pair(bytes: &[u8], off: usize) -> Result<[Challenge; 2], LayoutError> {
    Ok([read_ef(bytes, off)?, read_ef(bytes, off + EF_BYTES)?])
}

fn read_rows(bytes: &[u8], off: usize, q: usize) -> Result<Vec<[Val; 2]>, LayoutError> {
    (0..q)
        .map(|i| {
            let base = off + i * TRACE_WIDTH * F_BYTES;
            Ok([read_f(bytes, base)?, read_f(bytes, base + F_BYTES)?])
        })
        .collect()
}

fn read_digests(bytes: &[u8], off: usize, count: usize) -> Vec<[u8; DIGEST_BYTES]> {
    (0..count)
        .map(|i| read_digest(bytes, off + i * DIGEST_BYTES))
        .collect()
}

/// Decode a proof: layout (version, header, exact length) first, then every element with the
/// canonical-encoding check, in wire order.
pub fn decode_raw(bytes: &[u8], cfg: &FriConfig) -> Result<RawProof, LayoutError> {
    let layout = parse_layout(bytes, cfg)?;
    let p = &layout.prefix;
    let q = cfg.num_queries;

    let trace_root = read_digest(bytes, p.trace_root);
    let quotient_root = read_digest(bytes, p.quotient_root);
    let trace_local = read_ef_pair(bytes, p.trace_local)?;
    let trace_next = read_ef_pair(bytes, p.trace_next)?;
    let quotient_chunk = read_ef_pair(bytes, p.quotient_chunk)?;

    let mut commits = Vec::with_capacity(layout.rounds.len());
    let mut witnesses = Vec::with_capacity(layout.rounds.len());
    for r in 0..layout.rounds.len() {
        commits.push(read_digest(bytes, p.round_commits[r]));
        witnesses.push(read_f(bytes, p.round_pow_witnesses[r])?);
    }
    let final_poly = (0..cfg.final_poly_len())
        .map(|i| read_ef(bytes, p.final_poly + i * EF_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
    let query_pow_witness = read_f(bytes, p.query_pow_witness)?;

    let trace_block = &layout.blocks[0];
    let quotient_block = &layout.blocks[1];
    let trace_rows = read_rows(bytes, trace_block.rows_offset, q)?;
    let trace_siblings = read_digests(bytes, trace_block.siblings_offset, trace_block.sib_count);
    let quotient_rows = read_rows(bytes, quotient_block.rows_offset, q)?;
    let quotient_siblings = read_digests(
        bytes,
        quotient_block.siblings_offset,
        quotient_block.sib_count,
    );

    let mut rounds = Vec::with_capacity(layout.rounds.len());
    for (r, rl) in layout.rounds.iter().enumerate() {
        let per_query = (1usize << rl.log_arity) - 1;
        let mut sibling_values = Vec::with_capacity(q);
        for qi in 0..q {
            let base = rl.sibling_values_offset + qi * per_query * EF_BYTES;
            let vals = (0..per_query)
                .map(|j| read_ef(bytes, base + j * EF_BYTES))
                .collect::<Result<Vec<_>, _>>()?;
            sibling_values.push(vals);
        }
        rounds.push(RawRound {
            log_arity: rl.log_arity,
            commit: commits[r],
            pow_witness: witnesses[r],
            sibling_values,
            siblings: read_digests(bytes, rl.siblings_offset, rl.sib_count),
        });
    }

    let proof_id = keccak256(&bytes[..layout.p_end]);
    Ok(RawProof {
        degree_bits: layout.degree_bits,
        layout,
        trace_root,
        quotient_root,
        trace_local,
        trace_next,
        quotient_chunk,
        rounds,
        final_poly,
        query_pow_witness,
        trace_rows,
        trace_siblings,
        quotient_rows,
        quotient_siblings,
        proof_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FriConfig {
        crate::config::preset("c3").unwrap()
    }

    #[test]
    fn header_rules() {
        let c = cfg();
        assert!(validate_header(10, &[3, 3, 1], &c).is_ok());
        assert_eq!(
            validate_header(10, &[3, 3], &c),
            Err(LayoutError::BadHeader)
        );
        assert_eq!(
            validate_header(10, &[0, 3, 4], &c),
            Err(LayoutError::BadHeader)
        );
        assert_eq!(
            validate_header(10, &[4, 3], &c),
            Err(LayoutError::BadHeader)
        );
        assert_eq!(
            validate_header(30, &[3; 9], &c),
            Err(LayoutError::BadHeader)
        );
        assert_eq!(validate_header(0, &[], &c), Err(LayoutError::BadHeader));
    }

    #[test]
    fn short_inputs_are_length_errors() {
        let c = cfg();
        assert_eq!(parse_layout(&[], &c), Err(LayoutError::BadLength));
        assert_eq!(parse_layout(&[2], &c), Err(LayoutError::BadVersion));
        assert_eq!(parse_layout(&[1, 10], &c), Err(LayoutError::BadLength));
        assert_eq!(
            parse_layout(&[1, 10, 3, 3, 3, 1], &c),
            Err(LayoutError::BadLength)
        );
    }

    #[test]
    fn prefix_offsets_are_contiguous() {
        let p = prefix_layout(3, 8);
        assert_eq!(p.trace_root, 6);
        assert_eq!(p.quotient_root, 38);
        assert_eq!(p.trace_local, 70);
        assert_eq!(p.trace_next, 102);
        assert_eq!(p.quotient_chunk, 134);
        assert_eq!(p.round_commits, vec![166, 206, 246]);
        assert_eq!(p.round_pow_witnesses, vec![198, 238, 278]);
        assert_eq!(p.final_poly, 286);
        assert_eq!(p.query_pow_witness, 286 + 128);
        assert_eq!(p.p_end, 286 + 128 + 8);
    }

    #[test]
    fn non_canonical_is_rejected() {
        let mut bytes = vec![0u8; 8];
        bytes.copy_from_slice(&GOLDILOCKS_P.to_le_bytes());
        assert_eq!(read_f(&bytes, 0), Err(LayoutError::NonCanonicalElement));
        bytes.copy_from_slice(&(GOLDILOCKS_P - 1).to_le_bytes());
        assert!(read_f(&bytes, 0).is_ok());
    }
}
