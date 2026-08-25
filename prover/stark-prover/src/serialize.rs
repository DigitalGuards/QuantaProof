//! `Proof<Config>` <-> calldata layout v1.

use std::fmt;

use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
use p3_merkle_tree::{MerkleCap, PrunedMerklePaths};
use p3_uni_stark::{Commitments, OpenedValues};

use crate::config::{FriConfig, Proof, Val};
use crate::layout::{
    DIGEST_BYTES, EF_BYTES, LayoutError, RawProof, TRACE_WIDTH, VERSION, decode_raw, ef_bytes,
    f_bytes, validate_header,
};

/// Errors while encoding a proof whose shape is outside what layout v1 can express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializeError {
    Shape(String),
    TooManySiblings(usize),
}

impl fmt::Display for SerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializeError::Shape(s) => write!(f, "proof shape not representable: {s}"),
            SerializeError::TooManySiblings(n) => {
                write!(f, "sibling count {n} does not fit in a u16")
            }
        }
    }
}

impl std::error::Error for SerializeError {}

fn shape(msg: impl Into<String>) -> SerializeError {
    SerializeError::Shape(msg.into())
}

fn single_root(
    cap: &MerkleCap<Val, [u8; DIGEST_BYTES]>,
    what: &str,
) -> Result<[u8; 32], SerializeError> {
    let roots = cap.roots();
    if roots.len() != 1 {
        return Err(shape(format!(
            "{what}: expected a cap of height 0, got {} roots",
            roots.len()
        )));
    }
    Ok(roots[0])
}

fn push_sib_count(out: &mut Vec<u8>, count: usize) -> Result<(), SerializeError> {
    let c = u16::try_from(count).map_err(|_| SerializeError::TooManySiblings(count))?;
    out.extend_from_slice(&c.to_be_bytes());
    Ok(())
}

/// Encode a proof into calldata layout v1.
pub fn serialize_proof(proof: &Proof, cfg: &FriConfig) -> Result<Vec<u8>, SerializeError> {
    let q = cfg.num_queries;
    let fri = &proof.opening_proof;
    let rounds = fri.commit_phase_commits.len();
    if fri.commit_pow_witnesses.len() != rounds || fri.commit_phase_openings.len() != rounds {
        return Err(shape("commit phase vectors have different lengths"));
    }
    if rounds > 255 {
        return Err(shape("more than 255 FRI rounds"));
    }
    let degree_bits =
        u8::try_from(proof.degree_bits).map_err(|_| shape("degree_bits does not fit in a byte"))?;
    let log_arities: Vec<usize> = fri
        .commit_phase_openings
        .iter()
        .map(|s| s.log_arity as usize)
        .collect();
    validate_header(proof.degree_bits, &log_arities, cfg)
        .map_err(|e| shape(format!("header would not validate: {e}")))?;

    let ov = &proof.opened_values;
    if ov.trace_local.len() != TRACE_WIDTH {
        return Err(shape("trace_local width"));
    }
    let trace_next = ov
        .trace_next
        .as_ref()
        .ok_or_else(|| shape("trace_next missing"))?;
    if trace_next.len() != TRACE_WIDTH {
        return Err(shape("trace_next width"));
    }
    if ov.preprocessed_local.is_some() || ov.preprocessed_next.is_some() {
        return Err(shape("preprocessed openings present"));
    }
    if ov.quotient_chunks.len() != 1 || ov.quotient_chunks[0].len() != 2 {
        return Err(shape(
            "expected exactly one quotient chunk of two coefficients",
        ));
    }
    if ov.random.is_some() || proof.commitments.random.is_some() {
        return Err(shape("randomised (zk) commitments present"));
    }
    if fri.final_poly.len() != cfg.final_poly_len() {
        return Err(shape("final polynomial length"));
    }
    if fri.input_openings.len() != 2 {
        return Err(shape(
            "expected exactly two input batches (trace, quotient)",
        ));
    }

    let mut out = Vec::new();
    out.push(VERSION);
    out.push(degree_bits);
    out.push(rounds as u8);
    for &k in &log_arities {
        out.push(k as u8);
    }
    out.extend_from_slice(&single_root(&proof.commitments.trace, "trace commitment")?);
    out.extend_from_slice(&single_root(
        &proof.commitments.quotient_chunks,
        "quotient commitment",
    )?);
    for e in &ov.trace_local {
        out.extend_from_slice(&ef_bytes(e));
    }
    for e in trace_next {
        out.extend_from_slice(&ef_bytes(e));
    }
    for e in &ov.quotient_chunks[0] {
        out.extend_from_slice(&ef_bytes(e));
    }
    for (commit, witness) in fri
        .commit_phase_commits
        .iter()
        .zip(&fri.commit_pow_witnesses)
    {
        out.extend_from_slice(&single_root(commit, "commit phase commitment")?);
        out.extend_from_slice(&f_bytes(witness));
    }
    for e in &fri.final_poly {
        out.extend_from_slice(&ef_bytes(e));
    }
    out.extend_from_slice(&f_bytes(&fri.query_pow_witness));

    for (batch_idx, batch) in fri.input_openings.iter().enumerate() {
        if batch.opened_values.len() != q {
            return Err(shape(format!(
                "input batch {batch_idx}: expected {q} query rows"
            )));
        }
        for row_set in &batch.opened_values {
            if row_set.len() != 1 || row_set[0].len() != TRACE_WIDTH {
                return Err(shape(format!(
                    "input batch {batch_idx}: expected one matrix row of width {TRACE_WIDTH}"
                )));
            }
            for v in &row_set[0] {
                out.extend_from_slice(&f_bytes(v));
            }
        }
        push_sib_count(&mut out, batch.opening_proof.sibling_hashes.len())?;
        for d in &batch.opening_proof.sibling_hashes {
            out.extend_from_slice(d);
        }
    }

    for (r, step) in fri.commit_phase_openings.iter().enumerate() {
        let per_query = (1usize << log_arities[r]) - 1;
        if step.sibling_values.len() != q {
            return Err(shape(format!("round {r}: expected {q} sibling rows")));
        }
        for sv in &step.sibling_values {
            if sv.len() != per_query {
                return Err(shape(format!(
                    "round {r}: expected {per_query} sibling values"
                )));
            }
            for e in sv {
                out.extend_from_slice(&ef_bytes(e));
            }
        }
        push_sib_count(&mut out, step.opening_proof.sibling_hashes.len())?;
        for d in &step.opening_proof.sibling_hashes {
            out.extend_from_slice(d);
        }
    }

    Ok(out)
}

/// Rebuild the upstream proof structure from a decoded wire proof.
pub fn raw_to_proof(raw: &RawProof) -> Proof {
    let cap = |root: [u8; DIGEST_BYTES]| MerkleCap::<Val, [u8; DIGEST_BYTES]>::new(vec![root]);
    let paths = |siblings: &[[u8; DIGEST_BYTES]]| PrunedMerklePaths {
        sibling_hashes: siblings.to_vec(),
    };
    let rows = |rows: &[[Val; 2]]| -> Vec<Vec<Vec<Val>>> {
        rows.iter().map(|r| vec![r.to_vec()]).collect()
    };

    let input_openings = vec![
        BatchMultiOpening {
            opened_values: rows(&raw.trace_rows),
            opening_proof: paths(&raw.trace_siblings),
        },
        BatchMultiOpening {
            opened_values: rows(&raw.quotient_rows),
            opening_proof: paths(&raw.quotient_siblings),
        },
    ];
    let commit_phase_openings = raw
        .rounds
        .iter()
        .map(|r| CommitPhaseMultiStep {
            log_arity: r.log_arity as u8,
            sibling_values: r.sibling_values.clone(),
            opening_proof: paths(&r.siblings),
        })
        .collect();
    let opening_proof = FriProof {
        commit_phase_commits: raw.rounds.iter().map(|r| cap(r.commit)).collect(),
        commit_pow_witnesses: raw.rounds.iter().map(|r| r.pow_witness).collect(),
        input_openings,
        commit_phase_openings,
        final_poly: raw.final_poly.clone(),
        query_pow_witness: raw.query_pow_witness,
    };
    Proof {
        commitments: Commitments {
            trace: cap(raw.trace_root),
            quotient_chunks: cap(raw.quotient_root),
            random: None,
        },
        opened_values: OpenedValues {
            trace_local: raw.trace_local.to_vec(),
            trace_next: Some(raw.trace_next.to_vec()),
            preprocessed_local: None,
            preprocessed_next: None,
            quotient_chunks: vec![raw.quotient_chunk.to_vec()],
            random: None,
        },
        opening_proof,
        degree_bits: raw.degree_bits,
    }
}

/// Decode calldata layout v1 into the upstream proof structure.
pub fn deserialize_proof(bytes: &[u8], cfg: &FriConfig) -> Result<Proof, LayoutError> {
    let raw = decode_raw(bytes, cfg)?;
    Ok(raw_to_proof(&raw))
}

/// Byte length of a wire extension element, re-exported for size arithmetic.
pub const fn ef_wire_bytes() -> usize {
    EF_BYTES
}
