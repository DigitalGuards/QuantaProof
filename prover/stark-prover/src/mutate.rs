//! Negative test vectors: single-fault mutations of a valid proof, each paired with the error
//! the mirror (and therefore the on-chain verifier) raises for it.

use p3_field::{PrimeCharacteristicRing, PrimeField64};

use crate::config::{FriConfig, Val};
use crate::layout::{DIGEST_BYTES, EF_BYTES, F_BYTES, GOLDILOCKS_P, RawProof, SIB_COUNT_BYTES};
use crate::mirror::mirror_verify;

/// One mutated instance.
#[derive(Debug, Clone)]
pub struct Mutation {
    pub name: String,
    pub description: String,
    pub bytes: Vec<u8>,
    pub public_values: [Val; 3],
}

/// A mutation together with the error the mirror raised for it.
#[derive(Debug, Clone)]
pub struct ClassifiedMutation {
    pub mutation: Mutation,
    pub error: String,
}

fn xor_byte(bytes: &mut [u8], off: usize, mask: u8) {
    bytes[off] ^= mask;
}

/// Change a field element in place while keeping it canonical: flip the low bit of the
/// little-endian encoding, falling back to `v + 1 mod p` in the (astronomically rare) case the
/// flipped value would leave the field.
fn perturb_element(bytes: &mut [u8], off: usize) {
    let word: [u8; F_BYTES] = bytes[off..off + F_BYTES].try_into().unwrap();
    let v = u64::from_le_bytes(word);
    let flipped = v ^ 1;
    let new = if flipped < GOLDILOCKS_P {
        flipped
    } else {
        (v + 1) % GOLDILOCKS_P
    };
    bytes[off..off + F_BYTES].copy_from_slice(&new.to_le_bytes());
}

fn set_element(bytes: &mut [u8], off: usize, v: u64) {
    bytes[off..off + F_BYTES].copy_from_slice(&v.to_le_bytes());
}

fn set_sib_count(bytes: &mut [u8], off: usize, count: usize) {
    let c = u16::try_from(count).expect("count fits");
    bytes[off..off + SIB_COUNT_BYTES].copy_from_slice(&c.to_be_bytes());
}

/// Build every applicable mutation of `bytes`.
pub fn generate_mutations(
    cfg: &FriConfig,
    raw: &RawProof,
    bytes: &[u8],
    public_values: &[Val; 3],
    indices: &[usize],
) -> Vec<Mutation> {
    let layout = &raw.layout;
    let p = &layout.prefix;
    let trace_block = &layout.blocks[0];
    let mut out: Vec<Mutation> = Vec::new();
    let mut push = |name: &str, description: &str, bytes: Vec<u8>, pv: [Val; 3]| {
        out.push(Mutation {
            name: name.to_string(),
            description: description.to_string(),
            bytes,
            public_values: pv,
        });
    };
    let pv = *public_values;

    // Opened values and roots.
    {
        let mut b = bytes.to_vec();
        perturb_element(&mut b, p.trace_local);
        push("flip_trace_local", "trace_local[0].c0 changed", b, pv);
    }
    {
        let mut b = bytes.to_vec();
        perturb_element(&mut b, p.quotient_chunk);
        push("flip_quotient_chunk", "quotient_chunk[0].c0 changed", b, pv);
    }
    {
        let mut b = bytes.to_vec();
        perturb_element(&mut b, p.final_poly);
        push("flip_final_poly0", "final_poly[0].c0 changed", b, pv);
    }
    {
        let mut b = bytes.to_vec();
        xor_byte(&mut b, p.trace_root, 0x01);
        push("flip_trace_root", "trace_root byte 0 flipped", b, pv);
    }
    if let Some(&off) = p.round_commits.first() {
        let mut b = bytes.to_vec();
        xor_byte(&mut b, off, 0x01);
        push("flip_fri_commit0", "fri_commit[0] byte 0 flipped", b, pv);
    }

    // Merkle data.
    if trace_block.sib_count > 0 {
        let mut b = bytes.to_vec();
        xor_byte(&mut b, trace_block.siblings_offset, 0x01);
        push(
            "flip_input_sibling",
            "trace block sibling 0 byte 0 flipped",
            b,
            pv,
        );
    }
    if let Some((r, rl)) = layout
        .rounds
        .iter()
        .enumerate()
        .find(|(_, rl)| rl.sib_count > 0)
    {
        let mut b = bytes.to_vec();
        xor_byte(&mut b, rl.siblings_offset, 0x01);
        push(
            "flip_round_sibling",
            &format!("round[{r}] sibling 0 byte 0 flipped"),
            b,
            pv,
        );
    }
    if let Some(rl) = layout.rounds.first() {
        let mut b = bytes.to_vec();
        perturb_element(&mut b, rl.sibling_values_offset);
        push(
            "flip_sibling_value",
            "round[0] query 0 sibling value 0 c0 changed",
            b,
            pv,
        );
    }

    // Proof of work.
    {
        let mut b = bytes.to_vec();
        let current = raw.query_pow_witness.as_canonical_u64();
        set_element(
            &mut b,
            p.query_pow_witness,
            if current == 0 { 1 } else { 0 },
        );
        push("zero_query_pow_witness", "query_pow_witness zeroed", b, pv);
    }
    if cfg.commit_pow_bits > 0
        && let Some(&off) = p.round_pow_witnesses.first()
    {
        let mut b = bytes.to_vec();
        let current = raw.rounds[0].pow_witness.as_canonical_u64();
        set_element(&mut b, off, if current == 0 { 1 } else { 0 });
        push(
            "zero_commit_pow_witness",
            "commit_pow_witness[0] zeroed",
            b,
            pv,
        );
    }

    // Public values.
    {
        let mut pv2 = pv;
        pv2[2] = Val::from_u64((pv[2].as_canonical_u64() + 1) % GOLDILOCKS_P);
        push(
            "wrong_public_value",
            "public value x replaced by x + 1",
            bytes.to_vec(),
            pv2,
        );
    }

    // Header.
    {
        let mut b = bytes.to_vec();
        b[0] = 2;
        push("bad_version", "version byte = 2", b, pv);
    }
    {
        let mut b = bytes.to_vec();
        b[1] = b[1].wrapping_add(1);
        push("degree_bits_plus_one", "degree_bits + 1", b, pv);
    }
    if !layout.rounds.is_empty() {
        let mut b = bytes.to_vec();
        b[p.log_arity] = 0;
        push("log_arity_zero", "log_arity[0] = 0", b, pv);
        let mut b = bytes.to_vec();
        b[p.log_arity] = (cfg.max_log_arity + 1) as u8;
        push(
            "log_arity_too_large",
            "log_arity[0] = max_log_arity + 1",
            b,
            pv,
        );
    }
    if let Some(last) = layout.rounds.last() {
        let r = layout.rounds.len() - 1;
        let mut b = Vec::with_capacity(bytes.len());
        b.push(bytes[0]);
        b.push(bytes[1]);
        b.push((layout.rounds.len() - 1) as u8);
        b.extend_from_slice(&bytes[p.log_arity..p.log_arity + r]);
        b.extend_from_slice(&bytes[p.trace_root..p.round_commits[r]]);
        b.extend_from_slice(&bytes[p.final_poly..last.sibling_values_offset]);
        push(
            "drop_last_round",
            "last FRI round removed from header, prefix and query data",
            b,
            pv,
        );
    }

    // Length.
    {
        let mut b = bytes.to_vec();
        b.push(0);
        push("append_byte", "one zero byte appended", b, pv);
    }
    for (name, cut) in [
        ("truncate_1", 1usize),
        ("truncate_32", DIGEST_BYTES),
        ("truncate_half", bytes.len() / 2),
    ] {
        if cut < bytes.len() {
            let b = bytes[..bytes.len() - cut].to_vec();
            push(name, &format!("last {cut} bytes removed"), b, pv);
        }
    }

    // Canonical encoding.
    {
        let mut b = bytes.to_vec();
        set_element(&mut b, p.trace_local, u64::MAX);
        push(
            "non_canonical_element",
            "trace_local[0].c0 = 0xFFFFFFFFFFFFFFFF",
            b,
            pv,
        );
    }

    // Query rows.
    {
        let q = cfg.num_queries;
        let mut pair = None;
        'outer: for i in 0..q {
            for j in (i + 1)..q {
                if indices[i] != indices[j] && raw.trace_rows[i] != raw.trace_rows[j] {
                    pair = Some((i, j));
                    break 'outer;
                }
            }
        }
        if let Some((i, j)) = pair {
            let mut b = bytes.to_vec();
            let row = 2 * F_BYTES;
            let (oi, oj) = (
                trace_block.rows_offset + i * row,
                trace_block.rows_offset + j * row,
            );
            let ri: Vec<u8> = b[oi..oi + row].to_vec();
            let rj: Vec<u8> = b[oj..oj + row].to_vec();
            b[oi..oi + row].copy_from_slice(&rj);
            b[oj..oj + row].copy_from_slice(&ri);
            push(
                "swap_query_rows",
                &format!("trace rows of queries {i} and {j} swapped"),
                b,
                pv,
            );
        }
    }
    {
        let q = cfg.num_queries;
        let mut dup = None;
        'outer: for i in 0..q {
            for j in (i + 1)..q {
                if indices[i] == indices[j] {
                    dup = Some((i, j));
                    break 'outer;
                }
            }
        }
        if let Some((i, j)) = dup {
            let mut b = bytes.to_vec();
            perturb_element(&mut b, trace_block.rows_offset + j * 2 * F_BYTES);
            push(
                "duplicate_opening_mismatch",
                &format!("queries {i} and {j} open the same leaf; row of {j} changed"),
                b,
                pv,
            );
        }
    }

    // Sibling counts (trace block).
    {
        let mut b = bytes.to_vec();
        b.splice(trace_block.end..trace_block.end, [0u8; DIGEST_BYTES]);
        set_sib_count(
            &mut b,
            trace_block.sib_count_offset,
            trace_block.sib_count + 1,
        );
        push(
            "sib_count_plus_one",
            "trace block: sib_count + 1 with an extra zero digest appended",
            b,
            pv,
        );
    }
    if trace_block.sib_count > 0 {
        let mut b = bytes.to_vec();
        b.drain(trace_block.end - DIGEST_BYTES..trace_block.end);
        set_sib_count(
            &mut b,
            trace_block.sib_count_offset,
            trace_block.sib_count - 1,
        );
        push(
            "sib_count_minus_one",
            "trace block: sib_count - 1 with the last digest removed",
            b,
            pv,
        );
    }
    {
        let mut b = bytes.to_vec();
        set_sib_count(
            &mut b,
            trace_block.sib_count_offset,
            trace_block.sib_count + 1,
        );
        push(
            "sib_count_field_plus_one",
            "trace block: sib_count + 1 without changing the data",
            b,
            pv,
        );
    }
    {
        let _ = EF_BYTES;
    }

    out
}

/// Run the mirror on every mutation and attach the error it raised. Mutations the mirror
/// accepts (which a correct generator never produces) are returned in the second list.
pub fn classify(
    cfg: &FriConfig,
    mutations: Vec<Mutation>,
) -> (Vec<ClassifiedMutation>, Vec<Mutation>) {
    let mut rejected = Vec::new();
    let mut accepted = Vec::new();
    for m in mutations {
        match mirror_verify(cfg, &m.bytes, &m.public_values) {
            Ok(_) => accepted.push(m),
            Err(e) => rejected.push(ClassifiedMutation {
                mutation: m,
                error: e.name().to_string(),
            }),
        }
    }
    (rejected, accepted)
}
