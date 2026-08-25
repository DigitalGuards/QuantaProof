//! Calldata layout v1: serialise / deserialise round trip, offsets and the exact-length rule.

mod common;

use stark_prover::layout::{DIGEST_BYTES, decode_raw, parse_layout};
use stark_prover::prove::verify_upstream;
use stark_prover::serialize::{deserialize_proof, serialize_proof};

#[test]
fn serialize_deserialize_round_trip_is_lossless_and_verifies_upstream() {
    for (name, cfg, n) in common::test_cases() {
        let g = common::generate_case(name, &cfg, n);
        let decoded = deserialize_proof(&g.bytes, &cfg).expect("decode");
        let again = serialize_proof(&decoded, &cfg).expect("re-encode");
        assert_eq!(again, g.bytes, "{name}: re-encoding differs");
        let (res, transcript) = verify_upstream(&cfg, &decoded, &g.public_values);
        res.unwrap_or_else(|e| panic!("{name}: upstream rejected the decoded proof: {e:?}"));
        assert_eq!(
            transcript, g.verifier_transcript,
            "{name}: transcript changed after round trip"
        );
        // The serde view of the original and of the decoded proof agree as well.
        let a = serde_json::to_vec(&g.proof).unwrap();
        let b = serde_json::to_vec(&decoded).unwrap();
        assert_eq!(
            a, b,
            "{name}: serde view of the proof differs after round trip"
        );
    }
}

#[test]
fn layout_offsets_are_contiguous_and_exact() {
    for (name, cfg, n) in common::test_cases() {
        let g = common::generate_case(name, &cfg, n);
        let layout = parse_layout(&g.bytes, &cfg).expect("layout");
        assert_eq!(layout.total_len, g.bytes.len(), "{name}");
        assert_eq!(layout.degree_bits, n);
        assert_eq!(
            layout.log_arities,
            cfg.arity_schedule(n),
            "{name}: arity schedule"
        );
        assert_eq!(layout.p_end, layout.prefix.p_end);
        let r = layout.rounds.len();
        assert_eq!(
            layout.p_end,
            171 + 41 * r + 16 * cfg.final_poly_len(),
            "{name}: pEnd formula"
        );
        let mut cursor = layout.p_end;
        for b in &layout.blocks {
            assert_eq!(b.rows_offset, cursor, "{name}: block {} start", b.name);
            assert_eq!(b.rows_len, cfg.num_queries * 16);
            assert_eq!(b.sib_count_offset, b.rows_offset + b.rows_len);
            assert_eq!(b.siblings_offset, b.sib_count_offset + 2);
            assert_eq!(b.end, b.siblings_offset + b.sib_count * DIGEST_BYTES);
            cursor = b.end;
        }
        for (r, rl) in layout.rounds.iter().enumerate() {
            assert_eq!(rl.sibling_values_offset, cursor, "{name}: round {r} start");
            assert_eq!(
                rl.sibling_values_len,
                cfg.num_queries * ((1 << rl.log_arity) - 1) * 16
            );
            assert_eq!(
                rl.sib_count_offset,
                rl.sibling_values_offset + rl.sibling_values_len
            );
            assert_eq!(rl.siblings_offset, rl.sib_count_offset + 2);
            assert_eq!(rl.end, rl.siblings_offset + rl.sib_count * DIGEST_BYTES);
            cursor = rl.end;
        }
        assert_eq!(cursor, g.bytes.len(), "{name}: trailing bytes");
        // Every sibling count is what the frontier walk over the sampled indices requires.
        for (mb, lb) in g.mirror.merkle.iter().zip(layout.blocks.iter()) {
            assert_eq!(mb.sib_count, lb.sib_count, "{name}: {}", lb.name);
        }
        for (mb, rl) in g.mirror.merkle.iter().skip(2).zip(layout.rounds.iter()) {
            assert_eq!(mb.sib_count, rl.sib_count, "{name}: {}", mb.name);
        }
        let raw = decode_raw(&g.bytes, &cfg).unwrap();
        assert_eq!(raw.proof_id, g.mirror.proof_id);
        assert_eq!(raw.trace_rows.len(), cfg.num_queries);
    }
}

#[test]
fn extra_and_missing_bytes_are_length_errors() {
    let (name, cfg, n) = common::test_cases()[2];
    let g = common::generate_case(name, &cfg, n);
    let mut longer = g.bytes.clone();
    longer.push(0);
    assert_eq!(parse_layout(&longer, &cfg).unwrap_err().name(), "BadLength");
    let shorter = &g.bytes[..g.bytes.len() - 1];
    assert_eq!(parse_layout(shorter, &cfg).unwrap_err().name(), "BadLength");
    assert_eq!(
        parse_layout(&g.bytes[..5], &cfg).unwrap_err().name(),
        "BadLength"
    );
}
