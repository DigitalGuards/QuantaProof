//! Every mutation must be rejected by the decoder or the mirror, and (when it still decodes)
//! by the unmodified upstream verifier.

mod common;

use std::collections::BTreeSet;

use stark_prover::layout::decode_raw;
use stark_prover::mirror::{MirrorError, mirror_verify};
use stark_prover::mutate::generate_mutations;
use stark_prover::prove::verify_upstream;
use stark_prover::serialize::raw_to_proof;

#[test]
fn every_mutation_is_rejected_by_mirror_and_upstream() {
    let mut seen_errors = BTreeSet::new();
    let mut seen_mutations = BTreeSet::new();
    for (name, cfg, n) in common::test_cases() {
        let g = common::generate_case(name, &cfg, n);
        let raw = decode_raw(&g.bytes, &cfg).unwrap();
        let mutations = generate_mutations(
            &cfg,
            &raw,
            &g.bytes,
            &g.public_values,
            &g.mirror.challenges.indices,
        );
        assert!(
            mutations.len() >= 23,
            "{name}: only {} mutations",
            mutations.len()
        );
        for m in &mutations {
            seen_mutations.insert(m.name.clone());
            let err = match mirror_verify(&cfg, &m.bytes, &m.public_values) {
                Ok(_) => panic!("{name}: mutation {} accepted by the mirror", m.name),
                Err(e) => e,
            };
            assert!(
                MirrorError::ALL_NAMES.contains(&err.name()),
                "{name}: mutation {} raised the non-protocol error {err}",
                m.name
            );
            seen_errors.insert(err.name());
            if let Ok(decoded) = decode_raw(&m.bytes, &cfg) {
                let proof = raw_to_proof(&decoded);
                let (res, _) = verify_upstream(&cfg, &proof, &m.public_values);
                assert!(
                    res.is_err(),
                    "{name}: mutation {} decodes and is accepted by the upstream verifier",
                    m.name
                );
            }
            let expected = match m.name.as_str() {
                "bad_version" => Some("BadVersion"),
                "degree_bits_plus_one"
                | "log_arity_zero"
                | "log_arity_too_large"
                | "drop_last_round" => Some("BadHeader"),
                "append_byte"
                | "truncate_1"
                | "truncate_32"
                | "truncate_half"
                | "sib_count_field_plus_one" => Some("BadLength"),
                "non_canonical_element" => Some("NonCanonicalElement"),
                "sib_count_plus_one" | "sib_count_minus_one" => Some("SiblingCountMismatch"),
                "flip_input_sibling" | "flip_round_sibling" | "swap_query_rows" => {
                    Some("MerkleRootMismatch")
                }
                "flip_sibling_value" => Some("FinalPolyMismatch"),
                "flip_trace_local"
                | "flip_quotient_chunk"
                | "wrong_public_value"
                | "flip_trace_root" => Some("OodMismatch"),
                "duplicate_opening_mismatch" => Some("DuplicateOpeningMismatch"),
                _ => None,
            };
            if let Some(expected) = expected {
                assert_eq!(err.name(), expected, "{name}: mutation {}", m.name);
            }
        }
    }
    for required in [
        "BadVersion",
        "BadHeader",
        "BadLength",
        "NonCanonicalElement",
        "PowFailed",
        "SiblingCountMismatch",
        "MerkleRootMismatch",
        "FinalPolyMismatch",
        "OodMismatch",
        "DuplicateOpeningMismatch",
    ] {
        assert!(
            seen_errors.contains(required),
            "no mutation exercised {required}"
        );
    }
    assert!(
        seen_mutations.contains("duplicate_opening_mismatch"),
        "no colliding queries in any test case"
    );
}
