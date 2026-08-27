//! The mirror verifier: transcript equality with the unmodified upstream verifier, fold-form
//! agreement (binary == barycentric == upstream `fold_row`), and constraint folding.

mod common;

use core::marker::PhantomData;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
use stark_prover::challenger::RawEvent;
use stark_prover::config::{Challenge, Val, program_identifier};
use stark_prover::layout::{decode_raw, ef_from_coeffs};
use stark_prover::mirror::{
    TranscriptEvent, fold_row_barycentric, fold_row_binary, mirror_verify, recompose_quotient,
};

fn ef(s: &[String; 2]) -> Challenge {
    ef_from_coeffs(
        Val::from_u64(s[0].parse().unwrap()),
        Val::from_u64(s[1].parse().unwrap()),
    )
}

#[test]
fn mirror_transcript_equals_upstream_verifier_transcript() {
    for (name, cfg, n) in common::test_cases() {
        let g = common::generate_case(name, &cfg, n);
        assert_eq!(
            g.prover_transcript, g.verifier_transcript,
            "{name}: prover vs verifier"
        );
        assert_eq!(
            g.mirror.raw_transcript, g.verifier_transcript,
            "{name}: mirror vs verifier"
        );
        // The transcript starts with the program identifier, the three instance words, the
        // trace root and the public values in one observe run, then samples alpha.
        let events = &g.verifier_transcript.events;
        match &events[0] {
            RawEvent::Observe(bytes) => {
                assert_eq!(
                    bytes.len(),
                    32 + 3 * 8 + 32 + 3 * 8,
                    "{name}: first observe run"
                );
                assert_eq!(&bytes[..32], &program_identifier(&cfg), "{name}: step 0");
                assert_eq!(&bytes[32..40], &(n as u64).to_le_bytes());
                assert_eq!(&bytes[40..48], &(n as u64).to_le_bytes());
                assert_eq!(&bytes[48..56], &0u64.to_le_bytes());
            }
            other => panic!("{name}: first event is not an observe run: {other:?}"),
        }
        assert!(
            matches!(&events[1], RawEvent::Sample(b) if b.len() >= 16),
            "{name}: alpha"
        );
        match events.last().unwrap() {
            RawEvent::Sample(bytes) => {
                assert!(
                    bytes.len() >= 8 * cfg.num_queries,
                    "{name}: index sampling run"
                );
            }
            other => panic!("{name}: last event is not a sample run: {other:?}"),
        }
    }
}

#[test]
fn labelled_events_follow_the_protocol_order() {
    let (name, cfg, n) = common::test_cases()[2];
    let g = common::generate_case(name, &cfg, n);
    let labels: Vec<String> = g
        .mirror
        .events
        .iter()
        .filter_map(|e| match e {
            TranscriptEvent::Observe { label, .. } => Some(format!("observe {label}")),
            TranscriptEvent::SampleField { label, .. } => Some(format!("sample {label}")),
            TranscriptEvent::SampleBits { label, .. } => Some(format!("bits {label}")),
            TranscriptEvent::CheckPow { label, .. } => Some(format!("pow {label}")),
            _ => None,
        })
        .collect();
    let rounds = cfg.arity_schedule(n).len();
    let mut expected: Vec<String> = [
        "observe program_identifier",
        "observe degree_bits",
        "observe base_degree_bits",
        "observe preprocessed_width",
        "observe trace_root",
        "observe public_values[0]",
        "observe public_values[1]",
        "observe public_values[2]",
        "sample alpha.c0",
        "sample alpha.c1",
        "observe quotient_root",
        "sample zeta.c0",
        "sample zeta.c1",
        "observe trace_local[0]",
        "observe trace_local[1]",
        "observe trace_next[0]",
        "observe trace_next[1]",
        "observe quotient_chunk[0]",
        "observe quotient_chunk[1]",
        "sample fri_alpha.c0",
        "sample fri_alpha.c1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for r in 0..rounds {
        expected.push(format!("observe fri_commit[{r}]"));
        expected.push(format!("pow commit_pow[{r}]"));
        expected.push(format!("sample beta[{r}].c0"));
        expected.push(format!("sample beta[{r}].c1"));
    }
    for i in 0..cfg.final_poly_len() {
        expected.push(format!("observe final_poly[{i}]"));
    }
    for r in 0..rounds {
        expected.push(format!("observe log_arity[{r}]"));
    }
    expected.push("observe query_pow.witness".into());
    expected.push("bits query_pow".into());
    expected.push("pow query_pow".into());
    for q in 0..cfg.num_queries {
        expected.push(format!("bits index[{q}]"));
    }
    assert_eq!(labels, expected);
}

#[test]
fn fold_forms_agree_with_each_other_and_with_upstream() {
    let folding: TwoAdicFriFolding<(), ()> = TwoAdicFriFolding(PhantomData);
    for (name, cfg, n) in common::test_cases() {
        let g = common::generate_case(name, &cfg, n);
        let raw = decode_raw(&g.bytes, &cfg).unwrap();
        let betas: Vec<Challenge> = g.mirror.challenges.betas.iter().map(ef).collect();
        let h = n + cfg.log_blowup;
        for step in &g.mirror.fold {
            let row: Vec<Challenge> = step.row.iter().map(ef).collect();
            let folded_height = h - raw.rounds[..=step.round]
                .iter()
                .map(|r| r.log_arity)
                .sum::<usize>();
            let beta = betas[step.round];
            let a =
                fold_row_barycentric(step.folded_index, folded_height, step.log_arity, beta, &row);
            let b = fold_row_binary(step.folded_index, folded_height, step.log_arity, beta, &row);
            let c = <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<Val, Challenge>>::fold_row(
                &folding,
                step.folded_index,
                folded_height,
                step.log_arity,
                beta,
                row.iter().copied(),
            );
            assert_eq!(a, b, "{name}: query {} round {}", step.query, step.round);
            assert_eq!(
                a, c,
                "{name}: upstream fold_row differs at query {} round {}",
                step.query, step.round
            );
            assert_eq!(ef(&step.folded), b);
            assert_eq!(ef(&step.folded_barycentric), a);
        }
        assert_eq!(g.mirror.fold.len(), cfg.num_queries * raw.rounds.len());
    }
}

#[test]
fn quotient_recomposition_matches_basis_lift() {
    let q0 = ef_from_coeffs(Val::from_u64(11), Val::from_u64(12));
    let q1 = ef_from_coeffs(Val::from_u64(13), Val::from_u64(14));
    let x = Challenge::from_basis_coefficients_fn(|i| if i == 1 { Val::ONE } else { Val::ZERO });
    assert_eq!(recompose_quotient(&[q0, q1]), q0 + x * q1);
    assert_eq!(
        recompose_quotient(&[q0, q1]),
        ef_from_coeffs(Val::from_u64(11 + 7 * 14), Val::from_u64(12 + 13))
    );
}

#[test]
fn mirror_rejects_a_wrong_public_value() {
    let (name, cfg, n) = common::test_cases()[2];
    let g = common::generate_case(name, &cfg, n);
    let mut pv = g.public_values;
    pv[2] += Val::ONE;
    let err = mirror_verify(&cfg, &g.bytes, &pv).unwrap_err();
    assert_eq!(err.name(), "OodMismatch");
}
