# Security status and release gates

Status: 2026-08-25. This document records which security properties the current
QuantaStark implementation provides, which claims remain experimental, and the
gates that must close before a production deployment. QuantaStark remains a
research project and must not secure funds.

## Current classification

| Property                   | Current status                       | Evidence and consequence                                                                                                                                                                                                                                                                |
| -------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Computational integrity    | Implemented for the Fibonacci AIR    | The Rust prover, Rust verifier, JS mirror and Hyperion verifier agree on the committed vectors and reject the mutation corpus. This validates this implementation and AIR only.                                                                                                         |
| Transparent setup          | Implemented                          | The STARK uses hash commitments and FRI, with no trusted setup. Transparency is independent of zero knowledge.                                                                                                                                                                          |
| Zero knowledge             | Not implemented                      | `config.rs` uses the ordinary `TwoAdicFriPcs`; `serialize.rs` rejects proofs carrying `random` openings or commitments as `randomised (zk) commitments present`. Trace rows are opened directly. The current target prioritizes scalability and validity; privacy is outside its scope. |
| Production soundness       | Unresolved                           | Every named FRI preset is a benchmark profile. The displayed 116 to 118 bit values are ethSTARK-conjectured figures. Section 2.4 of `L2-ARCHITECTURE.md` records the lower rough proven regime and the 2025 proximity-gap results.                                                      |
| Batch bridge compatibility | Guarded, batch AIR absent            | The registry requires the verifier's canonical program identifier. `StateBridge` then requires that verifier, identifier and a 128-byte public-value statement. The Fibonacci verifier declares 24 bytes and cannot back the bridge.                                                    |
| Circuit hash suite         | Unresolved                           | Poseidon2 remains a candidate for benchmarking. No protocol identifier, state format, signature scheme or recursion layer may treat it as selected until the review gate below closes.                                                                                                  |
| Full protocol validation   | Gate implemented, clean pass pending | `test:protocol` requires source-matched binaries, a local chain, every Node and Rust gate, Hyperion compilation and all live QRVM contract suites. The scheduled workflow records provenance and gate results.                                                                          |
| External review            | Not completed                        | No independent audit covers the verifier, AIR, parameter selection, compiler snapshot or bridge.                                                                                                                                                                                        |

## Zero-knowledge boundary

STARK means scalable transparent argument of knowledge. A STARK can be built
with or without a zero-knowledge hiding layer. The current QuantaStark proof
opens sampled rows from the ordinary execution trace and includes no trace
randomization, hiding polynomial commitment or leakage test. The Fibonacci
example also has no private input: its three values are public.

The current rollup design assumes public transaction data and uses proofs to
amortize execution, so zero knowledge is not required for that stated product.
If privacy becomes a requirement, it is a separate protocol milestone. The
minimum gate is:

1. State the privacy policy: which witness fields are secret and what leakage is
   acceptable through public values, trace length, timing and proof size.
2. Move the pinned Plonky3 configuration to its hiding FRI construction and
   document whether the claim is statistical or perfect zero knowledge.
3. Add a new proof-layout version for randomized commitments and openings. Keep
   the current verifier bound to version 1.
4. Implement the corresponding Hyperion verification path and regenerate every
   vector. Never silently reinterpret a version 1 proof as a hiding proof.
5. Add witness-indistinguishability and transcript-distribution tests, then obtain
   an independent review of the claimed zero-knowledge property.

## FRI soundness and deployment policy

`c1`, `c2`, `c3`, their binary variants and the c3 arity/final-polynomial sweep
are measurement presets. `scripts/lib/presets.js::presetSecurity` classifies all
of them as `benchmark`, `experimental`, and `productionReady: false`.

`npm run deploy` permits these profiles without an override only on the gqrl
developer chain 1337 and the QuantaStark Kurtosis chain 3151909. Any other chain
requires `--allow-experimental-soundness` or
`STARK_ALLOW_EXPERIMENTAL_SOUNDNESS=1`. The override records an explicit research
decision; it does not make a preset production ready. The same acknowledgement
applies to the bridge skeleton on a non-local chain.

A production profile requires a written target and threat model, a current
proven soundness calculation for the complete protocol, a parameter set that
meets that target, proof-size and gas measurements, regenerated negative
vectors, and independent cryptographic review. The program identifier must
change when any security parameter or statement encoding changes.

## Poseidon and Poseidon2 checkpoint

The August 2026 paper [From Round Skipping to S-Box Skipping: Attacking
Poseidon's Partial Layer via Subspace
Restriction](https://eprint.iacr.org/2026/1692) gives a probability-one
distinguisher over reduced-round Poseidon and practical CICO results for 28 of
31 and 25 of 31 rounds in the reported KoalaBear width-24, alpha-3 setting. Its
formal target is the original Poseidon construction. It does not demonstrate an
attack on the Goldilocks Poseidon2 width-8 or width-12, alpha-7 instances being
considered here.

That distinction does not close the question. [Algebraic Cryptanalysis of the
HADES Design](https://eprint.iacr.org/2023/537) analyzes both Poseidon and
Poseidon2, reports that their polynomial systems have the same solving degree in
the tested regime, and states that Poseidon2 derives its algebraic-security
argument from Poseidon. Plonky3 `0.7.0-rc.1` makes the same inheritance explicit
in its [round-number
calculation](https://github.com/Plonky3/Plonky3/blob/47566c1535bba086c67f326c821e2ef23918f7bb/poseidon2/src/round_numbers.rs).
Its Goldilocks defaults use alpha 7, eight full rounds and 22 partial rounds at
width 8 and 12. Those numbers incorporate the 2023 correction and predate the
2026 attack.

The protocol decision is therefore open. Milestone M10 starts with a
hash-agnostic layout version 2 and a hash-suite interface. Poseidon2 can be used
in isolated benchmarks and test vectors, with an experimental suite identifier.
It cannot become the state-root, account-signature or recursion hash until all
of these are complete:

1. Determine whether generalized S-box skipping applies to the exact Poseidon2
   internal matrix and sponge modes under consideration.
2. Recalculate full and partial rounds for Goldilocks, alpha 7, widths 8 and 12
   against the 2023 and 2026 attacks, including a documented security margin.
3. Compare the resulting circuit and QRVM costs against a conservative Keccak
   baseline and any alternative with a current public analysis and maintained
   implementation.
4. Pin constants, domain separators, sponge capacity, input encoding and test
   vectors under a versioned hash-suite identifier.
5. Obtain independent cryptographic review before the suite is marked
   production ready.

## Bridge compatibility gate

Every `IStarkVerifier` reports `programIdentifier()` and
`publicValuesLength()`. The registry constructor requires the supplied program
identifier to match its verifier, then exposes the verifier address, identifier
and delegated public-value length. `StateBridge` checks all three in its
constructor. This closes the earlier path where the deployment script could
bind the bridge's 128-byte root-transition statement to the Fibonacci
verifier's 24-byte statement.

Bridge deployment now requires an explicit compatible verifier and program id:

```bash
STARK_BRIDGE_VERIFIER=Q... \
STARK_BRIDGE_PROGRAM_ID=0x... \
STARK_DEPLOY_BRIDGE=1 \
STARK_CONFIG=config/dev-node.json \
npm run deploy
```

Bridge-only mode selects `--preset none` automatically. Pass an explicit
`--preset` when the same run should also deploy Fibonacci benchmark verifiers.

The deployer checks code at the verifier address and calls
`programIdentifier()` and `publicValuesLength()` before it deploys either the
registry or bridge. A real batch AIR and its 128-byte public-value schema are
still required.

## Production release gate

Production remains closed until all of the following have evidence attached to
one reviewed revision:

1. A production FRI profile and complete soundness calculation.
2. A reviewed hash suite and exact constants.
3. A batch AIR whose public values bind the previous root, new root, data
   commitment, deposits, withdrawals and protocol version.
4. A decision on privacy, with a hiding proof implementation and review if zero
   knowledge is claimed.
5. Reproducible, fetchable Hyperion and go-qrl revisions with source-matched
   binaries.
6. A required full-protocol gate on the pinned compiler and a live QRVM, plus the
   Rust, JS, mutation, deployment and bridge suites.
7. Independent audits of the cryptography, Hyperion verifier and bridge, followed
   by a public testnet period with no production funds.
