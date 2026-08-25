//! Prover, calldata serializer, transcript mirror and test-vector tooling for the
//! QuantaProof on-chain STARK verifier.
//!
//! The proof system is Plonky3 `uni-stark` (pinned to the version in `../PLONKY3_VERSION`)
//! over Goldilocks with keccak256 Merkle trees and a keccak256 Fiat-Shamir transcript.
//! `docs/PROTOCOL.md` is the normative description of everything this crate emits.

pub mod challenger;
pub mod config;
pub mod constants;
pub mod fib_air;
pub mod keccak;
pub mod layout;
pub mod mirror;
pub mod mutate;
pub mod prove;
pub mod serialize;
pub mod sizes;
pub mod vectors;

pub use config::{Challenge, Config, FriConfig, Proof, Val};
