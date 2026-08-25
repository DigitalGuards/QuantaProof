//! JSON test vectors (`schema: 1`), generation pipeline and file naming.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};

use crate::challenger::RawTranscript;
use crate::config::{FriConfig, PLONKY3_VERSION, Proof, Val};
use crate::layout::{Layout, decode_raw, public_values_bytes, read_f};
use crate::mirror::{
    Challenges, Constraints, FinalPolyCheck, FoldStep, MerkleBlock, MirrorOutput, OpenInput,
    TranscriptEvent, f_str, hex0x, mirror_verify,
};
use crate::prove::{ProveOutput, prove_fibonacci, verify_upstream};
use crate::serialize::serialize_proof;

/// The vector schema version.
pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Expected {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation: Option<String>,
}

/// One vector file. Valid vectors carry every section; mutated vectors carry the hex fields,
/// the parameters and `expected` only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorFile {
    pub schema: u32,
    pub plonky3_version: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub config: FriConfig,
    pub air: String,
    pub degree_bits: usize,
    pub public_values: Vec<String>,
    pub proof_hex: String,
    pub public_values_hex: String,
    pub proof_length: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<Layout>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<Vec<TranscriptEvent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenges: Option<Challenges>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_inputs: Option<Vec<OpenInput>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fold: Option<Vec<FoldStep>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_poly_checks: Option<Vec<FinalPolyCheck>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle: Option<Vec<MerkleBlock>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    pub expected: Expected,
}

impl VectorFile {
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        decode_hex(&self.proof_hex)
    }

    pub fn public_values(&self) -> Result<[Val; 3]> {
        let bytes = decode_hex(&self.public_values_hex)?;
        ensure!(
            bytes.len() == 24,
            "publicValuesHex must hold three elements"
        );
        let mut out = [Val::ZERO; 3];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = read_f(&bytes, i * 8).context("public value is not canonical")?;
        }
        Ok(out)
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x")).context("invalid hex")
}

/// `fib_<preset>_n<N>`.
pub fn vector_name(preset: &str, degree_bits: usize) -> String {
    format!("fib_{preset}_n{degree_bits}")
}

/// Output path for a vector: `<out>/fib_<preset>_n<N>.json`, or under `<out>/large/` when
/// `degree_bits > 12`.
pub fn vector_path(out: &Path, name: &str, degree_bits: usize) -> PathBuf {
    let dir = if degree_bits > 12 {
        out.join("large")
    } else {
        out.to_path_buf()
    };
    dir.join(format!("{name}.json"))
}

/// Everything produced for one valid instance.
pub struct Generated {
    pub name: String,
    pub cfg: FriConfig,
    pub degree_bits: usize,
    pub public_values: [Val; 3],
    pub bytes: Vec<u8>,
    pub proof: Proof,
    pub prover_transcript: RawTranscript,
    pub verifier_transcript: RawTranscript,
    pub mirror: MirrorOutput,
}

/// Prove, verify upstream, serialise, round-trip, mirror, and cross-check the three transcripts.
pub fn generate(
    cfg: &FriConfig,
    name: &str,
    degree_bits: usize,
    a: u64,
    b: u64,
) -> Result<Generated> {
    let ProveOutput {
        proof,
        public_values,
        degree_bits,
        prover_transcript,
    } = prove_fibonacci(cfg, degree_bits, a, b);

    let (upstream, verifier_transcript) = verify_upstream(cfg, &proof, &public_values);
    if let Err(e) = upstream {
        bail!("{name}: upstream verifier rejected a fresh proof: {e:?}");
    }
    ensure!(
        prover_transcript == verifier_transcript,
        "{name}: prover and verifier transcripts differ"
    );

    let bytes = serialize_proof(&proof, cfg).with_context(|| format!("{name}: serialise"))?;
    let raw = decode_raw(&bytes, cfg).map_err(|e| anyhow::anyhow!("{name}: decode: {e}"))?;
    let rebuilt = crate::serialize::raw_to_proof(&raw);
    let bytes2 = serialize_proof(&rebuilt, cfg)?;
    ensure!(
        bytes == bytes2,
        "{name}: serialise(deserialise(bytes)) != bytes"
    );
    let (upstream2, _) = verify_upstream(cfg, &rebuilt, &public_values);
    if let Err(e) = upstream2 {
        bail!("{name}: upstream verifier rejected the decoded proof: {e:?}");
    }

    let mirror = mirror_verify(cfg, &bytes, &public_values)
        .map_err(|e| anyhow::anyhow!("{name}: mirror rejected a valid proof: {e}"))?;
    ensure!(
        mirror.raw_transcript == verifier_transcript,
        "{name}: mirror transcript differs from the upstream verifier transcript:\n--- mirror ---\n{}\n--- upstream ---\n{}",
        mirror.raw_transcript.dump(),
        verifier_transcript.dump()
    );

    Ok(Generated {
        name: name.to_string(),
        cfg: *cfg,
        degree_bits,
        public_values,
        bytes,
        proof,
        prover_transcript,
        verifier_transcript,
        mirror,
    })
}

/// The valid vector file for a generated instance.
pub fn valid_vector(g: &Generated) -> VectorFile {
    let m = &g.mirror;
    VectorFile {
        schema: SCHEMA,
        plonky3_version: PLONKY3_VERSION.to_string(),
        name: g.name.clone(),
        source: None,
        config: g.cfg,
        air: "fibonacci".to_string(),
        degree_bits: g.degree_bits,
        public_values: g.public_values.iter().map(f_str).collect(),
        proof_hex: hex0x(&g.bytes),
        public_values_hex: hex0x(&public_values_bytes(&g.public_values)),
        proof_length: g.bytes.len(),
        proof_id: Some(hex0x(&m.proof_id)),
        layout: Some(m.layout.clone()),
        transcript: Some(m.events.clone()),
        challenges: Some(m.challenges.clone()),
        open_inputs: Some(m.open_inputs.clone()),
        fold: Some(m.fold.clone()),
        final_poly_checks: Some(m.final_poly_checks.clone()),
        merkle: Some(m.merkle.clone()),
        constraints: Some(m.constraints.clone()),
        expected: Expected {
            valid: true,
            error: None,
            mutation: None,
        },
    }
}

/// A mutated vector file (hex fields, parameters and `expected` only).
pub fn mutated_vector(
    base: &VectorFile,
    mutation: &str,
    error: &str,
    bytes: &[u8],
    public_values: &[Val; 3],
) -> VectorFile {
    VectorFile {
        schema: SCHEMA,
        plonky3_version: PLONKY3_VERSION.to_string(),
        name: format!("{}__{}", base.name, mutation),
        source: Some(base.name.clone()),
        config: base.config,
        air: base.air.clone(),
        degree_bits: base.degree_bits,
        public_values: public_values.iter().map(f_str).collect(),
        proof_hex: hex0x(bytes),
        public_values_hex: hex0x(&public_values_bytes(public_values)),
        proof_length: bytes.len(),
        proof_id: None,
        layout: None,
        transcript: None,
        challenges: None,
        open_inputs: None,
        fold: None,
        final_poly_checks: None,
        merkle: None,
        constraints: None,
        expected: Expected {
            valid: false,
            error: Some(error.to_string()),
            mutation: Some(mutation.to_string()),
        },
    }
}

pub fn write_vector(path: &Path, v: &VectorFile, pretty: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = if pretty {
        serde_json::to_string_pretty(v)?
    } else {
        serde_json::to_string(v)?
    };
    std::fs::write(path, text + "\n").with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

pub fn read_vector(path: &Path) -> Result<VectorFile> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}
