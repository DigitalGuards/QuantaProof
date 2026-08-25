//! `stark-prover` command line.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use stark_prover::config::{FriConfig, all_presets, preset, preset_names};
use stark_prover::constants::write_constants;
use stark_prover::layout::decode_raw;
use stark_prover::mirror::{TranscriptEvent, mirror_verify};
use stark_prover::mutate::{classify, generate_mutations};
use stark_prover::prove::{seeded_start, verify_upstream};
use stark_prover::serialize::raw_to_proof;
use stark_prover::sizes;
use stark_prover::vectors::{
    Generated, generate, mutated_vector, read_vector, valid_vector, vector_name, vector_path,
    write_vector,
};

#[derive(Parser)]
#[command(
    name = "stark-prover",
    about = "Plonky3 Fibonacci STARK prover and test-vector tooling for the QuantaProof verifier"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone, Debug)]
struct PresetArgs {
    /// Preset name (c1, c2, c3, c1-binary, ..., c3-a<k>-f<l>) or `custom`.
    #[arg(long, default_value = "c3")]
    preset: String,
    #[arg(long)]
    log_blowup: Option<usize>,
    #[arg(long)]
    num_queries: Option<usize>,
    #[arg(long)]
    query_pow: Option<usize>,
    #[arg(long)]
    commit_pow: Option<usize>,
    #[arg(long)]
    max_log_arity: Option<usize>,
    #[arg(long)]
    log_final_poly_len: Option<usize>,
}

impl PresetArgs {
    fn resolve(&self) -> Result<(String, FriConfig)> {
        let base = if self.preset == "custom" {
            preset("c3").expect("c3 exists")
        } else {
            preset(&self.preset).with_context(|| {
                format!(
                    "unknown preset {}; known: {}",
                    self.preset,
                    preset_names().join(", ")
                )
            })?
        };
        let overridden = self.log_blowup.is_some()
            || self.num_queries.is_some()
            || self.query_pow.is_some()
            || self.commit_pow.is_some()
            || self.max_log_arity.is_some()
            || self.log_final_poly_len.is_some();
        let cfg = FriConfig {
            log_blowup: self.log_blowup.unwrap_or(base.log_blowup),
            num_queries: self.num_queries.unwrap_or(base.num_queries),
            query_pow_bits: self.query_pow.unwrap_or(base.query_pow_bits),
            commit_pow_bits: self.commit_pow.unwrap_or(base.commit_pow_bits),
            max_log_arity: self.max_log_arity.unwrap_or(base.max_log_arity),
            log_final_poly_len: self.log_final_poly_len.unwrap_or(base.log_final_poly_len),
        };
        ensure!(cfg.max_log_arity >= 1, "max_log_arity must be at least 1");
        ensure!(cfg.num_queries >= 1, "num_queries must be at least 1");
        ensure!(
            cfg.query_pow_bits < 64 && cfg.commit_pow_bits < 64,
            "pow bits must be < 64"
        );
        let name = if self.preset == "custom" || overridden {
            cfg.preset_name().unwrap_or("custom").to_string()
        } else {
            self.preset.clone()
        };
        Ok((name, cfg))
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Prove one Fibonacci instance, verify it upstream and with the mirror, write the vector.
    Prove {
        #[command(flatten)]
        preset: PresetArgs,
        /// log2 of the trace length.
        #[arg(long)]
        log_n: usize,
        #[arg(long, default_value_t = 0)]
        a: u64,
        #[arg(long, default_value_t = 1)]
        b: u64,
        /// Derive `a` and `b` pseudo-randomly from this seed (overrides --a/--b).
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long)]
        out: PathBuf,
        /// Also write the mutation set next to the vector (`<out dir>/mutations/`).
        #[arg(long)]
        mutations: bool,
    },
    /// Decode a vector's proof bytes and run the upstream and mirror verifiers.
    Verify { file: PathBuf },
    /// Generate the tracked vector set: `fib_<preset>_n<N>.json` plus `mutations/`.
    Vectors {
        /// Preset name, `all`, or a comma-separated list.
        #[arg(long, default_value = "all")]
        preset: String,
        /// Comma-separated log2 trace sizes; sizes above 12 are written to `<out>/large/`.
        #[arg(long, default_value = "10,12")]
        sizes: String,
        #[arg(long, default_value = "test/vectors")]
        out: PathBuf,
        /// Mutation policy: `core` (c1, c2, c3 at the smallest size), `smallest` (every preset
        /// at the smallest size plus c1/c2/c3 at every size), `all` (every vector), `none`.
        #[arg(long, default_value = "core")]
        mutations: String,
        /// Pretty-print the JSON (compact by default to keep the tracked vectors small).
        #[arg(long)]
        pretty: bool,
        /// Seed for the start values; without it `a = 0, b = 1`.
        #[arg(long)]
        seed: Option<u64>,
    },
    /// Write the mutation set of an existing valid vector.
    Mutate {
        #[arg(long)]
        vector: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Calldata size and gas model for a preset (exact when `--vector` is given).
    Sizes {
        #[command(flatten)]
        preset: PresetArgs,
        /// Comma-separated log2 trace sizes.
        #[arg(long, default_value = "10,12,16,20")]
        log_n: String,
        #[arg(long)]
        vector: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Print a vector's transcript byte by byte.
    Transcript { file: PathBuf },
    /// Print (and optionally write) the Goldilocks constants.
    Constants {
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn parse_sizes(s: &str) -> Result<Vec<usize>> {
    s.split(',')
        .map(|t| {
            t.trim()
                .parse::<usize>()
                .with_context(|| format!("bad size {t}"))
        })
        .collect()
}

fn start_values(seed: Option<u64>, a: u64, b: u64) -> (u64, u64) {
    match seed {
        Some(s) => seeded_start(s),
        None => (a, b),
    }
}

fn write_mutations(g: &Generated, out_dir: &Path) -> Result<usize> {
    let raw = decode_raw(&g.bytes, &g.cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let base = valid_vector(g);
    let muts = generate_mutations(
        &g.cfg,
        &raw,
        &g.bytes,
        &g.public_values,
        &g.mirror.challenges.indices,
    );
    let (rejected, accepted) = classify(&g.cfg, muts);
    for m in &accepted {
        eprintln!(
            "warning: {}: mutation {} was accepted by the mirror and is skipped",
            g.name, m.name
        );
    }
    let dir = out_dir.join("mutations");
    for cm in &rejected {
        let v = mutated_vector(
            &base,
            &cm.mutation.name,
            &cm.error,
            &cm.mutation.bytes,
            &cm.mutation.public_values,
        );
        write_vector(&dir.join(format!("{}.json", v.name)), &v, false)?;
    }
    Ok(rejected.len())
}

fn run_vectors(
    presets: &str,
    sizes: &str,
    out: &Path,
    mutations: &str,
    seed: Option<u64>,
    pretty: bool,
) -> Result<()> {
    let sizes = parse_sizes(sizes)?;
    ensure!(!sizes.is_empty(), "no sizes given");
    let smallest = *sizes.iter().min().unwrap();
    let selected: Vec<(String, FriConfig)> = if presets == "all" {
        all_presets()
            .into_iter()
            .map(|(n, c)| (n.to_string(), c))
            .collect()
    } else {
        presets
            .split(',')
            .map(|n| {
                let n = n.trim();
                preset(n)
                    .map(|c| (n.to_string(), c))
                    .with_context(|| format!("unknown preset {n}"))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let (a, b) = start_values(seed, 0, 1);
    let mut total_bytes = 0usize;
    for (name, cfg) in &selected {
        for &n in &sizes {
            let vname = vector_name(name, n);
            let started = std::time::Instant::now();
            let g = generate(cfg, &vname, n, a, b)?;
            let path = vector_path(out, &vname, n);
            let v = valid_vector(&g);
            write_vector(&path, &v, pretty)?;
            total_bytes += g.bytes.len();
            let is_core = matches!(name.as_str(), "c1" | "c2" | "c3");
            let want_mutations = match mutations {
                "all" => true,
                "none" => false,
                "core" => n == smallest && is_core,
                "smallest" => n == smallest || is_core,
                other => bail!("unknown mutation policy {other}"),
            };
            let mut_count = if want_mutations {
                write_mutations(&g, path.parent().unwrap())?
            } else {
                0
            };
            println!(
                "{vname}: {} bytes, {} rounds {:?}, {} transcript runs, {} mutations, {:.2}s -> {}",
                g.bytes.len(),
                g.mirror.layout.rounds.len(),
                g.mirror.layout.log_arities,
                g.verifier_transcript.events.len(),
                mut_count,
                started.elapsed().as_secs_f64(),
                path.display()
            );
        }
    }
    println!("total proof bytes across valid vectors: {total_bytes}");
    Ok(())
}

fn run_verify(file: &Path) -> Result<()> {
    let v = read_vector(file)?;
    let bytes = v.proof_bytes()?;
    let pv = v.public_values()?;
    let cfg = v.config;
    println!(
        "{}: {} bytes, preset {}, n = {}, expected {}",
        v.name,
        bytes.len(),
        cfg.preset_name().unwrap_or("custom"),
        v.degree_bits,
        if v.expected.valid {
            "valid".to_string()
        } else {
            format!("invalid ({})", v.expected.error.clone().unwrap_or_default())
        }
    );
    let decoded = decode_raw(&bytes, &cfg);
    let upstream = match &decoded {
        Ok(raw) => {
            let proof = raw_to_proof(raw);
            let (res, _) = verify_upstream(&cfg, &proof, &pv);
            Some(res)
        }
        Err(_) => None,
    };
    let mirror = mirror_verify(&cfg, &bytes, &pv);
    match &upstream {
        Some(Ok(())) => println!("upstream verify: accepted"),
        Some(Err(e)) => println!("upstream verify: rejected: {e:?}"),
        None => println!("upstream verify: skipped (calldata decode failed)"),
    }
    match &mirror {
        Ok(m) => println!(
            "mirror verify:   accepted (proofId {}, {} transcript events)",
            stark_prover::mirror::hex0x(&m.proof_id),
            m.events.len()
        ),
        Err(e) => println!("mirror verify:   rejected: {e}"),
    }
    if v.expected.valid {
        ensure!(
            matches!(upstream, Some(Ok(()))),
            "upstream verifier rejected a vector marked valid"
        );
        let m =
            mirror.map_err(|e| anyhow::anyhow!("mirror rejected a vector marked valid: {e}"))?;
        if let Some(recorded) = &v.challenges {
            ensure!(
                recorded.indices == m.challenges.indices,
                "query indices differ from the recorded ones"
            );
            ensure!(
                recorded.zeta == m.challenges.zeta,
                "zeta differs from the recorded one"
            );
        }
        if let Some(id) = &v.proof_id {
            ensure!(
                *id == stark_prover::mirror::hex0x(&m.proof_id),
                "proofId differs"
            );
        }
        println!("ok");
    } else {
        ensure!(
            !matches!(upstream, Some(Ok(()))),
            "upstream verifier accepted a vector marked invalid"
        );
        let err = mirror
            .err()
            .context("mirror accepted a vector marked invalid")?;
        if let Some(expected) = &v.expected.error {
            ensure!(
                err.name() == expected,
                "mirror raised {} but the vector expects {expected}",
                err.name()
            );
        }
        println!("ok (rejected as expected)");
    }
    Ok(())
}

fn run_transcript(file: &Path) -> Result<()> {
    let v = read_vector(file)?;
    let events = v.transcript.context("this vector carries no transcript")?;
    let mut observed = 0usize;
    let mut sampled = 0usize;
    for (i, e) in events.iter().enumerate() {
        match e {
            TranscriptEvent::Observe { label, bytes } => {
                let n = (bytes.len() - 2) / 2;
                observed += n;
                println!("{i:4} observe      {label:<24} {n:>3} B {bytes}");
            }
            TranscriptEvent::Flush {
                label,
                input,
                bytes,
            } => {
                println!(
                    "{i:4} flush        {label:<24} keccak256({} B) = {bytes}",
                    (input.len() - 2) / 2
                );
            }
            TranscriptEvent::SampleU64 {
                label,
                bytes,
                value,
            } => {
                sampled += 8;
                println!("{i:4} sample_u64   {label:<24} {bytes} = {value}");
            }
            TranscriptEvent::SampleField {
                label,
                value,
                rejected,
            } => {
                println!("{i:4} sample_field {label:<24} {value} (rejected {rejected:?})");
            }
            TranscriptEvent::SampleBits {
                label,
                bits,
                raw,
                value,
            } => {
                println!("{i:4} sample_bits  {label:<24} {bits} bits of {raw} = {value}");
            }
            TranscriptEvent::CheckPow {
                label,
                bits,
                witness,
                value,
                ok,
            } => {
                println!(
                    "{i:4} check_pow    {label:<24} bits {bits} witness {witness} -> {value:?} ok={ok}"
                );
            }
        }
    }
    println!(
        "{} events, {observed} bytes observed, {sampled} bytes sampled",
        events.len()
    );
    Ok(())
}

fn run_sizes(preset: &PresetArgs, log_n: &str, vector: Option<&Path>, json: bool) -> Result<()> {
    let mut reports = Vec::new();
    if let Some(path) = vector {
        let v = read_vector(path)?;
        let layout = v.layout.context("vector carries no layout")?;
        let merkle = v.merkle.context("vector carries no merkle trace")?;
        let name = v.config.preset_name().unwrap_or("custom");
        reports.push(sizes::exact(name, &v.config, &layout, &merkle));
    } else {
        let (name, cfg) = preset.resolve()?;
        for n in parse_sizes(log_n)? {
            reports.push(sizes::estimate(&name, &cfg, n));
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        for r in &reports {
            print!("{}", r.render());
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Prove {
            preset,
            log_n,
            a,
            b,
            seed,
            out,
            mutations,
        } => {
            let (name, cfg) = preset.resolve()?;
            let (a, b) = start_values(seed, a, b);
            let vname = vector_name(&name, log_n);
            let g = generate(&cfg, &vname, log_n, a, b)?;
            write_vector(&out, &valid_vector(&g), true)?;
            println!(
                "{vname}: {} bytes, proofId {} -> {}",
                g.bytes.len(),
                stark_prover::mirror::hex0x(&g.mirror.proof_id),
                out.display()
            );
            if mutations {
                let dir = out.parent().unwrap_or(Path::new("."));
                let count = write_mutations(&g, dir)?;
                println!("{count} mutations -> {}", dir.join("mutations").display());
            }
        }
        Cmd::Verify { file } => run_verify(&file)?,
        Cmd::Vectors {
            preset,
            sizes,
            out,
            mutations,
            seed,
            pretty,
        } => run_vectors(&preset, &sizes, &out, &mutations, seed, pretty)?,
        Cmd::Mutate { vector, out } => {
            let v = read_vector(&vector)?;
            ensure!(v.expected.valid, "mutate needs a valid vector");
            let (a, b) = (v.public_values()?[0], v.public_values()?[1]);
            let name = v.config.preset_name().unwrap_or("custom").to_string();
            let g = generate(
                &v.config,
                &vector_name(&name, v.degree_bits),
                v.degree_bits,
                p3_field::PrimeField64::as_canonical_u64(&a),
                p3_field::PrimeField64::as_canonical_u64(&b),
            )?;
            ensure!(
                g.bytes == v.proof_bytes()?,
                "regenerated proof differs from the vector (the prover is deterministic; was the vector produced by this build?)"
            );
            let count = write_mutations(&g, &out)?;
            println!("{count} mutations -> {}", out.join("mutations").display());
        }
        Cmd::Sizes {
            preset,
            log_n,
            vector,
            json,
        } => run_sizes(&preset, &log_n, vector.as_deref(), json)?,
        Cmd::Transcript { file } => run_transcript(&file)?,
        Cmd::Constants { out } => {
            let doc = stark_prover::constants::constants_json();
            println!("{}", serde_json::to_string_pretty(&doc)?);
            if let Some(path) = out {
                write_constants(&path)?;
                eprintln!("written {}", path.display());
            }
        }
    }
    Ok(())
}
