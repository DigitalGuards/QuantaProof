//! Calldata size and gas model (the plan's formulas; replaced by measurements in
//! `docs/GAS-REPORT.md`).

use serde::{Deserialize, Serialize};

use crate::config::FriConfig;
use crate::layout::{
    DIGEST_BYTES, EF_BYTES, F_BYTES, Layout, SIB_COUNT_BYTES, TRACE_WIDTH, prefix_layout,
};
use crate::mirror::MerkleBlock;

/// Per-block size accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockSize {
    pub name: String,
    pub log_height: usize,
    /// Rows (input blocks) or sibling values (rounds).
    pub values_bytes: usize,
    pub sib_count: usize,
    pub siblings_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SizeReport {
    pub preset: String,
    pub config: FriConfig,
    pub degree_bits: usize,
    pub log_height: usize,
    pub arity_schedule: Vec<usize>,
    /// `estimate` (model) or `exact` (from a vector).
    pub kind: String,
    pub prefix_bytes: usize,
    pub blocks: Vec<BlockSize>,
    pub total_bytes: usize,
    pub hashes: usize,
    pub calldata_gas: u64,
    pub compute_gas: u64,
    pub total_gas: u64,
}

/// Model of the pruned sibling count for `q` queries into a tree of `2^h` leaves:
/// `q * max(h - ceil(log2 q), 0) + min(q, 2^h)`.
pub fn estimated_sibling_count(q: usize, h: usize) -> usize {
    let log_q = usize::BITS as usize - (q.max(1) - 1).leading_zeros() as usize;
    q * h.saturating_sub(log_q) + q.min(1usize << h)
}

/// Model of the keccak calls for one block: unique leaves plus frontier compressions.
pub fn estimated_hashes(q: usize, h: usize) -> usize {
    (0..=h).map(|l| q.min(1usize << (h - l))).sum()
}

fn gas(cfg: &FriConfig, total_bytes: usize, hashes: usize, rounds: usize) -> (u64, u64, u64) {
    let q = cfg.num_queries as u64;
    let calldata = 16 * total_bytes as u64;
    let compute = 130 * hashes as u64 + 2500 * q * rounds as u64 + 3000 * q + 15 * q * q + 60_000;
    (calldata, compute, 21_000 + calldata + compute)
}

fn prefix_bytes(cfg: &FriConfig, rounds: usize) -> usize {
    prefix_layout(rounds, cfg.final_poly_len()).p_end
}

/// Model-based size for a preset at `degree_bits`.
pub fn estimate(preset: &str, cfg: &FriConfig, degree_bits: usize) -> SizeReport {
    let q = cfg.num_queries;
    let h = degree_bits + cfg.log_blowup;
    let schedule = cfg.arity_schedule(degree_bits);
    let mut blocks = Vec::new();
    let mut hashes = 0;
    for name in ["trace", "quotient"] {
        let sib = estimated_sibling_count(q, h);
        let values = q * TRACE_WIDTH * F_BYTES;
        blocks.push(BlockSize {
            name: name.to_string(),
            log_height: h,
            values_bytes: values,
            sib_count: sib,
            siblings_bytes: sib * DIGEST_BYTES,
            total_bytes: values + SIB_COUNT_BYTES + sib * DIGEST_BYTES,
        });
        hashes += estimated_hashes(q, h);
    }
    let mut height = h;
    for (r, &k) in schedule.iter().enumerate() {
        height -= k;
        let sib = estimated_sibling_count(q, height);
        let values = q * ((1usize << k) - 1) * EF_BYTES;
        blocks.push(BlockSize {
            name: format!("round[{r}]"),
            log_height: height,
            values_bytes: values,
            sib_count: sib,
            siblings_bytes: sib * DIGEST_BYTES,
            total_bytes: values + SIB_COUNT_BYTES + sib * DIGEST_BYTES,
        });
        hashes += estimated_hashes(q, height);
    }
    let prefix = prefix_bytes(cfg, schedule.len());
    let total = prefix + blocks.iter().map(|b| b.total_bytes).sum::<usize>();
    let (calldata_gas, compute_gas, total_gas) = gas(cfg, total, hashes, schedule.len());
    SizeReport {
        preset: preset.to_string(),
        config: *cfg,
        degree_bits,
        log_height: h,
        arity_schedule: schedule,
        kind: "estimate".to_string(),
        prefix_bytes: prefix,
        blocks,
        total_bytes: total,
        hashes,
        calldata_gas,
        compute_gas,
        total_gas,
    }
}

/// Exact sizes from a decoded layout plus the mirror's Merkle traces (for the hash count).
pub fn exact(preset: &str, cfg: &FriConfig, layout: &Layout, merkle: &[MerkleBlock]) -> SizeReport {
    let h = layout.degree_bits + cfg.log_blowup;
    let mut blocks = Vec::new();
    for b in &layout.blocks {
        blocks.push(BlockSize {
            name: b.name.clone(),
            log_height: h,
            values_bytes: b.rows_len,
            sib_count: b.sib_count,
            siblings_bytes: b.sib_count * DIGEST_BYTES,
            total_bytes: b.end - b.rows_offset,
        });
    }
    let mut height = h;
    for (r, rl) in layout.rounds.iter().enumerate() {
        height -= rl.log_arity;
        blocks.push(BlockSize {
            name: format!("round[{r}]"),
            log_height: height,
            values_bytes: rl.sibling_values_len,
            sib_count: rl.sib_count,
            siblings_bytes: rl.sib_count * DIGEST_BYTES,
            total_bytes: rl.end - rl.sibling_values_offset,
        });
    }
    let hashes: usize = merkle
        .iter()
        .map(|m| m.leaves.len() + m.levels.iter().map(|l| l.len()).sum::<usize>())
        .sum();
    let (calldata_gas, compute_gas, total_gas) =
        gas(cfg, layout.total_len, hashes, layout.rounds.len());
    SizeReport {
        preset: preset.to_string(),
        config: *cfg,
        degree_bits: layout.degree_bits,
        log_height: h,
        arity_schedule: layout.log_arities.clone(),
        kind: "exact".to_string(),
        prefix_bytes: layout.p_end,
        blocks,
        total_bytes: layout.total_len,
        hashes,
        calldata_gas,
        compute_gas,
        total_gas,
    }
}

impl SizeReport {
    /// A compact human-readable table.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "{} n={} ({}) log_height={} arities={:?} queries={} final_poly_len={}\n",
            self.preset,
            self.degree_bits,
            self.kind,
            self.log_height,
            self.arity_schedule,
            self.config.num_queries,
            self.config.final_poly_len()
        ));
        s.push_str(&format!(
            "  prefix            {:>8} bytes\n",
            self.prefix_bytes
        ));
        for b in &self.blocks {
            s.push_str(&format!(
                "  {:<12} h={:<2} {:>8} bytes  (values {:>7}, siblings {:>4} x 32 = {:>7})\n",
                b.name, b.log_height, b.total_bytes, b.values_bytes, b.sib_count, b.siblings_bytes
            ));
        }
        s.push_str(&format!(
            "  total             {:>8} bytes   keccak calls ~{}\n",
            self.total_bytes, self.hashes
        ));
        s.push_str(&format!(
            "  gas model: calldata {} + compute {} + base 21000 = {}\n",
            self.calldata_gas, self.compute_gas, self.total_gas
        ));
        s
    }
}
