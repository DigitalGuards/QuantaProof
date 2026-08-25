//! Goldilocks constants for the on-chain field library (`prover/constants.json`).

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use serde_json::{Value, json};

use crate::config::PLONKY3_VERSION;
use crate::layout::GOLDILOCKS_P;

fn num(v: u64) -> Value {
    json!({ "dec": v.to_string(), "hex": format!("0x{v:016x}") })
}

fn mask_512(pattern: &str) -> String {
    let unit = pattern.len();
    assert_eq!(128 % unit, 0);
    format!("0x{}", pattern.repeat(128 / unit))
}

/// Build the constants document.
pub fn constants_json() -> Value {
    let gens: Vec<Goldilocks> = Goldilocks::TWO_ADIC_GENERATORS.to_vec();
    let invs: Vec<Goldilocks> = gens.iter().map(|g| g.inverse()).collect();
    let inv2 = Goldilocks::ONE.halve();
    json!({
        "field": "goldilocks",
        "plonky3Version": PLONKY3_VERSION,
        "description": "Goldilocks constants used by the QuantaProof verifier. Field elements travel as canonical 8-byte little-endian words; the QRVM word is 512 bits (8 lanes of 64 bits).",
        "p": num(GOLDILOCKS_P),
        "pMinusOne": num(GOLDILOCKS_P - 1),
        "epsilon": num(0xFFFF_FFFF),
        "epsilonNote": "2^64 mod p = 2^32 - 1; used by the reduction x = lo + (2^32 - 1) * hi",
        "inv2": num(inv2.as_canonical_u64()),
        "w": num(7),
        "wNote": "Challenge field is F[X] / (X^2 - 7)",
        "generator": num(Goldilocks::GENERATOR.as_canonical_u64()),
        "generatorNote": "Multiplicative generator; every LDE lives on the coset 7 * K",
        "twoAdicity": Goldilocks::TWO_ADICITY,
        "twoAdicGenerators": gens.iter().map(|g| num(g.as_canonical_u64())).collect::<Vec<_>>(),
        "twoAdicGeneratorInverses": invs.iter().map(|g| num(g.as_canonical_u64())).collect::<Vec<_>>(),
        "twoAdicGeneratorsNote": "TWO_ADIC_GENERATORS[i] has order 2^i; [i+1]^2 == [i]; index 0 is 1",
        "laneMasks": {
            "lanesPerWord": 8,
            "lane64": num(u64::MAX),
            "bswap8": mask_512("00ff"),
            "bswap16": mask_512("0000ffff"),
            "bswap32": mask_512("00000000ffffffff"),
            "note": "Per-lane byte swap of a 512-bit calldata word: x = ((x >> 8) & bswap8) | ((x & bswap8) << 8); x = ((x >> 16) & bswap16) | ((x & bswap16) << 16); x = ((x >> 32) & bswap32) | ((x & bswap32) << 32). After the swap lane k (from the most significant lane) holds element k as a big-endian u64."
        }
    })
}

/// Write `constants_json()` to `path` (pretty JSON, trailing newline).
pub fn write_constants(path: &std::path::Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        path,
        serde_json::to_string_pretty(&constants_json())? + "\n",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_table_is_consistent() {
        let gens = Goldilocks::TWO_ADIC_GENERATORS;
        assert_eq!(gens[0], Goldilocks::ONE);
        for (i, g) in gens.iter().enumerate() {
            assert_eq!(*g * g.inverse(), Goldilocks::ONE);
            assert_eq!(g.exp_power_of_2(i), Goldilocks::ONE);
            if i > 0 {
                assert_eq!(g.exp_power_of_2(i - 1), Goldilocks::NEG_ONE);
                assert_eq!(g.square(), gens[i - 1]);
            }
            assert_eq!(*g, Goldilocks::two_adic_generator(i));
        }
        assert_eq!(
            Goldilocks::ONE.halve().as_canonical_u64(),
            0x7FFF_FFFF_8000_0001
        );
        assert_eq!(Goldilocks::ONE.halve() * Goldilocks::TWO, Goldilocks::ONE);
        assert_eq!(Goldilocks::GENERATOR.as_canonical_u64(), 7);
    }

    #[test]
    fn masks_are_512_bits() {
        let doc = constants_json();
        for key in ["bswap8", "bswap16", "bswap32"] {
            let s = doc["laneMasks"][key].as_str().unwrap();
            assert_eq!(s.len(), 2 + 128, "{key}");
        }
    }
}
