//! Independent keccak256 (via `tiny-keccak`), used by the transcript mirror and the Merkle
//! re-derivation so that neither depends on `p3-keccak`.

use tiny_keccak::{Hasher, Keccak};

/// keccak256 of `data` (the Ethereum variant, padding byte `0x01`).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// keccak256 of the concatenation of several byte slices.
pub fn keccak256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_digest() {
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn concat_matches_single_update() {
        let a = b"hello ";
        let b = b"world";
        assert_eq!(keccak256_concat(&[a, b]), keccak256(b"hello world"));
    }
}
