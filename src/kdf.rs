//! CryptoPro password-based key derivation.
//!
//! Mirrors `make2001_pwd_key` and `make2012_pwd_key` from the original C code.
//!
//! High-level idea (HMAC-like construction with a fixed "salt0" magic):
//!
//! ```text
//! 1. Spread each ASCII char of the password into a UTF-16LE byte
//!    (`pin[i*4] = pass[i]`).
//! 2. salt_pass = H(salt || pin).
//! 3. current = "DENEFH028.760246785.IUEFHWUIO.EF" || zeros[..].
//! 4. Iterate N times (2000 if password non-empty, else 2):
//!      current = H( current⊕0x36 || salt_pass || current⊕0x5C || salt_pass )
//!    (the ⊕ pads `current` to SIZE2 bytes; for 2012 the trailing zeros
//!     stay zero and so xor with 0x36/0x5C is constant)
//! 5. Final mix:
//!      current = H( current⊕0x36 || salt || current⊕0x5C || pin )
//!      out     = H(current)
//! ```
//!
//! The 2001 and 2012 variants differ only in:
//!   * hash function (Gost94/CryptoPro vs Streebog-256)
//!   * SIZE2 for the inner block (32 vs 64)

use digest::Digest;
use gost94::Gost94CryptoPro;
use streebog::Streebog256;
use zeroize::Zeroize;

const SALT0: &[u8; 32] = b"DENEFH028.760246785.IUEFHWUIO.EF";

/// Returns 32-byte key suitable for GOST 28147-89.
pub fn derive_2001(salt: &[u8], password: &str) -> [u8; 32] {
    derive::<Gost94CryptoPro>(salt, password, 32)
}

pub fn derive_2012(salt: &[u8], password: &str) -> [u8; 32] {
    derive::<Streebog256>(salt, password, 64)
}

/// Generic implementation. `size2` is the size of the "inner block" that
/// gets xor-padded with 0x36 / 0x5C. Output is always 32 bytes.
fn derive<H: Digest + Clone>(salt: &[u8], password: &str, size2: usize) -> [u8; 32] {
    // 1. Spread password chars into UTF-16LE-ish layout: c, 0, 0, 0, c, 0, 0, 0, ...
    let pin_bytes = spread_password(password);

    // 2. salt_pass = H(salt || pin)
    let mut h = H::new();
    h.update(salt);
    h.update(&pin_bytes);
    let salt_pass = h.finalize();
    let salt_pass = salt_pass.as_slice();
    debug_assert_eq!(salt_pass.len(), 32);

    // 3. current = SALT0 || zeros[size2-32]
    let mut current = vec![0u8; size2];
    current[..32].copy_from_slice(SALT0);

    // 4. iterate
    let n = if password.is_empty() { 2 } else { 2000 };
    let mut x36 = vec![0u8; size2];
    let mut x5c = vec![0u8; size2];
    for _ in 0..n {
        xor365c(&mut x36, &mut x5c, &current);

        let mut h = H::new();
        h.update(&x36);
        h.update(salt_pass);
        h.update(&x5c);
        h.update(salt_pass);
        let out = h.finalize();
        // Only the first 32 bytes of `current` are overwritten — the
        // tail (size2-32 bytes) keeps whatever was there before.  For
        // the 2012 variant this is the all-zero initial padding, so
        // it stays zero throughout.  Matches the C code exactly.
        current[..32].copy_from_slice(&out);
    }

    // 5. final mix: current = H(current⊕0x36 || salt || current⊕0x5C || pin)
    xor365c(&mut x36, &mut x5c, &current);
    let mut h = H::new();
    h.update(&x36[..32]); // note: original feeds HASH_SIZE here, not SIZE2
    h.update(salt);
    h.update(&x5c[..32]);
    h.update(&pin_bytes);
    let mixed = h.finalize();
    current[..32].copy_from_slice(&mixed);

    // out = H(current)
    let mut h = H::new();
    h.update(&current[..32]);
    let final_hash = h.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&final_hash);

    // Hygiene
    current.zeroize();
    x36.zeroize();
    x5c.zeroize();

    out
}

/// `pin[i*4] = password[i]` (other bytes zero) — mimics how the original
/// C code constructs a UTF-16LE-padded buffer from ASCII.
fn spread_password(password: &str) -> Vec<u8> {
    // The original code allocates a fixed 4*80 buffer and only uses
    // `pin_len*4` bytes.  We do the same: only the populated prefix is
    // hashed (length == 4 * char_count).
    let bytes = password.as_bytes();
    let mut out = vec![0u8; bytes.len() * 4];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 4] = *b;
    }
    out
}

#[inline]
fn xor365c(x36: &mut [u8], x5c: &mut [u8], src: &[u8]) {
    debug_assert_eq!(x36.len(), src.len());
    debug_assert_eq!(x5c.len(), src.len());
    for i in 0..src.len() {
        x36[i] = src[i] ^ 0x36;
        x5c[i] = src[i] ^ 0x5c;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;

    /// Streebog-256 test vector M1 from RFC 6986 §A.1.1.
    /// Message (in the order it appears as bytes in the RFC, after the
    /// "012345..." ASCII string):
    ///   M = "012345678901234567890123456789012345678901234567890123456789012"
    /// Expected H_256(M) =
    ///   9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500
    #[test]
    fn streebog256_rfc6986_m1() {
        let msg = b"012345678901234567890123456789012345678901234567890123456789012";
        let mut h = streebog::Streebog256::new();
        h.update(msg);
        let out = h.finalize();
        let expected =
            hex_to_bytes("9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    /// GOST R 34.11-94 with CryptoPro paramset: hash of the empty string.
    /// Well-known reference value.
    #[test]
    fn gost94_cryptopro_empty() {
        let mut h = gost94::Gost94CryptoPro::new();
        h.update(b"");
        let out = h.finalize();
        let expected =
            hex_to_bytes("981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0");
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    /// KDF must be deterministic for the same inputs.
    #[test]
    fn kdf_2012_deterministic() {
        let salt = [3u8; 12];
        let a = derive_2012(&salt, "hello");
        let b = derive_2012(&salt, "hello");
        assert_eq!(a, b);
    }

    #[test]
    fn kdf_2001_deterministic() {
        let salt = [7u8; 12];
        let a = derive_2001(&salt, "");
        let b = derive_2001(&salt, "");
        assert_eq!(a, b);
    }

    #[test]
    fn empty_password_iterates_twice() {
        // Empty-vs-non-empty produce different outputs (iteration count differs:
        // 2 for empty, 2000 otherwise).
        let salt = [1u8; 12];
        let a = derive_2012(&salt, "");
        let b = derive_2012(&salt, "x");
        assert_ne!(a, b);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let a = derive_2012(&[0u8; 12], "pw");
        let b = derive_2012(&[1u8; 12], "pw");
        assert_ne!(a, b);
        let c = derive_2001(&[0u8; 12], "pw");
        let d = derive_2001(&[1u8; 12], "pw");
        assert_ne!(c, d);
    }

    #[test]
    fn variants_are_distinct() {
        // 2001 and 2012 KDF must give different outputs from the same input
        // (different hash function under the hood).
        let salt = [42u8; 12];
        assert_ne!(derive_2001(&salt, "secret"), derive_2012(&salt, "secret"));
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
