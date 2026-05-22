//! Build the PEM output: certificate + PKCS#8 PrivateKeyInfo.
//!
//! We reuse the same fixed-byte ASN.1 templates as the original C code —
//! they're PKCS#8 envelopes with a hole into which the raw private-key
//! scalar is copied.  See the original `apk2001`, `apk2012_256`,
//! `apk2012_512` byte arrays for the layout.

use crate::container::Algorithm;
use pem::{EncodeConfig, LineEnding, Pem};

/// PKCS#8 PrivateKeyInfo template for GOST R 34.10-2001 (CryptoPro XchA).
const APK_2001: &[u8] = &[
    0x30, 67, 2, 1, 0, 0x30, 28, 6, 6, 42, 0x85, 3, 2, 2, 19, 0x30, 18, 6, 7, 42, 0x85, 3, 2, 2,
    36, 0, 6, 7, 42, 0x85, 3, 2, 2, 30, 1, 4, 32,
    // 32 bytes of zeros — placeholder for private key
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const APK_2001_KEY_OFFSET: usize = 37;

/// PKCS#8 PrivateKeyInfo template for GOST R 34.10-2012 256-bit.
const APK_2012_256: &[u8] = &[
    0x30, 70, 2, 1, 0, 0x30, 31, 6, 8, 0x2A, 0x85, 3, 7, 1, 1, 1, 1, 0x30, 19, 6, 7, 42, 0x85, 3,
    2, 2, 36, 0, 6, 8, 42, 0x85, 3, 7, 1, 1, 2, 2, 4, 32, // 32 bytes placeholder
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const APK_2012_256_KEY_OFFSET: usize = 40;

/// PKCS#8 PrivateKeyInfo template for GOST R 34.10-2012 512-bit.
const APK_2012_512: &[u8] = &[
    0x30, 94, 2, 1, 0, 0x30, 23, 6, 8, 42, 0x85, 3, 7, 1, 1, 1, 2, 0x30, 11, 6, 9, 42, 0x85, 3, 7,
    1, 2, 1, 2, 1, 4, 64, // 64 bytes placeholder
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
const APK_2012_512_KEY_OFFSET: usize = 32;

fn template_for(alg: Algorithm) -> (&'static [u8], usize, usize) {
    match alg {
        Algorithm::Gost2001 => (APK_2001, APK_2001_KEY_OFFSET, 32),
        Algorithm::Gost2012_256 => (APK_2012_256, APK_2012_256_KEY_OFFSET, 32),
        Algorithm::Gost2012_512 => (APK_2012_512, APK_2012_512_KEY_OFFSET, 64),
    }
}

/// Build the PKCS#8 PrivateKey DER blob by splicing the raw scalar bytes
/// into the appropriate template.
pub fn build_private_key_der(alg: Algorithm, raw_priv: &[u8]) -> Vec<u8> {
    let (tpl, offset, expected_len) = template_for(alg);
    assert_eq!(
        raw_priv.len(),
        expected_len,
        "raw private key has unexpected length"
    );
    let mut out = tpl.to_vec();
    out[offset..offset + expected_len].copy_from_slice(raw_priv);
    out
}

/// Produce the final PEM bundle (certificate + private key).
pub fn build_pem(cert_der: &[u8], pkcs8_der: &[u8]) -> String {
    let cert = Pem::new("CERTIFICATE".to_string(), cert_der.to_vec());
    let key = Pem::new("PRIVATE KEY".to_string(), pkcs8_der.to_vec());
    let cfg = EncodeConfig::new().set_line_ending(LineEnding::LF);
    let mut out = pem::encode_config(&cert, cfg);
    out.push_str(&pem::encode_config(&key, cfg));
    out
}
