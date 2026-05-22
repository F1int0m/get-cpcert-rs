//! Synthetic-container test: build a minimal *valid* CryptoPro 2012-256
//! container in memory from a known private key, run extraction, and
//! verify that the recovered key matches what we put in.
//!
//! This does not replace a real-sample test (which would catch
//! interpretation bugs in the wrapper formats), but it does confirm that
//! the *pipeline* — KDF → 28147-89 → mask removal → public-key check →
//! PKCS#8 emission — is internally self-consistent.
//!
//! Strategy:
//!   1. Pick `priv = 0x42424242...` (32 bytes).
//!   2. Compute `pub = priv · G` on CryptoPro_XchA, take 8 LE bytes of x.
//!   3. Pick a random mask `m`, compute `key_with_mask = priv · m mod q`,
//!      stored in little-endian.
//!   4. Encrypt that with GOST 28147-89 under `kdf_2012(salt, password)`.
//!   5. Wrap everything into minimal hand-rolled header.key / primary.key /
//!      masks.key files.
//!   6. Call get_cpcert::extract, then parse out the private-key bytes
//!      from the resulting PKCS#8 PEM and compare.

use std::fs;

use num_bigint_dig::BigUint;

use get_cpcert::extract;
use get_cpcert::gost28147::{Gost28147, SBox};
use get_cpcert::gost_ec::{to_be_bytes_padded, Curve, Point};
use get_cpcert::kdf;

#[test]
fn synthetic_2012_256_round_trip() {
    let tmp = tempdir();
    let dir = tmp.path();

    let curve = Curve::cryptopro_xch_a();
    let password = "synthetic-password";
    let salt = [0xABu8; 12];

    // 1. Private key (must be in [1, q-1]).
    let priv_be: Vec<u8> = (1..=32).collect(); // [1, 2, ..., 32]
    let d = BigUint::from_bytes_be(&priv_be);
    assert!(d < curve.q);

    // 2. Public key Q = d·G, take 8 LE bytes of x.
    let q_point = Point::base(&curve).scalar_mul(&d, &curve);
    let q_x = match q_point {
        Point::Affine { x, .. } => x,
        _ => panic!("Q is infinity"),
    };
    let mut q_x_le = to_be_bytes_padded(&q_x, 32);
    q_x_le.reverse();
    let pub8: [u8; 8] = q_x_le[..8].try_into().unwrap();

    // 3. Mask & masked key (k_with_mask = d · m mod q).
    let mask = BigUint::from_bytes_be(&[0xCDu8; 32]) % &curve.q;
    assert!(!mask.eq(&BigUint::from(0u32)));
    let masked = (&d * &mask) % &curve.q;
    let masked_be = to_be_bytes_padded(&masked, 32);
    let masked_le: Vec<u8> = masked_be.iter().rev().copied().collect();
    let mask_be = to_be_bytes_padded(&mask, 32);
    let mask_le: Vec<u8> = mask_be.iter().rev().copied().collect();

    // 4. Encrypt the masked key with GOST 28147-89 / TC26 Set Z under the KDF
    //    output for (salt, password).
    let pwd_key = kdf::derive_2012(&salt, password);
    let cipher = Gost28147::new(&pwd_key, SBox::TC26_Z);
    let mut primary_enc = masked_le.clone();
    // ECB encrypt (inverse of decrypt_ecb): block-by-block via encrypt_block.
    for chunk in primary_enc.chunks_exact_mut(8) {
        let mut b: [u8; 8] = chunk.try_into().unwrap();
        cipher.encrypt_block(&mut b);
        chunk.copy_from_slice(&b);
    }

    // 5. Hand-roll the three .key files.
    //
    // header.key: a minimal DER tree that
    //   * contains the algorithm OID 1.2.643.7.1.1.2.2 somewhere
    //   * has a primitive [10] octet string with pub8
    //   * has a primitive [5] octet string with the (placeholder) cert DER
    //
    // Our parser scans the whole tree for OIDs and for direct
    // context-specific children, so the layout below is sufficient.
    let cert_der = b"hello-fake-cert".to_vec();
    let header = build_header(&cert_der, &pub8);

    // primary.key: SEQUENCE { OCTET STRING (32 bytes) }
    let primary = build_octets_seq(&[&primary_enc]);

    // masks.key: SEQUENCE { OCTET STRING(mask 32 bytes), OCTET STRING(salt 12 bytes) }
    let masks = build_octets_seq(&[&mask_le, &salt]);

    fs::write(dir.join("header.key"), header).unwrap();
    fs::write(dir.join("primary.key"), primary).unwrap();
    fs::write(dir.join("masks.key"), masks).unwrap();

    // 6. Extract.
    let pem = extract(dir, password).expect("extract should succeed");
    assert!(pem.contains("BEGIN CERTIFICATE"));
    assert!(pem.contains("BEGIN PRIVATE KEY"));

    // Parse out the private key block, decode base64, and pluck the
    // last 32 bytes — that's where the raw scalar lives in the apk_2012_256
    // template (offset 40, length 32, file length 72 -> last 32 bytes).
    let pkcs8_der = extract_private_key_block(&pem);
    assert_eq!(pkcs8_der.len(), 72, "unexpected PKCS#8 length");
    let recovered_le = &pkcs8_der[40..72];
    let recovered_be: Vec<u8> = recovered_le.iter().rev().copied().collect();
    assert_eq!(
        recovered_be, priv_be,
        "round-trip mismatch: extracted private key differs from the one we put in"
    );
}

#[test]
fn synthetic_wrong_password_fails() {
    // Same setup but call extract with a different password — must error.
    let tmp = tempdir();
    let dir = tmp.path();

    let curve = Curve::cryptopro_xch_a();
    let salt = [0x11u8; 12];
    let password = "correct horse battery staple";

    let priv_be: Vec<u8> = (10..=41).collect();
    let d = BigUint::from_bytes_be(&priv_be);
    let q_point = Point::base(&curve).scalar_mul(&d, &curve);
    let q_x = match q_point {
        Point::Affine { x, .. } => x,
        _ => panic!(),
    };
    let mut q_x_le = to_be_bytes_padded(&q_x, 32);
    q_x_le.reverse();
    let pub8: [u8; 8] = q_x_le[..8].try_into().unwrap();

    let mask = BigUint::from_bytes_be(&[0x77u8; 32]) % &curve.q;
    let masked = (&d * &mask) % &curve.q;
    let masked_le: Vec<u8> = to_be_bytes_padded(&masked, 32)
        .iter()
        .rev()
        .copied()
        .collect();
    let mask_le: Vec<u8> = to_be_bytes_padded(&mask, 32)
        .iter()
        .rev()
        .copied()
        .collect();

    let pwd_key = kdf::derive_2012(&salt, password);
    let cipher = Gost28147::new(&pwd_key, SBox::TC26_Z);
    let mut primary_enc = masked_le;
    for chunk in primary_enc.chunks_exact_mut(8) {
        let mut b: [u8; 8] = chunk.try_into().unwrap();
        cipher.encrypt_block(&mut b);
        chunk.copy_from_slice(&b);
    }

    let header = build_header(b"cert", &pub8);
    let primary = build_octets_seq(&[&primary_enc]);
    let masks = build_octets_seq(&[&mask_le, &salt]);
    fs::write(dir.join("header.key"), header).unwrap();
    fs::write(dir.join("primary.key"), primary).unwrap();
    fs::write(dir.join("masks.key"), masks).unwrap();

    // Correct password works:
    extract(dir, password).expect("correct password should succeed");

    // Wrong password fails with InvalidPassword:
    let err = extract(dir, "wrong").unwrap_err();
    assert!(
        format!("{err}").contains("Invalid password"),
        "expected invalid-password error, got: {err}"
    );
}

// ---- helpers ---------------------------------------------------------------

/// Build a header.key body containing exactly:
///   SEQUENCE {
///     OID 1.2.643.7.1.1.2.2,
///     [5] IMPLICIT OCTET STRING <cert_der>,
///     [10] IMPLICIT OCTET STRING <pub8>,
///   }
fn build_header(cert_der: &[u8], pub8: &[u8; 8]) -> Vec<u8> {
    // OID 1.2.643.7.1.1.2.2: BER bytes 2A 85 03 07 01 01 02 02 (8 bytes)
    let oid_content = [0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02];
    let mut inner = Vec::new();
    inner.extend(make_tlv(0x06, &oid_content)); // OID
    inner.extend(make_tlv(0x85, cert_der)); // [5] primitive
    inner.extend(make_tlv(0x8A, pub8)); // [10] primitive
    make_tlv(0x30, &inner) // SEQUENCE
}

/// Build a SEQUENCE containing several primitive OCTET STRINGs.
fn build_octets_seq(parts: &[&[u8]]) -> Vec<u8> {
    let mut inner = Vec::new();
    for p in parts {
        inner.extend(make_tlv(0x04, p));
    }
    make_tlv(0x30, &inner)
}

/// Emit a BER TLV with the given identifier byte and content.
fn make_tlv(id: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(id);
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else {
        unimplemented!("length encoding for {} bytes not implemented", len);
    }
    out.extend_from_slice(content);
    out
}

/// Pluck and base64-decode the PRIVATE KEY PEM block.
fn extract_private_key_block(pem: &str) -> Vec<u8> {
    let blocks = pem::parse_many(pem).expect("valid PEM");
    blocks
        .into_iter()
        .find(|p| p.tag() == "PRIVATE KEY")
        .expect("no PRIVATE KEY block")
        .contents()
        .to_vec()
}

/// Minimal in-process temp directory — keeps the test file self-contained
/// without pulling in the `tempfile` crate.
struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!("get-cpcert-test-{pid}-{n}"));
    fs::create_dir_all(&path).expect("mkdir tempdir");
    TempDir { path }
}
