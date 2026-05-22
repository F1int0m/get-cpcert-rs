//! Synthetic .pfx test: build a minimal valid PKCS#12 file in memory from
//! a known cert + PKCS#8 key, run `extract_from_pfx`, and verify the
//! recovered PEM contains the cert and key we put in.
//!
//! Structure of what we build:
//!
//!   PFX SEQUENCE {
//!       INTEGER 3,
//!       ContentInfo {                                -- authSafe
//!           id-data,
//!           [0] EXPLICIT OCTET STRING {              -- AuthenticatedSafe bytes
//!               SEQUENCE OF ContentInfo {
//!                   ContentInfo {                    -- single, unencrypted SafeContents
//!                       id-data,
//!                       [0] EXPLICIT OCTET STRING {
//!                           SafeContents SEQUENCE OF SafeBag {
//!                               SafeBag certBag {certBag(x509), [0] EXPL OCTET STRING(cert_der)},
//!                               SafeBag shroudedKey {pkcs8ShroudedKeyBag,
//!                                                    [0] EXPL EncryptedPrivateKeyInfo}
//!                           }
//!                       }
//!                   }
//!               }
//!           }
//!       }
//!       -- no macData
//!   }
//!
//! The shroudedKeyBag is encrypted with PBES2 (PBKDF2-HMAC-Streebog256 +
//! GOST 28147-89 CFB / TC26 set Z) — matching exactly what the importer
//! supports.

use get_cpcert::extract_from_pfx;
use get_cpcert::gost28147::{Gost28147, SBox};
use get_cpcert::pfx::pbkdf2_streebog256;

// ---- OIDs we need (computed by encode_oid below) ----------------------------

const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_PBES2: &str = "1.2.840.113549.1.5.13";
const OID_PBKDF2: &str = "1.2.840.113549.1.5.12";
const OID_HMAC_STREEBOG_256: &str = "1.2.643.7.1.1.4.1";
const OID_GOST28147: &str = "1.2.643.2.2.21";
const OID_SBOX_TC26_Z: &str = "1.2.643.7.1.2.5.1.1";
const OID_CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const OID_SHROUDED_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
const OID_CERT_X509: &str = "1.2.840.113549.1.9.22.1";

#[test]
fn synthetic_pfx_extracts_cert_and_key() {
    let password = "test-password-123";
    let salt = [0xA5u8; 16];
    let iv = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let iterations: u32 = 100;

    // -- fake PKCS#8 PrivateKeyInfo --
    // Smallest legal-looking SEQUENCE: { INTEGER 0, SEQUENCE { OID }, OCTET STRING(...) }
    // The importer doesn't introspect the PKCS#8 contents — it just round-trips
    // whatever bytes the shroudedKey decrypts to.  Any DER blob will do.
    let pkcs8 = build_seq(&[
        tlv(0x02, &[0x00]), // INTEGER 0
        build_seq(&[encode_oid(OID_GOST28147)]),
        tlv(0x04, b"FAKE-PRIVATE-KEY-OCTETS"),
    ]);

    // -- fake X.509 cert (also any DER blob) --
    let cert_der = build_seq(&[
        tlv(0x02, &[0x42]),
        tlv(0x04, b"PRETEND-THIS-IS-A-CERT-BODY"),
    ]);

    // -- encrypt PKCS#8 with PBES2 / PBKDF2-HMAC-Streebog / GOST28147 CFB --
    let key = pbkdf2_streebog256(password.as_bytes(), &salt, iterations, 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key[..32]);
    let mut ciphertext = pkcs8.clone();
    Gost28147::new(&key_arr, SBox::TC26_Z).encrypt_cfb(&iv, &mut ciphertext);

    // -- shroudedKeyBag = SEQUENCE { algId, OCTET STRING(ciphertext) } --
    let alg_id = build_pbes2_alg(&salt, iterations, &iv);
    let encrypted_pki = build_seq(&[alg_id.clone(), tlv(0x04, &ciphertext)]);

    let shrouded_bag = build_seq(&[encode_oid(OID_SHROUDED_KEY_BAG), explicit0(&encrypted_pki)]);

    // -- certBag = SEQUENCE { certBagOid, [0] EXPLICIT CertBag } --
    // CertBag ::= SEQUENCE { certId, [0] EXPLICIT OCTET STRING(cert_der) }
    let cert_bag_value = build_seq(&[encode_oid(OID_CERT_X509), explicit0(&tlv(0x04, &cert_der))]);
    let cert_bag = build_seq(&[encode_oid(OID_CERT_BAG), explicit0(&cert_bag_value)]);

    // -- SafeContents = SEQUENCE OF SafeBag --
    let safe_contents = build_seq(&[cert_bag, shrouded_bag]);

    // -- wrap in id-data ContentInfo (outer SafeContents is plaintext) --
    let inner_ci = build_seq(&[encode_oid(OID_DATA), explicit0(&tlv(0x04, &safe_contents))]);

    // -- AuthenticatedSafe = SEQUENCE OF ContentInfo --
    let authsafe = build_seq(&[inner_ci]);

    // -- outer authSafe ContentInfo --
    let outer_ci = build_seq(&[encode_oid(OID_DATA), explicit0(&tlv(0x04, &authsafe))]);

    // -- PFX = SEQUENCE { version, authSafe } --
    let pfx = build_seq(&[tlv(0x02, &[0x03]), outer_ci]);

    // -- run the importer --
    let pem = extract_from_pfx(&pfx, password).expect("extract_from_pfx should succeed");
    assert!(
        pem.contains("BEGIN CERTIFICATE"),
        "PEM lacks certificate: {pem}"
    );
    assert!(
        pem.contains("BEGIN PRIVATE KEY"),
        "PEM lacks private key: {pem}"
    );

    // Sanity: the decoded cert block matches what we put in.
    let blocks = pem::parse_many(&pem).unwrap();
    let cert_block = blocks.iter().find(|b| b.tag() == "CERTIFICATE").unwrap();
    assert_eq!(cert_block.contents(), cert_der.as_slice());
    let key_block = blocks.iter().find(|b| b.tag() == "PRIVATE KEY").unwrap();
    assert_eq!(
        key_block.contents(),
        pkcs8.as_slice(),
        "decrypted private key bytes differ from original"
    );
}

#[test]
fn synthetic_pfx_wrong_password_fails() {
    let password = "right";
    let salt = [0x11u8; 16];
    let iv = [0u8; 8];
    let iterations: u32 = 50;

    let pkcs8 = build_seq(&[
        tlv(0x02, &[0x00]),
        build_seq(&[encode_oid(OID_GOST28147)]),
        tlv(0x04, b"SECRET"),
    ]);
    let cert_der = build_seq(&[tlv(0x02, &[0x01]), tlv(0x04, b"CERT")]);

    let key = pbkdf2_streebog256(password.as_bytes(), &salt, iterations, 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key[..32]);
    let mut ct = pkcs8.clone();
    Gost28147::new(&key_arr, SBox::TC26_Z).encrypt_cfb(&iv, &mut ct);

    let alg_id = build_pbes2_alg(&salt, iterations, &iv);
    let epki = build_seq(&[alg_id, tlv(0x04, &ct)]);
    let shrouded = build_seq(&[encode_oid(OID_SHROUDED_KEY_BAG), explicit0(&epki)]);
    let cert_bag_value = build_seq(&[encode_oid(OID_CERT_X509), explicit0(&tlv(0x04, &cert_der))]);
    let cert_bag = build_seq(&[encode_oid(OID_CERT_BAG), explicit0(&cert_bag_value)]);
    let safe_contents = build_seq(&[cert_bag, shrouded]);
    let inner_ci = build_seq(&[encode_oid(OID_DATA), explicit0(&tlv(0x04, &safe_contents))]);
    let authsafe = build_seq(&[inner_ci]);
    let outer_ci = build_seq(&[encode_oid(OID_DATA), explicit0(&tlv(0x04, &authsafe))]);
    let pfx = build_seq(&[tlv(0x02, &[0x03]), outer_ci]);

    // Correct password works.
    extract_from_pfx(&pfx, password).expect("right password works");

    // Wrong password: decryption produces garbage; the PKCS#8 sanity check
    // catches it and surfaces as InvalidPassword.
    let err = extract_from_pfx(&pfx, "wrong").expect_err("wrong password must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("Invalid password"),
        "expected invalid-password error, got: {msg}"
    );
}

// ---- builders ---------------------------------------------------------------

fn build_pbes2_alg(salt: &[u8], iter: u32, iv: &[u8; 8]) -> Vec<u8> {
    // KDF params: PBKDF2 with explicit prf = HMAC-Streebog-256
    let pbkdf2_params = build_seq(&[
        tlv(0x04, salt),                                                 // salt OCTET STRING
        tlv(0x02, &encode_uint(iter)),                                   // iterationCount INTEGER
        build_seq(&[encode_oid(OID_HMAC_STREEBOG_256), tlv(0x05, &[])]), // prf AlgId
    ]);
    let kdf_alg = build_seq(&[encode_oid(OID_PBKDF2), pbkdf2_params]);

    // Enc params: GOST28147 { iv OCTET STRING(8), sbox OID }
    let gost_params = build_seq(&[tlv(0x04, iv), encode_oid(OID_SBOX_TC26_Z)]);
    let enc_alg = build_seq(&[encode_oid(OID_GOST28147), gost_params]);

    let pbes2_params = build_seq(&[kdf_alg, enc_alg]);
    build_seq(&[encode_oid(OID_PBES2), pbes2_params])
}

fn build_seq(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut inner = Vec::new();
    for p in parts {
        inner.extend_from_slice(p);
    }
    tlv(0x30, &inner)
}

fn explicit0(inner: &[u8]) -> Vec<u8> {
    // [0] EXPLICIT, constructed context-specific tag 0.
    tlv(0xA0, inner)
}

/// Emit a single TLV with given identifier and content. Definite length only.
fn tlv(id: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
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
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

/// Encode a dotted-OID string as a DER OID TLV.
fn encode_oid(dotted: &str) -> Vec<u8> {
    let parts: Vec<u64> = dotted.split('.').map(|s| s.parse().unwrap()).collect();
    assert!(parts.len() >= 2);
    let mut content = vec![(parts[0] * 40 + parts[1]) as u8];
    for &p in &parts[2..] {
        content.extend(encode_base128(p));
    }
    tlv(0x06, &content)
}

fn encode_base128(mut v: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        buf.push((v & 0x7f) as u8);
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    buf.reverse();
    let n = buf.len();
    for (i, b) in buf.iter_mut().enumerate() {
        if i + 1 < n {
            *b |= 0x80;
        }
    }
    buf
}

/// Minimal-encoding unsigned big-endian (DER positive integer body).
fn encode_uint(v: u32) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    bytes
}
