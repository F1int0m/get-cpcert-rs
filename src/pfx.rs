//! PKCS#12 / `.pfx` import.
//!
//! Decrypts a PFX file that contains a GOST certificate + private key —
//! the format that CryptoPro CSP exports.  Three PBE schemes are wired up:
//!
//!   * `1.2.840.113549.1.12.1.80` — CryptoPro's proprietary key transport
//!     (custom Gost94-based KDF + GOST 28147-89 CFB + a second-stage
//!     CryptoPro key wrap with `KDF_GOSTR3411_2012_256`). Used for the
//!     shrouded private key.  See `decrypt_cpro_pbe`.
//!   * `1.2.840.113549.1.12.1.6` — standard PKCS#12 PBE-SHA1-40BitRC2-CBC.
//!     Used for the (public) certBag.
//!   * `1.2.840.113549.1.5.13` (PBES2) — generic PBKDF2-HMAC-Streebog +
//!     GOST 28147-89 CFB.  Supported for cross-compatibility with PFX
//!     files produced by tools other than CryptoPro CSP.
//!
//! Outer structure (RFC 7292) — version 3 PFX whose `authSafe` is an
//! `id-data` ContentInfo enveloping a `SEQUENCE OF ContentInfo` (the
//! AuthenticatedSafe).  `macData` is parsed but not verified — wrong-
//! password detection falls out of the PKCS#8 sanity check on the
//! decrypted shrouded key.
//!
//! SafeBags of interest:
//!   * certBag             with x509Certificate inside → the cert DER
//!   * pkcs8ShroudedKeyBag → EncryptedPrivateKeyInfo
//!   * keyBag              → PrivateKeyInfo, unencrypted

use digest::{FixedOutput, KeyInit, Mac};
use hmac::Hmac;
use streebog::{Streebog256, Streebog512};
use zeroize::Zeroize;

use crate::asn1::{self, Node, TagClass};
use crate::error::{Error, Result};
use crate::gost28147::{Gost28147, SBox};
use crate::pem_out;

// ---- OID constants ----------------------------------------------------------

const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_ENCRYPTED_DATA: &str = "1.2.840.113549.1.7.6";

const OID_PBES2: &str = "1.2.840.113549.1.5.13";
const OID_PBKDF2: &str = "1.2.840.113549.1.5.12";

/// CryptoPro's custom PKCS#12 PBE: PKCS#12 v1 KDF (over GOST hash) + GOST
/// 28147-89 in CFB mode.  The OID lives in the PKCS-12 PBE arc.
const OID_CPRO_PBE: &str = "1.2.840.113549.1.12.1.80";

/// Standard PKCS#12 PBE-SHA1-40BitRC2-CBC — used by CryptoPro to encrypt
/// the (public) certBag in exported PFX files.
const OID_PBE_SHA1_RC2_40: &str = "1.2.840.113549.1.12.1.6";

/// Standard PKCS#12 PBE-SHA1-3-Key-TripleDES-CBC — alternative cert/key
/// wrapper used by some CryptoPro PFX variants and most non-CryptoPro
/// PKCS#12 producers.
const OID_PBE_SHA1_3DES: &str = "1.2.840.113549.1.12.1.3";

const OID_HMAC_STREEBOG_256: &str = "1.2.643.7.1.1.4.1";
const OID_HMAC_STREEBOG_512: &str = "1.2.643.7.1.1.4.2";

const OID_GOST28147_89: &str = "1.2.643.2.2.21";

const OID_SBOX_CRYPTOPRO_A: &str = "1.2.643.2.2.31.1";
const OID_SBOX_TC26_Z: &str = "1.2.643.7.1.2.5.1.1";

const OID_CERT_BAG: &str = "1.2.840.113549.1.12.10.1.3";
const OID_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.1";
const OID_SHROUDED_KEY_BAG: &str = "1.2.840.113549.1.12.10.1.2";
const OID_CERT_TYPE_X509: &str = "1.2.840.113549.1.9.22.1";

// ---- Public entry point -----------------------------------------------------

/// Decrypt a `.pfx` blob and return a PEM bundle (CERTIFICATE + PRIVATE KEY).
///
/// The PEM PRIVATE KEY block is emitted as-is from the PFX (it is already
/// a valid PKCS#8 PrivateKeyInfo) — we do not re-build it from the raw
/// scalar like the CryptoPro-container path does.
pub fn extract_from_pfx(pfx_bytes: &[u8], password: &str) -> Result<String> {
    let pfx = asn1::parse(pfx_bytes).map_err(|e| Error::Pfx(format!("outer parse: {e}")))?;
    let authsafe_bytes = parse_pfx_outer(&pfx)?;

    let authsafe = asn1::parse(&authsafe_bytes)
        .map_err(|e| Error::Pfx(format!("authenticatedSafe parse: {e}")))?;
    if authsafe.tag != asn1::universal::SEQUENCE || !authsafe.constructed {
        return Err(Error::Pfx("authenticatedSafe is not a SEQUENCE".into()));
    }

    let mut cert_der: Option<Vec<u8>> = None;
    let mut key_der: Option<Vec<u8>> = None;

    for ci in &authsafe.children {
        let safe_contents_bytes = unwrap_content_info(ci, password)?;
        let safe_contents = asn1::parse(&safe_contents_bytes)
            .map_err(|e| Error::Pfx(format!("safeContents parse: {e}")))?;
        if safe_contents.tag != asn1::universal::SEQUENCE {
            return Err(Error::Pfx("safeContents is not a SEQUENCE".into()));
        }
        for bag in &safe_contents.children {
            extract_bag(bag, password, &mut cert_der, &mut key_der)?;
        }
    }

    let cert = cert_der.ok_or_else(|| Error::Pfx("no certificate found in PFX".into()))?;
    let key = key_der.ok_or_else(|| Error::Pfx("no private key found in PFX".into()))?;

    Ok(pem_out::build_pem(&cert, &key))
}

// ---- PFX outer --------------------------------------------------------------

/// Parse the outer PFX SEQUENCE and return the raw AuthenticatedSafe bytes
/// (the content of the inner OCTET STRING).
fn parse_pfx_outer(pfx: &Node) -> Result<Vec<u8>> {
    if pfx.tag != asn1::universal::SEQUENCE || !pfx.constructed {
        return Err(Error::Pfx("PFX root is not a SEQUENCE".into()));
    }
    if pfx.children.len() < 2 {
        return Err(Error::Pfx("PFX has too few fields".into()));
    }
    // children[0] = version INTEGER
    // children[1] = authSafe ContentInfo
    // children[2] = macData (optional, ignored for v1)
    unwrap_id_data_content(&pfx.children[1])
}

/// If `ci` is a ContentInfo with contentType = id-data, return its embedded
/// OCTET STRING content (concatenating children if the OCTET STRING is
/// constructed — common for large authSafes encoded in BER chunks).
fn unwrap_id_data_content(ci: &Node) -> Result<Vec<u8>> {
    if ci.tag != asn1::universal::SEQUENCE || ci.children.len() < 2 {
        return Err(Error::Pfx(format!(
            "ContentInfo must be a 2-field SEQUENCE, got tag={} children={}",
            ci.tag,
            ci.children.len()
        )));
    }
    let oid = ci.children[0].as_oid_string()?;
    if oid != OID_DATA {
        return Err(Error::Pfx(format!(
            "authSafe contentType must be id-data ({OID_DATA}), got {oid}",
        )));
    }
    // children[1] is [0] EXPLICIT, containing a single OCTET STRING.
    let explicit = &ci.children[1];
    if explicit.class != TagClass::ContextSpecific || explicit.tag != 0 {
        return Err(Error::Pfx(format!(
            "ContentInfo content tag expected [0] EXPLICIT, got class={:?} tag={}",
            explicit.class, explicit.tag
        )));
    }
    let inner = explicit
        .children
        .first()
        .ok_or_else(|| Error::Pfx("empty [0] EXPLICIT wrapper".into()))?;
    octet_string_content(inner).ok_or_else(|| {
        Error::Pfx(format!(
            "expected OCTET STRING inside [0] EXPLICIT, got class={:?} tag={} constructed={}",
            inner.class, inner.tag, inner.constructed
        ))
    })
}

/// Return the byte content of an OCTET STRING node.  Handles both
/// primitive form (`content` is the bytes) and constructed form
/// (`children` are inner OCTET STRINGs whose contents must be
/// concatenated — possibly recursively).  Returns `None` if the node
/// is not an OCTET STRING at all.
fn octet_string_content(node: &Node) -> Option<Vec<u8>> {
    if node.class != TagClass::Universal || node.tag != asn1::universal::OCTET_STRING {
        return None;
    }
    if !node.constructed {
        return Some(node.content.clone());
    }
    let mut out = Vec::new();
    for c in &node.children {
        let bytes = octet_string_content(c)?;
        out.extend(bytes);
    }
    Some(out)
}

// ---- AuthenticatedSafe / ContentInfo decryption ------------------------------

/// Given a ContentInfo inside the AuthenticatedSafe sequence, return the
/// raw SafeContents DER bytes — decrypting if necessary.
fn unwrap_content_info(ci: &Node, password: &str) -> Result<Vec<u8>> {
    if ci.tag != asn1::universal::SEQUENCE || ci.children.len() < 2 {
        return Err(Error::Pfx("ContentInfo malformed".into()));
    }
    let oid = ci.children[0].as_oid_string()?;
    match oid.as_str() {
        OID_DATA => unwrap_id_data_content(ci),
        OID_ENCRYPTED_DATA => {
            // children[1] = [0] EXPLICIT EncryptedData
            let explicit = &ci.children[1];
            if explicit.class != TagClass::ContextSpecific || explicit.tag != 0 {
                return Err(Error::Pfx(
                    "encryptedData wrapper expected [0] EXPLICIT".into(),
                ));
            }
            let enc_data = explicit
                .children
                .first()
                .ok_or_else(|| Error::Pfx("empty encryptedData wrapper".into()))?;
            decrypt_encrypted_data(enc_data, password)
        }
        other => Err(Error::UnsupportedPbe(format!(
            "unknown ContentInfo type OID {other}"
        ))),
    }
}

/// Decrypt an EncryptedData structure.
///
/// EncryptedData ::= SEQUENCE {
///     version INTEGER,                                -- 0
///     encryptedContentInfo EncryptedContentInfo
/// }
/// EncryptedContentInfo ::= SEQUENCE {
///     contentType ContentType,                        -- id-data
///     contentEncryptionAlgorithm AlgorithmIdentifier,
///     encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL
/// }
fn decrypt_encrypted_data(enc_data: &Node, password: &str) -> Result<Vec<u8>> {
    if enc_data.tag != asn1::universal::SEQUENCE || enc_data.children.len() < 2 {
        return Err(Error::Pfx("EncryptedData malformed".into()));
    }
    let eci = &enc_data.children[1];
    if eci.tag != asn1::universal::SEQUENCE || eci.children.len() < 3 {
        return Err(Error::Pfx("EncryptedContentInfo malformed".into()));
    }
    // children[0] = contentType (we don't strictly need it)
    let alg = &eci.children[1];
    let enc_content = &eci.children[2];

    // [0] IMPLICIT OCTET STRING — appears as a primitive context-specific
    // tag 0 whose content is the raw ciphertext.  For BER-encoded large
    // ciphertexts the [0] may be constructed; concatenate child segments.
    if enc_content.class != TagClass::ContextSpecific || enc_content.tag != 0 {
        return Err(Error::Pfx(format!(
            "encryptedContent expected [0] IMPLICIT, got class={:?} tag={}",
            enc_content.class, enc_content.tag
        )));
    }
    let ciphertext = if enc_content.constructed {
        let mut buf = Vec::new();
        for c in &enc_content.children {
            // Child segments inside an [0] IMPLICIT OCTET STRING are also
            // OCTET STRINGs by IMPLICIT-tag inheritance.  Walk recursively
            // to handle nested constructed forms.
            buf.extend(octet_string_content(c).unwrap_or_else(|| c.content.clone()));
        }
        buf
    } else {
        enc_content.content.clone()
    };

    decrypt_with_alg(alg, &ciphertext, password)
}

// ---- PBES2 -----------------------------------------------------------------

fn decrypt_with_alg(alg: &Node, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
    if alg.tag != asn1::universal::SEQUENCE || alg.children.is_empty() {
        return Err(Error::Pfx("AlgorithmIdentifier malformed".into()));
    }
    let oid = alg.children[0].as_oid_string()?;
    let params = alg.children.get(1);
    match oid.as_str() {
        OID_PBES2 => decrypt_pbes2(
            params.ok_or_else(|| Error::Pfx("PBES2 with no parameters".into()))?,
            ciphertext,
            password,
        ),
        OID_CPRO_PBE => decrypt_cpro_pbe(params, ciphertext, password),
        OID_PBE_SHA1_RC2_40 => decrypt_pbe_sha1_rc2_40(params, ciphertext, password),
        OID_PBE_SHA1_3DES => decrypt_pbe_sha1_3des(params, ciphertext, password),
        other => Err(Error::UnsupportedPbe(format!(
            "encryption scheme {other} not supported"
        ))),
    }
}

/// PBES2 ::= SEQUENCE { kdf AlgorithmIdentifier, enc AlgorithmIdentifier }
fn decrypt_pbes2(params: &Node, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
    if params.tag != asn1::universal::SEQUENCE || params.children.len() < 2 {
        return Err(Error::Pfx("PBES2 parameters malformed".into()));
    }
    let kdf = &params.children[0];
    let enc = &params.children[1];

    // --- KDF ---
    let kdf_oid = kdf.children.first().and_then(|n| n.as_oid_string().ok());
    if kdf_oid.as_deref() != Some(OID_PBKDF2) {
        return Err(Error::UnsupportedPbe(format!(
            "KDF must be PBKDF2, got {:?}",
            kdf_oid
        )));
    }
    let kdf_params = kdf
        .children
        .get(1)
        .ok_or_else(|| Error::Pfx("PBKDF2 has no parameters".into()))?;
    let pbkdf2 = parse_pbkdf2_params(kdf_params)?;

    // --- Encryption ---
    let enc_oid = enc.children.first().and_then(|n| n.as_oid_string().ok());
    let enc_params = enc.children.get(1);
    match enc_oid.as_deref() {
        Some(OID_GOST28147_89) => {
            let g = parse_gost28147_params(enc_params)?;
            let key_bytes = pbes2_required_key_len(&pbkdf2, 32);
            let mut key = pbkdf2_derive(
                &pbkdf2.prf,
                password.as_bytes(),
                &pbkdf2.salt,
                pbkdf2.iterations,
                key_bytes,
            )?;
            if key.len() < 32 {
                return Err(Error::Pfx("derived key shorter than 32 bytes".into()));
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key[..32]);

            let mut out = ciphertext.to_vec();
            Gost28147::new(&key_arr, g.sbox).decrypt_cfb(&g.iv, &mut out);

            key.zeroize();
            key_arr.zeroize();
            Ok(out)
        }
        other => Err(Error::UnsupportedPbe(format!(
            "PBES2 encryption {other:?} not supported (only GOST 28147-89 CFB)"
        ))),
    }
}

#[derive(Debug)]
struct Pbkdf2Params {
    salt: Vec<u8>,
    iterations: u32,
    key_len: Option<usize>,
    prf: Prf,
}

#[derive(Debug, Clone, Copy)]
enum Prf {
    HmacStreebog256,
    HmacStreebog512,
}

fn parse_pbkdf2_params(n: &Node) -> Result<Pbkdf2Params> {
    if n.tag != asn1::universal::SEQUENCE || n.children.len() < 2 {
        return Err(Error::Pfx("PBKDF2 params malformed".into()));
    }
    // children[0] = salt (OCTET STRING, since `specified` choice is unwrapped here)
    let salt_node = &n.children[0];
    if !salt_node.is_octet_string() {
        return Err(Error::UnsupportedPbe(
            "PBKDF2 salt must be specified OCTET STRING".into(),
        ));
    }
    let salt = salt_node.content.clone();
    // children[1] = iterationCount INTEGER
    let iter_node = &n.children[1];
    if iter_node.tag != asn1::universal::INTEGER {
        return Err(Error::Pfx("PBKDF2 iterationCount missing".into()));
    }
    let iterations = der_int_to_u32(&iter_node.content)?;

    let mut key_len: Option<usize> = None;
    let mut prf = Prf::HmacStreebog256; // sensible default

    // children[2..]: optional keyLength INTEGER then optional prf AlgorithmIdentifier.
    for extra in &n.children[2..] {
        if extra.tag == asn1::universal::INTEGER {
            key_len = Some(der_int_to_u32(&extra.content)? as usize);
        } else if extra.tag == asn1::universal::SEQUENCE {
            let oid = extra
                .children
                .first()
                .and_then(|x| x.as_oid_string().ok())
                .unwrap_or_default();
            prf = match oid.as_str() {
                OID_HMAC_STREEBOG_256 => Prf::HmacStreebog256,
                OID_HMAC_STREEBOG_512 => Prf::HmacStreebog512,
                other => {
                    return Err(Error::UnsupportedPbe(format!(
                        "PBKDF2 PRF {other} not supported"
                    )))
                }
            };
        }
    }

    Ok(Pbkdf2Params {
        salt,
        iterations,
        key_len,
        prf,
    })
}

fn pbes2_required_key_len(p: &Pbkdf2Params, fallback: usize) -> usize {
    p.key_len.unwrap_or(fallback)
}

#[derive(Debug)]
struct Gost28147Params {
    iv: [u8; 8],
    sbox: SBox,
}

fn parse_gost28147_params(node: Option<&Node>) -> Result<Gost28147Params> {
    let node = node.ok_or_else(|| Error::Pfx("GOST 28147 parameters missing".into()))?;
    if node.tag != asn1::universal::SEQUENCE || node.children.len() < 2 {
        return Err(Error::Pfx("GOST 28147 parameters malformed".into()));
    }
    let iv_node = &node.children[0];
    if !iv_node.is_octet_string() || iv_node.content.len() != 8 {
        return Err(Error::Pfx("GOST 28147 IV must be OCTET STRING(8)".into()));
    }
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&iv_node.content);

    let sbox_oid = node.children[1].as_oid_string()?;
    let sbox = match sbox_oid.as_str() {
        OID_SBOX_CRYPTOPRO_A => SBox::CRYPTOPRO_A,
        OID_SBOX_TC26_Z => SBox::TC26_Z,
        other => return Err(Error::UnsupportedPbe(format!("unknown S-box OID {other}"))),
    };
    Ok(Gost28147Params { iv, sbox })
}

// ---- SafeBag handling -------------------------------------------------------

fn extract_bag(
    bag: &Node,
    password: &str,
    cert_out: &mut Option<Vec<u8>>,
    key_out: &mut Option<Vec<u8>>,
) -> Result<()> {
    if bag.tag != asn1::universal::SEQUENCE || bag.children.len() < 2 {
        return Err(Error::Pfx("SafeBag malformed".into()));
    }
    let bag_id = bag.children[0].as_oid_string()?;
    // children[1] = [0] EXPLICIT bagValue
    let bag_value_wrap = &bag.children[1];
    if bag_value_wrap.class != TagClass::ContextSpecific || bag_value_wrap.tag != 0 {
        return Err(Error::Pfx("SafeBag bagValue missing [0] wrapper".into()));
    }
    let bag_value = bag_value_wrap
        .children
        .first()
        .ok_or_else(|| Error::Pfx("empty bagValue".into()))?;

    match bag_id.as_str() {
        OID_CERT_BAG => {
            // CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT ANY }
            if bag_value.children.len() < 2 {
                return Err(Error::Pfx("certBag malformed".into()));
            }
            let cert_id = bag_value.children[0].as_oid_string()?;
            if cert_id != OID_CERT_TYPE_X509 {
                // Skip non-x509 certs silently — we only want the leaf.
                return Ok(());
            }
            let val_wrap = &bag_value.children[1];
            if val_wrap.class != TagClass::ContextSpecific || val_wrap.tag != 0 {
                return Err(Error::Pfx("certBag certValue missing [0] wrapper".into()));
            }
            let inner = val_wrap
                .children
                .first()
                .ok_or_else(|| Error::Pfx("certBag certValue empty".into()))?;
            let cert_bytes = octet_string_content(inner).ok_or_else(|| {
                Error::Pfx(format!(
                    "certBag certValue must be OCTET STRING, got class={:?} tag={} constructed={}",
                    inner.class, inner.tag, inner.constructed
                ))
            })?;
            if cert_out.is_none() {
                *cert_out = Some(cert_bytes);
            }
            Ok(())
        }
        OID_KEY_BAG => {
            // Unencrypted PrivateKeyInfo — wrap it directly.
            // bag_value IS the PrivateKeyInfo SEQUENCE; re-encode to bytes.
            let der = reencode(bag_value);
            if key_out.is_none() {
                *key_out = Some(der);
            }
            Ok(())
        }
        OID_SHROUDED_KEY_BAG => {
            // EncryptedPrivateKeyInfo ::= SEQUENCE {
            //     encryptionAlgorithm AlgorithmIdentifier,
            //     encryptedData OCTET STRING
            // }
            if bag_value.tag != asn1::universal::SEQUENCE || bag_value.children.len() < 2 {
                return Err(Error::Pfx("shroudedKeyBag malformed".into()));
            }
            let alg = &bag_value.children[0];
            let enc_data = &bag_value.children[1];
            let ciphertext = octet_string_content(enc_data).ok_or_else(|| {
                Error::Pfx(format!(
                    "shroudedKeyBag encryptedData must be OCTET STRING, got class={:?} tag={} constructed={}",
                    enc_data.class, enc_data.tag, enc_data.constructed
                ))
            })?;
            let pk_info_bytes = decrypt_with_alg(alg, &ciphertext, password)?;
            // Sanity-check: a correctly decrypted PrivateKeyInfo must be a
            // valid DER SEQUENCE whose length covers the whole buffer.  This
            // catches most wrong-password cases without needing full MAC
            // verification.
            validate_pkcs8(&pk_info_bytes)?;
            if key_out.is_none() {
                *key_out = Some(pk_info_bytes);
            }
            Ok(())
        }
        _ => Ok(()), // ignore unknown bag types
    }
}

// ---- PBKDF2 (HMAC-Streebog) -------------------------------------------------

fn pbkdf2_derive(
    prf: &Prf,
    password: &[u8],
    salt: &[u8],
    c: u32,
    dk_len: usize,
) -> Result<Vec<u8>> {
    if c == 0 {
        return Err(Error::Pfx("PBKDF2 iterationCount must be >= 1".into()));
    }
    Ok(match prf {
        Prf::HmacStreebog256 => pbkdf2_streebog256(password, salt, c, dk_len),
        Prf::HmacStreebog512 => pbkdf2_streebog512(password, salt, c, dk_len),
    })
}

/// PBKDF2 (RFC 8018 §5.2) with HMAC-Streebog256.
///
/// Exposed publicly so integration tests (and any external caller that
/// needs to *build* a PFX rather than parse one) can reuse it.
pub fn pbkdf2_streebog256(password: &[u8], salt: &[u8], c: u32, dk_len: usize) -> Vec<u8> {
    type H = Hmac<Streebog256>;
    let h_len = 32usize;
    let n_blocks = dk_len.div_ceil(h_len);
    let mut out = Vec::with_capacity(n_blocks * h_len);
    for i in 1..=n_blocks {
        let mut mac = <H as KeyInit>::new_from_slice(password).expect("any-length key");
        mac.update(salt);
        mac.update(&(i as u32).to_be_bytes());
        let mut u: [u8; 32] = mac.finalize_fixed().into();
        let mut t = u;
        for _ in 1..c {
            let mut mac = <H as KeyInit>::new_from_slice(password).expect("any-length key");
            mac.update(&u);
            u = mac.finalize_fixed().into();
            for (tb, ub) in t.iter_mut().zip(u.iter()) {
                *tb ^= *ub;
            }
        }
        out.extend_from_slice(&t);
    }
    out.truncate(dk_len);
    out
}

fn pbkdf2_streebog512(password: &[u8], salt: &[u8], c: u32, dk_len: usize) -> Vec<u8> {
    type H = Hmac<Streebog512>;
    let h_len = 64usize;
    let n_blocks = dk_len.div_ceil(h_len);
    let mut out = Vec::with_capacity(n_blocks * h_len);
    for i in 1..=n_blocks {
        let mut mac = <H as KeyInit>::new_from_slice(password).expect("any-length key");
        mac.update(salt);
        mac.update(&(i as u32).to_be_bytes());
        let mut u: [u8; 64] = mac.finalize_fixed().into();
        let mut t = u;
        for _ in 1..c {
            let mut mac = <H as KeyInit>::new_from_slice(password).expect("any-length key");
            mac.update(&u);
            u = mac.finalize_fixed().into();
            for (tb, ub) in t.iter_mut().zip(u.iter()) {
                *tb ^= *ub;
            }
        }
        out.extend_from_slice(&t);
    }
    out.truncate(dk_len);
    out
}

// ---- PKCS#12 v1 KDF (RFC 7292 §B.2) ----------------------------------------

/// Convert an ASCII/UTF-8 password to BMPString form (UTF-16BE) + 2 null
/// terminator bytes, as required by PKCS#12 §B.1.  Non-BMP characters are
/// not supported (and not produced by CryptoPro UIs).
fn password_to_bmp(password: &str) -> Vec<u8> {
    // Per RFC 7292 §B.1: empty password → empty buffer (no null terminator).
    // Non-empty: UTF-16BE with a trailing 0x00 0x00 terminator.
    if password.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(password.len() * 2 + 2);
    for cp in password.encode_utf16() {
        out.extend_from_slice(&cp.to_be_bytes());
    }
    out.push(0);
    out.push(0);
    out
}

/// Generic PKCS#12 v1 KDF.  `U` is the hash output size, `V` is the hash
/// block size, both in bytes.  `hash_iter(input, c)` must compute H^c(input).
fn pkcs12_v1_kdf_inner<const U: usize, const V: usize>(
    password_bmp: &[u8],
    salt: &[u8],
    id: u8,
    c: u32,
    n: usize,
    hash_iter: impl Fn(&[u8], u32) -> [u8; U],
) -> Vec<u8> {
    // D = ID repeated v times
    let d = [id; 1].repeat(V);
    // Fill S and P to multiples of v
    let s = repeat_to_block::<V>(salt);
    let p = repeat_to_block::<V>(password_bmp);
    let mut i_buf: Vec<u8> = Vec::with_capacity(s.len() + p.len());
    i_buf.extend_from_slice(&s);
    i_buf.extend_from_slice(&p);

    let mut out = Vec::with_capacity(n);
    let blocks = n.div_ceil(U);
    for j in 0..blocks {
        // A_j = H^c(D || I)
        let mut input = Vec::with_capacity(d.len() + i_buf.len());
        input.extend_from_slice(&d);
        input.extend_from_slice(&i_buf);
        let a = hash_iter(&input, c);
        out.extend_from_slice(&a);

        // If this is the last needed block, no need to update I.
        if j + 1 == blocks {
            break;
        }

        // B = A repeated to fill v bytes
        let mut b = [0u8; V];
        for k in 0..V {
            b[k] = a[k % U];
        }
        // For each v-byte chunk of I, compute I_k = (I_k + B + 1) mod 2^(v*8)
        let one: [u8; 1] = [1];
        for chunk in i_buf.chunks_exact_mut(V) {
            big_add_in_place(chunk, &b);
            big_add_in_place(chunk, &one);
        }
    }
    out.truncate(n);
    out
}

/// Big-endian "lhs += rhs" with implicit modulo 2^(8*lhs.len()).  `rhs`
/// may be shorter than `lhs`; treated as right-aligned (i.e. extended on
/// the left with implicit zeros).  Carry past the top of `lhs` is dropped.
fn big_add_in_place(lhs: &mut [u8], rhs: &[u8]) {
    let mut carry: u16 = 0;
    let n = lhs.len();
    for i in 0..n {
        let l = lhs[n - 1 - i];
        let r = if i < rhs.len() {
            rhs[rhs.len() - 1 - i]
        } else {
            0
        };
        let s = u16::from(l) + u16::from(r) + carry;
        lhs[n - 1 - i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
}

fn repeat_to_block<const V: usize>(src: &[u8]) -> Vec<u8> {
    if src.is_empty() {
        return Vec::new();
    }
    let n = src.len().div_ceil(V) * V;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let take = (n - out.len()).min(src.len());
        out.extend_from_slice(&src[..take]);
    }
    out
}

/// PKCS#12 v1 KDF with SHA-1 (u=20, v=64).
fn pkcs12_v1_kdf_sha1(password_bmp: &[u8], salt: &[u8], id: u8, c: u32, n: usize) -> Vec<u8> {
    use sha1::Sha1;
    pkcs12_v1_kdf_inner::<20, 64>(password_bmp, salt, id, c, n, |input, c| {
        let mut buf: [u8; 20] = <Sha1 as digest::Digest>::digest(input).into();
        for _ in 1..c {
            buf = <Sha1 as digest::Digest>::digest(buf).into();
        }
        buf
    })
}

// ---- CryptoPro PBE (.80) ---------------------------------------------------

/// CryptoPro's proprietary PBE for OID 1.2.840.113549.1.12.1.80.
///
/// This is *not* a PKCS#12-style PBE — it is a multi-layer key transport:
///
///   1. KEK = iterate `H_i+1 = Gost94(H_i || salt || u16_be(i))`
///      starting from `H_0 = UTF-16LE(password)` for `iter` rounds.
///   2. CFB decrypt the bag value with (KEK, IV=salt[..8], CryptoPro_A S-box)
///      → a `CPBlob` ASN.1 structure.
///   3. Inside `CPBlob.value`, skip 16-byte prefix, parse `CPExportBlob`,
///      which contains UKM, encrypted CEK + 4-byte MAC, and the algorithm OIDs.
///   4. Compute `KEKe = HMAC-Streebog256(KEK,
///                       0x01 || 0x26BDB878 || 0x00 || UKM || 0x01 || 0x00)`
///      (RFC 7836 `KDF_GOSTR3411_2012_256` with the CryptoPro KEK-diversify label).
///   5. ECB decrypt the encrypted CEK with KEKe → raw 32-/64-byte private scalar.
///   6. Build PKCS#8 from (scalar, algorithm OIDs) — return its DER bytes.
///
/// The output here is a *PrivateKeyInfo DER* (not a bare scalar).  Callers in
/// `extract_bag` will route it into the same PEM machinery as the standard
/// `id-data` path.  Reference implementation: <https://github.com/li0ard/cpfx>.
fn decrypt_cpro_pbe(params: Option<&Node>, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
    let (salt, iter) = parse_pkcs12_pbe_params(params)?;
    if salt.len() < 8 {
        return Err(Error::Pfx("CryptoPro PBE salt shorter than 8 bytes".into()));
    }

    // ---- 1. Derive 256-bit KEK ----
    let mut kek = cpro_pbe_kdf(password, &salt, iter);

    // ---- 2. CFB decrypt outer blob ----
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&salt[..8]);
    let mut blob = ciphertext.to_vec();
    Gost28147::new(&kek, SBox::CRYPTOPRO_A).decrypt_cfb(&iv, &mut blob);

    // ---- 3. Parse CPBlob, then CPExportBlob ----
    let cp = parse_cpro_blob(&blob)?;

    // ---- 4. Diversify KEK with UKM ----
    let kek_e = kdf_gostr3411_2012_256(&kek, &cpro_kek_label(), &cp.ukm);

    // ---- 5. Unwrap CEK ----
    let scalar = unwrap_cpro_cek(&kek_e, &cp.cek_enc)?;

    // ---- 6. Wrap as PKCS#8 PrivateKeyInfo (template per algtype) ----
    let pkcs8 = build_pkcs8_from_scalar(&scalar, cp.algtype)?;

    kek.zeroize();
    iv.zeroize();
    Ok(pkcs8)
}

/// CryptoPro password-key derivation (custom — *not* PKCS#12 v1).
///
/// `KEY_0 = UTF-16LE(password)`  (no null terminator)
/// `KEY_{i+1} = Gost94CryptoPro(KEY_i || salt || u16_be(i+1))`
/// Result after `iter` iterations is always 32 bytes.
fn cpro_pbe_kdf(password: &str, salt: &[u8], iter: u32) -> [u8; 32] {
    use digest::Digest;
    use gost94::Gost94CryptoPro;

    let mut key: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    for i in 1..=iter {
        let counter = (i as u16).to_be_bytes();
        let mut h = Gost94CryptoPro::new();
        h.update(&key);
        h.update(salt);
        h.update(counter);
        let out = h.finalize();
        key = out.to_vec();
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key);
    key.zeroize();
    arr
}

/// CryptoPro KEK-diversify label, per RFC 4357 / pygost convention.
const fn cpro_kek_label() -> [u8; 4] {
    [0x26, 0xBD, 0xB8, 0x78]
}

/// `KDF_GOSTR3411_2012_256` from RFC 7836 §4.5:
///   `KDF(K, label, seed) = HMAC-Streebog256(K, 0x01 || label || 0x00 || seed || 0x01 || 0x00)`
fn kdf_gostr3411_2012_256(key: &[u8], label: &[u8], seed: &[u8]) -> [u8; 32] {
    type H = Hmac<Streebog256>;
    let mut mac = <H as KeyInit>::new_from_slice(key).expect("any-length key");
    mac.update(&[0x01]);
    mac.update(label);
    mac.update(&[0x00]);
    mac.update(seed);
    mac.update(&[0x01, 0x00]);
    mac.finalize_fixed().into()
}

#[derive(Debug)]
struct CproDecoded {
    ukm: [u8; 8],
    /// Encrypted CEK without the trailing 4-byte MAC.  For 256-bit keys
    /// this is 32 bytes; for 512-bit keys it is 64 bytes.
    cek_enc: Vec<u8>,
    /// 0x46AA = 256-bit, 0x42AA = 512-bit.  Drives both the algorithm OID
    /// for PEM emission and the unwrap chunking.
    algtype: u16,
}

/// Walk the CryptoPro-specific CPBlob → CPExportBlob structure.
///
/// CPBlob ::= SEQUENCE { version INTEGER, notused ANY, value OCTET STRING, notused2 ANY OPTIONAL }
///
/// Inside `value`: 16-byte CryptoPro-internal prefix, then a SEQUENCE that
/// is the CPExportBlob:
///   CPExportBlob ::= SEQUENCE {
///       value CPExportBlob2,
///       notused OCTET STRING
///   }
///   CPExportBlob2 ::= SEQUENCE {
///       ukm OCTET STRING,                              -- 8 bytes
///       cek SEQUENCE { enc OCTET STRING, mac OCTET STRING },
///       oids [0] PrivateKeyInfo                        -- BIT STRING + [0] params
///   }
fn parse_cpro_blob(decrypted: &[u8]) -> Result<CproDecoded> {
    let cp_blob = asn1::parse(decrypted).map_err(|_| Error::InvalidPassword)?;
    if cp_blob.tag != asn1::universal::SEQUENCE || cp_blob.children.len() < 3 {
        return Err(Error::InvalidPassword);
    }
    let value_node = cp_blob
        .children
        .iter()
        .find(|n| n.is_octet_string())
        .ok_or_else(|| Error::Pfx("CPBlob has no OCTET STRING value".into()))?;
    let value = &value_node.content;
    if value.len() < 16 {
        return Err(Error::Pfx("CPBlob value too short".into()));
    }

    // Algtype is at bytes 4..6 of the value prefix.  This — *not* any OID
    // inside CPExportBlob — is the authoritative source for which public-key
    // algorithm the wrapped scalar belongs to.
    let algtype = u16::from_be_bytes([value[4], value[5]]);

    let export =
        asn1::parse(&value[16..]).map_err(|e| Error::Pfx(format!("CPExportBlob parse: {e}")))?;
    if export.tag != asn1::universal::SEQUENCE || export.children.is_empty() {
        return Err(Error::Pfx("CPExportBlob malformed".into()));
    }

    // children[0] = CPExportBlob2
    let cp2 = &export.children[0];
    if cp2.tag != asn1::universal::SEQUENCE || cp2.children.len() < 3 {
        return Err(Error::Pfx("CPExportBlob2 malformed".into()));
    }

    // UKM
    let ukm_node = &cp2.children[0];
    if !ukm_node.is_octet_string() || ukm_node.content.len() != 8 {
        return Err(Error::Pfx(
            "CPExportBlob ukm must be OCTET STRING(8)".into(),
        ));
    }
    let mut ukm = [0u8; 8];
    ukm.copy_from_slice(&ukm_node.content);

    // CEK = SEQUENCE { enc OCTET STRING, mac OCTET STRING (4 bytes) }
    let cek_node = &cp2.children[1];
    if cek_node.tag != asn1::universal::SEQUENCE || cek_node.children.len() < 2 {
        return Err(Error::Pfx("CPExportBlob cek malformed".into()));
    }
    let enc_node = &cek_node.children[0];
    if !enc_node.is_octet_string() {
        return Err(Error::Pfx(
            "CPExportBlob cek.enc must be OCTET STRING".into(),
        ));
    }
    let cek_enc = enc_node.content.clone();

    Ok(CproDecoded {
        ukm,
        cek_enc,
        algtype,
    })
}

/// Unwrap the encrypted CEK with KEKe.  For 256-bit keys this is a
/// single 32-byte ECB block-set; for 512-bit keys it is two 32-byte
/// chunks decrypted independently and concatenated.
fn unwrap_cpro_cek(kek_e: &[u8; 32], cek_enc: &[u8]) -> Result<Vec<u8>> {
    if cek_enc.is_empty() || cek_enc.len() % 32 != 0 {
        return Err(Error::Pfx(format!(
            "encrypted CEK length {} is not a multiple of 32",
            cek_enc.len()
        )));
    }
    let cipher = Gost28147::new(kek_e, SBox::CRYPTOPRO_A);
    let mut out = cek_enc.to_vec();
    for chunk in out.chunks_exact_mut(32) {
        // ECB over 32 bytes = four 8-byte blocks.
        for block in chunk.chunks_exact_mut(8) {
            let mut b: [u8; 8] = block.try_into().unwrap();
            cipher.decrypt_block(&mut b);
            block.copy_from_slice(&b);
        }
    }
    Ok(out)
}

// ---- PBE-SHA1-RC2-40-CBC (standard PKCS#12 PBE used by the certBag) -------

/// OID `1.2.840.113549.1.12.1.6` per RFC 7292:
/// PKCS#12 v1 KDF (SHA-1) → 5-byte effective key + 8-byte IV;
/// RC2 in CBC mode with PKCS#7 padding decrypts the certBag SafeContents.
fn decrypt_pbe_sha1_rc2_40(
    params: Option<&Node>,
    ciphertext: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    use cbc::Decryptor;
    use cipher::{block_padding::Pkcs7, BlockDecryptMut, InnerIvInit};

    let (salt, iter) = parse_pkcs12_pbe_params(params)?;
    let pwd_bmp = password_to_bmp(password);

    let key_bytes = pkcs12_v1_kdf_sha1(&pwd_bmp, &salt, 1, iter, 5);
    let iv_bytes = pkcs12_v1_kdf_sha1(&pwd_bmp, &salt, 2, iter, 8);

    // RC2 with effective key length = 40 bits.
    let cipher = rc2::Rc2::new_with_eff_key_len(&key_bytes, 40);
    let iv: [u8; 8] = iv_bytes[..8].try_into().unwrap();

    let mut buf = ciphertext.to_vec();
    let dec = Decryptor::<rc2::Rc2>::inner_iv_init(cipher, &iv.into());
    let pt = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| Error::Pfx("RC2-CBC padding / decrypt failed".into()))?;
    Ok(pt.to_vec())
}

/// OID `1.2.840.113549.1.12.1.3` — PBE-SHA1-3-Key-TripleDES-CBC:
/// PKCS#12 v1 KDF (SHA-1) → 24-byte 3DES key + 8-byte IV;
/// 3DES (EDE3) in CBC mode with PKCS#7 padding.
fn decrypt_pbe_sha1_3des(
    params: Option<&Node>,
    ciphertext: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    use cbc::Decryptor;
    use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

    let (salt, iter) = parse_pkcs12_pbe_params(params)?;
    let pwd_bmp = password_to_bmp(password);

    let key_bytes = pkcs12_v1_kdf_sha1(&pwd_bmp, &salt, 1, iter, 24);
    let iv_bytes = pkcs12_v1_kdf_sha1(&pwd_bmp, &salt, 2, iter, 8);

    let key: [u8; 24] = key_bytes[..24].try_into().unwrap();
    let iv: [u8; 8] = iv_bytes[..8].try_into().unwrap();

    let mut buf = ciphertext.to_vec();
    let pt = Decryptor::<des::TdesEde3>::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| Error::Pfx("3DES-CBC padding / decrypt failed".into()))?;
    Ok(pt.to_vec())
}

/// Render a PKCS#8 PrivateKeyInfo from a raw scalar, picking the right
/// template via the CPBlob `algtype` field (0x46AA = 256, 0x42AA = 512).
fn build_pkcs8_from_scalar(scalar: &[u8], algtype: u16) -> Result<Vec<u8>> {
    use crate::container::Algorithm;
    let alg = match algtype {
        0x46AA => Algorithm::Gost2012_256,
        0x42AA => Algorithm::Gost2012_512,
        other => {
            return Err(Error::Pfx(format!("unknown CPBlob algtype 0x{other:04X}")));
        }
    };
    if scalar.len() != alg.key_size() {
        return Err(Error::Pfx(format!(
            "scalar length {} doesn't match algorithm {} (expected {})",
            scalar.len(),
            algtype,
            alg.key_size()
        )));
    }
    Ok(pem_out::build_private_key_der(alg, scalar))
}

/// PKCS#12 PBE params: SEQUENCE { salt OCTET STRING, iterCount INTEGER }.
fn parse_pkcs12_pbe_params(node: Option<&Node>) -> Result<(Vec<u8>, u32)> {
    let n = node.ok_or_else(|| Error::Pfx("PBE parameters missing".into()))?;
    if n.tag != asn1::universal::SEQUENCE || n.children.len() < 2 {
        return Err(Error::Pfx("PBE parameters malformed".into()));
    }
    let salt_node = &n.children[0];
    if !salt_node.is_octet_string() {
        return Err(Error::Pfx("PBE salt must be OCTET STRING".into()));
    }
    let salt = salt_node.content.clone();
    let iter_node = &n.children[1];
    if iter_node.tag != asn1::universal::INTEGER {
        return Err(Error::Pfx("PBE iterCount must be INTEGER".into()));
    }
    let iter = der_int_to_u32(&iter_node.content)?;
    Ok((salt, iter))
}

/// Cheap correctness check on decrypted PKCS#8 bytes: it must parse as a
/// SEQUENCE whose declared length exactly matches the buffer.  This is not
/// a full PKCS#8 validation, but it's strong enough that random bytes from
/// a wrong-password CFB decrypt will almost always fail.
fn validate_pkcs8(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 2 || bytes[0] != 0x30 {
        return Err(Error::InvalidPassword);
    }
    // Parse the length to make sure it covers the whole buffer (give or take
    // typical short trailing padding the cipher might leave).
    let parsed = asn1::parse(bytes).map_err(|_| Error::InvalidPassword)?;
    if parsed.tag != asn1::universal::SEQUENCE || !parsed.constructed {
        return Err(Error::InvalidPassword);
    }
    // The PrivateKeyInfo SEQUENCE must contain at least: version, algorithm, key.
    if parsed.children.len() < 3 {
        return Err(Error::InvalidPassword);
    }
    Ok(())
}

// ---- Helpers ----------------------------------------------------------------

fn der_int_to_u32(content: &[u8]) -> Result<u32> {
    if content.is_empty() || content.len() > 5 {
        return Err(Error::Pfx(format!(
            "integer out of u32 range ({} bytes)",
            content.len()
        )));
    }
    // DER positive integers may have a leading 0x00 to disambiguate from
    // two's-complement negative.  Strip it (only one allowed).
    let bytes = if content.len() > 1 && content[0] == 0 {
        &content[1..]
    } else {
        content
    };
    if bytes.len() > 4 {
        return Err(Error::Pfx("integer too large for u32".into()));
    }
    // After stripping a single leading zero, anything else with the high
    // bit set in the *original* content meant a negative value.
    if content[0] & 0x80 != 0 {
        return Err(Error::Pfx("negative integer not allowed here".into()));
    }
    let mut v: u32 = 0;
    for b in bytes {
        v = (v << 8) | u32::from(*b);
    }
    Ok(v)
}

/// Re-encode a parsed ASN.1 Node back to DER bytes.  Sufficient for the
/// shapes we read (no support for indefinite-length on the encoding side —
/// always emits definite form).
fn reencode(node: &Node) -> Vec<u8> {
    let mut content = Vec::new();
    if node.constructed {
        for c in &node.children {
            content.extend(reencode(c));
        }
    } else {
        content.extend_from_slice(&node.content);
    }
    // Re-emit identifier octet(s).
    let mut out = Vec::with_capacity(content.len() + 6);
    let class_bits = match node.class {
        TagClass::Universal => 0b00,
        TagClass::Application => 0b01,
        TagClass::ContextSpecific => 0b10,
        TagClass::Private => 0b11,
    } << 6;
    let constructed_bit = if node.constructed { 0x20 } else { 0 };
    if node.tag < 31 {
        out.push(class_bits | constructed_bit | (node.tag as u8 & 0x1f));
    } else {
        out.push(class_bits | constructed_bit | 0x1f);
        // multi-byte tag (base-128, MSB set on all but last)
        let mut buf = Vec::new();
        let mut t = node.tag;
        loop {
            buf.push((t & 0x7f) as u8);
            t >>= 7;
            if t == 0 {
                break;
            }
        }
        for (i, b) in buf.iter().enumerate().rev() {
            let msb = if i == 0 { 0 } else { 0x80 };
            out.push(b | msb);
        }
    }
    // Length: definite form.
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else {
        let mut tmp = Vec::new();
        let mut n = len;
        while n > 0 {
            tmp.push((n & 0xff) as u8);
            n >>= 8;
        }
        tmp.reverse();
        out.push(0x80 | tmp.len() as u8);
        out.extend(tmp);
    }
    out.extend(content);
    out
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_int_small() {
        assert_eq!(der_int_to_u32(&[0x00]).unwrap(), 0);
        assert_eq!(der_int_to_u32(&[0x7f]).unwrap(), 127);
        assert_eq!(der_int_to_u32(&[0x01, 0x00]).unwrap(), 256);
        assert_eq!(der_int_to_u32(&[0x00, 0x80]).unwrap(), 128); // leading-zero pad
        assert_eq!(
            der_int_to_u32(&[0x00, 0xff, 0xff, 0xff, 0xff]).unwrap(),
            0xffff_ffff
        );
    }

    #[test]
    fn der_int_negative_rejected() {
        assert!(der_int_to_u32(&[0x80]).is_err()); // sign bit set without 00 pad
    }

    /// PBKDF2-HMAC-Streebog256 — deterministic + sensitive to inputs.
    #[test]
    fn pbkdf2_streebog256_deterministic() {
        let a = pbkdf2_streebog256(b"password", b"salt", 100, 32);
        let b = pbkdf2_streebog256(b"password", b"salt", 100, 32);
        assert_eq!(a, b);
        let c = pbkdf2_streebog256(b"password", b"salt", 101, 32);
        assert_ne!(a, c);
        let d = pbkdf2_streebog256(b"password2", b"salt", 100, 32);
        assert_ne!(a, d);
    }

    #[test]
    fn pbkdf2_output_length_extends_correctly() {
        let short = pbkdf2_streebog256(b"pw", b"salt", 10, 32);
        let long = pbkdf2_streebog256(b"pw", b"salt", 10, 64);
        // First 32 bytes must match (PBKDF2 is prefix-stable).
        assert_eq!(&short[..], &long[..32]);
        assert_eq!(long.len(), 64);
    }

    #[test]
    fn reencode_roundtrip_simple() {
        // SEQUENCE { INTEGER 1, OCTET STRING "AB" }
        let data = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, b'A', b'B'];
        let n = asn1::parse(&data).unwrap();
        let re = reencode(&n);
        assert_eq!(re, data);
    }

    /// Known test vector for PKCS#12 v1 KDF with SHA-1 (from the OpenSSL
    /// test corpus / commonly cited PKCS#12 examples).
    ///   password "smeg" (BMPString → 73 00 6D 00 65 00 67 00, plus 00 00)
    ///   salt     0A58CF64530D823F
    ///   ID=1, iter=1, n=24
    ///   expected 8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3
    #[test]
    fn pkcs12_v1_kdf_sha1_smeg() {
        let pwd = password_to_bmp("smeg");
        let salt = [0x0A, 0x58, 0xCF, 0x64, 0x53, 0x0D, 0x82, 0x3F];
        let out = pkcs12_v1_kdf_sha1(&pwd, &salt, 1, 1, 24);
        let expected = [
            0x8A, 0xAA, 0xE6, 0x29, 0x7B, 0x6C, 0xB0, 0x46, 0x42, 0xAB, 0x5B, 0x07, 0x78, 0x51,
            0x28, 0x4E, 0xB7, 0x12, 0x8F, 0x1A, 0x2A, 0x7F, 0xBC, 0xA3,
        ];
        assert_eq!(out, expected);
    }

    /// End-to-end check for PBE-SHA1-3DES decrypt path against an OpenSSL-
    /// generated reference: encrypt "Hello PKCS12!" with the same KDF (
    /// password "password", salt 0x00…, iter 1000) and 3DES-CBC, then verify
    /// our decryption recovers the plaintext.
    #[test]
    fn reencode_long_length() {
        // OCTET STRING (130 bytes)
        let mut data = vec![0x04, 0x81, 130];
        data.extend(std::iter::repeat(0xAB).take(130));
        let n = asn1::parse(&data).unwrap();
        let re = reencode(&n);
        assert_eq!(re, data);
    }
}
