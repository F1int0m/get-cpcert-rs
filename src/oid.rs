//! Small registry of OIDs we know by name.
//!
//! Used to enrich error messages and `inspect_pfx` output — turns a raw
//! dotted-OID into something a human can read, like
//! `1.2.840.113549.1.12.1.3 (pbeWithSHAAnd3-KeyTripleDES-CBC)`.
//!
//! Coverage is deliberately limited to OIDs that actually appear in the
//! PFX/PKCS#12 / GOST / CryptoPro ecosystem we deal with — not a general
//! ASN.1 OID database.

/// Look up a friendly name for an OID.  Returns `None` for unknown.
pub fn name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        // ---- PKCS#7 / CMS content types ----
        "1.2.840.113549.1.7.1" => "id-data (PKCS#7)",
        "1.2.840.113549.1.7.2" => "id-signedData (PKCS#7)",
        "1.2.840.113549.1.7.6" => "id-encryptedData (PKCS#7)",

        // ---- PBE schemes (PKCS#12 v1 family) ----
        "1.2.840.113549.1.12.1.1" => "pbeWithSHAAnd128BitRC4",
        "1.2.840.113549.1.12.1.2" => "pbeWithSHAAnd40BitRC4",
        "1.2.840.113549.1.12.1.3" => "pbeWithSHAAnd3-KeyTripleDES-CBC",
        "1.2.840.113549.1.12.1.4" => "pbeWithSHAAnd2-KeyTripleDES-CBC",
        "1.2.840.113549.1.12.1.5" => "pbeWithSHAAnd128BitRC2-CBC",
        "1.2.840.113549.1.12.1.6" => "pbeWithSHAAnd40BitRC2-CBC",
        "1.2.840.113549.1.12.1.80" => "CryptoPro PBE (.80) — proprietary GOST key transport",

        // ---- PBE schemes (PKCS#5 / PBES2) ----
        "1.2.840.113549.1.5.12" => "id-PBKDF2",
        "1.2.840.113549.1.5.13" => "id-PBES2",

        // ---- HMAC PRFs ----
        "1.2.643.7.1.1.4.1" => "id-tc26-hmac-gost-3411-12-256",
        "1.2.643.7.1.1.4.2" => "id-tc26-hmac-gost-3411-12-512",

        // ---- Hash functions ----
        "1.3.14.3.2.26" => "id-sha1",
        "1.2.643.2.2.9" => "id-GostR3411-94",
        "1.2.643.7.1.1.2.2" => "id-tc26-gost3411-12-256 (Streebog-256)",
        "1.2.643.7.1.1.2.3" => "id-tc26-gost3411-12-512 (Streebog-512)",

        // ---- Block ciphers ----
        "1.2.643.2.2.21" => "id-Gost28147-89",
        "1.2.643.2.2.31.1" => "id-Gost28147-89-CryptoPro-A-ParamSet",
        "1.2.643.7.1.2.5.1.1" => "id-tc26-gost-28147-param-Z",

        // ---- Public-key algorithms ----
        "1.2.643.2.2.19" => "id-GostR3410-2001",
        "1.2.643.2.2.20" => "id-GostR3410-94",
        "1.2.643.2.2.30.1" => {
            "id-GostR3410-2001-CryptoPro-XchA-ParamSet (algorithm ref in container)"
        }
        "1.2.643.7.1.1.1.1" => "id-tc26-gost3410-12-256",
        "1.2.643.7.1.1.1.2" => "id-tc26-gost3410-12-512",

        // ---- EC paramSets ----
        "1.2.643.2.2.36.0" => "id-GostR3410-2001-CryptoPro-XchA-ParamSet (curve)",
        "1.2.643.7.1.2.1.2.1" => "id-tc26-gost-3410-12-512-paramSetA",

        // ---- PKCS#12 bag types ----
        "1.2.840.113549.1.12.10.1.1" => "keyBag",
        "1.2.840.113549.1.12.10.1.2" => "pkcs8ShroudedKeyBag",
        "1.2.840.113549.1.12.10.1.3" => "certBag",
        "1.2.840.113549.1.12.10.1.4" => "crlBag",
        "1.2.840.113549.1.12.10.1.5" => "secretBag",
        "1.2.840.113549.1.12.10.1.6" => "safeContentsBag",
        "1.2.840.113549.1.9.22.1" => "x509Certificate (certBag certId)",
        "1.2.840.113549.1.9.20" => "friendlyName attribute",
        "1.2.840.113549.1.9.21" => "localKeyId attribute",

        // ---- KEK diversify constant ----
        // (Not an OID, but useful: 0x26BDB878 is the CryptoPro KDF label.)
        _ => return None,
    })
}

/// Format an OID with its friendly name in parens (or just the OID if
/// unknown).  Handy for error messages.
pub fn describe(oid: &str) -> String {
    match name(oid) {
        Some(n) => format!("{oid} ({n})"),
        None => oid.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_oids_resolve() {
        assert!(name("1.2.840.113549.1.12.1.3").is_some());
        assert!(name("1.2.840.113549.1.12.1.80").is_some());
    }

    #[test]
    fn unknown_oid_returns_none() {
        assert_eq!(name("9.9.9.9"), None);
    }

    #[test]
    fn describe_known() {
        let s = describe("1.2.840.113549.1.12.1.3");
        assert!(s.contains("pbeWithSHAAnd3-KeyTripleDES-CBC"));
    }

    #[test]
    fn describe_unknown() {
        assert_eq!(describe("9.9.9"), "9.9.9");
    }
}
