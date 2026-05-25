# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- PBE-SHA1-3-Key-TripleDES-CBC (`1.2.840.113549.1.12.1.3`) — handles PFX variants where cert or key bags are wrapped with 3DES instead of RC2-40. New dependency: `des`. Verified end-to-end against an OpenSSL-generated reference PFX (cert+key both wrapped with 3DES).
- BER constructed-form OCTET STRING handling in authSafe, certBag and shroudedKeyBag — fixes "authSafe must be id-data" on PFX files whose large OCTET STRINGs are chunked.
- OID registry (`get_cpcert::oid::{name, describe}`) covering the PKCS#7, PKCS#12, PBE, GOST hash/cipher, EC paramSet and ГОСТ public-key OIDs we touch. Used to format error messages and inspector output.
- Structural PFX inspector: `get_cpcert::pfx::inspect_pfx(bytes) -> PfxReport` plus `Display`. Walks the PFX tree, identifies every ContentInfo / SafeBag, surfaces PBE OIDs, salt, iteration count, and MAC parameters — without decrypting and without a password.
- CLI `--inspect` flag: `get-cpcert --inspect cert.pfx` prints the report to stdout and exits. Ideal for diagnosing unfamiliar files when extraction fails.
- New integration test `pfx_inspect_runs_on_all_samples` verifies the inspector across every fixture (no password needed).

### Changed

- `Error::UnsupportedPbe` and related messages now include the friendly OID name and a hint to run `--inspect`.

## [0.2.0] — PFX / PKCS#12 import

### Added

- `extract_from_pfx(bytes, password) -> Result<String>` library entry point.
- CLI now auto-detects directory vs file: `get-cpcert ./MyKey.000` reads the container, `get-cpcert cert.pfx` reads PFX.
- WASM binding `extract_pem_from_pfx(bytes, password)`.
- Three PBE schemes:
  - `1.2.840.113549.1.12.1.80` — CryptoPro CSP proprietary key transport (custom Gost94CryptoPro-iterated KDF + GOST 28147-89 CFB + RFC 4357/7836 key wrap with `KDF_GOSTR3411_2012_256`).
  - `1.2.840.113549.1.12.1.6` — standard PKCS#12 PBE-SHA1-40BitRC2-CBC for the certBag.
  - `1.2.840.113549.1.5.13` (PBES2) — generic PBKDF2-HMAC-Streebog256 + GOST 28147-89 CFB for standards-compliant ГОСТ PFX from other tools.
- Cipher additions: GOST 28147-89 CFB encrypt/decrypt; PKCS#12 v1 KDF over SHA-1 (verified against the published "smeg" test vector).
- New dependencies: `hmac`, `sha1`, `rc2`, `cbc`, `cipher`.
- New integration test harness `tests/integration_pfx.rs` discovers `tests/samples_pfx/<name>/{cert.pfx,password,expected.pem}` and pins byte-for-byte output.
- New synthetic round-trip test `tests/synthetic_pfx.rs` builds a valid PBES2 PFX from scratch and verifies the importer can recover the original cert+key.
- New real-PFX fixture: `tests/samples_pfx/test_cert/` — CryptoPro CSP export of GOST 34.10-2012/256, password empty. The matching container is committed alongside as `tests/samples/test_app_cert/` (password `123`); both produce the same PEM byte-for-byte, validating both pipelines against the same ground truth.

### Notes

- Wrong-password detection in PFX falls back to PKCS#8 structural validation of the decrypted shrouded key; full HMAC `MacData` verification is not yet implemented.
- CryptoPro `.80` reverse-engineered from [li0ard/cpfx](https://github.com/li0ard/cpfx) (Python) and cross-verified with pygost during development.

## [0.1.0] — Initial release

### Added

- Rust port of [`kov-serg/get-cpcert`](https://github.com/kov-serg/get-cpcert).
- Support for CryptoPro 4/5 containers using GOST R 34.10-2001, GOST R 34.10-2012/256, and GOST R 34.10-2012/512.
- Fallback support for `primary2.key` / `masks2.key` (newer CryptoPro layout).
- WebAssembly bindings (`get-cpcert-wasm`) for in-browser extraction.
- Browser demo (`wasm/demo/index.html`) with drag-and-drop UI.
- GitHub Actions CI: tests on Linux/macOS/Windows, MSRV 1.75, clippy `-D warnings`, rustfmt, wasm-pack build, cargo-audit.
- 31 tests:
  - 27 unit tests (ASN.1 parser, GOST 28147-89, EC math, KDF)
  - 2 synthetic round-trip tests
  - 2 integration tests verifying byte-identical PEM output against the original C utility on 5 sample containers
- Password input via TTY (`rpassword`) by default; `--password` / `--password-file` flags for scripts.
- Secrets cleared via `zeroize`.

### Notable differences from the original

- Pure Rust, no C dependency, no OpenSSL linking.
- Typed errors via `thiserror` instead of numeric exit codes.
- Reusable as a library (`get_cpcert::extract`) and from JavaScript (via WASM).
- Password is read from TTY by default, not exposed in `ps`/shell history.
