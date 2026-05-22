# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
