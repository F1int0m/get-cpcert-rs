//! Integration tests against real CryptoPro `.pfx` files.
//!
//! Layout — drop a directory under `tests/samples_pfx/<name>/`:
//!
//!   cert.pfx        binary PFX (or `cert.p12`, `key.pfx`, etc — any `*.pfx`/`*.p12`)
//!   password        text, exactly the password (no trailing newline; empty file OK)
//!   expected.pem    text, the reference PEM bundle to match byte-for-byte
//!
//! Each subdirectory becomes a sub-test.  When no samples are present the
//! suite prints a friendly skip and exits clean — keeps CI green in
//! sandboxes without test data.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use get_cpcert::extract_from_pfx;

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("samples_pfx")
}

/// A sample is a directory containing exactly one `.pfx`/`.p12` file.
fn list_samples() -> Vec<(PathBuf, PathBuf)> {
    let root = samples_dir();
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    let entries = match fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        let pfx = match find_pfx(&path) {
            Some(p) => p,
            None => continue,
        };
        out.push((path, pfx));
    }
    out.sort();
    out
}

fn find_pfx(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for ent in entries.flatten() {
        let p = ent.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().and_then(OsStr::to_str).unwrap_or("");
        if ext.eq_ignore_ascii_case("pfx") || ext.eq_ignore_ascii_case("p12") {
            return Some(p);
        }
    }
    None
}

fn read_password(dir: &Path) -> String {
    match fs::read_to_string(dir.join("password")) {
        Ok(s) => s.trim_end_matches(['\r', '\n']).to_string(),
        Err(_) => String::new(),
    }
}

fn label(dir: &Path) -> String {
    dir.file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("<unknown>")
        .to_string()
}

#[test]
fn pfx_samples_extract_correctly() {
    let samples = list_samples();
    if samples.is_empty() {
        eprintln!(
            "\n  [SKIP] No samples in tests/samples_pfx/.\n  \
             To run end-to-end PFX checks, drop a directory with cert.pfx, \
             password, and expected.pem.\n"
        );
        return;
    }

    let mut failures = Vec::new();

    for (dir, pfx_path) in &samples {
        let name = label(dir);
        let password = read_password(dir);
        let pfx_bytes = match fs::read(pfx_path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("[{name}] read {}: {e}", pfx_path.display()));
                continue;
            }
        };

        let actual = match extract_from_pfx(&pfx_bytes, &password) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("[{name}] extract_from_pfx failed: {e}"));
                continue;
            }
        };

        let expected_path = dir.join("expected.pem");
        let expected = match fs::read_to_string(&expected_path) {
            Ok(s) => s,
            Err(_) => {
                eprintln!(
                    "[{name}] no expected.pem — extracted successfully \
                     ({} bytes); save output as expected.pem to pin it.",
                    actual.len()
                );
                continue;
            }
        };

        let normalize = |s: &str| s.replace("\r\n", "\n");
        if normalize(&actual) != normalize(&expected) {
            failures.push(format!(
                "[{name}] PEM mismatch:\n--- expected ---\n{}\n\
                 --- actual ---\n{}\n",
                &expected.chars().take(300).collect::<String>(),
                &actual.chars().take(300).collect::<String>(),
            ));
        } else {
            eprintln!("[{name}] OK ({} bytes)", actual.len());
        }
    }

    if !failures.is_empty() {
        panic!("PFX sample failures:\n{}", failures.join("\n\n"));
    }
}

#[test]
fn pfx_samples_layout_helper() {
    let samples = list_samples();
    eprintln!(
        "discovered {} PFX sample(s): {:?}",
        samples.len(),
        samples.iter().map(|(d, _)| label(d)).collect::<Vec<_>>()
    );
}
