// The CLI uses clap/rpassword, which are not available on wasm.  On wasm
// targets we compile a stub `main` that does nothing — the WASM consumer
// is the `get-cpcert-wasm` crate, not this binary.
#![cfg(not(target_family = "wasm"))]

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "get-cpcert",
    version,
    about = "Extract certificate + private key from a CryptoPro 4/5 container",
    long_about = "\
Reads a CryptoPro container directory (xxx.000) and writes a PEM bundle
(CERTIFICATE + PRIVATE KEY) to stdout, suitable for use with GOST-enabled
OpenSSL 1.1.1 or later.

Supports GOST R 34.10-2001, -2012/256 and -2012/512 containers."
)]
struct Cli {
    /// Path to the container directory (e.g. /path/to/MyKey.000).
    container: PathBuf,

    /// Password. If omitted, the program prompts on the TTY.
    /// (Passing on the CLI exposes it in shell history & process list.)
    #[arg(short, long)]
    password: Option<String>,

    /// Read password from this file instead of prompting.
    #[arg(long, conflicts_with = "password")]
    password_file: Option<PathBuf>,

    /// Write output to this file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let password = match resolve_password(&cli) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    match get_cpcert::extract(&cli.container, &password) {
        Ok(pem) => {
            if let Some(path) = cli.output {
                if let Err(e) = std::fs::write(&path, pem) {
                    eprintln!("error writing {}: {}", path.display(), e);
                    return ExitCode::from(3);
                }
            } else {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                if let Err(e) = handle.write_all(pem.as_bytes()) {
                    eprintln!("error: {e}");
                    return ExitCode::from(3);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn resolve_password(cli: &Cli) -> anyhow::Result<String> {
    if let Some(p) = &cli.password {
        return Ok(p.clone());
    }
    if let Some(path) = &cli.password_file {
        let raw = std::fs::read_to_string(path)?;
        // Strip trailing newline, leave everything else (passwords may
        // legitimately contain spaces/quotes).
        return Ok(raw.trim_end_matches(['\r', '\n']).to_string());
    }
    Ok(rpassword::prompt_password("Container password: ")?)
}
