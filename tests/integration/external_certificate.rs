use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn extracts_nonexportable_container_with_external_certificate() -> anyhow::Result<()> {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/nonexportable_g2012256");

    let output = Command::new(env!("CARGO_BIN_EXE_get-cpcert"))
        .arg(sample.join("container.000"))
        .arg("--cert")
        .arg(sample.join("certificate.cer"))
        .arg("--password-file")
        .arg(sample.join("password"))
        .output()?;

    assert!(
        output.status.success(),
        "get-cpcert failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, fs::read(sample.join("expected.pem"))?);
    Ok(())
}
