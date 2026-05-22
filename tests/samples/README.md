# Test samples for `tests/integration.rs`

This directory should hold real CryptoPro containers used for end-to-end regression testing. They are **not** checked into the repository — drop them in locally.

## Where to get them

Three reference containers come bundled with the original C utility:

```
https://github.com/kov-serg/get-cpcert/releases/download/v1.0.1/get-cpcert-bin.tar.gz
```

The archive's `samples/` directory contains three CryptoPro containers — one each for GOST-2001, GOST-2012-256 and GOST-2012-512 — together with the C `get-cpcert` binary and a `README` listing the password for each container (empty for most of them).

## Layout per sample

For each container, create a sub-directory here named however you like (e.g. `test_2001`, `test_2012_256`, `test_2012_512`) with:

```
tests/samples/test_2001/
    header.key       # binary, from the container
    primary.key      # binary
    masks.key        # binary
    password         # text — empty file = empty password (no trailing newline)
    expected.pem     # reference output from the original C utility
```

To generate `expected.pem`, run the original binary against the container:

```
./get-cpcert /path/to/container.000 "" > expected.pem
```

Then drop `expected.pem` alongside the three `.key` files.

## Running

```
cargo test --release samples_extract_correctly -- --nocapture
```

If no samples are present, the test prints a skip-message and exits green so CI without test data still passes.
