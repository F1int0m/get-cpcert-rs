//! WebAssembly bindings for the get-cpcert library.
//!
//! Exposes a single function `extract_pem(header, primary, masks, password)`
//! that consumes raw container bytes and returns a PEM bundle, all without
//! ever touching a filesystem.  This lets a browser-side UI process a
//! CryptoPro container that the user dragged in, without uploading the
//! key material to a server.
//!
//! Build:
//!     wasm-pack build wasm --target web
//!
//! Usage from JavaScript:
//!     import init, { extract_pem } from './pkg/get_cpcert_wasm.js';
//!     await init();
//!     const pem = extract_pem(headerBytes, primaryBytes, masksBytes, "password");

use wasm_bindgen::prelude::*;

use get_cpcert::{container, extract_from_container};

#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Extract certificate + PKCS#8 private key from raw container bytes.
///
/// All four arguments are required. The function never touches the
/// filesystem; it works purely on the byte buffers handed in.
///
/// Returns the PEM bundle as a string on success, or throws a JS
/// exception (string) on error.
#[wasm_bindgen]
pub fn extract_pem(
    header: &[u8],
    primary: &[u8],
    masks: &[u8],
    password: &str,
) -> Result<String, JsValue> {
    let c = container::from_bytes(header, primary, masks)
        .map_err(|e| JsValue::from_str(&format!("container: {e}")))?;
    extract_from_container(&c, password).map_err(|e| JsValue::from_str(&format!("extract: {e}")))
}
