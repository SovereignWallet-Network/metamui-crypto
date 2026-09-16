//! WASM bindings for Falcon512
//!
//! The browser-facing cryptographic operations intentionally fail closed until
//! the Falcon core and binding layer stop relying on simplified internals and
//! insecure randomness fallbacks.

use wasm_bindgen::prelude::*;

const BINDINGS_UNAVAILABLE: &str =
    "Falcon512 WASM bindings are unavailable until secure randomness and full Falcon serialization are implemented";

fn bindings_unavailable_message() -> &'static str {
    BINDINGS_UNAVAILABLE
}

#[wasm_bindgen]
pub struct Falcon512Wasm {
    keypair: Option<(Vec<u8>, Vec<u8>)>,
}

#[wasm_bindgen]
impl Falcon512Wasm {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Falcon512Wasm, JsValue> {
        Ok(Falcon512Wasm { keypair: None })
    }

    #[wasm_bindgen]
    pub fn generate_keypair(&mut self) -> Result<(), JsValue> {
        Err(JsValue::from_str(bindings_unavailable_message()))
    }

    #[wasm_bindgen]
    pub fn get_public_key(&self) -> Result<Vec<u8>, JsValue> {
        match &self.keypair {
            Some((pk, _)) => Ok(pk.clone()),
            None => Err(JsValue::from_str("No keypair generated")),
        }
    }

    #[wasm_bindgen]
    pub fn get_private_key(&self) -> Result<Vec<u8>, JsValue> {
        match &self.keypair {
            Some((_, sk)) => Ok(sk.clone()),
            None => Err(JsValue::from_str("No keypair generated")),
        }
    }

    #[wasm_bindgen]
    pub fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, JsValue> {
        Err(JsValue::from_str(bindings_unavailable_message()))
    }

    #[wasm_bindgen]
    pub fn verify(&self, _message: &[u8], _signature: &[u8]) -> Result<bool, JsValue> {
        Err(JsValue::from_str(bindings_unavailable_message()))
    }
}

#[wasm_bindgen]
pub fn falcon512_generate_keypair() -> Result<Vec<u8>, JsValue> {
    Err(JsValue::from_str(bindings_unavailable_message()))
}

#[wasm_bindgen]
pub fn falcon512_sign(_private_key: &[u8], _message: &[u8]) -> Result<Vec<u8>, JsValue> {
    Err(JsValue::from_str(bindings_unavailable_message()))
}

#[wasm_bindgen]
pub fn falcon512_verify(_public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<bool, JsValue> {
    Err(JsValue::from_str(bindings_unavailable_message()))
}

#[cfg(test)]
mod tests {
    use super::bindings_unavailable_message;

    #[test]
    fn wasm_bindings_report_unavailable_message() {
        assert_eq!(
            bindings_unavailable_message(),
            "Falcon512 WASM bindings are unavailable until secure randomness and full Falcon serialization are implemented"
        );
    }
}
