use biscuit_auth as biscuit;
use log::*;
use rand::prelude::*;
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct KeyPair(biscuit::KeyPair);

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> KeyPair {
        KeyPair(biscuit::KeyPair::new())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.public())
    }

    pub fn private(&self) -> PrivateKey {
        PrivateKey(self.0.private())
    }
}

/// Public key
#[wasm_bindgen]
pub struct PublicKey(biscuit::PublicKey);

#[wasm_bindgen]
impl PublicKey {
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<(), JsValue> {
        if out.len() != 32 {
            return Err("invalid length".into());
        }

        out.copy_from_slice(&self.0.to_bytes());
        Ok(())
    }

    pub fn from_bytes(&self, data: &[u8]) -> Result<PublicKey, JsValue> {
        let key = biscuit_auth::PublicKey::from_bytes(data).map_err(|e| e.to_string())?;
        Ok(PublicKey(key))
    }
}
#[wasm_bindgen]
pub struct PrivateKey(biscuit::PrivateKey);

#[wasm_bindgen]
impl PrivateKey {
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<(), JsValue> {
        if out.len() != 32 {
            return Err("invalid length".into());
        }

        out.copy_from_slice(&self.0.to_bytes());
        Ok(())
    }

    pub fn from_bytes(&self, data: &[u8]) -> Result<PrivateKey, JsValue> {
        let key = biscuit_auth::PrivateKey::from_bytes(data).map_err(|e| e.to_string())?;
        Ok(PrivateKey(key))
    }
}



#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen(start)]
pub fn run_app() {
    wasm_logger::init(wasm_logger::Config::default());
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    unsafe { log("biscuit-wasm loading") }
}
