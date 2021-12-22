use biscuit_auth as biscuit;
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct Biscuit(biscuit::Biscuit);

#[wasm_bindgen]
impl Biscuit {
    pub fn builder() -> BiscuitBuilder {
        BiscuitBuilder::new()
    }

    pub fn create_block(&self) -> BlockBuilder {
        BlockBuilder(self.0.create_block())
    }

    pub fn append(&self, block: BlockBuilder) -> Result<Biscuit, JsValue> {
        Ok(Biscuit(self.0.append(block.0).map_err(|e| e.to_string())?))
    }

    pub fn authorizer(&self) -> Result<Authorizer, JsValue> {
        Ok(Authorizer {
            token: Some(self.0.clone()),
            ..Authorizer::default()
        })
    }

    pub fn seal(&self) -> Result<Biscuit, JsValue> {
        Ok(Biscuit(self.0.seal().map_err(|e| e.to_string())?))
    }

    pub fn from_bytes(data: &[u8], root: &PublicKey) -> Result<Biscuit, JsValue> {
        Ok(Biscuit(
            biscuit::Biscuit::from(data, |_| root.0).map_err(|e| e.to_string())?,
        ))
    }

    pub fn from_base64(data: &str, root: &PublicKey) -> Result<Biscuit, JsValue> {
        Ok(Biscuit(
            biscuit::Biscuit::from_base64(data, |_| root.0).map_err(|e| e.to_string())?,
        ))
    }

    pub fn to_bytes(&self) -> Result<Box<[u8]>, JsValue> {
        Ok(self
            .0
            .to_vec()
            .map_err(|e| e.to_string())?
            .into_boxed_slice())
    }

    pub fn to_base64(&self) -> Result<String, JsValue> {
        Ok(self.0.to_base64().map_err(|e| e.to_string())?)
    }

    pub fn revocation_identifiers(&self) -> Box<[JsValue]> {
        let ids: Vec<_> = self
            .0
            .revocation_identifiers()
            .into_iter()
            .map(|id| base64::encode_config(id, base64::URL_SAFE).into())
            .collect();
        ids.into_boxed_slice()
    }

    pub fn block_count(&self) -> usize {
        self.0.block_count()
    }

    pub fn block_source(&self, index: usize) -> Option<String> {
        self.0.print_block_source(index)
    }
}

#[wasm_bindgen]
#[derive(Default)]
pub struct Authorizer {
    token: Option<biscuit::Biscuit>,
    facts: Vec<biscuit::builder::Fact>,
    rules: Vec<biscuit::builder::Rule>,
    checks: Vec<biscuit::builder::Check>,
    policies: Vec<biscuit::builder::Policy>,
}

#[wasm_bindgen]
impl Authorizer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Authorizer {
        Authorizer::default()
    }

    pub fn add_fact(&mut self, fact: &str) -> Result<(), JsValue> {
        self.facts.push(
            fact.try_into()
                .map_err(|e: biscuit::error::Token| e.to_string())?,
        );
        Ok(())
    }

    pub fn add_rule(&mut self, rule: &str) -> Result<(), JsValue> {
        self.rules.push(
            rule.try_into()
                .map_err(|e: biscuit::error::Token| e.to_string())?,
        );
        Ok(())
    }

    pub fn add_check(&mut self, check: &str) -> Result<(), JsValue> {
        self.checks.push(
            check
                .try_into()
                .map_err(|e: biscuit::error::Token| e.to_string())?,
        );
        Ok(())
    }

    pub fn add_policy(&mut self, policy: &str) -> Result<(), JsValue> {
        self.policies.push(
            policy
                .try_into()
                .map_err(|e: biscuit::error::Token| e.to_string())?,
        );
        Ok(())
    }

    pub fn authorize(&self) -> Result<usize, JsValue> {
        let mut authorizer = match &self.token {
            Some(token) => token.authorizer().map_err(|e| e.to_string())?,
            None => biscuit::Authorizer::new().map_err(|e| e.to_string())?,
        };

        for fact in self.facts.iter() {
            authorizer
                .add_fact(fact.clone())
                .map_err(|e| e.to_string())?;
        }
        for rule in self.rules.iter() {
            authorizer
                .add_rule(rule.clone())
                .map_err(|e| e.to_string())?;
        }
        for check in self.checks.iter() {
            authorizer
                .add_check(check.clone())
                .map_err(|e| e.to_string())?;
        }
        for policy in self.policies.iter() {
            authorizer
                .add_policy(policy.clone())
                .map_err(|e| e.to_string())?;
        }

        Ok(authorizer.authorize().map_err(|e| e.to_string())?)
    }
}

#[wasm_bindgen]
pub struct BiscuitBuilder {
    facts: Vec<biscuit::builder::Fact>,
    rules: Vec<biscuit::builder::Rule>,
    checks: Vec<biscuit::builder::Check>,
}

#[wasm_bindgen]
impl BiscuitBuilder {
    fn new() -> BiscuitBuilder {
        BiscuitBuilder {
            facts: Vec::new(),
            rules: Vec::new(),
            checks: Vec::new(),
        }
    }

    pub fn build(self, root: &KeyPair) -> Result<Biscuit, JsValue> {
        let mut builder = biscuit_auth::Biscuit::builder(&root.0);
        for fact in self.facts.into_iter() {
            builder
                .add_authority_fact(fact)
                .map_err(|e| e.to_string())?;
        }
        for rule in self.rules.into_iter() {
            builder
                .add_authority_rule(rule)
                .map_err(|e| e.to_string())?;
        }
        for check in self.checks.into_iter() {
            builder
                .add_authority_check(check)
                .map_err(|e| e.to_string())?;
        }

        Ok(Biscuit(builder.build().map_err(|e| e.to_string())?))
    }

    pub fn add_authority_fact(&mut self, fact: &str) -> Result<(), JsValue> {
        self.facts.push(
            fact.try_into()
                .map_err(|e: biscuit::error::Token| e.to_string())?,
        );
        Ok(())
    }

    pub fn add_authority_rule(&mut self, rule: &str) -> Result<(), JsValue> {
        self.rules.push(
            rule.try_into()
                .map_err(|e: biscuit::error::Token| e.to_string())?,
        );
        Ok(())
    }

    pub fn add_authority_check(&mut self, check: &str) -> Result<(), JsValue> {
        self.checks.push(
            check
                .try_into()
                .map_err(|e: biscuit::error::Token| e.to_string())?,
        );
        Ok(())
    }
}

#[wasm_bindgen]
pub struct BlockBuilder(biscuit::builder::BlockBuilder);

#[wasm_bindgen]
impl BlockBuilder {
    pub fn add_fact(&mut self, fact: &str) -> Result<(), JsValue> {
        Ok(self
            .0
            .add_fact(fact)
            .map_err(|e: biscuit::error::Token| e.to_string())?)
    }

    pub fn add_rule(&mut self, rule: &str) -> Result<(), JsValue> {
        Ok(self
            .0
            .add_rule(rule)
            .map_err(|e: biscuit::error::Token| e.to_string())?)
    }

    pub fn add_check(&mut self, check: &str) -> Result<(), JsValue> {
        Ok(self
            .0
            .add_check(check)
            .map_err(|e: biscuit::error::Token| e.to_string())?)
    }
}

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

    log("biscuit-wasm loading")
}
