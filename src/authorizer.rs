use std::collections::HashMap;

use biscuit_auth as biscuit;
use serde::Deserialize;
use std::time::Duration;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{Biscuit, BlockBuilder, Check, Fact, Policy, PublicKey, Rule, Term};

#[derive(Deserialize)]
pub struct RunLimits {
    pub max_facts: Option<u64>,
    pub max_iterations: Option<u64>,
    pub max_time_micro: Option<u64>,
}

impl RunLimits {
    pub fn to_rust_limits(&self) -> biscuit::datalog::RunLimits {
        let defaults = biscuit::datalog::RunLimits::default();
        biscuit::datalog::RunLimits {
            max_facts: self.max_facts.unwrap_or(defaults.max_facts),
            max_iterations: self.max_iterations.unwrap_or(defaults.max_iterations),
            max_time: self
                .max_time_micro
                .map(Duration::from_micros)
                .unwrap_or(defaults.max_time),
        }
    }
}

/// The Authorizer verifies a request according to its policies and the provided token
#[wasm_bindgen]
//#[derive(Default)]
pub struct Authorizer(pub(crate) biscuit::Authorizer);

#[wasm_bindgen]
impl Authorizer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Authorizer {
        Authorizer(biscuit::Authorizer::new())
    }

    #[wasm_bindgen(js_name = addToken)]
    pub fn add_token(&mut self, token: &Biscuit) -> Result<(), JsValue> {
        self.0
            .add_token(&token.0)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Adds a Datalog fact
    #[wasm_bindgen(js_name = addFact)]
    pub fn add_fact(&mut self, fact: &Fact) -> Result<(), JsValue> {
        self.0
            .add_fact(fact.0.clone())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Adds a Datalog rule
    #[wasm_bindgen(js_name = addRule)]
    pub fn add_rule(&mut self, rule: &Rule) -> Result<(), JsValue> {
        self.0
            .add_rule(rule.0.clone())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Adds a check
    ///
    /// All checks, from authorizer and token, must be validated to authorize the request
    #[wasm_bindgen(js_name = addCheck)]
    pub fn add_check(&mut self, check: &Check) -> Result<(), JsValue> {
        self.0
            .add_check(check.0.clone())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Adds a policy
    ///
    /// The authorizer will test all policies in order of addition and stop at the first one that
    /// matches. If it is a "deny" policy, the request fails, while with an "allow" policy, it will
    /// succeed
    #[wasm_bindgen(js_name = addPolicy)]
    pub fn add_policy(&mut self, policy: &Policy) -> Result<(), JsValue> {
        self.0
            .add_policy(policy.0.clone())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Merges the contents of another authorizer
    #[wasm_bindgen(js_name = merge)]
    pub fn merge(&mut self, other: &Authorizer) {
        self.0.merge(other.0.clone())
    }

    /// Merges the contents of a block builder
    #[wasm_bindgen(js_name = mergeBlock)]
    pub fn merge_block(&mut self, other: &BlockBuilder) {
        self.0.merge_block(other.0.clone())
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCode)]
    pub fn add_code(&mut self, source: &str) -> Result<(), JsValue> {
        self.0
            .add_code(source)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Adds facts, rules, checks and policies as one code block
    #[wasm_bindgen(js_name = addCodeWithParameters)]
    pub fn add_code_with_parameters(
        &mut self,
        source: &str,
        parameters: JsValue,
        scope_parameters: JsValue,
    ) -> Result<(), JsValue> {
        let parameters: HashMap<String, Term> = serde_wasm_bindgen::from_value(parameters).unwrap();

        let parameters = parameters
            .into_iter()
            .map(|(k, t)| (k, t.0))
            .collect::<HashMap<_, _>>();

        let scope_parameters: HashMap<String, PublicKey> =
            serde_wasm_bindgen::from_value(scope_parameters).unwrap();
        let scope_parameters = scope_parameters
            .into_iter()
            .map(|(k, p)| (k, p.0))
            .collect::<HashMap<_, _>>();

        self.0
            .add_code_with_params(source, parameters, scope_parameters)
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Runs the authorization checks and policies
    ///
    /// Returns the index of the matching allow policy, or an error containing the matching deny
    /// policy or a list of the failing checks
    #[wasm_bindgen(js_name = authorize)]
    pub fn authorize(&mut self) -> Result<usize, JsValue> {
        self.0
            .authorize()
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    #[wasm_bindgen(js_name = authorizeWithLimits)]
    pub fn authorizer_with_limits(&mut self, limits: JsValue) -> Result<usize, JsValue> {
        let limits: RunLimits = serde_wasm_bindgen::from_value(limits)?;
        self.0
            .authorize_with_limits(limits.to_rust_limits())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())
    }

    /// Executes a query over the authorizer
    #[wasm_bindgen(js_name = query)]
    pub fn query(&mut self, rule: &Rule) -> Result<js_sys::Array, JsValue> {
        let v: Vec<biscuit::builder::Fact> = self
            .0
            .query(rule.0.clone())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?;

        let facts = js_sys::Array::new();
        for f in v.into_iter().map(Fact) {
            facts.push(&JsValue::from(f));
        }

        Ok(facts)
    }

    /// Executes a query over the authorizer
    #[wasm_bindgen(js_name = queryWithLimits)]
    pub fn query_with_limits(
        &mut self,
        rule: &Rule,
        limits: JsValue,
    ) -> Result<js_sys::Array, JsValue> {
        let limits: RunLimits = serde_wasm_bindgen::from_value(limits)?;
        let v: Vec<biscuit::builder::Fact> = self
            .0
            .query_with_limits(rule.0.clone(), limits.to_rust_limits())
            .map_err(|e| serde_wasm_bindgen::to_value(&e).unwrap())?;

        let facts = js_sys::Array::new();
        for f in v.into_iter().map(Fact) {
            facts.push(&JsValue::from(f));
        }

        Ok(facts)
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.print_world()
    }
}

impl Default for Authorizer {
    fn default() -> Self {
        Self::new()
    }
}
