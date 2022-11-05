import  {Biscuit, PrivateKey, KeyPair, Fact} from '@biscuit-auth/biscuit-wasm';
// necessary for esm support, see https://docs.rs/getrandom/latest/getrandom/#nodejs-es-module-support
import { webcrypto } from 'node:crypto'
globalThis.crypto = webcrypto

console.log("a");
console.log("b");

let builder = Biscuit.builder();
console.log(JSON.stringify(builder));

let priv = new KeyPair();

let pk = PrivateKey.from_hex("473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97");
let root = KeyPair.from(pk);

console.log("created the root key");

let token = builder.build(root.private());
console.log("created the token");
console.log(token);

var authorizer = token.authorizer();
console.log("created the authorizer");

let fact = Fact.from_str("user({id})");
console.log("created a fact");

fact.set("id", 1234);
console.log("set a parameter on a fact");

authorizer.add_fact(fact);
console.log("added a fact to the authorizer");

authorizer.add_code("allow if user(1234); deny if true;");
console.log("added code to the authorizer");

var policy = authorizer.authorize();
console.log("policy: "+policy);
