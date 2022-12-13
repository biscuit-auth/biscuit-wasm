import  {Biscuit, PrivateKey, KeyPair, Fact} from '@biscuit-auth/biscuit-wasm';
// necessary for esm support, see https://docs.rs/getrandom/latest/getrandom/#nodejs-es-module-support
import { webcrypto } from 'node:crypto'
globalThis.crypto = webcrypto

let builder = Biscuit.builder();
console.log(JSON.stringify(builder));

let priv = new KeyPair();

let pk = PrivateKey.fromString("473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97");
let root = KeyPair.fromPrivateKey(pk);

console.log("created the root key");

let token = builder.build(root.getPrivateKey());
console.log("created the token");
console.log(token);

var authorizer = token.getAuthorizer();
console.log("created the authorizer");

let fact = Fact.fromString("user({id})");
console.log("created a fact");

fact.set("id", 1234);
console.log("set a parameter on a fact");

authorizer.addFact(fact);
console.log("added a fact to the authorizer");

authorizer.addCode("allow if user(1234); deny if true;");
console.log("added code to the authorizer");

var policy = authorizer.authorize();
console.log("policy: "+policy);
