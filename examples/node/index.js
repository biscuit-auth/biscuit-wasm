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
//let root = new KeyPair();
let root = KeyPair.from(pk);

//builder.add_authority_fact("user(1234)");
let fact = Fact.from_str("user($id)")
console.log("bb")

fact.set("id", 1234)

console.log("c");

let token = builder.build(root.private());
console.log(token);

var authorizer = token.authorizer();

authorizer.add_fact(fact)
authorizer.add_code("allow if user(1234); deny if true;");
var policy = authorizer.authorize();
console.log("policy: "+policy);
