import  {Biscuit, PrivateKey, KeyPair, Fact, Rule, biscuit, authorizer, block, rule} from '@biscuit-auth/biscuit-wasm';
// necessary for esm support, see https://docs.rs/getrandom/latest/getrandom/#nodejs-es-module-support
import { webcrypto } from 'node:crypto'

// this is not required anymore with node19+
if(parseInt(process.version.match(/v(\d+)\.(\d+)\.(\d+)/)[1], 10) <= 18) {
  globalThis.crypto = webcrypto
}

let keypair = new KeyPair();

let pk = PrivateKey.fromString("473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97");
let root = KeyPair.fromPrivateKey(pk);

console.log("created the root key");

let id = 1234;
let biscuitBuilder = biscuit`user(${id});`;

for (let right of ["read", "write"]) {
  biscuitBuilder.merge(block`right(${right})`);
}

let token =
  biscuitBuilder
    .build(root.getPrivateKey()) // biscuit token
    .appendBlock(block`check if user($u)`); // attenuated biscuit token
console.log(token.toString());
let serializedToken = token.toBase64();
console.log("created the token and signed it with the private key");
console.log(serializedToken);

let parsedToken = Biscuit.fromBase64(serializedToken, root.getPublicKey());
console.log("Parsed the token and verified its signatures with the public key");

let auth = authorizer`allow if user(${id})`;
auth.addToken(parsedToken);

let policy = auth.authorize();
console.log("Authorized the token with the provided rules");
console.log("matched policy: "+ policy);

let otherKeyPair = new KeyPair();
let r =  rule`u($id) <- user($id), $id == ${id} trusting authority, ${otherKeyPair.getPublicKey()}`;
console.log(r.toString());
let facts = auth.query(r);
console.log("Queried the token (and the authorization context) and got the following results");

for(let f of facts) {
  console.log(f.toString());
}
