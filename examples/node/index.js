//import init, {Biscuit} from '@biscuit-auth/biscuit-wasm';
//import pkg from '@biscuit-auth/biscuit-wasm';
//const {Biscuit} = pkg;
const {Biscuit, KeyPair} = require('@biscuit-auth/biscuit-wasm');

console.log("a");
console.log("b");

var builder = Biscuit.builder();
console.log(JSON.stringify(builder));
builder.add_authority_fact("user(1234)");

console.log("c");

var root = new KeyPair();
var token = builder.build(root);
console.log(token);

var authorizer = token.authorizer();

authorizer.add_code("allow if user(1234); deny if true;");
var policy = authorizer.authorize();
console.log("policy: "+policy);
