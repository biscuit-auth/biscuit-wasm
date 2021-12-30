const {Biscuit, KeyPair} = require('@biscuit-auth/biscuit-wasm');

console.log("a");
console.log("b");

let builder = Biscuit.builder();
console.log(JSON.stringify(builder));
builder.add_authority_fact("user(1234)");

console.log("c");

let root = new KeyPair();
let token = builder.build(root);
console.log(token);

var authorizer = token.authorizer();

authorizer.add_code("allow if user(1234); deny if true;");
var policy = authorizer.authorize();
console.log("policy: "+policy);
