(()=>{"use strict";const{Biscuit:o,KeyPair:e,Fact:l}=require("@biscuit-auth/biscuit-wasm");console.log("a"),console.log("b");let i=o.builder();console.log(JSON.stringify(i));let s=l.from_str("user($id)");console.log("bb"),s.set("id",1234),console.log("c");let t=new e,c=i.build(t.private());console.log(c);var r=c.authorizer();r.add_fact(s),r.add_code("allow if user(1234); deny if true;");var a=r.authorize();console.log("policy: "+a)})();