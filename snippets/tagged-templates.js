import {Biscuit,Authorizer} from "./biscuit_bg.js";

function prepareTerm(value) {
  if(value instanceof Date) {
    return { "date": value.toISOString()};
  } else if(typeof value.toDatalogParameter === "function") {
    return value.toDatalogParameter();
  } else {
    return value;
  }
}

export function biscuit(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if(i < values.length){
      code += `{_param_${i}}`
    } 
  }

  const termParameters = Object.fromEntries(values.map((v, i) => {
    return [
      `_param_${i}`,
      prepareTerm(v)
    ];
  }));

  const isKeyParam = (v) => {
    return typeof v === "string" && v.startsWith("ed25519/")  || v.toDatalogParameter;
  };

  const keyParameters = Object.fromEntries(
    values.map((v,i) => [i,v])
          .filter(([i,v]) => isKeyParam(v))
          .map(([i,v]) => {
            return [
              `_param_${i}`,
              prepareTerm(v)
            ];
          })
  );

  const builder = Biscuit.builder();
  builder.addCodeWithParameters(code, termParameters, keyParameters);
  return builder;
}

export function block(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if(i < values.length){
      code += `{_param_${i}}`
    } 
  }

  const termParameters = Object.fromEntries(values.map((v, i) => {
    return [
      `_param_${i}`,
      prepareTerm(v)
    ];
  }));

  const isKeyParam = (v) => {
    return typeof v === "string" && v.startsWith("ed25519/")  || v.toDatalogParameter;
  };

  const keyParameters = Object.fromEntries(
    values.map((v,i) => [i,v])
          .filter(([i,v]) => isKeyParam(v))
          .map(([i,v]) => {
            return [
              `_param_${i}`,
              prepareTerm(v)
            ];
          })
  );

  const builder = Biscuit.block_builder();
  builder.addCodeWithParameters(code, termParameters, keyParameters);
  return builder;
}

export function authorizer(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if(i < values.length){
      code += `{_param_${i}}`
    } 
  }

  const termParameters = Object.fromEntries(values.map((v, i) => {
    return [
      `_param_${i}`,
      prepareTerm(v)
    ];
  }));

  const isKeyParam = (v) => {
    return typeof v === "string" && v.startsWith("ed25519/")  || v.toDatalogParameter;
  };

  const keyParameters = Object.fromEntries(
    values.map((v,i) => [i,v])
          .filter(([i,v]) => isKeyParam(v))
          .map(([i,v]) => {
            return [
              `_param_${i}`,
              prepareTerm(v)
            ];
          })
  );

  const builder = new Authorizer();
  builder.addCodeWithParameters(code, termParameters, keyParameters);
  return builder;
}
