import {Biscuit,Authorizer} from "./biscuit_bg.js";

export function biscuit(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if(i < values.length){
      code += `{_param_${i}}`
    } 
  }

  const parameters = Object.fromEntries(values.map((v, i) => {
    return [
      `_param_${i}`,
      v.toDatalogParameter ? v.toDatalogParameter() : v
    ];
  }));

  const builder = Biscuit.builder();
  builder.addCodeWithParameters(code, parameters, parameters);
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

  const isKeyParam = (v) => {
    return typeof v === "string" && v.startsWith("ed25519/")  || v.toDatalogParameter;
  };

  const termParameters = Object.fromEntries(values.map((v, i) => {
    return [
      `_param_${i}`,
      v.toDatalogParameter ? v.toDatalogParameter() : v
    ];
  }));

  const keyParameters = Object.fromEntries(
    values.map((v,i) => [i,v])
          .filter(([i,v]) => isKeyParam(v))
          .map(([i,v]) => {
            return [
              `_param_${i}`,
              v.toDatalogParameter ? v.toDatalogParameter() : v
            ];
          })
  );

  const builder = new Authorizer();
  builder.addCodeWithParameters(code, termParameters, keyParameters);
  return builder;
}
