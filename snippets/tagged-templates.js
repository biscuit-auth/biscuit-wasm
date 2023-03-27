import { Biscuit, Authorizer, Rule } from "./biscuit_bg.js";

function prepareTerm(value) {
  if (value instanceof Date) {
    return { date: value.toISOString() };
  } else if (typeof value.toDatalogParameter === "function") {
    return value.toDatalogParameter();
  } else {
    return value;
  }
}

function tagged(builder) {
  return (strings, ...values) => {
    let code = "";
    for (let i = 0; i < strings.length; i++) {
      code += strings[i];
      if (i < values.length) {
        code += `{_param_${i}}`;
      }
    }

    const termParameters = Object.fromEntries(
      values.map((v, i) => {
        return [`_param_${i}`, prepareTerm(v)];
      })
    );

    const isKeyParam = (v) => {
      return (
        (typeof v === "string" && v.startsWith("ed25519/")) ||
        v.toDatalogParameter
      );
    };

    const keyParameters = Object.fromEntries(
      values
        .map((v, i) => [i, v])
        .filter(([i, v]) => isKeyParam(v))
        .map(([i, v]) => {
          return [`_param_${i}`, prepareTerm(v)];
        })
    );

    builder.addCodeWithParameters(code, termParameters, keyParameters);
    return builder;
  };
}

export function biscuit(strings, ...values) {
  const builder = Biscuit.builder();
  return tagged(builder)(strings, ...values);
}

export function block(strings, ...values) {
  const builder = Biscuit.block_builder();
  return tagged(builder)(strings, ...values);
}

export function authorizer(strings, ...values) {
  const builder = new Authorizer();
  return tagged(builder)(strings, ...values);
}

export function rule(strings, ...values) {
  let code = "";
  for (let i = 0; i < strings.length; i++) {
    code += strings[i];
    if (i < values.length) {
      code += `{_param_${i}}`;
    }
  }

  const params = new Map(
    values.map((v, i) => {
      return [`_param_${i}`, prepareTerm(v)];
    })
  );

  const r = Rule.fromString(code);
  const unboundParams = r.unboundParameters();
  const unboundScopeParams = r.unboundScopeParameters();

  for (let p of unboundParams) {
    r.set(p, params.get(p));
  }

  for (let p of unboundScopeParams) {
    r.setScope(p, params.get(p));
  }

  return r;
}
