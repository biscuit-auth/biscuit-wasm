# Biscuit-Wasm

This library wraps the [Rust implementation](https://github.com/biscuit-auth) of [Biscuit tokens](https://www.biscuitsec.org) in WebAssembly, for usage in NodeJS and browsers.

It provides an EcmaScript module, along with TypeScript type definitions.

## Usage

Add this dependency to your `package.json`:

```json
{
    "dependencies": {
        "@biscuit-auth/biscuit-wasm": "0.4.0-alpha1"
    }
}
```

### Node

*see the example code in examples/node*

Due to some wasm side dependencies, to work in Node, biscuit-wasm requires that this be added to the application:

```javascript
import { webcrypto } from 'node:crypto'
globalThis.crypto = webcrypto
```

The `node` executable must also be started with the [`--experimental-wasm-modules` flag](https://nodejs.org/api/esm.html#wasm-modules).

### In browser

*see the example code in examples/frontend*

Importing a WebAssembly library with a bundler can take a bit of configuration. We have a working example with
Webpack, and would welcome example configuration for other bundlers:

```javascript
const path = require('path');

module.exports = {
  entry: './index.js',
  output: {
    filename: 'index.js',
    path: path.resolve(__dirname, 'dist'),
  },
  experiments: {
    asyncWebAssembly: true
  }
};
```

## License

Licensed under the Apache 2.0 License.

Copyright 2021 Geoffroy Couprie
