# Litecoin Nucleo applet

A Litecoin P2WPKH applet for NucleoVM: public key generation and signing of
32-byte hashes. This repository includes the JavaScript source, an NJBC v2
build, the API contract, and an independent example of compatible ECDSA signing.
OS, firmware, interpreter, and native binding implementations are not included.

## Quick start

Requires Node.js 24 or newer.

```sh
npm ci
npm run build
npm test
npm run example -- --format js
npm run example -- --format njbc
```

The example creates a synthetic previous transaction, computes a Litecoin
BIP143 SIGHASH_ALL digest, signs it with secp256k1, and independently verifies
it using Node.js OpenSSL. Modifying the transaction invalidates the signature.
The output includes a `tltc1...` testnet address, a DER signature in the witness,
the raw transaction, and its txid. It runs locally with **public test keys**,
without connecting to a wallet or broadcasting a transaction.
Do not send funds to example addresses.

The build produces these files in `dist/`:

- `litecoin-p2wpkh-v2.js`: an exact copy of the existing JavaScript applet.
- `litecoin-p2wpkh-v2.njbc`: NJBC v2 binary.
- `manifest.json`: sizes, SHA256 hashes, exports, namespaces, and code bindings.
- `SHA256SUMS`: checksums of the code artifacts.

[GitHub Actions](https://github.com/tripylon/Litecoin-nucleo-applet/actions/workflows/build.yml)
runs the tests, checks build reproducibility, and uploads these files as the
`litecoin-nucleo-applet` artifact.

## Applet API

| Function | Parameters | Result |
| --- | --- | --- |
| `getPublicKey` | `{keyIndex}` | `{applet, publicKey}` |
| `signHash` | `{keyIndex, hash}` | `{applet, publicKey, signatureDER, hashForSign}` |

`keyIndex` is an integer from 0 through 2^31 - 1. `hash` is exactly 32 bytes
encoded as hex without a `0x` prefix. `publicKey` is a compressed secp256k1
public key, encoded as 33 bytes of hex. `signatureDER` excludes the SIGHASH_ALL
byte: the application appends `01` when assembling the witness.
The `applet` field is `litecoin-p2wpkh-v2`.

The applet uses four runtime primitives:

| Primitive | Purpose |
| --- | --- |
| `appletNonce8()` | Returns the applet-specific nonce; the applet uses its `.hex` field |
| `deriveSecp256k1Key(nonceHex, keyIndex)` | Derives a private key within applet execution |
| `secp256k1PublicKey(keyHex)` | Returns a compressed public key |
| `secp256k1SignHash(hashHex, keyHex)` | Signs a digest after device confirmation |

The contract does not request the wallet secret. The applet returns only a
public key and a signature. The device signs the supplied digest; the
application must validate the recipient, amount, UTXOs, and fee before invoking it.

## Device integration

```js
import {
  appletRequest, parseVM, offlineTransfer, verifyOfflineTransfer
} from './lib/applet.mjs';

const network = 'testnet';
const format = 'njbc'; // or 'js'
const index = 0;

// rpc is your application's existing transport implementing vmRun.
const invoke = request => rpc('vmRun', request);
const key = parseVM(await invoke(appletRequest(index, '', network, format)), network, format);
const plan = offlineTransfer(key.publicKey, network);

// On a real wallet, this call requires signature confirmation.
const signed = parseVM(await invoke(appletRequest(index, plan.hash, network, format)), network, format);
const result = verifyOfflineTransfer(plan, signed);
```

This snippet also uses a synthetic UTXO. A real transfer requires verified
inputs and an application-provided transaction plan. The transport and OS
implementation are outside this repository.

JavaScript requests contain `code`, `namespace`, and a separate
`invoke: {name, params}`. NJBC requests contain `format: 'njbc'` and hex-encoded
`bytecode` instead of `code`. Both public exports are exposed through
`src/njbc-exports.js`, which adapts the JavaScript `applet` object to this
interface. JavaScript requires code-bound protocol 2; NJBC requires NJBC v2 support.

Namespaces:

- Testnet: `org.tripylon.litecoin.p2wpkh.v1/testnet`.
- Mainnet: `org.tripylon.litecoin.p2wpkh.v1/mainnet`.

## Identity and compatibility

The exact bytes of `src/litecoin-p2wpkh-v2.js` are preserved from the applet
currently used by the application. Its SHA256 is pinned in `compatibility.json`;
the build stops if the source changes. `.gitattributes` disables line-ending
conversion for applet sources. Formatting, an added newline, or changes to the
namespace or code change the code binding and derived keys.

**NJBC has a separate binding and different keys and addresses from JavaScript**,
even with equivalent logic. Switching to NJBC does not migrate funds or storage
from the JavaScript applet. Compiler or public export changes can also change
the bytecode, so the compiler is pinned to a commit.

## Test coverage

`tests/fixture.mjs` implements the public contract of the four primitives using
open cryptographic libraries. It uses its own public test derivation rather than
reproducing the OS secret derivation algorithm. Example keys do not match keys
on a real wallet.

Tests cover the API, deterministic example keys, distinct indices and networks,
public-only results, denied confirmation, DER/BIP143 signing, independent
OpenSSL verification, and rejection of modified transactions. NJBC checks cover
compilation, export metadata, and equivalence of the decompiled program.
Tests do not execute NJBC on the device engine or verify OS isolation.
Node's `vm` runs only this repository's trusted code and is not used as a
security sandbox.

## Dependencies and provenance

`vendor/nucleovm` contains only the public JavaScript compiler and opcode table
from [NucleoVM](https://github.com/tripylon/NucleoVM), pinned to commit
`087b5f00cdcfe08950f6955470dd067ed1f5e9b1`. Neither the interpreter nor OS source
is copied or downloaded by the build. The project is licensed under
AGPL-3.0-only; upstream notices are preserved alongside the compiler.
