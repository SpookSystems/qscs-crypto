# qscs-crypto

Browser-side request signer for sites fronted by a QSCS substrate node with
an `auth=identity` origin. Drop these two files onto your web root, include
the script tag before your application JS, and every same-origin `fetch()`
your app makes will be signed transparently with an ed25519 keypair held in
the user's IndexedDB.

This is the same client shim used in production by `spook.systems` and
`spooksystems.net`.

## Contents

```
dist/
  qscs-crypto.js       ~12 KB, plain ES5, no build step needed
```

The matching `qscs-substrate.wasm` binary (~16 KB) ships **as a release
asset** on each tagged release rather than inside the repo, so the git
history stays binary-free. Grab it from:

https://github.com/SpookSystems/qscs-crypto/releases/latest

(or pin to a specific tag, e.g.
`https://github.com/SpookSystems/qscs-crypto/releases/download/v20260513c/qscs-substrate.wasm`).

The `.js` and the `.wasm` are versioned together — always download the
`.wasm` that ships with the same release tag as the `.js` you're using.

## Install

Download `dist/qscs-crypto.js` from this repo and `qscs-substrate.wasm`
from the matching release, then copy them to your web root so they are
served from:

```
https://<your-host>/js/qscs-crypto.js
https://<your-host>/wasm/qscs-substrate.wasm
```

The script defaults `WASM_URL` to `/wasm/qscs-substrate.wasm`. To host the
WASM at a different path, set `window.QSCS_WASM_URL` **before** the
`qscs-crypto.js` script tag:

```html
<script>window.QSCS_WASM_URL = '/assets/qscs/qscs-substrate.wasm';</script>
<script src="/js/qscs-crypto.js?v=YOUR-CACHE-BUSTER"></script>
<script src="/js/your-app.js?v=…"></script>
```

That's it. `qscs-crypto.js` installs a monkey-patched `window.fetch` and
exposes a small public API on `window.qscsCrypto`.

## What it does

1. On first load, opens an IndexedDB database `qscs-identity` and either
   loads the existing wrap key (non-extractable AES-GCM, generated via
   `crypto.subtle.generateKey`) or generates a new one and stores it.
2. Loads `/wasm/qscs-substrate.wasm` via `WebAssembly.instantiateStreaming`.
3. Either decrypts the existing wrapped ed25519 keypair blob out of
   IndexedDB and loads it into the WASM module, or asks the module to
   generate a new keypair and persists the encrypted blob.
4. Replaces `window.fetch` with `signedFetch`, which for every same-origin
   request appends four signing headers:

   ```
   X-QSCS-Client-Uuid   16-byte hex client UUID (= hash of pubkey)
   X-QSCS-Ts            unix-ms timestamp
   X-QSCS-Nonce         16-byte hex random nonce
   X-QSCS-Sig           base64 ed25519 signature over
                          METHOD\nPATH\nTS\nNONCE\nSHA-256(body)
   ```

5. Cross-origin requests bypass signing untouched.

## Bootstrap order and the "ready" promise

The WASM compile + IndexedDB open is asynchronous. Any `fetch()` called
before the bootstrap finishes is queued behind a `readyPromise` and signed
once the module is up. **However**, if your application code reads
`window.qscsCrypto.clientUuidHex()` or `pubkeyHex()` directly (for example
to put them in a JSON body), those return `null` until ready. Always await
`qscsCrypto.ready` before reading the cached identity values:

```js
var ready = (window.qscsCrypto && window.qscsCrypto.ready) || Promise.resolve();
ready.then(function () {
  return fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: u,
      password: p,
      client_uuid: window.qscsCrypto.clientUuidHex(),
      pubkey:      window.qscsCrypto.pubkeyHex()
    })
  });
});
```

Mobile devices (slow WASM streaming compile, IndexedDB transaction latency)
will lose this race more often than desktops. We learned that the hard way.

## Public API

```js
window.qscsCrypto = {
  ready:          Promise<void>,            // resolves when WASM + IDB are up
  clientUuidHex:  () => string | null,      // 32 hex chars, null until ready
  pubkeyHex:      () => string | null,      // 64 hex chars, null until ready
  signedFetch:    (input, init) => Promise<Response>
};
```

`window.fetch` is the same as `window.qscsCrypto.signedFetch` after
bootstrap. The original `fetch` is captured before the monkey-patch and used
for cross-origin requests and for any post-failure fallback.

## When the gate carves things out for you

The QSCS substrate's identity gate exempts a fixed set of paths from
signature enforcement so a fresh browser can bootstrap before it has an
identity:

- `GET /` — your SPA shell
- `/auth/*` — `status`, `login`, `logout`, `register`, password-reset
- `POST /?api=register|forgot-password|verify-email|reset-password|resend-verification`
- `/.well-known/*` — ACME, etc.
- Static assets and anything under `[Static Pages]`

Everything else requires a valid ed25519-signed request. If you see `401
identity required` from the substrate, you are either:

1. Hitting an endpoint that should be in the carve-out (open an issue), or
2. Calling `fetch` from a context where `window.qscsCrypto` isn't installed
   (a worker, an iframe with a different origin, a bookmarklet, etc.), or
3. Constructing the body before `qscsCrypto.ready` resolved, so the body
   carries empty `client_uuid` / `pubkey` and the server rejects it.

## Non-browser clients

`qscs-crypto.js` is the browser binding. If you want to sign requests from
a mobile app, a CLI, or a server-to-server integration, re-implement the
wire format above against any ed25519 library. The signed string is exactly:

```
canonical = METHOD + "\n" + PATH + "\n" + TS + "\n" + NONCE + "\n" + SHA-256(body)
```

`PATH` is the request-line path (`/foo/bar?x=1`), `TS` is integer
milliseconds since epoch, `NONCE` is 16 random bytes hex-encoded, `body` is
the request body bytes (empty string if there is none). Sign `canonical`
with your ed25519 private key, base64 the 64-byte signature, and send the
four headers.

## Browser support

- Chrome / Edge / Brave / Opera / Samsung Internet — fine.
- Firefox — fine.
- Safari (desktop + iOS) — fine, but the WASM compile + IDB transaction
  latency is meaningfully higher than other browsers. Always await
  `qscsCrypto.ready` before any code that reads the cached identity.
- Private / Incognito on iOS Safari — IndexedDB may be unavailable. The
  shim falls through to unsigned `origFetch`, which the server will then
  reject at the gate. Tell your users not to use private browsing on
  identity-gated hosts, or detect the failure and surface a clear error.

## Versioning

The on-the-wire format is stable. The script and WASM blob are versioned
together; treat them as a pair when you upgrade.

| version  | notes                                                |
|----------|------------------------------------------------------|
| 3b6f0ad | current production build                            |

## Licence

MIT. See [LICENSE](LICENSE).
