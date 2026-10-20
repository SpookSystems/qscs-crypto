# qscs-crypto

Browser request signing for applications behind the QSCS identity gate. The SDK
loads its matching WebAssembly module, manages a browser identity and signs
same-origin `fetch()` requests with Ed25519.

## Install

Use both files from the same repository checkout or the
[v20261020 source archive](https://github.com/SpookSystems/qscs-crypto/archive/refs/tags/v20261020.zip):

```
dist/qscs-crypto.js
dist/qscs-substrate.wasm
dist/SHA256SUMS
```

Host the JavaScript at `/static/qscs-crypto.js` and the WASM at
`/wasm/qscs-substrate.wasm`. Serve the WASM as `application/wasm` over HTTPS.
`qscs-crypto.js` is also the loader: no `qscs-substrate.js` is required.

```html
<script src="/static/qscs-crypto.js" defer></script>
<script src="/static/app.js" defer></script>
```

For another WASM location, define `window.QSCS_WASM_URL` in a configuration script
loaded before the SDK. It must be a same-origin URL. Deploy matching files
atomically and use versioned URLs when caching release assets.

## Login, requests and logout

Await `qscsCrypto.ready` before reading the UUID or public key. Both are `null`
until initialization completes. The promise rejects if the browser cannot load
or persist its identity; show a retry action rather than continuing unsigned.

```js
async function login(username, password) {
  await qscsCrypto.ready;
  await qscsCrypto.rotateIdentity();
  const response = await qscsCrypto.signedFetch('/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      username, password,
      client_uuid: qscsCrypto.clientUuidHex(),
      pubkey: qscsCrypto.pubkeyHex()
    })
  });
  const result = await response.json();
  if (!response.ok || result.ok !== true) throw new Error('Sign-in was not accepted');
  return result;
}

async function logout() {
  await qscsCrypto.ready;
  const response = await qscsCrypto.signedFetch('/auth/logout', {method: 'POST', body: ''});
  const result = await response.json();
  if (!response.ok || result.ok !== true) throw new Error('Sign-out was not confirmed');
  await qscsCrypto.rotateIdentity();
}

// After successful login:
const response = await fetch('/api/account');
if (!response.ok) throw new Error('Account request failed');
const account = await response.json();
```

Pause protected requests during login/logout and prevent concurrent auth actions.
Sign out an existing session before changing accounts. Keep the current identity
if logout fails so the signed logout can be retried. Rotation creates and persists
a fresh identity; it does not revoke the previous server binding by itself.

The [browser example](examples/) includes this sequencing. The full
[integration guide](https://spooksystems.io/documentation/gated-identity/) covers
origin configuration and application authorization.

## Application configuration

```ini
[Identity Auth]
IdentityAuthUrl = https://identity.example.com/qscs/verify

[Origins]
app.example.com = 127.0.0.1:8081 Auth=identity Proxy=all
```

QSCS calls the verifier with a JSON object:

```json
{"uuid":"<32 hex>","origin":"app.example.com","credentials":"alice:password"}
```

Split `credentials` at the first colon; usernames must not contain colons.
Validate against your own account store, including account state, and return
HTTP 200 with a flat JSON object:

```json
{"authenticated":true,"subject":"account:42"}
```

`subject` is a stable account identifier, 1–256 characters from
`A-Z a-z 0-9 . _ - : @`. Return `{"authenticated":false}` for a rejected login.
Serve the verifier over HTTPS with a trusted certificate, or loopback HTTP when
it runs on the same machine. Restrict it to your nodes and rate-limit attempts.
It must be reachable without passing through the identity gate it authenticates.
Keep account checks and permissions in the application.

QSCS stores the origin-scoped public-key binding in SpookDB and forwards verified
requests with `X-QSCS-Identity` (browser UUID), `X-QSCS-Authenticated-Subject`
(account identifier) and `X-QSCS-Identity-Issuer` (authenticating host). The node
removes incoming copies of these headers. Only trust them on a backend reachable
through your trusted QSCS path; keep direct public access to that backend closed.
The application should verify the expected issuer, resolve the subject and check
permissions for every protected operation.

## Public API

| API | Meaning |
| --- | --- |
| `ready` | Promise resolving after WASM and persisted identity are ready; rejects on failure |
| `clientUuidHex()` | 32 hex characters, or `null` before readiness |
| `pubkeyHex()` | 64 hex characters, or `null` before readiness |
| `signedFetch(input, init)` | Fetch with request signing; also installed as `window.fetch` |
| `rotateIdentity()` | Persist a new keypair/UUID; queues signing while rotation completes |
| `reset()` | Clear the local identity and reload; does not revoke a server binding |

`/auth/status` is a same-origin UUID status lookup, not an authorization proof.
Await `ready` first if you need the persisted identity's status. Login and logout
can return HTTP 200 with `ok:false`; check the JSON result.

## JSON API delta transport

The [API delta example](examples/README.md#signed-json-api-deltas) adds explicit
JSON reconstruction around the signer for allowlisted GET routes, including
federated APIs. Identity signing alone does not negotiate response deltas.

## Signed request format

Sign the exact concatenation below, without a trailing newline:

```
METHOD + LF + HOST + LF + URI + LF + BODY + LF + TS_MS + LF + NONCE_HEX
```

- `METHOD`: uppercase HTTP method.
- `HOST`: destination hostname without its port; preserve the public hostname through your proxy.
- `URI`: transmitted path and query string, without decoding or rearranging.
- `BODY`: transmitted raw bytes, empty when absent; do not hash or reserialize them.
- `TS_MS`: decimal Unix milliseconds.
- `NONCE_HEX`: 16 fresh random bytes encoded as 32 lowercase hex characters.

Send `X-QSCS-Client-Uuid`, `X-QSCS-Ts`, `X-QSCS-Nonce` and `X-QSCS-Sig`.
The signature is standard base64 of 64 Ed25519 signature bytes (88 characters
including padding). The gate checks timestamps within ±60 seconds and rejects
nonce reuse. Keep node clocks synchronized.

Strings, JSON strings, `URLSearchParams`, `ArrayBuffer`, typed arrays and existing
`Request` bodies are supported. Convert a `Blob` to bytes before signing.
Direct `FormData` and streaming bodies are not supported because their final
wire representation must be known before signing. Preserve any required content
type when constructing a `Request` or byte body.

## Federated requests

Cross-origin requests are untouched unless explicitly allowed before SDK loading:

```js
window.QSCS_FEDERATED_IDENTITY_ORIGINS = ['https://reports.example.com'];
```

Only exact HTTPS origins are accepted. Allowed requests sign the receiving
hostname and omit its cookies. Configure issuer/audience trust on the nodes and
CORS at the recipient, including the four signature headers. Browser configuration
alone does not establish federation. Only include origins you control and trust.

## Browser and deployment considerations

Use HTTPS, WebAssembly, Web Crypto and IndexedDB. Your CSP must permit the SDK,
its WASM fetch and WebAssembly compilation (typically `script-src 'self'
'wasm-unsafe-eval'` and `connect-src 'self'`, plus explicit federation recipients).

The signer wraps the persisted key blob using a non-extractable Web Crypto
AES-GCM key. Plaintext key material passes between WASM and JavaScript during
loading and wrapping. Protect the page against injected scripts; WASM is not an
isolation boundary against code running in the same page.

The SDK wraps `window.fetch`; it does not sign native form submissions, XHR,
resource tags or full-page navigation. Keep the login shell and bootstrap assets
public, and use signed fetches for protected APIs. QSCS has public bootstrap and
static-asset exemptions; do not place private data in those paths. Automatic
browser navigation and delta reconstruction are separate from identity signing.

Logout removes the serving node's origin binding and propagates revocation to
peers. Allow for propagation across the cluster and federated recipients; clearing
browser storage alone is not server-side logout.

## Tests

Run `node --test tests/sdk.test.mjs` with Node.js 22 or later. Tests use the packaged
WASM and verify its signatures independently with Web Crypto. The Core source
repository's `tests/run-custom-identity-integration.py` runs the real listener
against this SDK, a local credential verifier and a local application backend.

## Licence

MIT. See [LICENSE](LICENSE).
