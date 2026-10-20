# Browser example

Serve `index.html` at `/`, `app.mjs` and `session.mjs` under `/static/`, and the
SDK's matched files at `/static/qscs-crypto.js` and `/wasm/qscs-substrate.wasm`.
Serve JavaScript modules as `text/javascript`. Use HTTPS and configure the
origin/verifier as described in the main README. The example expects your
protected `/api/account` endpoint to return JSON.

The example disables concurrent auth actions and protected requests while an
authentication transition is running. It keeps credentials out of storage,
checks the login/logout JSON result and only rotates after confirmed logout.
Status is used to choose the UI; the protected API must still enforce verified
identity and your application's account permissions.

## Signed JSON API deltas

`api-delta-client.mjs` is a standalone reference adapter for GET JSON responses.
Serve it from your application, import `createApiDeltaClient`, and pass exact API
route URLs (without queries) and the same-origin matching WASM URL. Queries remain
part of each baseline key. It does not patch fetch or enable node-side caching.

```js
import {createApiDeltaClient} from '/static/api-delta-client.mjs';
const api = createApiDeltaClient({
  routes: ['https://reports.example.com/api/reports']
});
await qscsCrypto.ready;
await api.ready;
const response = await api.fetch(qscsCrypto,
  'https://reports.example.com/api/reports?range=1h&__qscs_issuer=app.example.com',
  {credentials: 'omit'});
if (!response.ok) throw new Error('Report request was not accepted');
const report = await response.json();
```

Complete login first. Cross-origin use also requires the SDK's exact
`QSCS_FEDERATED_IDENTITY_ORIGINS` allowlist and node issuer/audience rules. See the
[API delta guide](https://spooksystems.io/documentation/delta-api/) for configuration.
Use `Delta=all` for JSON; no private backend cache opt-in is required for browser
delta transfer alone.

Call `api.clear()` on logout, account changes and authorization-scope changes;
abort your in-flight requests and keep authentication transitions serialized.
Keep one representation per identity and URL. Include language, tenant or other
representation choices in the URL when appropriate and validate their permissions
server-side. Do not use this adapter for streams or arbitrary binary payloads.

The adapter keeps up to 32 JSON baselines in memory, at most 2 MiB per entry and
8 MiB in aggregate. It never persists account responses. Each same-identity,
same-URL request is queued, and aborted/cleared requests cannot restore old
baselines. A missing decoder uses full signed requests. A malformed delta causes
one freshly signed full-response retry; errors never replay stale account data.
`ready` resolves after the decoder attempt; `status().ready` reports whether
compression is available. Full signed JSON remains usable when it is false.

This is a transport baseline, not an offline or stale-response cache: every call
contacts the server. Handle API errors and application-level retries separately.
Run `node --test tests/api-delta.test.mjs` to test reconstruction, recovery,
identity/query separation, cancellation and memory bounds with the packaged WASM.
