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
