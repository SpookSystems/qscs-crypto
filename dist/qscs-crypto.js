/*
 * qscs-crypto.js — browser-side WASM identity bootstrap and signed-fetch
 * wrapper for applications behind the QSCS identity gate.
 *
 * Responsibilities:
 *   1. Load /wasm/qscs-substrate.wasm.
 *   2. Bootstrap a per-origin ed25519 identity:
 *        - Try to load encrypted blob from IndexedDB and unwrap with a
 *          non-extractable AES-GCM CryptoKey also stored in IndexedDB.
 *        - Otherwise generate a fresh identity inside WASM and persist
 *          the encrypted blob.
 *   3. Monkey-patch window.fetch so every request is signed with
 *      ed25519 and carries:
 *          X-QSCS-Client-Uuid : 32 hex
 *          X-QSCS-Ts          : decimal unix milliseconds
 *          X-QSCS-Nonce       : 32 hex
 *          X-QSCS-Sig         : base64 of 64-byte signature
 *
 * Identity blobs are wrapped with WebCrypto before IndexedDB storage. The JS
 * harness handles the unwrapped blob transiently; this is not an XSS sandbox.
 */
(function () {
  'use strict';

  if (window.qscsCrypto) return;

  var DB_NAME = 'qscs-identity';
  var STORE = 'kv';
  var WRAP_ALG = { name: 'AES-GCM', length: 256 };
  var WRAP_IV_BYTES = 12;
  var WASM_URL = window.QSCS_WASM_URL || '/wasm/qscs-substrate.wasm';
  var wasmLocation = new URL(WASM_URL, window.location.href);
  if (wasmLocation.origin !== window.location.origin) throw new Error('QSCS_WASM_URL must be same-origin');
  WASM_URL = wasmLocation.href;
  var READY_PROMISE_TIMEOUT_MS = 10000;
  var INIT_FETCH_WAIT_MS = 4000;
  // Federated requests are opt-in. Configure exact HTTPS origins before this
  // script loads, for example:
  // window.QSCS_FEDERATED_IDENTITY_ORIGINS = ['https://monitor.example.com'];
  // Invalid values are ignored so a broad or malformed setting can never
  // cause credentials to be sent to an arbitrary cross-origin destination.
  function configuredFederatedOrigins() {
    var configured;
    try { configured = window.QSCS_FEDERATED_IDENTITY_ORIGINS; } catch (e) {}
    if (!Array.isArray(configured)) return [];
    var origins = [];
    for (var i = 0; i < configured.length; i++) {
      if (typeof configured[i] !== 'string') continue;
      try {
        var parsed = new URL(configured[i]);
        if (parsed.protocol !== 'https:' || parsed.username || parsed.password ||
            parsed.pathname !== '/' || parsed.search || parsed.hash) continue;
        if (origins.indexOf(parsed.origin) === -1) origins.push(parsed.origin);
      } catch (e) {}
    }
    return Object.freeze(origins);
  }
  var FEDERATED_IDENTITY_ORIGINS = configuredFederatedOrigins();
  var managedFederation = false, managedRecipients = [], federationChecked = 0, federationLoading = null;
  function discoverFederation() {
    if (federationLoading) return federationLoading;
    federationChecked = Date.now();
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, 3000);
    federationLoading = origFetch('/auth/federation', {credentials:'same-origin',cache:'no-store',redirect:'error',signal:controller.signal})
      .then(function (response) { if (!response.ok) throw new Error('Federation unavailable'); return response.json(); })
      .then(function (policy) {
        if (!policy || typeof policy.managed !== 'boolean' || !Array.isArray(policy.recipients)) throw new Error('Invalid federation policy');
        // Once managed, an unavailable or expired policy never falls back to
        // the application's older static allowlist.
        if (policy.managed) managedFederation = true;
        managedRecipients = policy.managed ? policy.recipients.filter(function (rule) {
          if (!rule || typeof rule.origin !== 'string' || !Array.isArray(rule.paths) || rule.paths.length > 16) return false;
          try { var u = new URL(rule.origin); if (u.protocol !== 'https:' || u.origin !== rule.origin || u.username || u.password) return false; } catch(e) { return false; }
          return rule.paths.every(function (p) { return typeof p === 'string' && /^\/[A-Za-z0-9/_.-]*$/.test(p) && p.indexOf('..') === -1 && p.indexOf('//') === -1; });
        }) : [];
      }).catch(function () { managedRecipients = []; })
      .finally(function () { clearTimeout(timer); federationLoading = null; });
    return federationLoading;
  }


  // Origin host for the canonical message.  Must match what the server
  // uses from the Host header, with the port removed.
  function canonicalHost() {
    return new URL(window.location.href).hostname;
  }

  /* ── IndexedDB helpers ──────────────────────────── */

  function openDb() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = function () {
        req.result.createObjectStore(STORE);
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror   = function () { reject(req.error); };
    });
  }

  function dbGet(key) {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE, 'readonly');
        var rq = tx.objectStore(STORE).get(key);
        rq.onsuccess = function () { resolve(rq.result); };
        rq.onerror   = function () { reject(rq.error); };
      });
    });
  }

  function dbPut(key, value) {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).put(value, key);
        tx.oncomplete = function () { resolve(); };
        tx.onerror    = function () { reject(tx.error); };
      });
    });
  }

  function dbDelete(key) {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).delete(key);
        tx.oncomplete = function () { resolve(); };
        tx.onerror    = function () { reject(tx.error); };
      });
    });
  }

  // Wipe persisted identity material.  Used when the stored blob can no
  // longer be decrypted by the stored wrap key (e.g. iOS Safari evicts
  // one of the two records independently, or the substrate format has
  // changed across deploys).  After wipe, the next bootstrap regenerates
  // a fresh identity and the user re-logs in.
  function wipeIdentity() {
    return Promise.all([
      dbDelete('blob').catch(function () {}),
      dbDelete('wrapKey').catch(function () {})
    ]);
  }

  /* ── Wrap key bootstrap ─────────────────────────── */

  function loadOrCreateWrapKey() {
    return dbGet('wrapKey').then(function (existing) {
      if (existing) return existing;
      return crypto.subtle.generateKey(WRAP_ALG, false /* non-extractable */,
                                       ['encrypt', 'decrypt'])
        .then(function (k) {
          return dbPut('wrapKey', k).then(function () { return k; });
        });
    });
  }

  function encryptBlob(wrapKey, plaintext) {
    var iv = crypto.getRandomValues(new Uint8Array(WRAP_IV_BYTES));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, wrapKey, plaintext)
      .then(function (ct) {
        var out = new Uint8Array(WRAP_IV_BYTES + ct.byteLength);
        out.set(iv, 0);
        out.set(new Uint8Array(ct), WRAP_IV_BYTES);
        return out;
      });
  }

  function decryptBlob(wrapKey, wrapped) {
    var iv = wrapped.slice(0, WRAP_IV_BYTES);
    var ct = wrapped.slice(WRAP_IV_BYTES);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, wrapKey, ct)
      .then(function (pt) { return new Uint8Array(pt); });
  }

  /* ── WASM loader ────────────────────────────────── */

  function loadWasm() {
    var memoryRef = { mem: null, exports: null };

    function memU8() {
      return new Uint8Array(memoryRef.exports.memory.buffer);
    }

    var imports = {
      env: {
        js_random: function (ptr, len) {
          var u8 = memU8();
          crypto.getRandomValues(u8.subarray(ptr, ptr + len));
        },
        js_now_ms_lo: function () {
          return Date.now() & 0xffffffff;
        },
        js_now_ms_hi: function () {
          return Math.floor(Date.now() / 0x100000000) & 0xffffffff;
        },
        js_log: function (ptr, len) {
          try {
            var u8 = memU8();
            console.log('[qscs]', new TextDecoder().decode(u8.subarray(ptr, ptr + len)));
          } catch (e) {}
        },
        // substrate.c expects js_schedule; provide a no-op since we are
        // only using the crypto half here.
        js_schedule: function () {},
        // strlen is left undefined by the linker (--allow-undefined) and
        // appears as an import.  Provide a minimal implementation.
        strlen: function (ptr) {
          var u8 = memU8();
          var i = ptr;
          while (u8[i] !== 0) i++;
          return i - ptr;
        }
      }
    };

    return WebAssembly.instantiateStreaming(origFetch(WASM_URL), imports)
      .then(function (r) {
        memoryRef.exports = r.instance.exports;
        // The binary ships with only 2 initial pages (128KB), almost
        // entirely consumed by data + stack — leaving barely any heap.
        // Grow by 8 pages (512KB) so the bump allocator has ~500KB of
        // free space, enough for ~1,000+ signRequest calls per session.
        try { memoryRef.exports.memory.grow(8); } catch (e) {}
        return memoryRef.exports;
      });
  }

  /* ── Identity bootstrap ─────────────────────────── */

  function bootstrapIdentity(exports, wrapKey) {
    var u8 = function () { return new Uint8Array(exports.memory.buffer); };
    var blobBytes = 1 + 16 + 32 + 64; // QSCS_BLOB_BYTES = 113

    return dbGet('blob').then(function (wrapped) {
      if (wrapped) {
        return decryptBlob(wrapKey, wrapped).then(function (plain) {
          var ptr = exports.qscs_alloc(plain.length);
          u8().set(plain, ptr);
          var rc = exports.qscs_identity_load_blob(ptr, plain.length);
          if (rc !== 0) {
            // Persisted blob unusable; regenerate and overwrite.
            console.warn('[qscs] stored blob rejected by WASM (rc=' + rc + '), regenerating');
            return generateAndPersist(exports, wrapKey);
          }
          return null;
        }, function (err) {
          // Decrypt failure — wrap key no longer matches the stored blob.
          // This happens on iOS Safari when one of the two IndexedDB rows
          // is evicted independently, after a format change, or after
          // any storage-partition reshuffle.  Wipe both records so the
          // outer init re-runs from scratch.
          console.warn('[qscs] stored blob decrypt failed, wiping and regenerating:', err);
          return wipeIdentity().then(function () {
            // Regenerate inline with the *current* wrapKey we have in hand.
            // (loadOrCreateWrapKey will pick up the fresh one on next page load.)
            return generateAndPersist(exports, wrapKey);
          });
        });
      }
      return generateAndPersist(exports, wrapKey);
    });
  }

  function generateAndPersist(exports, wrapKey) {
    var rc = exports.qscs_identity_generate();
    if (rc !== 0) throw new Error('qscs_identity_generate failed: ' + rc);
    var blobBytes = 1 + 16 + 32 + 64;
    var ptr = exports.qscs_alloc(blobBytes);
    var written = exports.qscs_identity_export_blob(ptr, blobBytes);
    if (written !== blobBytes) {
      throw new Error('qscs_identity_export_blob short write: ' + written);
    }
    var plain = new Uint8Array(exports.memory.buffer, ptr, blobBytes).slice();
    return encryptBlob(wrapKey, plain).then(function (wrapped) {
      return dbPut('blob', wrapped);
    });
  }

  /* ── Public API ─────────────────────────────────── */

  var exportsRef = null;
  var clientUuidHexCached = null;
  var pubkeyHexCached = null;
  var encoder = new TextEncoder();

  function readHex(fn, len) {
    var ptr = exportsRef.qscs_alloc(len + 1);
    var n = fn(ptr, len + 1);
    if (n <= 0) return '';
    var u8 = new Uint8Array(exportsRef.memory.buffer, ptr, n);
    return new TextDecoder().decode(u8);
  }

  function refreshCache() {
    clientUuidHexCached = readHex(exportsRef.qscs_get_client_uuid_hex, 32);
    pubkeyHexCached     = readHex(exportsRef.qscs_get_pubkey_hex, 64);
  }

  // True iff the WASM substrate has a loaded identity and we have a
  // non-empty cached UUID hex.  Used as a precondition by signedFetch
  // to decide whether to self-heal before sending.
  function identityReady() {
    return !!clientUuidHexCached && clientUuidHexCached.length === 32;
  }

  function bodyToBytes(body) {
    if (body == null) return new Uint8Array(0);
    if (typeof body === 'string') return encoder.encode(body);
    if (body instanceof URLSearchParams) return encoder.encode(body.toString());
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    throw new TypeError('Unsupported signed body; use JSON/text, URLSearchParams or bytes');
  }

  function signRequest(method, uri, body, hostOverride) {
    if (!identityReady()) {
      throw new Error('qscs identity not ready (empty client uuid)');
    }
    var host = hostOverride || canonicalHost();
    var bodyBytes = bodyToBytes(body);

    var methodU8 = encoder.encode(method);
    var hostU8   = encoder.encode(host);
    var uriU8    = encoder.encode(uri);
    var bodyU8   = bodyBytes;

    // Allocate scratch buffers in WASM linear memory for inputs + outputs.
    var totalIn = methodU8.length + hostU8.length + uriU8.length + bodyU8.length;
    var allocSize = totalIn + 33 + 89;
    var basePtr = exportsRef.qscs_alloc(allocSize);
    var mU8 = new Uint8Array(exportsRef.memory.buffer);
    // Guard against allocator exhaustion (bump allocator never frees;
    // fails with 0 or a sentinel past memory end after many calls).
    if (!basePtr || (basePtr + allocSize) > mU8.byteLength) {
      throw new Error('qscs_alloc: OOM (ptr=' + basePtr + ', need=' + allocSize + ', mem=' + mU8.byteLength + ')');
    }

    var mPtr = basePtr;
    var hPtr = mPtr + methodU8.length;
    var uPtr = hPtr + hostU8.length;
    var bPtr = uPtr + uriU8.length;
    var nPtr = bPtr + bodyU8.length;
    var sPtr = nPtr + 33;

    mU8.set(methodU8, mPtr);
    mU8.set(hostU8,   hPtr);
    mU8.set(uriU8,    uPtr);
    mU8.set(bodyU8,   bPtr);

    var ts = Date.now();
    var tsLo = ts & 0xffffffff;
    var tsHi = Math.floor(ts / 0x100000000) & 0xffffffff;

    var rc = exportsRef.qscs_sign_request(
      mPtr, methodU8.length,
      hPtr, hostU8.length,
      uPtr, uriU8.length,
      bPtr, bodyU8.length,
      tsLo, tsHi,
      nPtr,
      sPtr
    );
    // qscs_sign_request returns the base64 length (88) on success, negative on error.
    if (rc < 0) throw new Error('qscs_sign_request failed: ' + rc);

    var mem = new Uint8Array(exportsRef.memory.buffer);
    var nonceHex = new TextDecoder().decode(mem.subarray(nPtr, nPtr + 32));
    var sigB64   = new TextDecoder().decode(mem.subarray(sPtr, sPtr + 88));

    return {
      'X-QSCS-Client-Uuid': clientUuidHexCached,
      'X-QSCS-Ts': String(ts),
      'X-QSCS-Nonce': nonceHex,
      'X-QSCS-Sig': sigB64
    };
  }

  /* ── fetch monkey-patch ─────────────────────────── */

  var origFetch = window.fetch.bind(window);

  // One-shot self-heal guard: once per page load we are willing to wipe
  // IndexedDB and re-bootstrap.  Without this guard, a persistent fault
  // could cause an infinite re-init loop on every fetch.
  var selfHealUsed = false;
  var selfHealPromise = null;
  var rotationPromise = null;

  // Auth transitions get a new UUID/keypair. Never reuse a revoked UUID while
  // peer replication and federated binding caches still contain its history.
  // Commit encrypted storage before switching the live signer; failure keeps
  // the old identity available for a retry of server-side logout.
  function rotateIdentity() {
    if (rotationPromise) return rotationPromise;
    rotationPromise = initPromise.then(function () { return selfHealPromise; })
      .then(function () { return Promise.all([loadWasm(), loadOrCreateWrapKey()]); })
      .then(function (results) {
        return generateAndPersist(results[0], results[1]).then(function () {
          exportsRef = results[0];
          refreshCache();
          selfHealUsed = false;
          selfHealPromise = null;
          if (!identityReady()) throw new Error('identity rotation failed');
        });
      }).finally(function () { rotationPromise = null; });
    return rotationPromise;
  }

  function selfHeal(reason) {
    if (selfHealPromise) return selfHealPromise;
    if (selfHealUsed) {
      return Promise.reject(new Error('qscs self-heal already used'));
    }
    selfHealUsed = true;
    console.warn('[qscs] self-healing identity:', reason);
    // Reload the WASM module so we get a fresh linear-memory allocator.
    // The existing identity blob stays in IndexedDB — no wipeIdentity().
    // bootstrapIdentity will re-load it; if it fails it regenerates.
    selfHealPromise = Promise.all([loadWasm(), loadOrCreateWrapKey()])
      .then(function (results) {
        exportsRef = results[0];
        return bootstrapIdentity(exportsRef, results[1]);
      })
      .then(function () {
        refreshCache();
        if (!identityReady()) {
          throw new Error('self-heal did not produce a usable identity');
        }
      });
    return selfHealPromise;
  }

  function signedFetch(input, init) {
    if (rotationPromise) return rotationPromise.then(function () { return signedFetch(input, init); });
    init = init || {};
    var url, method, body;
    if (input instanceof URL) input = input.href;
    if (typeof input === 'string') {
      url = input;
      method = (init.method || 'GET').toUpperCase();
      body = init.body;
    } else {
      url = input.url;
      method = (init.method || input.method || 'GET').toUpperCase();
      body = init.body;
    }

    // Same-origin requests are signed as usual. A tightly allow-listed
    // recipient may receive a federated request signed over *its* Host;
    // every other cross-origin request (CDN, analytics, third parties) is
    // deliberately left untouched.
    var sameOrigin = true;
    var federatedOrigin = false;
    var targetHost = canonicalHost();
    try {
      var parsed = new URL(url, window.location.href);
      sameOrigin = (parsed.origin === window.location.origin);
      if (!sameOrigin && (federationLoading || Date.now() - federationChecked > 20000)) {
        return discoverFederation().then(function () { return signedFetch(input, init); });
      }
      federatedOrigin = !sameOrigin && (managedFederation
        ? method === 'GET' && managedRecipients.some(function (r) { return r.origin === parsed.origin && r.paths.some(function(p) { return parsed.pathname.indexOf(p) === 0; }); })
        : FEDERATED_IDENTITY_ORIGINS.indexOf(parsed.origin) !== -1);
      targetHost = parsed.hostname;
      url = parsed.pathname + parsed.search;
    } catch (e) {}

    if (!sameOrigin && !federatedOrigin) {
      return origFetch(input, init);
    }

    // Never route substrate bootstrap through signedFetch; that can
    // deadlock init if window.fetch is already monkey-patched.
    if (parsed && parsed.origin === wasmLocation.origin && parsed.pathname === wasmLocation.pathname) {
      return origFetch(input, init);
    }

    // /auth/status must never block on crypto bootstrap, but it does need
    // X-QSCS-Client-Uuid so the backend can resolve the current identity.
    if (sameOrigin && (url === '/auth/status' || url.startsWith('/auth/status?'))) {
      var statusHeaders = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined) || {});
      if (clientUuidHexCached) statusHeaders.set('X-QSCS-Client-Uuid', clientUuidHexCached);
      return origFetch(input, Object.assign({}, init, { headers: statusHeaders }));
    }

    // Reconstruct Request bodies before signing; sign exactly the transmitted bytes.
    if (typeof input !== 'string' && init.body === undefined && !['GET','HEAD'].includes(method)) {
      return input.clone().arrayBuffer().then(function (bytes) {
        return signedFetch(input, Object.assign({}, init, {body: new Uint8Array(bytes)}));
      });
    }
    try { bodyToBytes(body); } catch (error) { return Promise.reject(error); }

    var doSigned = function () {
      var headers = signRequest(method, url, body, targetHost);
      var mergedHeaders = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined) || {});
      Object.keys(headers).forEach(function (k) { mergedHeaders.set(k, headers[k]); });
      var newInit = Object.assign({}, init, { headers: mergedHeaders });
      // Federated identity is header/signature based. Do not send or depend on
      // cookies belonging to the receiving origin.
      if (federatedOrigin) newInit.credentials = 'omit';
      return origFetch(input, newInit);
    };

    // Reinitialise the signer once if its scratch memory is exhausted.
    // A signed request is never retried as an unsigned request.
    var attempt = function () {
      try { return doSigned(); }
      catch (error) {
        if (selfHealUsed) return Promise.reject(error);
        return selfHeal('sign failed: ' + (error && error.message)).then(doSigned);
      }
    };

    if (!exportsRef || !identityReady()) {
      // Do not hang indefinitely behind init. If bootstrap is wedged on a
      // device/browser, reject so the app can render error states instead
      // of freezing forever.
      return Promise.race([
        initPromise.then(function () { return 'ready'; }, function () { return 'failed'; }),
        new Promise(function (resolve) {
          setTimeout(function () { resolve('timeout'); }, INIT_FETCH_WAIT_MS);
        })
      ]).then(function (state) {
        if (state === 'ready' && exportsRef && identityReady()) return attempt();
        throw new Error('qscs_identity_not_ready');
      });
    }
    return attempt();
  }

  /* ── Init ───────────────────────────────────────── */

  // Manual reset hatch: visiting any application URL with
  // `?qscs-reset=1` wipes the IndexedDB identity and reloads.  Lets a
  // user on a phone (no dev tools) recover from a wedged identity
  // without having to clear site data through Safari settings.
  var resetRequested = false;
  try {
    var sp = new URLSearchParams(window.location.search);
    resetRequested = sp.get('qscs-reset') === '1';
  } catch (e) {}

  var preInit = resetRequested
    ? wipeIdentity().then(function () {
        // Strip the query param and reload so the freshly generated
        // identity is in place before any app code runs.
        var u = new URL(window.location.href);
        u.searchParams.delete('qscs-reset');
        window.location.replace(u.toString());
        // Return a never-resolving promise — page is navigating away.
        return new Promise(function () {});
      })
    : Promise.resolve();

  var initPromise = preInit
    .then(function () {
      return Promise.all([loadWasm(), loadOrCreateWrapKey()]);
    })
    .then(function (results) {
      exportsRef = results[0];
      var wrapKey = results[1];
      // Resolve initialization only after persistence and identity loading finish.
      return bootstrapIdentity(exportsRef, wrapKey)
        .then(function () {
          refreshCache();
          if (!identityReady()) {
            // Leave recovery to the lazy self-heal path so app startup can
            // continue even if the first bootstrap left us with no UUID.
            console.warn('[qscs] bootstrap completed without a usable uuid');
          }
        });
    })
    .catch(function (e) {
      console.error('[qscs] init failed:', e);
      throw e;
    });

  // Application code awaits qscsCrypto.ready before reading uuid/pubkey. Never
  // let that await block forever on a browser-specific IDB/WASM stall.
  var readyPromise = new Promise(function (resolve, reject) {
    var timer = setTimeout(function () { reject(new Error('qscs_identity_ready_timeout')); }, READY_PROMISE_TIMEOUT_MS);
    initPromise.then(function () {
      clearTimeout(timer);
      if (!identityReady()) return reject(new Error('qscs_identity_not_ready'));
      resolve();
    }, function (error) { clearTimeout(timer); reject(error); });
  });
  // Keep pages without an auth consumer from generating an unhandled rejection.
  readyPromise.catch(function () {});

  // Install the monkey-patch immediately so requests issued before WASM
  // is ready are queued (signedFetch awaits readyPromise when exportsRef
  // is still null).
  window.fetch = signedFetch;

  window.qscsCrypto = {
    ready: readyPromise,
    clientUuidHex: function () { return clientUuidHexCached; },
    pubkeyHex:     function () { return pubkeyHexCached; },
    signedFetch:   signedFetch,
    rotateIdentity: rotateIdentity,
    // Manual self-heal from the JS console: `qscsCrypto.reset()` wipes
    // IndexedDB and reloads the page.  Also available via URL param
    // `?qscs-reset=1` for users without dev tools.
    reset: function () {
      return wipeIdentity().then(function () {
        window.location.reload();
      });
    }
  };
})();
