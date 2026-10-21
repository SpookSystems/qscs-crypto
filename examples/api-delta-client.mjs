/** Explicit signed JSON delta adapter. Baselines stay in memory, scoped by
 * browser identity and exact URL. This module does not patch window.fetch.
 * Call clear() on logout/account changes and before changing authorization scope.
 */
export function createApiDeltaClient({routes: routeInputs, wasmUrl: wasmInput = '/wasm/qscs-substrate.wasm'}) {
  const routes = routeInputs.map(value => {
    const url = new URL(value, window.location.href);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
      throw new TypeError('Routes must be exact HTTPS URLs without query strings or fragments');
    }
    return url;
  });
  const wasmUrl = new URL(wasmInput, window.location.href);
  if (wasmUrl.origin !== window.location.origin) throw new TypeError('WASM must be same-origin');
  var MAX_ENTRY_BYTES = 2 * 1024 * 1024;
  var MAX_CACHE_BYTES = 8 * 1024 * 1024;
  var MAX_ENTRIES = 32;
  var baselines = new Map();
  var queues = new Map();
  var cacheBytes = 0;
  var generation = 0;
  var wasm = null;
  var encoder = new TextEncoder();
  var decoder = new TextDecoder('utf-8', { fatal: true });

  function loadDecoder() {
    var instance = null;
    var imports = { env: {
      js_random: function (ptr, len) {
        crypto.getRandomValues(new Uint8Array(instance.exports.memory.buffer, ptr, len));
      },
      js_now_ms_lo: function () { return Date.now() & 0xffffffff; },
      js_now_ms_hi: function () { return Math.floor(Date.now() / 0x100000000) & 0xffffffff; },
      js_log: function () {},
      js_schedule: function () {},
      strlen: function (ptr) {
        var bytes = new Uint8Array(instance.exports.memory.buffer), end = ptr;
        while (end < bytes.length && bytes[end]) end++;
        return end - ptr;
      }
    } };
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, 10000);
    return fetch(wasmUrl.href, { credentials: 'omit', signal: controller.signal })
      .then(function (response) {
        if (!response.ok) throw new Error('decoder_unavailable');
        return response.arrayBuffer();
      })
      .then(function (bytes) { return WebAssembly.instantiate(bytes, imports); })
      .then(function (result) {
        instance = result.instance;
        var api = instance.exports;
        ['qscs_alloc', 'qscs_set_prev_state', 'qscs_tick_delta', 'qscs_get_result_ptr', 'qscs_get_result_len'].forEach(function (name) {
          if (typeof api[name] !== 'function') throw new Error('decoder_incompatible');
        });
        if (typeof api.init === 'function') api.init();
        wasm = instance;
      })
      .catch(function () {
        // Full signed JSON remains usable. Never advertise delta capability
        // without a functioning decoder, and never load a weaker signer.
        wasm = null;
      })
      .finally(function () { clearTimeout(timer); });
  }

  function cacheDelete(key) {
    var previous = baselines.get(key);
    if (previous) cacheBytes -= previous.bytes;
    baselines.delete(key);
  }

  function hashBytes(bytes) {
    var hash = 0x811c9dc5;
    for (var i = 0; i < bytes.length; i++) hash = Math.imul(hash ^ bytes[i], 0x01000193);
    return ('0000000' + (hash >>> 0).toString(16)).slice(-8);
  }

  function cacheSet(key, text) {
    cacheDelete(key);
    var bytes = encoder.encode(text);
    if (bytes.length > MAX_ENTRY_BYTES) return;
    // Only valid JSON becomes a future baseline, never error HTML or a delta.
    JSON.parse(text);
    while (baselines.size >= MAX_ENTRIES || cacheBytes + bytes.length > MAX_CACHE_BYTES) {
      cacheDelete(baselines.keys().next().value);
    }
    baselines.set(key, { text: text, bytes: bytes.length, hash: hashBytes(bytes) });
    cacheBytes += bytes.length;
  }

  function routeAllowed(url, options) {
    return (options.method || 'GET').toUpperCase() === 'GET' &&
      routes.some(function (route) {
        return url.origin === route.origin && url.pathname === route.pathname;
      });
  }

  function applyDelta(base, encoded) {
    if (!wasm || encoded.length > MAX_ENTRY_BYTES * 2) throw new Error('delta_unavailable');
    var binary = atob(encoded);
    var delta = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) delta[i] = binary.charCodeAt(i);
    // Reject malformed length/count fields before they reach the WASM arena.
    // The native decoder trusts its server-produced packet; this boundary
    // also handles truncated/corrupted packets with a bounded full resync.
    if (delta.length < 34) throw new Error('delta_truncated');
    var view = new DataView(delta.buffer);
    var offset = 26;
    function readLength() {
      if (offset + 4 > delta.length) throw new Error('delta_truncated');
      var length = view.getUint32(offset, true); offset += 4;
      return length;
    }
    function skipChunk() {
      var length = readLength();
      if (length > delta.length - offset) throw new Error('delta_truncated');
      offset += length;
    }
    skipChunk();
    var entries = readLength();
    if (entries > Math.floor((delta.length - offset) / 8)) throw new Error('delta_invalid_count');
    for (var entry = 0; entry < entries; entry++) { skipChunk(); skipChunk(); }
    if (offset !== delta.length) throw new Error('delta_trailing_bytes');
    var api = wasm.exports;
    var baseBytes = encoder.encode(base);
    var basePtr = api.qscs_alloc(baseBytes.length);
    new Uint8Array(api.memory.buffer, basePtr, baseBytes.length).set(baseBytes);
    api.qscs_set_prev_state(basePtr, baseBytes.length);
    var deltaPtr = api.qscs_alloc(delta.length);
    new Uint8Array(api.memory.buffer, deltaPtr, delta.length).set(delta);
    var result = api.qscs_tick_delta(deltaPtr, delta.length);
    if (result < 0) throw new Error('delta_rejected');
    if (result === 0) return base;
    var resultLength = api.qscs_get_result_len();
    var resultPtr = api.qscs_get_result_ptr();
    if (resultLength < 0 || resultLength > MAX_ENTRY_BYTES) throw new Error('delta_oversized');
    var text = decoder.decode(new Uint8Array(api.memory.buffer, resultPtr, resultLength));
    JSON.parse(text);
    return text;
  }

  function reconstructed(response, text) {
    var headers = new Headers(response.headers);
    headers.delete('content-length');
    headers.delete('content-encoding');
    headers.set('Content-Type', 'application/json; charset=utf-8');
    headers.set('X-QSCS-Reconstructed', '1');
    return new Response(text, { status: response.status, statusText: response.statusText, headers: headers });
  }

  async function deltaFetch(signer, input, options) {
    await signer.ready;
    options = options || {};
    var url = new URL(input, window.location.href);
    if (!routeAllowed(url, options)) return signer.signedFetch(input, options);
    var key = signer.clientUuidHex() + '|' + url.href;
    var requestGeneration = generation;
    var previous = queues.get(key) || Promise.resolve();
    var operation = previous.catch(function () {}).then(function () {
      if (requestGeneration !== generation || (options.signal && options.signal.aborted)) {
        throw new DOMException('Request was cancelled.', 'AbortError');
      }
      var base = baselines.get(key);
      var headers = new Headers(options.headers || {});
      headers.delete('X-QSCS-Delta');
      headers.delete('X-QSCS-Base-Hash');
      headers.delete('X-QSCS-Base-Key');
      if (base && wasm) {
        headers.set('X-QSCS-Delta', typeof wasm.exports.qscs_delta_version === 'function' && wasm.exports.qscs_delta_version() >= 2 ? '2' : '1');
        headers.set('X-QSCS-Base-Hash', base.hash);
      }
      function send(forceFull) {
        if (forceFull) {
          headers.delete('X-QSCS-Delta');
          headers.delete('X-QSCS-Base-Hash');
          cacheDelete(key);
        }
        return signer.signedFetch(input, Object.assign({}, options, { headers: headers })).then(function (response) {
          if (requestGeneration !== generation || (options.signal && options.signal.aborted)) throw new DOMException('Request cancelled.', 'AbortError');
          if (!response.ok || response.status !== 200) {
            cacheDelete(key);
            return response;
          }
          var mode = (response.headers.get('X-QSCS-Mode') || '').toLowerCase();
          var contentType = (response.headers.get('Content-Type') || '').toLowerCase();
          // The content type also identifies a delta if old CORS policy hid
          // its mode header. Treat that as a resync, not JSON or stale data.
          // Mode also describes origin-side changes on ordinary full JSON.
          // Decode only an explicitly encoded client delta, never mode alone.
          var isDelta = contentType.indexOf('application/x-qscs-delta') !== -1 ||
            (mode === 'incremental' && (response.headers.get('X-QSCS-Encoding') || '').toLowerCase() === 'base64');
          if (!isDelta && mode !== 'nochange') {
            return response.clone().text().then(function (text) {
              if (requestGeneration === generation && !(options.signal && options.signal.aborted)) {
                try { cacheSet(key, text); } catch (e) { cacheDelete(key); }
              }
              return response;
            });
          }
          return response.text().then(function (raw) {
            try {
              // A direct full-body origin validation can legitimately retain
              // the nochange label. Only a delta or empty body needs a base.
              if (forceFull && (isDelta || !raw)) throw new Error('resync_failed: mode=' + mode + ', type=' + contentType + ', bytes=' + raw.length);
              var text;
              if (!isDelta && raw) {
                // Older nochange responses can still carry a full body.
                JSON.parse(raw); text = raw;
              } else if (!base || !wasm) {
                throw new Error('missing_base');
              } else if (isDelta) {
                if ((response.headers.get('X-QSCS-Encoding') || '').toLowerCase() !== 'base64') {
                  throw new Error('unsupported_delta_encoding');
                }
                text = applyDelta(base.text, raw);
              } else {
                text = base.text;
              }
              var expected = response.headers.get('X-QSCS-Payload-Bytes');
              if (expected && /^\d+$/.test(expected) && encoder.encode(text).length !== Number(expected)) {
                throw new Error('reconstruction_size_mismatch');
              }
              if (requestGeneration !== generation || (options.signal && options.signal.aborted)) throw new DOMException('Request cancelled.', 'AbortError');
              cacheSet(key, text);
              return reconstructed(response, text);
            } catch (error) {
              if (forceFull || error.name === 'AbortError') throw error;
              // One full signed retry, with a fresh nonce from the signer.
              // Do not return an old baseline when decompression failed.
              return send(true);
            }
          });
        });
      }
      return send(false);
    });
    var onAbort;
    var pending = options.signal ? Promise.race([operation, new Promise(function (_, reject) {
      onAbort = function () { reject(new DOMException('Request cancelled.', 'AbortError')); };
      if (options.signal.aborted) onAbort(); else options.signal.addEventListener('abort', onAbort, { once: true });
    })]) : operation;
    queues.set(key, pending);
    return pending.finally(function () {
      if (onAbort) options.signal.removeEventListener('abort', onAbort);
      if (queues.get(key) === pending) queues.delete(key);
    });
  }

  const ready = loadDecoder();
  return Object.freeze({
    ready,
    fetch: deltaFetch,
    clear: function () {
      generation++;
      baselines.clear();
      queues.clear();
      cacheBytes = 0;
    },
    status: function () { return { ready: !!wasm, baselines: baselines.size, bytes: cacheBytes }; }
  });
}
