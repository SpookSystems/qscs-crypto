import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const wasmBytes = await readFile(new URL('../dist/qscs-substrate.wasm', import.meta.url));
const moduleSource = await readFile(new URL('../examples/api-delta-client.mjs', import.meta.url), 'utf8');
const source = moduleSource.replace('export function createApiDeltaClient', 'function createApiDeltaClient') + `
window.apiDelta = createApiDeltaClient({routes:['https://reports.example.com/api/reports', 'https://app.example.com/api/account']});`;
const resource = 'https://reports.example.com/api/reports?__qscs_issuer=app.example.com&type=traffic&period=1h&offset=0';
const MAX_ENTRY_BYTES = 2 * 1024 * 1024;

function json(text, headers = {}) {
  return new Response(text, { headers: { 'Content-Type': 'application/json', ...headers } });
}

function bootstrap(username='fixture-account', extra={}) {
  return json(JSON.stringify({account:{username},nodes:[],origins:[],clusters:[],...extra}));
}

function u32(number) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(number);
  return bytes;
}

function chunk(value) {
  const bytes = Buffer.from(value);
  return Buffer.concat([u32(bytes.length), bytes]);
}

function packet(text) {
  const header = Buffer.alloc(26);
  header.writeUInt16LE(200, 24);
  return Buffer.concat([header, chunk('application/json'), u32(1), chunk('op:00000'), chunk('I' + text)]).toString('base64');
}

function incremental(text, headers = {}, encoded = packet(text)) {
  return new Response(encoded, { headers: {
    'Content-Type': 'application/x-qscs-delta', 'X-QSCS-Mode': 'incremental',
    'X-QSCS-Encoding': 'base64', 'X-QSCS-Payload-Bytes': String(Buffer.byteLength(text)),
    'X-QSCS-Wire-Bytes': String(Buffer.byteLength(encoded)), ...headers
  } });
}

function impossibleCount() {
  const bytes = Buffer.from(packet('{}'), 'base64');
  bytes.writeUInt32LE(0xffffffff, 26 + 4 + Buffer.byteLength('application/json'));
  return bytes.toString('base64');
}

async function setup({ unavailable = false } = {}) {
  let instance;
  const storage = new Map();
  const context = vm.createContext({
    console, AbortController, DOMException, URL, URLSearchParams, Map, Set, Object,
    Date, Promise, Number, TextEncoder, TextDecoder, Headers, Response, Uint8Array,
    crypto: webcrypto, atob, setTimeout, clearTimeout,
    fetch: async () => unavailable ? new Response('', { status: 503 }) : new Response(wasmBytes),
    WebAssembly: { instantiate: async (...args) => {
      const result = await WebAssembly.instantiate(...args);
      instance = result.instance;
      return result;
    } },
    window: { location: { origin: 'https://app.example.com', href: 'https://app.example.com/control-panel/' },
      localStorage: {getItem:key=>storage.get(key)||null,setItem:(key,value)=>storage.set(key,value)}, addEventListener() {} },
    localStorage: { getItem() { throw Error('private baseline persistence forbidden'); }, setItem() { throw Error('private baseline persistence forbidden'); } },
    indexedDB: { open() { throw Error('decoder must not access signing identity storage'); } }
  });
  vm.runInContext(source, context, { filename: 'api-delta-client.mjs' });
  for (let attempt = 0; !unavailable && !context.window.apiDelta.status().ready && attempt < 100; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.equal(context.window.apiDelta.status().ready, !unavailable);
  const queue = [], requests = [];
  const signer = {
    clientUuidHex: () => 'a'.repeat(32), pubkeyHex: () => 'b'.repeat(64),
    rotateIdentity: async () => {},
    signedFetch: async (url, options = {}) => {
      requests.push({ url: String(url), headers: new Headers(options.headers), options });
      assert.ok(queue.length, 'unexpected signed request');
      const response = queue.shift();
      return typeof response === 'function' ? response(url, options) : response;
    }
  };
  return { context, delta: context.window.apiDelta, queue, requests, signer, instance: () => instance,
    fetch: (url = resource, options = {}) => context.window.apiDelta.fetch(signer, url, options) };
}

test('real WASM reconstructs full -> incremental -> nochange and preserves wire metrics', async () => {
  const h = await setup();
  h.queue.push(json('{"value":1}'), incremental('{"value":2}'), json('', {
    'X-QSCS-Mode': 'nochange', 'X-QSCS-Payload-Bytes': '11', 'X-QSCS-Wire-Bytes': '0'
  }));
  assert.deepEqual(await (await h.fetch()).json(), { value: 1 });
  assert.equal(h.requests[0].headers.has('X-QSCS-Delta'), false);
  const changed = await h.fetch();
  assert.deepEqual(await changed.json(), { value: 2 });
  assert.equal(changed.headers.get('X-QSCS-Reconstructed'), '1');
  assert.equal(changed.headers.get('X-QSCS-Wire-Bytes'), String(packet('{"value":2}').length));
  assert.equal(h.requests[1].headers.get('X-QSCS-Delta'), '1');
  assert.match(h.requests[1].headers.get('X-QSCS-Base-Hash'), /^[0-9a-f]{8}$/);
  const unchanged = await h.fetch();
  assert.deepEqual(await unchanged.json(), { value: 2 });
  assert.equal(unchanged.headers.get('X-QSCS-Wire-Bytes'), '0');
  assert.notEqual(h.requests[1].headers.get('X-QSCS-Base-Hash'), h.requests[2].headers.get('X-QSCS-Base-Hash'));
});

for (const [name, badResponse] of [
  ['malformed base64', () => incremental('{"value":2}', {}, '%%%%')],
  ['impossible packet operation count', () => incremental('{}', {}, impossibleCount())],
  ['unsupported encoding mode', () => incremental('{"value":2}', { 'X-QSCS-Encoding': 'unknown' })],
  ['mismatched reconstructed length', () => incremental('{"value":2}', { 'X-QSCS-Payload-Bytes': '1024' })],
  ['oversized encoded delta', () => incremental('{}', {}, 'A'.repeat(MAX_ENTRY_BYTES * 2 + 1))],
  ['oversized reconstructed body', () => incremental(JSON.stringify({ value: 'x'.repeat(MAX_ENTRY_BYTES) }))]
]) {
  test(`${name} performs exactly one fresh signed full resync`, async () => {
    const h = await setup();
    h.queue.push(json('{"value":1}'), badResponse(), json('{"value":3}'));
    await h.fetch();
    assert.deepEqual(await (await h.fetch()).json(), { value: 3 });
    assert.equal(h.requests.length, 3);
    assert.equal(h.requests[1].headers.get('X-QSCS-Delta'), '1');
    assert.equal(h.requests[2].headers.has('X-QSCS-Delta'), false);
    assert.equal(h.requests[2].headers.has('X-QSCS-Base-Hash'), false);
  });
}

test('broken full resync fails closed without looping or returning the stale baseline', async () => {
  const h = await setup();
  h.queue.push(json('{"value":1}'), incremental('{}', {}, '%%%'), incremental('{}'));
  await h.fetch();
  await assert.rejects(h.fetch(), /resync_failed/);
  assert.equal(h.requests.length, 3);
  assert.equal(h.delta.status().baselines, 0);
});

test('full resync accepts a valid full body labelled origin nochange', async () => {
  const h=await setup();
  h.queue.push(json('{"value":1}'),incremental('{}',{},'%%%'),json('{"value":3}',{'X-QSCS-Mode':'nochange','X-QSCS-Payload-Bytes':'11'}));
  await h.fetch(); assert.deepEqual(await (await h.fetch()).json(),{value:3});
  assert.equal(h.requests.length,3);
});

test('origin incremental labels on full JSON are not client deltas, including cold load and resync', async () => {
  const h=await setup();
  h.queue.push(json('{"value":1}',{'X-QSCS-Mode':'incremental'}),
    json('{"value":2}',{'X-QSCS-Mode':'incremental'}),
    incremental('{}',{},'%%%'),json('{"value":3}',{'X-QSCS-Mode':'incremental'}));
  assert.deepEqual(await (await h.fetch()).json(),{value:1});
  assert.deepEqual(await (await h.fetch()).json(),{value:2});
  assert.deepEqual(await (await h.fetch()).json(),{value:3});
  assert.equal(h.requests.length,4);
});

test('logout clears private baselines; a late pre-logout reply cannot repopulate them', async () => {
  const h = await setup();
  h.queue.push(json('{"value":1}'));
  await h.fetch();
  let release;
  h.queue.push(() => new Promise(resolve => { release = resolve; }));
  const inFlight = h.fetch();
  await new Promise(resolve => setTimeout(resolve, 0));
  h.delta.clear();
  release(json('{"value":"old account"}'));
  await assert.rejects(inFlight, { name: 'AbortError' });
  assert.equal(h.delta.status().baselines, 0);
  h.queue.push(json('{"value":"new account"}'));
  await h.fetch();
  assert.equal(h.requests.at(-1).headers.has('X-QSCS-Delta'), false);
});

test('baseline URL, time window, issuer selector and signing identity stay partitioned', async () => {
  const h = await setup();
  for (const url of [resource, resource.replace('offset=0', 'offset=3600'), resource.replace('app.example.com', 'accounts.example.com')]) {
    h.queue.push(json('{}'));
    await h.fetch(url);
    assert.equal(h.requests.at(-1).headers.has('X-QSCS-Delta'), false);
  }
  h.signer.clientUuidHex = () => 'c'.repeat(32);
  h.queue.push(json('{}'));
  await h.fetch();
  assert.equal(h.requests.at(-1).headers.has('X-QSCS-Delta'), false);
  assert.equal(h.delta.status().baselines, 4);
});

test('no decoder advertises no delta capability and ordinary routes remain untouched', async () => {
  const h = await setup({ unavailable: true });
  h.queue.push(json('{}'), json('{}'), json('{}'));
  await h.fetch();
  await h.fetch();
  const headers = { 'X-Custom': 'retained' };
  await h.fetch('https://app.example.com/auth/status', { headers });
  assert.equal(h.requests[0].headers.has('X-QSCS-Delta'), false);
  assert.equal(h.requests[1].headers.has('X-QSCS-Delta'), false);
  assert.equal(h.requests[2].options.headers, headers);
  assert.equal(h.delta.status().baselines, 1);
});

test('cancellation releases the URL queue even when transport ignores abort', async () => {
  const h=await setup(), controller=new AbortController();let release;
  h.queue.push(()=>new Promise(resolve=>release=resolve));
  const first=h.fetch(resource,{signal:controller.signal});
  for(let i=0;!release&&i<20;i++) await Promise.resolve();
  controller.abort(); await assert.rejects(first,{name:'AbortError'});
  h.queue.push(json('{"new":true}'));
  assert.deepEqual(await (await h.fetch()).json(),{new:true});
  release(json('{"old":true}')); await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(h.delta.status().baselines,1);
  h.queue.push(json('',{'X-QSCS-Mode':'nochange'}));
  assert.deepEqual(await (await h.fetch()).json(),{new:true});
});

test('repeated WASM decode cycles reuse the arena instead of growing with each poll', async () => {
  const h = await setup();
  const text = JSON.stringify({ value: 'x'.repeat(64 * 1024) });
  h.queue.push(json(text));
  await h.fetch();
  let warmedMemoryBytes;
  for (let cycle = 0; cycle < 120; cycle++) {
    h.queue.push(incremental(text));
    assert.equal((await (await h.fetch()).json()).value.length, 64 * 1024);
    if (cycle === 8) warmedMemoryBytes = h.instance().exports.memory.buffer.byteLength;
    if (cycle > 8) assert.equal(h.instance().exports.memory.buffer.byteLength, warmedMemoryBytes);
  }
});

test('baseline count and aggregate byte budget are bounded', async () => {
  const h = await setup();
  for (let index = 0; index < 35; index++) {
    h.queue.push(json(JSON.stringify({ value: 'x'.repeat(300 * 1024) })));
    await h.fetch(resource + '&test=' + index);
  }
  assert.ok(h.delta.status().baselines <= 32);
  assert.ok(h.delta.status().bytes <= 8 * 1024 * 1024);
});


test('unlisted destinations and writes are not delta-negotiated',async()=>{
 const h=await setup();h.queue.push(json('{}'),json('{}'));
 await h.fetch('https://untrusted.example.com/api/reports');
 await h.fetch(resource,{method:'POST',body:'{}'});
 assert.ok(h.requests.every(r=>!r.headers.has('X-QSCS-Delta')));
 assert.equal(h.delta.status().baselines,0);
});
