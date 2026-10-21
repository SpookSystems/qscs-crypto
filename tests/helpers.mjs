import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';
const source = await readFile(new URL('../dist/qscs-crypto.js', import.meta.url), 'utf8');
const wasm = await readFile(new URL('../dist/qscs-substrate.wasm', import.meta.url));

export async function setup(storage = new Map(), configuration = {}) {
  const writes = {fail:false};
  const requests = [];
  const indexedDB = {open() {
    const request = {};
    setImmediate(() => {
      request.result = {transaction() {
        const tx = {objectStore:() => ({
          get(key) { const req = {}; setImmediate(()=>{req.result=storage.get(key);req.onsuccess();}); return req; },
          put(value,key) { setImmediate(()=>{if(writes.fail){tx.error=new Error('storage failed');tx.onerror();}else{storage.set(key,value);tx.oncomplete();}}); },
          delete(key) { setImmediate(()=>{storage.delete(key);tx.oncomplete();}); }
        })};
        return tx;
      }};
      request.onsuccess();
    });
    return request;
  }};
  const context = vm.createContext({console,crypto:webcrypto,indexedDB,WebAssembly,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,AbortController,Headers,Request,Response,URL,URLSearchParams,FormData,
    setTimeout:(cb,ms)=>{const t=setTimeout(cb,ms);t.unref();return t;}, clearTimeout,
    location:{origin:'https://app.example.test',host:'app.example.test',href:'https://app.example.test/control-panel/',search:''},
    fetch:async (url,options)=>{
      if(String(url).endsWith('/wasm/qscs-substrate.wasm') || String(url).endsWith('/assets/identity.wasm')) return new Response(wasm,{headers:{'Content-Type':'application/wasm'}});
      if (String(url)==='/auth/federation') return new Response(JSON.stringify(configuration.federationPolicy || {managed:false,recipients:[]}));
      requests.push({url,options}); return new Response('{}');
    }
  });
  context.window=context;Object.assign(context, configuration);
  vm.runInContext(source,context);
  await context.qscsCrypto.ready;
  assert.match(context.qscsCrypto.clientUuidHex(),/^[0-9a-f]{32}$/);
  return {signer:context.qscsCrypto,storage,writes,requests};
}

