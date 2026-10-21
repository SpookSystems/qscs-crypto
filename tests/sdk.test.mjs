import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {setup} from './helpers.mjs';
test('real WASM rotation replaces UUID and public key, persists them, and queues signatures', async()=>{
  const h=await setup();
  const oldUuid=h.signer.clientUuidHex(), oldKey=h.signer.pubkeyHex();
  const rotating=h.signer.rotateIdentity();
  const signed=h.signer.signedFetch('/api/portal/read?resource=account');
  await Promise.all([rotating,signed]);
  assert.notEqual(h.signer.clientUuidHex(),oldUuid);
  assert.notEqual(h.signer.pubkeyHex(),oldKey);
  assert.equal(h.requests[0].options.headers.get('X-QSCS-Client-Uuid'),h.signer.clientUuidHex());
  assert.ok(h.requests[0].options.headers.get('X-QSCS-Sig'));
  const reload=await setup(h.storage);
  assert.equal(reload.signer.clientUuidHex(),h.signer.clientUuidHex());
  assert.equal(reload.signer.pubkeyHex(),h.signer.pubkeyHex());
});

test('failed identity persistence keeps the old key for retrying signed revocation',async()=>{
  const h=await setup(), oldUuid=h.signer.clientUuidHex();
  h.writes.fail=true;
  await assert.rejects(h.signer.rotateIdentity(),/storage failed/);
  assert.equal(h.signer.clientUuidHex(),oldUuid);
  await h.signer.signedFetch('/auth/logout',{method:'POST',body:''});
  assert.equal(h.requests[0].options.headers.get('X-QSCS-Client-Uuid'),oldUuid);
});

async function verify(h, request, body=Buffer.alloc(0), method='GET', target='/api/example') {
  const headers=request.options.headers;
  const parsed=new URL(target,'https://app.example.test');
  const canonical=Buffer.concat([Buffer.from(`${method}\n${parsed.hostname}\n${parsed.pathname}${parsed.search}\n`),body,Buffer.from(`\n${headers.get('X-QSCS-Ts')}\n${headers.get('X-QSCS-Nonce')}`)]);
  const key=await webcrypto.subtle.importKey('raw',Buffer.from(h.signer.pubkeyHex(),'hex'),'Ed25519',false,['verify']);
  assert.equal(await webcrypto.subtle.verify('Ed25519',key,Buffer.from(headers.get('X-QSCS-Sig'),'base64'),canonical),true);
}
test('packaged WASM signs the exact Core wire format including query and JSON body',async()=>{
 const h=await setup();const body=JSON.stringify({message:'quote " and café',value:17});
 await h.signer.signedFetch('/api/example?x=1',{method:'POST',body});
 await verify(h,h.requests[0],Buffer.from(body),'POST','/api/example?x=1');
});
test('binary bytes are signed without lossy UTF-8 decoding',async()=>{
 const h=await setup();const body=new Uint8Array([0,255,128,13,10]);
 await h.signer.signedFetch('/api/example',{method:'POST',body});await verify(h,h.requests[0],Buffer.from(body),'POST');
});
test('Request body and init method override are honoured',async()=>{
 const h=await setup();const request=new Request('https://app.example.test/api/example',{method:'POST',body:'stored body'});
 await h.signer.signedFetch(request,{method:'PUT'});await verify(h,h.requests[0],Buffer.from('stored body'),'PUT');
});
test('URL objects and an explicitly configured same-origin WASM path work',async()=>{
 const h=await setup(new Map(),{QSCS_WASM_URL:'/assets/identity.wasm'});
 await h.signer.signedFetch(new URL('https://app.example.test/api/example'));await verify(h,h.requests[0]);
});
test('cross-origin destinations stay unsigned unless exactly allow-listed',async()=>{
 const h=await setup(new Map(),{QSCS_FEDERATED_IDENTITY_ORIGINS:['https://reports.example.test','https://bad.example.test/path']});
 await h.signer.signedFetch('https://reports.example.test/api/example',{credentials:'include'});
 await verify(h,h.requests[0],Buffer.alloc(0),'GET','https://reports.example.test/api/example');assert.equal(h.requests[0].options.credentials,'omit');
 await h.signer.signedFetch('https://other.example.test/api/example');assert.equal(h.requests[1].options.headers,undefined);
 await h.signer.signedFetch('https://bad.example.test/api/example');assert.equal(h.requests[2].options.headers,undefined);
});
test('unsupported body rejects without transmitting an unsigned request',async()=>{
 const h=await setup();const body=new FormData();body.set('field','value');
 await assert.rejects(h.signer.signedFetch('/api/example',{method:'POST',body}),/Unsupported signed body/);assert.equal(h.requests.length,0);
});
test('storage failure rejects ready instead of resolving with an empty identity',async()=>{
 await assert.rejects(setup(new Map(),{indexedDB:{open(){throw new Error('storage denied');}}}),/storage denied/);
});

test('nondefault ports use the portless host required by Core',async()=>{
 const h=await setup(new Map(),{location:{origin:'https://app.example.test:8443',host:'app.example.test:8443',href:'https://app.example.test:8443/',search:''}});
 await h.signer.signedFetch('/api/example');await verify(h,h.requests[0]);
});
test('federated auth/status remains signed and omits recipient cookies',async()=>{
 const h=await setup(new Map(),{QSCS_FEDERATED_IDENTITY_ORIGINS:['https://reports.example.test']});
 await h.signer.signedFetch('https://reports.example.test/auth/status');
 assert.equal(h.requests[0].options.credentials,'omit');
 await verify(h,h.requests[0],Buffer.alloc(0),'GET','https://reports.example.test/auth/status');
});
test('managed federation discovers permitted GET paths and supersedes static recipients',async()=>{
 const h=await setup(new Map(),{QSCS_FEDERATED_IDENTITY_ORIGINS:['https://old.example.test'],federationPolicy:{managed:true,recipients:[{origin:'https://api.example.test',paths:['/api/reports/']}]}});
 await h.signer.signedFetch('https://api.example.test/api/reports/1');
 assert.ok(h.requests[0].options.headers.get('X-QSCS-Sig'));assert.equal(h.requests[0].options.credentials,'omit');
 await h.signer.signedFetch('https://api.example.test/api/admin');
 assert.equal(h.requests[1].options.headers,undefined);
 await h.signer.signedFetch('https://old.example.test/api/reports/1');
 assert.equal(h.requests[2].options.headers,undefined);
 await h.signer.signedFetch('https://api.example.test/api/reports/1',{method:'POST',body:'{}'});
 assert.equal(h.requests[3].options.headers,undefined);
});
test('managed recipient discovery rejects credentials and malformed destination paths',async()=>{
 const h=await setup(new Map(),{federationPolicy:{managed:true,recipients:[{origin:'https://user@api.example.test',paths:['/']},{origin:'https://api.example.test',paths:['/api/../admin']}]}});
 await h.signer.signedFetch('https://api.example.test/api/reports');assert.equal(h.requests[0].options.headers,undefined);
});
