import assert from 'node:assert/strict';
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {setup} from './helpers.mjs';
import {login as exampleLogin,logout as exampleLogout} from '../examples/session.mjs';
const port=process.argv[2],wasm=await readFile(new URL('../dist/qscs-substrate.wasm',import.meta.url));
const sends=[];
const bridge=async(input,init={})=>{
 const url=new URL(typeof input==='string'?input:input.url,'https://app.example.test');
 if(url.pathname.endsWith('.wasm'))return new Response(wasm,{headers:{'Content-Type':'application/wasm'}});
 const headers=new Headers(init.headers);headers.set('Host','app.example.test');
 sends.push({url,init:{...init,headers}});
 return new Promise((resolve,reject)=>{
  const request=http.request({hostname:'127.0.0.1',port,path:url.pathname+url.search,method:init.method||'GET',headers:Object.fromEntries(headers)},response=>{
   const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.on('end',()=>resolve(new Response(Buffer.concat(chunks),{status:response.statusCode,headers:response.headers})));
  });request.on('error',reject);request.end(init.body ? Buffer.from(init.body) : undefined);
 });
};
const h=await setup(new Map(),{fetch:bridge});
async function login(username,password='test secret " with \\ and café') {
 await h.signer.rotateIdentity();
 return (await h.signer.signedFetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,client_uuid:h.signer.clientUuidHex(),pubkey:h.signer.pubkeyHex()})})).json();
}
for(const user of ['bad-status','bad-json','false-result','nested','duplicate','missing-subject','unsafe-subject'])assert.equal((await login(user)).ok,false,user);
const signedOut=await bridge('/api/whoami');assert.equal(signedOut.status,401);
const result=await login('alice');assert.equal(result.ok,true);assert.equal(result.origin,'app.example.test');
const status=await(await h.signer.signedFetch('/auth/status')).json();assert.equal(status.authenticated,true);
const response=await h.signer.signedFetch('/api/whoami',{headers:{'X-QSCS-Identity':'forged','X-QSCS-Authenticated-Subject':'admin','X-QSCS-Identity-Issuer':'attacker'}});
assert.equal(response.status,200);assert.deepEqual(await response.json(),{subject:'account:42',issuer:'app.example.test',uuid:h.signer.clientUuidHex()});
const replay=sends.at(-1);assert.equal((await bridge(replay.url.href,replay.init)).status,401);
const savedUuid=h.signer.clientUuidHex();assert.equal((await(await h.signer.signedFetch('/auth/logout',{method:'POST',body:''})).json()).ok,true);
assert.equal((await h.signer.signedFetch('/api/whoami')).status,401);
await h.signer.rotateIdentity();assert.notEqual(h.signer.clientUuidHex(),savedUuid);
assert.equal((await login('alice')).ok,true);assert.equal((await h.signer.signedFetch('/api/whoami')).status,200);
await exampleLogout(h.signer);
await exampleLogin(h.signer,'alice','test secret \" with \\ and café');
assert.equal((await h.signer.signedFetch('/api/whoami')).status,200);
console.log('PASS browser example + real SDK + WASM + QSCSCore: custom verifier, escaped credentials, rejection cases, trusted subject, spoof stripping, replay, logout and immediate relogin');
