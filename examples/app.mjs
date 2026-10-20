import {login, logout} from './session.mjs';
const form=document.querySelector('#login'), account=document.querySelector('#account'), signOut=document.querySelector('#logout'), status=document.querySelector('#status');
const sdk=window.qscsCrypto;
let authenticated=false, busy=true;
function update() {
  for(const input of form.elements) input.disabled=busy||authenticated;
  account.disabled=signOut.disabled=busy||!authenticated;
}
async function action(operation) {
  if(busy)return;
  busy=true;update();
  try{await operation();}catch(error){status.textContent=error.message;}
  finally{busy=false;update();}
}
update();
try {
  await sdk.ready;
  const response=await sdk.signedFetch('/auth/status');
  const result=await response.json();
  authenticated=response.ok&&result.authenticated===true;
  status.textContent=authenticated?'Signed in.':'Ready to sign in.';
  busy=false;update();
}catch(error){status.textContent='Sign-in could not initialize. Reload to retry.';}
form.addEventListener('submit',event=>{event.preventDefault();void action(async()=>{
  const username=form.elements.username.value,password=form.elements.password.value;
  form.elements.password.value='';
  await login(sdk,username,password);authenticated=true;status.textContent='Signed in.';
});});
account.addEventListener('click',()=>void action(async()=>{
  const response=await sdk.signedFetch('/api/account');
  if(!response.ok)throw new Error('Account request was not accepted');
  status.textContent=JSON.stringify(await response.json());
}));
signOut.addEventListener('click',()=>void action(async()=>{
  await logout(sdk);authenticated=false;status.textContent='Signed out.';
}));
