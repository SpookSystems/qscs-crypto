// Pause background API work while calling these helpers. Serialize auth actions.
export async function login(sdk, username, password) {
  await sdk.ready;
  await sdk.rotateIdentity();
  const response = await sdk.signedFetch('/auth/login', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, password, client_uuid: sdk.clientUuidHex(), pubkey: sdk.pubkeyHex()})
  });
  const result = await response.json();
  if (!response.ok || result.ok !== true) throw new Error('Sign-in was not accepted');
  return result;
}
export async function logout(sdk) {
  await sdk.ready;
  const response = await sdk.signedFetch('/auth/logout', {method: 'POST', body: ''});
  const result = await response.json();
  if (!response.ok || result.ok !== true) throw new Error('Sign-out was not confirmed');
  await sdk.rotateIdentity();
  return result;
}
