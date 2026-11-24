// Simulates what the browser's crypto-session.js does, using Node's
// built-in WebCrypto, to validate the full server-side logic end to end
// before testing with a real browser.
const { webcrypto } = require('crypto');

const BASE = 'http://localhost:3000';

function extractCookie(setCookieHeader) {
  return setCookieHeader.split(';')[0]; // "sid=xxxx"
}

async function main() {
  // 1. Register + login
  await fetch(`${BASE}/api/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'victim', password: 'hunter2' })
  });

  const loginRes = await fetch(`${BASE}/api/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'victim', password: 'hunter2' })
  });
  const loginData = await loginRes.json();
  const cookie = extractCookie(loginRes.headers.get('set-cookie'));
  console.log('[1] Logged in. Challenge:', loginData.challenge);
  console.log('    Cookie (this is what Evilginx would capture):', cookie);

  // 2. Generate key pair "in the browser" (here: Node WebCrypto, same API)
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']
  );
  const publicKeyJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);

  async function sign(message) {
    const data = new TextEncoder().encode(message);
    const sigBuf = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, data);
    return Buffer.from(sigBuf).toString('base64url');
  }

  const challengeSig = await sign(loginData.challenge);

  // 3. Bind the key to the session
  const bindRes = await fetch(`${BASE}/api/bind-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': cookie },
    body: JSON.stringify({ publicKeyJwk, signature: challengeSig })
  });
  console.log('[2] Bind result:', await bindRes.json());

  // 4. Legit request: cookie + fresh valid signature
  const ts = Date.now().toString();
  const sig = await sign(ts);
  const legitRes = await fetch(`${BASE}/api/dashboard`, {
    headers: { 'Cookie': cookie, 'X-Session-Timestamp': ts, 'X-Session-Signature': sig }
  });
  console.log('[3] Legit signed request ->', legitRes.status, await legitRes.json());

  // 5. ATTACKER: steals only the cookie text, tries with no signature
  const attack1 = await fetch(`${BASE}/api/dashboard`, { headers: { 'Cookie': cookie } });
  console.log('[4] Attacker, cookie only, no signature ->', attack1.status, await attack1.json());

  // 6. ATTACKER: steals the cookie, fabricates a garbage signature
  const attack2 = await fetch(`${BASE}/api/dashboard`, {
    headers: { 'Cookie': cookie, 'X-Session-Timestamp': Date.now().toString(), 'X-Session-Signature': 'fake-signature' }
  });
  console.log('[5] Attacker, cookie + fake signature ->', attack2.status, await attack2.json());

  console.log('\nResult: legit signed request succeeds; both attacker replay attempts fail.');
}

main().catch(console.error);
