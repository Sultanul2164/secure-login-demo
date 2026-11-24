/**
 * attacker-simulate.js
 * ---------------------
 * Simulates an attacker who captured ONLY the session cookie value
 * (exactly what Evilginx would see in a live AiTM relay) and tries
 * to reuse it later from a completely separate HTTP client — no
 * browser, no private key, nothing but the cookie string.
 *
 * Usage:
 *   1. Log in normally through the browser at http://localhost:3000
 *   2. Open DevTools > Application > Cookies, copy the "sid" value
 *   3. Run: node attacker-simulate.js <stolen_sid_value>
 *
 * Expected result: 401 Unauthorized, because this script has no
 * private key and cannot produce the required signature headers.
 */

const stolenSid = process.argv[2];

if (!stolenSid) {
  console.log('Usage: node attacker-simulate.js <stolen_sid_cookie_value>');
  process.exit(1);
}

async function tryReplayWithCookieOnly() {
  console.log('\n[Attempt 1] Replaying the stolen cookie with NO signature headers...');
  const res1 = await fetch('http://localhost:3000/api/dashboard', {
    headers: { 'Cookie': `sid=${stolenSid}` }
  });
  console.log('Status:', res1.status);
  console.log('Response:', await res1.json());

  console.log('\n[Attempt 2] Replaying the stolen cookie WITH a fabricated/garbage signature...');
  const res2 = await fetch('http://localhost:3000/api/dashboard', {
    headers: {
      'Cookie': `sid=${stolenSid}`,
      'X-Session-Timestamp': Date.now().toString(),
      'X-Session-Signature': 'totally-fake-signature-attacker-made-up'
    }
  });
  console.log('Status:', res2.status);
  console.log('Response:', await res2.json());

  console.log('\nConclusion: the stolen cookie is useless without the private key,');
  console.log('which never left the victim\'s browser and cannot be forged.');
}

tryReplayWithCookieOnly().catch(console.error);
