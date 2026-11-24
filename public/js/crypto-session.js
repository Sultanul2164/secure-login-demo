/**
 * crypto-session.js
 * ------------------
 * Generates a non-extractable ECDSA (P-256) key pair inside the
 * browser and stores it in IndexedDB. CryptoKey objects can be
 * stored directly in IndexedDB via the structured clone algorithm,
 * WITHOUT ever exposing the raw private key bytes to JavaScript.
 *
 * Even if an attacker injects malicious JS into this page (XSS) or
 * steals the session cookie over the network (Evilginx-style AiTM),
 * they cannot export or exfiltrate the private key itself — it only
 * ever exists as an opaque, non-exportable handle inside the browser.
 */

const DB_NAME = 'secure-login-demo';
const STORE_NAME = 'keys';
const KEY_RECORD_ID = 'current-session-key';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function idbSet(key, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function generateKeyPair() {
  // extractable: false on the PRIVATE key. Per the Web Crypto spec,
  // the public key is always exportable regardless of this flag —
  // only the private key's non-extractability is what matters here.
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify']
  );
}

// Always generates a FRESH key pair for a new login (one key pair per
// session, not reused across logins). Overwrites any previous record.
async function createAndStoreNewKeyPair() {
  const keyPair = await generateKeyPair();
  await idbSet(KEY_RECORD_ID, keyPair);
  return keyPair;
}

async function loadStoredKeyPair() {
  return idbGet(KEY_RECORD_ID);
}

async function exportPublicKeyJwk(publicKey) {
  return crypto.subtle.exportKey('jwk', publicKey);
}

async function signString(privateKey, message) {
  const data = new TextEncoder().encode(message);
  const sigBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );
  return bufferToBase64Url(sigBuffer);
}

function bufferToBase64Url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Builds the two headers a protected request needs: a fresh timestamp
// and a signature over that timestamp using the session's bound
// private key. Call this right before every fetch() to a protected route.
async function getSignedHeaders() {
  const keyPair = await loadStoredKeyPair();
  if (!keyPair) throw new Error('No session key found — log in first.');
  const ts = Date.now().toString();
  const sig = await signString(keyPair.privateKey, ts);
  return {
    'X-Session-Timestamp': ts,
    'X-Session-Signature': sig
  };
}

window.SecureSession = {
  createAndStoreNewKeyPair,
  loadStoredKeyPair,
  exportPublicKeyJwk,
  signString,
  getSignedHeaders
};
