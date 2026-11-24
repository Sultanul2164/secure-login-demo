/**
 * Secure Login Demo — Device-Bound Session Credentials (DIY)
 * ------------------------------------------------------------
 * Purpose: demonstrate a mitigation against AiTM (Evilginx-style)
 * cookie theft by binding each session cookie to a non-extractable
 * ECDSA key pair generated inside the victim's own browser.
 *
 * A stolen cookie, replayed from a different browser/machine,
 * cannot produce a valid signature for the bound public key and
 * is therefore rejected, even though the cookie value itself is
 * identical to the real one.
 *
 * THIS IS A TEACHING DEMO, NOT PRODUCTION CODE.
 * - Storage is in-memory (resets on restart)
 * - Passwords use bcrypt (fine for demo)
 * - No HTTPS/TLS setup included (add a reverse proxy like nginx
 *   with a real cert for anything beyond localhost testing)
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { webcrypto } = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---- In-memory "databases" (demo only) ----
const users = new Map();     // username -> { passwordHash }
const sessions = new Map();  // sessionId -> { username, challenge, publicKeyJwk, bound, createdAt }

// How old a signed request is allowed to be (anti-replay window)
const SIGNATURE_FRESHNESS_MS = 30 * 1000;

// ---------------- Helpers ----------------

function randomChallenge() {
  return Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString('base64url');
}

async function importVerifyKey(jwk) {
  return webcrypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

async function verifySignature(publicKeyJwk, message, signatureB64) {
  try {
    const key = await importVerifyKey(publicKeyJwk);
    const sig = Buffer.from(signatureB64, 'base64url');
    const data = new TextEncoder().encode(message);
    return await webcrypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sig,
      data
    );
  } catch (e) {
    return false;
  }
}

// Middleware: require a valid session cookie PLUS a fresh, valid signature.
// This is the core defense. Without a matching signature, the cookie alone
// (exactly what Evilginx would capture) is useless.
async function requireBoundSession(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid) return res.status(401).json({ error: 'No session cookie' });

  const session = sessions.get(sid);
  if (!session) return res.status(401).json({ error: 'Unknown session' });

  if (!session.bound) {
    return res.status(401).json({ error: 'Session not key-bound yet' });
  }

  const sig = req.get('X-Session-Signature');
  const ts = req.get('X-Session-Timestamp');

  if (!sig || !ts) {
    return res.status(401).json({
      error: 'Missing signature headers — cookie alone is not accepted',
      hint: 'This is exactly what blocks a replayed stolen cookie.'
    });
  }

  const age = Date.now() - Number(ts);
  if (Number.isNaN(age) || age < -5000 || age > SIGNATURE_FRESHNESS_MS) {
    return res.status(401).json({ error: 'Signature timestamp stale or invalid' });
  }

  // NOTE: the message to sign is just the timestamp. The browser's
  // session cookie is httpOnly (JS can't read its value), so we don't
  // need the raw sid in the signed payload — the server already knows
  // which session it's checking against via the cookie lookup above,
  // and the signature is verified against THAT session's specific
  // bound public key, so cross-session replay isn't possible anyway.
  const message = `${ts}`;
  const valid = await verifySignature(session.publicKeyJwk, message, sig);
  if (!valid) {
    return res.status(401).json({
      error: 'Signature does not match bound key — request rejected',
      hint: 'A stolen cookie without the matching private key fails here.'
    });
  }

  req.session = session;
  req.sid = sid;
  next();
}

// ---------------- Routes ----------------

// Register a demo user
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (users.has(username)) return res.status(409).json({ error: 'user already exists' });

  const passwordHash = await bcrypt.hash(password, 10);
  users.set(username, { passwordHash });
  res.json({ ok: true });
});

// Step 1: normal password login. Issues a session cookie that is
// NOT yet usable for protected routes — it must be key-bound first.
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });

  const sid = uuidv4();
  const challenge = randomChallenge();

  sessions.set(sid, {
    username,
    challenge,
    publicKeyJwk: null,
    bound: false,
    createdAt: Date.now()
  });

  // httpOnly: JS on the page can't read the cookie value directly (defense in depth).
  // In production, also set `secure: true` and serve over HTTPS.
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'strict' });
  res.json({ ok: true, challenge });
});

// Step 2: browser generated a key pair locally, signs the login
// challenge with the private key, and sends the PUBLIC key + signature
// here. The server binds that public key to the session.
app.post('/api/bind-key', async (req, res) => {
  const sid = req.cookies.sid;
  const session = sessions.get(sid);
  if (!session) return res.status(401).json({ error: 'no session' });
  if (session.bound) return res.status(400).json({ error: 'session already bound' });

  const { publicKeyJwk, signature } = req.body;
  if (!publicKeyJwk || !signature) return res.status(400).json({ error: 'missing key or signature' });

  const valid = await verifySignature(publicKeyJwk, session.challenge, signature);
  if (!valid) return res.status(401).json({ error: 'challenge signature invalid' });

  session.publicKeyJwk = publicKeyJwk;
  session.bound = true;
  res.json({ ok: true });
});

// Protected route — requires cookie AND a valid fresh signature.
app.get('/api/dashboard', requireBoundSession, (req, res) => {
  res.json({
    ok: true,
    message: `Welcome, ${req.session.username}! This route is protected by device-bound session signing.`,
    sessionCreated: new Date(req.session.createdAt).toISOString()
  });
});

// --- Demo-only introspection endpoint, NOT for production ---
// Lets the "attacker" script see what a stolen cookie looks like,
// to make the classroom demo concrete.
app.get('/api/_debug/sessions', (req, res) => {
  const list = [...sessions.entries()].map(([sid, s]) => ({
    sid, username: s.username, bound: s.bound
  }));
  res.json(list);
});

app.listen(PORT, () => {
  console.log(`Secure login demo running at http://localhost:${PORT}`);
});
