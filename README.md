# Device-Bound Session Keys — Mitigating AiTM Session Cookie Theft

A minimal, working login system that defeats the **asynchronous reuse**
of stolen session cookies — the attack technique behind tools like
**Evilginx** and Phishing-as-a-Service operations (e.g. BigBear 2.0,
Tycoon2FA) that bypass MFA by stealing the session cookie *after* a
victim has already logged in and passed MFA.

> A stolen cookie, replayed from any machine other than the one that
> logged in, is rejected — even though it's the exact same cookie
> value the real server issued.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for full sequence diagrams.

---

## The problem

Modern phishing kits (Evilginx and similar) don't need to guess your
password. They sit as a transparent reverse proxy between you and the
real site:

1. You type your real username and password into what looks exactly
   like the real login page.
2. The proxy relays it to the real site, which asks for MFA, exactly
   as normal.
3. You complete MFA. The real site issues a session cookie.
4. The proxy captures that cookie as it flows back to you.
5. The attacker now has a fully authenticated session — no password,
   no MFA code needed ever again — and can reuse it hours or days
   later, from their own machine.

Standard cookie protections (`HttpOnly`, `Secure`, `SameSite`) do
**not** stop this, because the attacker isn't using JavaScript or
cross-site tricks — they're a network proxy that sees the raw cookie
value directly.

## The fix: bind the session to a key that never leaves the browser

1. On login, the browser generates an **ECDSA (P-256) key pair**
   using the Web Crypto API, with the private key marked
   **non-extractable**.
2. The key pair is stored in **IndexedDB**. The private key can never
   be exported via JavaScript — not even by an attacker who managed
   to inject malicious script into the page.
3. The browser sends only the **public key** to the server, which
   binds it to the session.
4. **Every subsequent request** to a protected route must include a
   signature, freshly generated from the private key, over the
   current timestamp.
5. The server verifies that signature against the bound public key on
   every single request. No valid signature → rejected, regardless of
   whether the cookie itself is perfectly valid.

Because the private key never travels over the network — not at
login, not ever — a network-based proxy like Evilginx can capture the
cookie text but has no way to produce a matching signature later.

## What this does NOT fix (stated plainly, on purpose)

| Scenario | Protected? |
|---|---|
| Attacker replays a stolen cookie later, from a different machine | Blocked |
| Attacker replays a stolen cookie + a fabricated signature | Blocked |
| Attacker is actively relaying traffic *while the victim's tab is still open* (live AiTM) | Not blocked — the victim's own browser is still signing requests in real time |
| Device-level malware with the same OS privilege as the browser | Partial — JS-level extraction is blocked, but a sophisticated infostealer reading the browser's storage at the OS level may not be |
| Full protection for the malware case | Requires **WebAuthn with a platform authenticator** (hardware-backed TPM/Secure Enclave keys) — a natural next step, not implemented here |

This project targets a specific, well-defined threat: **the
harvest-now-use-later business model that most commodity
Phishing-as-a-Service operations run on.** It does not claim to solve
phishing or session hijacking as a whole category.

## Setup

```bash
npm install
npm start
```

Visit `http://localhost:3000`, register a user, log in, and open the
dashboard — every request there is signed automatically.

## Proving the cookie alone doesn't work

```bash
# 1. Log in through the browser normally
# 2. DevTools -> Application -> Cookies -> copy the "sid" value
# 3. Run:
node attacker-simulate.js <stolen_sid_value>
```

Expected output: both replay attempts return `401 Unauthorized`.

Or run the full automated end-to-end test (login, bind, legit
request, two attacker attempts) in one shot:

```bash
node test-full-flow.js
```

## Testing against real Evilginx (isolated lab only)

1. Point Evilginx at this app's login page via a custom phishlet, in
   a network you fully control.
2. Log in through the Evilginx-proxied URL as the "victim."
3. Capture the `sid` cookie from Evilginx's session database.
4. From a **separate** terminal/machine, run `attacker-simulate.js`
   with that captured cookie.
5. Document: the live login/MFA flow succeeds through the proxy (as
   expected — this fix targets replay, not live relay), but the
   **replayed cookie afterward is rejected**.

## Project structure

```
.
├── server.js                  # Express server: sessions, key binding, signature verification
├── attacker-simulate.js       # Demonstrates the stolen-cookie-replay failure
├── test-full-flow.js          # End-to-end automated test of the whole flow
├── ARCHITECTURE.md            # Sequence diagrams + component breakdown
├── public/
│   ├── index.html             # Login / register page
│   ├── dashboard.html         # Protected page -- signs every request
│   └── js/
│       └── crypto-session.js  # Browser-side key generation, storage, and signing
├── package.json
└── LICENSE
```

## Tech stack

- Node.js + Express
- Web Crypto API (`crypto.subtle`) -- ECDSA P-256
- IndexedDB (browser-native key storage)
- bcrypt for password hashing (demo-grade)

## Disclaimer

This is a teaching/portfolio project, not production-hardened code.
Session storage is in-memory and resets on restart; there's no HTTPS
setup included (add a reverse proxy with a real certificate for
anything beyond localhost). Only test against systems and lab
environments you own or are explicitly authorized to test.

## License

MIT -- see [LICENSE](./LICENSE).
