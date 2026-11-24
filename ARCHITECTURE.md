# Architecture

This document explains the components, data flow, and the exact point
where a stolen session cookie gets rejected.

## Components

```
┌──────────────────────────────┐        ┌──────────────────────────────┐
│          BROWSER             │        │            SERVER            │
│                               │        │                               │
│  ┌─────────────────────────┐ │        │  ┌─────────────────────────┐ │
│  │  index.html / dashboard │ │        │  │        server.js         │ │
│  │  (UI, fetch() calls)    │ │        │  │  Express routes +        │ │
│  └───────────┬─────────────┘ │        │  │  signature middleware    │ │
│              │                │        │  └───────────┬─────────────┘ │
│  ┌───────────▼─────────────┐ │  HTTPS │              │               │
│  │  crypto-session.js      │◄┼────────┼──────────────►│               │
│  │  (Web Crypto + IndexedDB)│ │        │  ┌───────────▼─────────────┐ │
│  └───────────┬─────────────┘ │        │  │   sessions Map (demo)    │ │
│              │                │        │  │ sid -> {publicKeyJwk,   │ │
│  ┌───────────▼─────────────┐ │        │  │         bound, user}    │ │
│  │   IndexedDB              │ │        │  └─────────────────────────┘ │
│  │   private key (never     │ │        │                               │
│  │   leaves this box)       │ │        │                               │
│  └─────────────────────────┘ │        │                               │
└──────────────────────────────┘        └──────────────────────────────┘
```

- **Browser**: runs the UI and `crypto-session.js`, which generates a
  non-extractable ECDSA (P-256) key pair via the Web Crypto API and
  stores it in IndexedDB. The private key never leaves this box, not
  even to the server.
- **Server**: Express app (`server.js`) that issues session cookies,
  binds public keys to sessions, and verifies a fresh signature on
  every protected request.

## Flow 1 — Normal login and key binding

```mermaid
sequenceDiagram
    participant U as User's Browser
    participant S as Server

    U->>S: POST /api/login (username, password)
    S->>S: verify password hash
    S->>S: create session (sid), generate challenge
    S-->>U: Set-Cookie: sid=... (httpOnly) + { challenge }

    U->>U: generate ECDSA key pair (non-extractable)
    U->>U: store key pair in IndexedDB
    U->>U: sign(challenge) with private key

    U->>S: POST /api/bind-key { publicKeyJwk, signature }
    S->>S: verify signature against publicKeyJwk
    S->>S: store publicKeyJwk on session, mark bound = true
    S-->>U: { ok: true }

    Note over U,S: Session is now key-bound.<br/>Cookie alone is no longer sufficient.
```

## Flow 2 — Legitimate use of a protected route

```mermaid
sequenceDiagram
    participant U as User's Browser
    participant S as Server

    U->>U: ts = Date.now()
    U->>U: sig = sign(ts) with private key (from IndexedDB)
    U->>S: GET /api/dashboard<br/>Cookie: sid=...<br/>X-Session-Timestamp: ts<br/>X-Session-Signature: sig
    S->>S: look up session by sid
    S->>S: verify sig against session.publicKeyJwk
    S->>S: check timestamp freshness (< 30s old)
    S-->>U: 200 OK { dashboard data }
```

## Flow 3 — Stolen cookie replay (the attack this project stops)

```mermaid
sequenceDiagram
    participant V as Victim's Browser
    participant E as Evilginx (AiTM Proxy)
    participant A as Attacker (separate browser/script)
    participant S as Server

    V->>E: Logs in through fake domain
    E->>S: Relays login traffic
    S-->>E: Set-Cookie: sid=...
    E-->>V: Relays cookie back (victim is logged in normally)
    E->>E: Captures sid value from traffic

    Note over E,A: Attacker now has the COOKIE TEXT only.<br/>They never had the private key —<br/>it was never transmitted anywhere.

    A->>S: GET /api/dashboard<br/>Cookie: sid=stolen_value<br/>(no signature headers)
    S-->>A: 401 Unauthorized<br/>"Missing signature headers"

    A->>S: GET /api/dashboard<br/>Cookie: sid=stolen_value<br/>X-Session-Signature: fake
    S->>S: verify sig against session.publicKeyJwk → fails
    S-->>A: 401 Unauthorized<br/>"Signature does not match bound key"
```

## Why this works

The server never trusts the cookie alone. It trusts a **signature**
produced by a private key that:

1. Was generated inside one specific browser via `crypto.subtle.generateKey()`
   with `extractable: false`.
2. Is stored in that browser's IndexedDB and never serialized or sent
   over the network, ever.
3. Can only produce valid signatures from inside that same browser.

A copy of the cookie text — exactly what a network-based AiTM proxy
like Evilginx can capture — carries no proof of possessing that key,
so it is rejected by the `requireBoundSession` middleware in `server.js`.

## Known limitations (see README for full discussion)

- Does **not** stop a *live*, actively-relayed AiTM session (the
  victim's browser is still the one signing requests in that case).
- Does **not** protect against device-level malware with the same
  privilege as the browser — only hardware-backed keys (WebAuthn
  platform authenticators / TPM / Secure Enclave) close that gap.
- Every protected route must use the `requireBoundSession` middleware,
  or it bypasses the whole scheme.
