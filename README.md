# Messenger

A small, self-hosted, end-to-end-encrypted web messenger for moving text and files between your own devices (and a few invited people) — phone ↔ laptop, browser only, no apps to install, runs entirely on free-tier infrastructure.

Built as a system-engineering learning project: every architectural decision, tradeoff, and failure (including the hosting provider dying mid-project) is documented in [PLAN.md](PLAN.md) and the commit history.

## What it does

- **Person-to-person chat** and **"Notes to self"** — a private channel for tossing links, text, and files between your own phone and laptop
- **Live delivery** over WebSocket — messages appear instantly, no refresh
- **Invite-only** — no open registration; the first account is bootstrapped from server logs, everyone else joins via single-use invite links
- **Session manager** — see every logged-in device, revoke any of them; revoked devices are kicked *live* over the same WebSocket
- **End-to-end encryption** — X25519 device keypairs + AES-256-GCM conversation keys via WebCrypto; the server stores only ciphertext, for messages and file attachments alike
- **Installable** — PWA manifest; "Add to Home Screen" on the phone makes it feel like a native app while staying a plain web page

## Architecture

```
[phone browser]  ⇄ HTTPS/WSS ⇄  [axum on Render]   ⇄  [Neon Postgres]
[laptop browser] ⇄ HTTPS/WSS ⇗   serves static TS/HTML too
```

One Rust binary does everything: serves the static frontend, exposes a REST API (auth, history, sends), and pushes live events over WebSocket. Messages are store-and-forward — offline devices catch up via an `after=<id>` cursor on reconnect.

**Stack:** Rust (axum + tokio + sqlx) · vanilla TypeScript (no framework, esbuild) · Postgres · Docker on Render free tier + Neon free Postgres.

**Why this stack:** the project optimizes for learning fundamentals — a systems language on the backend, the bare browser platform (fetch, WebSocket, WebCrypto, DOM) on the frontend, zero framework magic in between.

## Security design

| Layer | Mechanism |
|---|---|
| Passwords | Argon2id, verified in constant-time-ish fashion (dummy-hash for unknown users — no timing-based username probing) |
| Sessions | 256-bit random tokens in `HttpOnly; Secure; SameSite=Strict` cookies; DB stores only the SHA-256 of the token, so a leaked sessions table can't be replayed |
| Registration | Single-use invite codes with 7-day expiry; no open signup, no account enumeration (uniform errors) |
| Transport | TLS everywhere (Render-terminated) |
| Content *(phase 4)* | E2EE: per-device X25519 keypairs (non-extractable, IndexedDB), per-conversation AES-256-GCM keys wrapped for each member device via ECDH → HKDF |

### Threat model — honest version

**Protected against:** network eavesdroppers (TLS), database leaks (hashed passwords, hashed session tokens, and — from phase 4 — ciphertext-only message storage), nosy hosting/DB providers (E2EE), strangers finding the URL (invite-only).

**Not protected against:** a fully malicious server. This is a web app; the server ships the JavaScript that performs the crypto, so a hostile operator could serve a backdoored client. That is an inherent limit of browser-delivered E2EE — accepted here, since the operator and the users are the same person. Signal-grade guarantees require an installed, verifiable client, which is explicitly out of scope.

There is no forward secrecy (static keys, no ratchet): a compromised device key exposes past messages of its conversations. Accepted for this scale.

## Running it

```bash
# local dev
docker run -d --name pg -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=messenger -p 5433:5432 postgres:18
cd frontend && npm install && npm run build && cd ..
DATABASE_URL=postgres://postgres:dev@localhost:5433/messenger cargo run
# first start prints a BOOTSTRAP INVITE CODE to the logs — register with it
```

Deploy: any Docker host works. `render.yaml` is included — connect the repo to Render, set `DATABASE_URL`, done. Migrations run automatically at startup.

## Project status

- [x] Phase 1 — scaffold + hello-deploy
- [x] Phase 2 — auth, sessions, invites
- [x] Phase 3 — messaging core + WebSocket live push + live session kick
- [x] Phase 4 — end-to-end encryption
- [x] Phase 5 — encrypted media (≤10 MB, client-side encrypted blobs) + PWA
- [ ] Phase 6 — hardening (rate limits, CSP, retention)

## License

MIT
