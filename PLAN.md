# Messenger — design & build plan

## Context

A browser-only instant messenger for moving text and small multimedia between one person's phone and laptop (plus a few trusted people), free to run, with real end-to-end encryption. Primary goal is **learning end-to-end project planning and system engineering on a deliberately small scale** — 10–20 devices, low volume, latency-tolerant.

**Locked decisions** (2026-07-12):
- Backend: **Rust** (axum + tokio + sqlx), hosted on **Render free tier** (Docker) + **Neon free Postgres**. *Was Shuttle — Shuttle ceased operations (dead by mid-2026, discovered when `api.shuttle.dev` stopped resolving). The "free provider can vanish" tradeoff, demonstrated live; fallback activated same day.*
- Frontend: **vanilla TypeScript + WebCrypto**, no framework, served as static files by the same axum service; PWA manifest for "Add to Home Screen"
- Encryption: **E2EE with static X25519 keypairs** (no ratchet) — server stores ciphertext only
- Registration: **invite codes** — seeded first account, one-time invite links

**Accepted tradeoffs** (stated, not hidden):
- Free tier spin-down → first request after idle waits ~30–60 s; fine per requirements
- Web-delivered E2EE protects against DB leaks / host snooping, NOT a fully hostile server (server ships the JS). Signal-grade is out of scope.
- Free DB can vanish → data-loss tolerated (content is copy-paste ephemera). No backups in v1.

## Architecture

Single Render web service (Docker):

```
[phone browser]  ⇄ HTTPS/WSS ⇄  [axum on Render]   ⇄  [Neon Postgres]
[laptop browser] ⇄ HTTPS/WSS ⇗   serves static TS/HTML too
```

- **Transport:** REST for auth/history/uploads; WebSocket (`axum::extract::ws`) for live message push; store-and-forward via DB so offline devices catch up on reconnect.
- **Static frontend:** `tower-http::services::ServeDir`; TypeScript compiled with `esbuild` (single command, no bundler config).

### Data model (Postgres, sqlx migrations)

- `users(id, username, password_hash /*argon2id*/, created_at)`
- `devices(id, user_id, name, public_key /*X25519*/, created_at)` — keypair is **per device**
- `invites(code, created_by, used_by, expires_at)`
- `sessions(token_hash, user_id, user_agent, created_at, expires_at)` — HttpOnly+Secure+SameSite cookie; session manager UI lists/revokes these
- `conversations(id, kind /*p2p | self*/)` + `conversation_members(conversation_id, user_id)`
- `conversation_keys(conversation_id, device_id, wrapped_key)` — conversation AES key wrapped for each member device
- `messages(id, conversation_id, sender_id, content /*ciphertext from phase 4*/, created_at)`
- Blobs ≤ **10 MB**, encrypted client-side, stored inline in Postgres (`bytea`) — revisit only if it hurts.

### E2EE scheme (WebCrypto)

1. On device registration, browser generates X25519 keypair; private key kept **non-extractable in IndexedDB**, public key uploaded. (ECDH P-256 fallback if a browser lacks X25519.)
2. Conversation creator generates random AES-256-GCM conversation key, wraps it for every member device via ECDH(own private, their public) → HKDF → wrap; uploads wrapped copies.
3. Messages/blobs: AES-GCM with per-message random nonce. Server never sees plaintext or unwrapped keys.
4. New device joins → any existing member device wraps the conversation key for it. Losing all devices = history unreadable (accepted).
5. MITM/impersonation residual risk: key fingerprint shown in UI for manual verification (cheap, honest).

### Hardening (v1, not afterthought)

Argon2id password hashing; per-IP + per-account rate limiting (tower middleware); strict CSP (no third-party origins, no CDNs — everything self-hosted); no account enumeration (uniform auth errors); invite codes single-use with expiry; optional per-conversation retention (auto-delete after N days, default off).

## Build phases (each ends deployed + demonstrated)

1. **Scaffold + hello-deploy** — repo, axum skeleton, health endpoint + static "hello" page, Dockerfile + render.yaml, live on Render URL. ✅ *(Shuttle attempted first — platform dead, pivoted same day.)*
2. **Auth + sessions + invites** — register via invite, login, Argon2id, cookie sessions, session-manager page (list/revoke). ✅
3. **Plaintext messaging core** — conversations (p2p + self), REST history, WebSocket live push + live session kick, store-and-forward. Plaintext first so transport bugs aren't confused with crypto bugs. ✅
4. **E2EE layer** — device keypairs, key wrapping, encrypt/decrypt in client. Proof: DB dump shows only ciphertext while UI shows plaintext.
5. **Media + PWA** — encrypted blob upload/download ≤10 MB, image preview, PWA manifest + icon.
6. **Hardening + demo** — rate limits, CSP, retention option, key fingerprints, real second user.

## Verification

- Per phase: `cargo test` + integration test suite + manual round-trip on the **deployed** URL from a real phone on mobile data (not just LAN).
- E2EE proof: query `messages` in psql → ciphertext only; tamper a ciphertext byte → client shows decryption failure, not garbage (GCM auth).
- Cold start: let service idle >15 min, measure first-request wait, confirm WebSocket auto-reconnect + missed-message catch-up.
- Security pass at phase 6: check headers (CSP, HSTS), rate-limit lockout, session revocation kills live WebSocket (✅ shipped in phase 3).
