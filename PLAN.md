# Messenger — phone ↔ laptop web messenger (learning project)

## Context

Ivan wants a browser-only instant messenger to move text + small multimedia between his phone and laptop (and a few trusted people), free to run, with real E2EE. Primary goal is **learning end-to-end project planning, system engineering, and Claude Code-driven development** — the app itself is deliberately small-scale (10–20 devices, low volume, latency-tolerant).

**Locked decisions** (confirmed 2026-07-12):
- Backend: **Rust** (axum + tokio + sqlx), hosted on **Shuttle** free tier (Postgres via `shuttle-shared-db`)
- Frontend: **vanilla TypeScript + WebCrypto**, no framework, served as static files by the same axum service; PWA manifest for "Add to Home Screen"
- Encryption: **E2EE with static X25519 keypairs** (no ratchet) — server stores ciphertext only
- Registration: **invite codes** — seeded first account, one-time invite links
- No Java anywhere; the "API" is HTTP/WebSocket endpoints on the Rust server, called by browser JS

**Accepted tradeoffs** (stated, not hidden):
- Free tier spin-down → first request after idle waits ~30–60 s; fine per requirements
- Web-delivered E2EE protects against DB leaks / host snooping, NOT a fully hostile server (server ships the JS). Signal-grade is out of scope.
- Free DB can vanish → data-loss tolerated (content is copy-paste ephemera). No backups in v1.

## Witness stack (Ivan's own rule)

- **Audience:** <!-- TODO: name one person who gets the demo link --> 
- **Show date:** <!-- TODO: set before build starts; suggestion: 2 weeks from kickoff -->
- "Done" = link sent + message exchanged with them, not "works on my machine".

## Architecture

Single Shuttle service:

```
[phone browser]  ⇄ HTTPS/WSS ⇄  [axum on Shuttle]  ⇄  [Shuttle Postgres]
[laptop browser] ⇄ HTTPS/WSS ⇗   serves static TS/HTML too
```

- **Transport:** REST for auth/history/uploads; WebSocket (`axum::extract::ws`) for live message push; store-and-forward via DB so offline devices catch up on reconnect.
- **Static frontend:** `tower-http::services::ServeDir`; TypeScript compiled with `esbuild` (single command, no bundler config).

### Data model (Postgres, sqlx migrations)

- `users(id, username, password_hash /*argon2id*/, created_at)`
- `devices(id, user_id, name, public_key /*X25519*/, created_at)` — keypair is **per device**
- `invites(code, created_by, used_by, expires_at)`
- `sessions(token_hash, device_id, user_agent, created_at, expires_at)` — HttpOnly+Secure+SameSite cookie; session manager UI lists/revokes these
- `conversations(id, kind /*p2p | self*/)` + `conversation_members(conversation_id, user_id)`
- `conversation_keys(conversation_id, device_id, wrapped_key)` — conversation AES key wrapped for each member device
- `messages(id, conversation_id, sender_device_id, ciphertext, nonce, content_type /*text | blob*/, created_at)`
- Blobs ≤ **10 MB**, encrypted client-side, stored inline in Postgres (`bytea`) — revisit only if it hurts.

### E2EE scheme (WebCrypto)

1. On device registration, browser generates X25519 keypair; private key kept **non-extractable in IndexedDB**, public key uploaded. (ECDH P-256 fallback if a browser lacks X25519.)
2. Conversation creator generates random AES-256-GCM conversation key, wraps it for every member device via ECDH(own private, their public) → HKDF → wrap; uploads wrapped copies.
3. Messages/blobs: AES-GCM with per-message random nonce. Server never sees plaintext or unwrapped keys.
4. New device joins → any existing member device wraps the conversation key for it. Losing all devices = history unreadable (accepted).
5. MITM/impersonation residual risk: key fingerprint shown in UI for manual verification (cheap, honest).

### Opsec hardening (v1, not afterthought)

Argon2id password hashing; per-IP + per-account rate limiting (tower middleware); strict CSP (no third-party origins, no CDNs — everything self-hosted); no account enumeration (uniform auth errors); invite codes single-use with expiry; optional per-conversation retention (auto-delete after N days, default off).

## Build phases (each ends SHOWN — deploy from day one)

1. **Scaffold + hello-deploy** — vault project entry (see below), git init in `~/projects/messenger`, `cargo shuttle init` (axum), health endpoint + static "hello" page **live on Shuttle URL, opened from phone**. Verify current Shuttle free-tier limits here; fallback if unusable: Render + Neon Postgres (same code, add Dockerfile).
2. **Auth + sessions + invites** — register via invite, login, Argon2id, cookie sessions, session-manager page (list/revoke). Shown: log in from phone, revoke that session from laptop.
3. **Plaintext messaging core** — conversations (p2p + self), REST history, WebSocket live push, store-and-forward. Shown: phone→laptop text round-trip on the live URL. (Plaintext first so transport bugs aren't confused with crypto bugs.)
4. **E2EE layer** — device keypairs, key wrapping, encrypt/decrypt in client. Shown: `psql` dump displays only ciphertext while UI shows plaintext.
5. **Media + PWA** — encrypted blob upload/download ≤10 MB, image preview, PWA manifest + icon. Shown: photo phone→laptop; app icon on phone home screen.
6. **Hardening + demo** — rate limits, CSP, retention option, key fingerprints, invite a real second user. Shown: **witness demo** per show date above.

## Vault project entry (phase 1, per `06 Skills/new-project.md`)

Follow the skill's scaffold steps with already-known answers (skip interview): duplicate `04 Projects/(PROJECT TEMPLATE)` → `04 Projects/Messenger`; folders `00 Design/`, `01 Build Log/`, `02 Shipped/` + standard `System/Skills/Attachments/Iteration Logs`; write project CLAUDE.md with prime directive "shipped = witness demo on show date"; update vault root CLAUDE.md project list. Note: skill text says `03 Projects/` but the real path is `04 Projects/`.

## Verification

- Per phase: `cargo test` (auth, invite, wrapping-metadata logic) + manual round-trip on the **deployed** URL from a real phone on mobile data (not just LAN).
- E2EE proof: query `messages` in psql → ciphertext only; tamper a ciphertext byte → client shows decryption failure, not garbage (GCM auth).
- Cold start: let service idle >15 min, measure first-request wait, confirm WebSocket auto-reconnect + missed-message catch-up.
- Security pass at phase 6: check headers (CSP, HSTS), rate-limit lockout, session revocation actually kills live WebSocket.
