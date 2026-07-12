// E2EE core. Scheme:
//   - each device: X25519 keypair, private key non-extractable in IndexedDB
//   - each conversation: random AES-256-GCM key
//   - the conversation key is delivered to a device "wrapped": encrypted with
//     a KEK derived via ECDH(wrapper private, target public) -> HKDF
//   - messages: AES-GCM(conversation key, fresh 12-byte nonce)
// The server only ever sees public keys, wrapped keys, and ciphertext.

const DB_NAME = "messenger-crypto";
const STORE = "device";

export interface DeviceIdentity {
  deviceId: number;
  publicKeyB64: string;
  keyPair: CryptoKeyPair;
}

export interface WrappedKey {
  wrapped_key: string;
  nonce: string;
  wrapper_pub: string;
}

export interface Envelope {
  v: 1;
  n: string; // nonce, base64url
  ct: string; // ciphertext, base64url
}

// ---------- base64url ----------

export function toB64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64(s: string): Uint8Array {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---------- IndexedDB (stores live CryptoKey objects) ----------

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE).objectStore(STORE).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

async function dbSet(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------- device identity ----------

export function supportsX25519(): Promise<boolean> {
  return crypto.subtle
    .generateKey({ name: "X25519" }, false, ["deriveBits"])
    .then(() => true)
    .catch(() => false);
}

/**
 * Load this browser's device identity for the given user, or create one
 * (generate keypair, register public key with the server) on first use.
 * Identities are stored per (browser, username): the same browser logged into
 * a different account is a different device with its own keypair — otherwise
 * the server rejects a device id owned by another user and key delivery
 * stalls.
 *
 * `verifyFn` returns the ids of this user's devices as the server knows them;
 * if our stored device vanished server-side (DB reset, pruning), we discard
 * the stale identity and register a fresh one.
 */
export async function initDevice(
  username: string,
  registerFn: (publicKeyB64: string, name: string) => Promise<number>,
  verifyFn: () => Promise<number[]>,
): Promise<DeviceIdentity> {
  const slot = `identity:${username}`;
  const known = await verifyFn().catch(() => null);
  const owns = (d: DeviceIdentity | undefined): d is DeviceIdentity =>
    !!d && known !== null && known.includes(d.deviceId);

  // Pre-v0.5.0 identities lived in a single per-browser slot. If that legacy
  // device belongs to this account, prefer it — it is the device the
  // conversation keys were wrapped for; a newer per-account identity created
  // by the botched v0.5.0 migration holds no keys. Adopt it into the
  // per-account slot.
  const legacy = await dbGet<DeviceIdentity>("identity");
  if (owns(legacy)) {
    await dbSet(slot, legacy);
    return legacy;
  }

  const existing = await dbGet<DeviceIdentity>(slot);
  if (existing && (known === null || known.includes(existing.deviceId))) {
    return existing;
  }

  const keyPair = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const raw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const publicKeyB64 = toB64(raw);
  const name = navigator.userAgent.slice(0, 60);
  const deviceId = await registerFn(publicKeyB64, name);
  const identity: DeviceIdentity = { deviceId, publicKeyB64, keyPair };
  await dbSet(slot, identity);
  return identity;
}

// ---------- key wrapping ----------

async function importPeerPublic(pubB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", fromB64(pubB64).buffer as ArrayBuffer, { name: "X25519" }, true, []);
}

/** ECDH(private, peer public) -> HKDF -> AES-256-GCM key-encryption-key. */
async function deriveKek(
  privateKey: CryptoKey,
  peerPubB64: string,
  conversationId: number,
): Promise<CryptoKey> {
  const peer = await importPeerPublic(peerPubB64);
  const shared = await crypto.subtle.deriveBits(
    { name: "X25519", public: peer },
    privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  const enc = new TextEncoder();
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode(`msgr-v1:conv:${conversationId}`),
      info: enc.encode("wrap"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function generateConversationKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function wrapConversationKey(
  convKey: CryptoKey,
  me: DeviceIdentity,
  targetPubB64: string,
  conversationId: number,
): Promise<WrappedKey> {
  const kek = await deriveKek(me.keyPair.privateKey, targetPubB64, conversationId);
  const raw = await crypto.subtle.exportKey("raw", convKey);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, kek, raw);
  return {
    wrapped_key: toB64(wrapped),
    nonce: toB64(nonce),
    wrapper_pub: me.publicKeyB64,
  };
}

export async function unwrapConversationKey(
  wrapped: WrappedKey,
  me: DeviceIdentity,
  conversationId: number,
): Promise<CryptoKey> {
  const kek = await deriveKek(me.keyPair.privateKey, wrapped.wrapper_pub, conversationId);
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(wrapped.nonce).buffer as ArrayBuffer },
    kek,
    fromB64(wrapped.wrapped_key).buffer as ArrayBuffer,
  );
  // Extractable so this device can wrap the key for newly joined devices.
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);
}

// ---------- message encryption ----------

export async function encryptText(convKey: CryptoKey, text: string): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    convKey,
    new TextEncoder().encode(text),
  );
  const envelope: Envelope = { v: 1, n: toB64(nonce), ct: toB64(ct) };
  return JSON.stringify(envelope);
}

export function parseEnvelope(content: string): Envelope | null {
  if (!content.startsWith('{"v":1')) return null;
  try {
    const e = JSON.parse(content);
    if (e.v === 1 && typeof e.n === "string" && typeof e.ct === "string") return e;
  } catch {
    /* not an envelope */
  }
  return null;
}

export async function decryptEnvelope(
  convKey: CryptoKey,
  envelope: Envelope,
): Promise<string> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(envelope.n).buffer as ArrayBuffer },
    convKey,
    fromB64(envelope.ct).buffer as ArrayBuffer,
  );
  return new TextDecoder().decode(pt);
}

// ---------- blob encryption (attachments) ----------

export async function encryptBytes(
  convKey: CryptoKey,
  bytes: ArrayBuffer,
): Promise<{ nonceB64: string; ciphertext: ArrayBuffer }> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    convKey,
    bytes,
  );
  return { nonceB64: toB64(nonce), ciphertext };
}

export async function decryptBytes(
  convKey: CryptoKey,
  nonceB64: string,
  ciphertext: ArrayBuffer,
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(nonceB64).buffer as ArrayBuffer },
    convKey,
    ciphertext,
  );
}

/**
 * Plaintext protocol inside envelopes: ordinary messages are plain strings;
 * file messages are JSON `{"t":"file",att,name,mime,n}` where `att` is the
 * attachment id, `n` the blob nonce. The server sees none of these fields.
 */
export interface FileMeta {
  t: "file";
  att: number;
  name: string;
  mime: string;
  n: string;
}

export function parseFileMeta(plaintext: string): FileMeta | null {
  if (!plaintext.startsWith('{"t":"file"')) return null;
  try {
    const meta = JSON.parse(plaintext);
    if (
      meta.t === "file" &&
      typeof meta.att === "number" &&
      typeof meta.name === "string" &&
      typeof meta.mime === "string" &&
      typeof meta.n === "string"
    ) {
      return meta;
    }
  } catch {
    /* not a file message */
  }
  return null;
}
