// Conversation-key lifecycle: fetch-and-unwrap, first-time creation, and
// wrapping for devices that joined after the key was created.

import {
  ApiError,
  conversationDevices,
  getConversationKey,
  listConversations,
  postConversationKeys,
  WrapEntry,
} from "./api";
import {
  DeviceIdentity,
  generateConversationKey,
  unwrapConversationKey,
  wrapConversationKey,
} from "./crypto";

/** Thrown when another device holds the key but none is wrapped for us yet. */
export class KeyPending extends Error {
  constructor() {
    super(
      "waiting for a conversation key — open the app on a device that already has this chat, then retry",
    );
  }
}

const cache = new Map<number, CryptoKey>();

export function dropKeyCache() {
  cache.clear();
}

async function wrapForMissing(
  conversationId: number,
  key: CryptoKey,
  me: DeviceIdentity,
): Promise<void> {
  const { devices } = await conversationDevices(conversationId);
  const missing = devices.filter((d) => !d.has_key);
  if (missing.length === 0) return;
  const entries: WrapEntry[] = [];
  for (const d of missing) {
    entries.push({
      device_id: d.device_id,
      ...(await wrapConversationKey(key, me, d.public_key, conversationId)),
    });
  }
  await postConversationKeys(conversationId, false, entries);
}

export async function ensureConvKey(
  conversationId: number,
  me: DeviceIdentity,
): Promise<CryptoKey> {
  const cached = cache.get(conversationId);
  if (cached) return cached;

  // 1) Try the wrapped copy addressed to this device.
  try {
    const wrapped = await getConversationKey(conversationId, me.deviceId);
    const key = await unwrapConversationKey(wrapped, me, conversationId);
    cache.set(conversationId, key);
    void wrapForMissing(conversationId, key, me).catch(() => {});
    return key;
  } catch (e) {
    if (!(e instanceof ApiError) || e.status !== 404) throw e;
  }

  // 2) No copy for us. Either nobody has a key yet (we create it), or another
  //    device must wrap for us first.
  const { devices } = await conversationDevices(conversationId);
  if (devices.some((d) => d.has_key)) throw new KeyPending();

  const key = await generateConversationKey();
  const entries: WrapEntry[] = [];
  for (const d of devices) {
    entries.push({
      device_id: d.device_id,
      ...(await wrapConversationKey(key, me, d.public_key, conversationId)),
    });
  }
  try {
    await postConversationKeys(conversationId, true, entries);
  } catch (e) {
    if (e instanceof ApiError && e.status === 409) {
      // Lost the creation race — someone else seeded the key; fetch theirs.
      const wrapped = await getConversationKey(conversationId, me.deviceId);
      const theirs = await unwrapConversationKey(wrapped, me, conversationId);
      cache.set(conversationId, theirs);
      return theirs;
    }
    throw e;
  }
  cache.set(conversationId, key);
  return key;
}

/**
 * Background sweep: for every conversation where this device holds the key,
 * wrap it for member devices that still lack one (e.g. a freshly registered
 * phone). Called on app entry.
 */
export async function sweepWrapMissing(me: DeviceIdentity): Promise<void> {
  try {
    const { conversations } = await listConversations();
    for (const c of conversations) {
      const key = cache.get(c.id) ?? (await tryGetKey(c.id, me));
      if (key) await wrapForMissing(c.id, key, me).catch(() => {});
    }
  } catch {
    /* sweep is best-effort */
  }
}

async function tryGetKey(
  conversationId: number,
  me: DeviceIdentity,
): Promise<CryptoKey | null> {
  try {
    const wrapped = await getConversationKey(conversationId, me.deviceId);
    const key = await unwrapConversationKey(wrapped, me, conversationId);
    cache.set(conversationId, key);
    return key;
  } catch {
    return null;
  }
}
