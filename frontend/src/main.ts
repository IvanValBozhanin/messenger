import {
  ApiError,
  ChatMessage,
  createConversation,
  createInvite,
  getMe,
  listConversations,
  listInvites,
  listMessages,
  listSessions,
  login,
  logout,
  register,
  registerDevice,
  revokeSession,
  sendMessage,
  WsEvent,
} from "./api";
import {
  decryptBytes,
  decryptEnvelope,
  DeviceIdentity,
  encryptBytes,
  encryptText,
  initDevice,
  parseEnvelope,
  parseFileMeta,
  supportsX25519,
} from "./crypto";
import { downloadAttachment, listMyDevices, uploadAttachment } from "./api";
import { dropKeyCache, ensureConvKey, KeyPending, sweepWrapMissing } from "./keysync";

const $ = <T extends HTMLElement>(id: string): T =>
  document.getElementById(id) as T;

// ---------- state ----------

let loggedIn = false;
let socket: WebSocket | null = null;
let currentConv: number | null = null;
let currentKey: CryptoKey | null = null;
let lastMsgId = 0;
let identity: DeviceIdentity | null = null;

// ---------- views ----------

type View = "auth" | "chats" | "chat" | "settings";

function show(view: View) {
  $("view-auth").hidden = view !== "auth";
  $("view-chats").hidden = view !== "chats";
  $("view-chat").hidden = view !== "chat";
  $("view-settings").hidden = view !== "settings";
  $("topbar").hidden = view === "auth";
  if (view !== "chat") {
    currentConv = null;
    currentKey = null;
  }
}

function setError(id: string, message: string) {
  $(id).textContent = message;
}

function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof KeyPending) return e.message;
  return "network error — server may be waking up, retry in a minute";
}

// ---------- websocket ----------

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${proto}://${location.host}/api/ws`);
  socket.onmessage = async (ev) => {
    const event: WsEvent = JSON.parse(ev.data);
    if (event.type === "message") {
      await onIncoming(event.conversation_id, event.message);
    } else if (event.type === "session_revoked") {
      loggedIn = false;
      identity = null;
      dropKeyCache();
      socket?.close();
      show("auth");
      setError("login-error", "this session was revoked from another device");
    } else if (event.type === "sync_keys") {
      // Someone registered a new device — wrap conversation keys we hold.
      if (identity) void sweepWrapMissing(identity);
    } else if (event.type === "keys_updated") {
      // Fresh keys landed; if this chat was waiting for one, retry now.
      if (currentConv === event.conversation_id && !currentKey && identity) {
        const title = $("chat-title").textContent ?? "";
        void openConversation(event.conversation_id, title);
      }
    }
  };
  socket.onclose = () => {
    socket = null;
    if (loggedIn) {
      setTimeout(() => {
        if (!loggedIn) return;
        connectWs();
        if (currentConv !== null) void loadNewMessages(currentConv);
        else if (!$("view-chats").hidden) void renderConversations();
      }, 3000);
    }
  };
}

async function onIncoming(conversationId: number, message: ChatMessage) {
  if (currentConv === conversationId && message.id > lastMsgId) {
    lastMsgId = message.id;
    await appendMessage(message);
  } else if (!$("view-chats").hidden) {
    void renderConversations();
  }
}

// ---------- chats ----------

async function enterApp(username: string) {
  loggedIn = true;
  $("topbar-user").textContent = username;

  if (!(await supportsX25519())) {
    show("chats");
    setError(
      "new-conv-error",
      "this browser lacks X25519 WebCrypto — encrypted messaging unavailable; update your browser",
    );
    return;
  }
  identity = await initDevice(
    username,
    async (pub, name) => {
      const d = await registerDevice(pub, name);
      return d.id;
    },
    async () => (await listMyDevices()).device_ids,
  );
  void sweepWrapMissing(identity);

  if (!socket) connectWs();
  show("chats");
  await renderConversations();
}

async function renderConversations() {
  const { conversations } = await listConversations();
  const list = $("conv-list");
  list.replaceChildren(
    ...conversations.map((c) => {
      const li = document.createElement("li");
      li.className = "conv";
      const title = document.createElement("strong");
      title.textContent = c.kind === "self" ? "Notes to self" : c.peers;
      const preview = document.createElement("span");
      preview.className = "muted";
      preview.textContent = c.last_message
        ? parseEnvelope(c.last_message)
          ? " 🔒"
          : ` ${c.last_message.slice(0, 40)}`
        : " (no messages yet)";
      li.append(title, preview);
      li.onclick = () => void openConversation(c.id, title.textContent ?? "");
      return li;
    }),
  );
}

async function openConversation(id: number, title: string) {
  currentConv = id;
  currentKey = null;
  lastMsgId = 0;
  $("chat-title").textContent = title;
  $("message-list").replaceChildren();
  setError("chat-error", "");
  $<HTMLInputElement>("send-input").disabled = false;
  show("chat");
  currentConv = id; // show() clears it

  try {
    if (!identity) throw new Error("no device identity");
    currentKey = await ensureConvKey(id, identity);
  } catch (e) {
    setError("chat-error", errorMessage(e));
    if (e instanceof KeyPending) {
      $<HTMLInputElement>("send-input").disabled = true;
    }
  }
  await loadNewMessages(id);
}

async function loadNewMessages(id: number) {
  const { messages } = await listMessages(id, lastMsgId || undefined);
  if (currentConv !== id) return;
  for (const m of messages) {
    lastMsgId = Math.max(lastMsgId, m.id);
    await appendMessage(m);
  }
}

async function renderContent(content: string): Promise<{ text: string; note?: string }> {
  const envelope = parseEnvelope(content);
  if (!envelope) return { text: content, note: "unencrypted" };
  if (!currentKey) return { text: "🔒 (no key on this device yet)" };
  try {
    return { text: await decryptEnvelope(currentKey, envelope) };
  } catch {
    return { text: "⚠ cannot decrypt (wrong or missing key)" };
  }
}

async function appendMessage(m: ChatMessage) {
  const { text, note } = await renderContent(m.content);
  const list = $("message-list");
  const li = document.createElement("li");
  li.className = m.sender === $("topbar-user").textContent ? "msg mine" : "msg";
  const meta = document.createElement("div");
  meta.className = "muted";
  meta.textContent =
    `${m.sender} · ${m.created_at.slice(5, 16)}` + (note ? ` · ${note}` : "");
  const body = document.createElement("div");

  const file = parseFileMeta(text);
  if (file && currentKey) {
    const key = currentKey;
    const btn = document.createElement("button");
    btn.textContent = `📎 ${file.name}`;
    btn.onclick = async () => {
      btn.disabled = true;
      try {
        const ct = await downloadAttachment(file.att);
        const pt = await decryptBytes(key, file.n, ct);
        const url = URL.createObjectURL(new Blob([pt], { type: file.mime }));
        if (file.mime.startsWith("image/")) {
          const img = document.createElement("img");
          img.src = url;
          img.style.maxWidth = "100%";
          img.style.borderRadius = "0.4rem";
          body.replaceChildren(img);
        } else {
          const a = document.createElement("a");
          a.href = url;
          a.download = file.name;
          a.textContent = `save ${file.name}`;
          body.replaceChildren(a);
          a.click();
        }
      } catch {
        btn.textContent = `⚠ failed to fetch/decrypt ${file.name}`;
        btn.disabled = false;
      }
    };
    body.append(btn);
  } else {
    body.textContent = text;
  }

  li.append(meta, body);
  list.append(li);
  li.scrollIntoView({ block: "end" });
}

// ---------- settings ----------

async function renderSettings() {
  show("settings");
  await Promise.all([renderSessions(), renderInvites()]);
}

async function renderSessions() {
  const { sessions } = await listSessions();
  const list = $("session-list");
  list.replaceChildren(
    ...sessions.map((s) => {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = `${s.created_at.slice(0, 16)} — ${
        s.user_agent ?? "unknown device"
      }`;
      li.append(label);
      if (s.current) {
        const badge = document.createElement("strong");
        badge.textContent = " (this device)";
        li.append(badge);
      } else {
        const btn = document.createElement("button");
        btn.textContent = "revoke";
        btn.onclick = async () => {
          await revokeSession(s.id);
          await renderSessions();
        };
        li.append(btn);
      }
      return li;
    }),
  );
}

async function renderInvites() {
  const { invites } = await listInvites();
  const list = $("invite-list");
  list.replaceChildren(
    ...invites.map((inv) => {
      const li = document.createElement("li");
      const code = document.createElement("code");
      code.textContent = inv.code;
      li.append(code);
      const status = document.createElement("span");
      status.textContent = inv.used
        ? " — used"
        : inv.live
          ? ` — valid until ${inv.expires_at.slice(0, 10)}`
          : " — expired";
      li.append(status);
      if (!inv.used && inv.live) {
        const btn = document.createElement("button");
        btn.textContent = "copy link";
        btn.onclick = () =>
          navigator.clipboard.writeText(
            `${location.origin}/?invite=${inv.code}`,
          );
        li.append(btn);
      }
      return li;
    }),
  );
}

// ---------- wiring ----------

function init() {
  const inviteParam = new URLSearchParams(location.search).get("invite");
  if (inviteParam) {
    $<HTMLInputElement>("reg-invite").value = inviteParam;
  }

  $("login-form").onsubmit = async (e) => {
    e.preventDefault();
    setError("login-error", "");
    try {
      const me = await login(
        $<HTMLInputElement>("login-username").value,
        $<HTMLInputElement>("login-password").value,
      );
      await enterApp(me.username);
    } catch (err) {
      setError("login-error", errorMessage(err));
    }
  };

  $("register-form").onsubmit = async (e) => {
    e.preventDefault();
    setError("register-error", "");
    try {
      const me = await register(
        $<HTMLInputElement>("reg-invite").value,
        $<HTMLInputElement>("reg-username").value,
        $<HTMLInputElement>("reg-password").value,
      );
      await enterApp(me.username);
    } catch (err) {
      setError("register-error", errorMessage(err));
    }
  };

  $("tab-chats").onclick = () => {
    show("chats");
    void renderConversations();
  };
  $("tab-settings").onclick = () => void renderSettings();

  $("logout-btn").onclick = async () => {
    await logout();
    loggedIn = false;
    identity = null;
    dropKeyCache();
    socket?.close();
    show("auth");
  };

  $("back-btn").onclick = () => {
    show("chats");
    void renderConversations();
  };

  $("self-conv-btn").onclick = async () => {
    const conv = await createConversation("self");
    await openConversation(conv.id, "Notes to self");
  };

  $("new-conv-form").onsubmit = async (e) => {
    e.preventDefault();
    setError("new-conv-error", "");
    const input = $<HTMLInputElement>("new-conv-username");
    const username = input.value.trim();
    try {
      const conv = await createConversation("p2p", username);
      input.value = "";
      await openConversation(conv.id, username);
    } catch (err) {
      setError("new-conv-error", errorMessage(err));
    }
  };

  $("send-form").onsubmit = async (e) => {
    e.preventDefault();
    const input = $<HTMLInputElement>("send-input");
    const content = input.value.trim();
    if (!content || currentConv === null) return;
    if (content.length > 4000) {
      setError("chat-error", "message too long (max 4000 chars)");
      return;
    }
    try {
      if (!currentKey) throw new KeyPending();
      const ciphertext = await encryptText(currentKey, content);
      const sent = await sendMessage(currentConv, ciphertext);
      input.value = "";
      if (sent.id > lastMsgId) {
        lastMsgId = sent.id;
        await appendMessage(sent);
      }
    } catch (err) {
      setError("chat-error", errorMessage(err));
    }
  };

  $("new-invite-btn").onclick = async () => {
    await createInvite();
    await renderInvites();
  };

  $("attach-btn").onclick = () => $<HTMLInputElement>("attach-input").click();
  $("attach-input").onchange = async () => {
    const input = $<HTMLInputElement>("attach-input");
    const file = input.files?.[0];
    input.value = "";
    if (!file || currentConv === null) return;
    if (file.size > 10 * 1024 * 1024) {
      setError("chat-error", "file too large (max 10 MB)");
      return;
    }
    setError("chat-error", "");
    try {
      if (!currentKey) throw new KeyPending();
      const { nonceB64, ciphertext } = await encryptBytes(
        currentKey,
        await file.arrayBuffer(),
      );
      const attId = await uploadAttachment(currentConv, ciphertext);
      const meta = JSON.stringify({
        t: "file",
        att: attId,
        name: file.name.slice(0, 120),
        mime: file.type || "application/octet-stream",
        n: nonceB64,
      });
      const sent = await sendMessage(
        currentConv,
        await encryptText(currentKey, meta),
      );
      if (sent.id > lastMsgId) {
        lastMsgId = sent.id;
        await appendMessage(sent);
      }
    } catch (err) {
      setError("chat-error", errorMessage(err));
    }
  };

  getMe()
    .then((me) => enterApp(me.username))
    .catch(() => show("auth"));
}

init();
