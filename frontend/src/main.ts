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
  revokeSession,
  sendMessage,
  WsEvent,
} from "./api";

const $ = <T extends HTMLElement>(id: string): T =>
  document.getElementById(id) as T;

// ---------- state ----------

let loggedIn = false;
let socket: WebSocket | null = null;
let currentConv: number | null = null;
let lastMsgId = 0;

// ---------- views ----------

type View = "auth" | "chats" | "chat" | "settings";

function show(view: View) {
  $("view-auth").hidden = view !== "auth";
  $("view-chats").hidden = view !== "chats";
  $("view-chat").hidden = view !== "chat";
  $("view-settings").hidden = view !== "settings";
  $("topbar").hidden = view === "auth";
  if (view !== "chat") currentConv = null;
}

function setError(id: string, message: string) {
  $(id).textContent = message;
}

function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  return "network error — server may be waking up, retry in a minute";
}

// ---------- websocket ----------

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${proto}://${location.host}/api/ws`);
  socket.onmessage = (ev) => {
    const event: WsEvent = JSON.parse(ev.data);
    if (event.type === "message") {
      onIncoming(event.conversation_id, event.message);
    } else if (event.type === "session_revoked") {
      loggedIn = false;
      socket?.close();
      show("auth");
      setError("login-error", "this session was revoked from another device");
    }
  };
  socket.onclose = () => {
    socket = null;
    if (loggedIn) {
      // Reconnect and catch up on anything missed while offline.
      setTimeout(() => {
        if (!loggedIn) return;
        connectWs();
        if (currentConv !== null) void loadNewMessages(currentConv);
        else if (!$("view-chats").hidden) void renderConversations();
      }, 3000);
    }
  };
}

function onIncoming(conversationId: number, message: ChatMessage) {
  if (currentConv === conversationId && message.id > lastMsgId) {
    appendMessage(message);
    lastMsgId = message.id;
  } else if (!$("view-chats").hidden) {
    void renderConversations();
  }
}

// ---------- chats ----------

async function enterApp(username: string) {
  loggedIn = true;
  $("topbar-user").textContent = username;
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
        ? ` ${c.last_message.slice(0, 40)}`
        : " (no messages yet)";
      li.append(title, preview);
      li.onclick = () => void openConversation(c.id, title.textContent ?? "");
      return li;
    }),
  );
}

async function openConversation(id: number, title: string) {
  currentConv = id;
  lastMsgId = 0;
  $("chat-title").textContent = title;
  $("message-list").replaceChildren();
  show("chat");
  currentConv = id; // show() clears it
  await loadNewMessages(id);
}

async function loadNewMessages(id: number) {
  const { messages } = await listMessages(id, lastMsgId || undefined);
  if (currentConv !== id) return;
  for (const m of messages) {
    appendMessage(m);
    lastMsgId = Math.max(lastMsgId, m.id);
  }
}

function appendMessage(m: ChatMessage) {
  const list = $("message-list");
  const li = document.createElement("li");
  li.className = m.sender === $("topbar-user").textContent ? "msg mine" : "msg";
  const meta = document.createElement("div");
  meta.className = "muted";
  meta.textContent = `${m.sender} · ${m.created_at.slice(5, 16)}`;
  const body = document.createElement("div");
  body.textContent = m.content;
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
    try {
      const sent = await sendMessage(currentConv, content);
      input.value = "";
      if (sent.id > lastMsgId) {
        appendMessage(sent);
        lastMsgId = sent.id;
      }
    } catch (err) {
      setError("chat-error", errorMessage(err));
    }
  };

  $("new-invite-btn").onclick = async () => {
    await createInvite();
    await renderInvites();
  };

  getMe()
    .then((me) => enterApp(me.username))
    .catch(() => show("auth"));
}

init();
