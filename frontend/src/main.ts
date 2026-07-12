import {
  ApiError,
  createInvite,
  getMe,
  listInvites,
  listSessions,
  login,
  logout,
  register,
  revokeSession,
} from "./api";

const $ = <T extends HTMLElement>(id: string): T =>
  document.getElementById(id) as T;

function show(view: "auth" | "home") {
  $("view-auth").hidden = view !== "auth";
  $("view-home").hidden = view !== "home";
}

function setError(id: string, message: string) {
  $(id).textContent = message;
}

function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  return "network error — server may be waking up, retry in a minute";
}

async function renderHome(username: string) {
  $("home-user").textContent = username;
  show("home");
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

function init() {
  // Prefill invite code from ?invite=... links.
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
      await renderHome(me.username);
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
      await renderHome(me.username);
    } catch (err) {
      setError("register-error", errorMessage(err));
    }
  };

  $("logout-btn").onclick = async () => {
    await logout();
    show("auth");
  };

  $("new-invite-btn").onclick = async () => {
    await createInvite();
    await renderInvites();
  };

  getMe()
    .then((me) => renderHome(me.username))
    .catch(() => show("auth"));
}

init();
