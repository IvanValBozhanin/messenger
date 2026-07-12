export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    throw new ApiError(res.status, await res.text());
  }
  return res.json() as Promise<T>;
}

export interface Me {
  username: string;
}

export interface Session {
  id: number;
  user_agent: string | null;
  created_at: string;
  current: boolean;
}

export interface Invite {
  code: string;
  used: boolean;
  expires_at: string;
  live: boolean;
}

export const getMe = () => api<Me>("/api/me");

export const login = (username: string, password: string) =>
  api<Me>("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

export const register = (invite: string, username: string, password: string) =>
  api<Me>("/api/register", {
    method: "POST",
    body: JSON.stringify({ invite, username, password }),
  });

export const logout = () => api<unknown>("/api/logout", { method: "POST" });

export const listSessions = () =>
  api<{ sessions: Session[] }>("/api/sessions");

export const revokeSession = (id: number) =>
  api<unknown>(`/api/sessions/${id}`, { method: "DELETE" });

export const createInvite = () =>
  api<{ code: string; expires_at: string }>("/api/invites", { method: "POST" });

export const listInvites = () => api<{ invites: Invite[] }>("/api/invites");
