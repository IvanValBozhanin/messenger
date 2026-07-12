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

export interface Conversation {
  id: number;
  kind: "p2p" | "self";
  peers: string;
  last_message: string | null;
  last_at: string | null;
}

export interface ChatMessage {
  id: number;
  sender: string;
  content: string;
  created_at: string;
}

export type WsEvent =
  | { type: "message"; conversation_id: number; message: ChatMessage }
  | { type: "session_revoked" };

export const listConversations = () =>
  api<{ conversations: Conversation[] }>("/api/conversations");

export const createConversation = (kind: "p2p" | "self", username?: string) =>
  api<{ id: number; kind: string }>("/api/conversations", {
    method: "POST",
    body: JSON.stringify({ kind, username }),
  });

export const listMessages = (conversationId: number, after?: number) =>
  api<{ messages: ChatMessage[] }>(
    `/api/conversations/${conversationId}/messages${after ? `?after=${after}` : ""}`,
  );

export const sendMessage = (conversationId: number, content: string) =>
  api<ChatMessage>(`/api/conversations/${conversationId}/messages`, {
    method: "POST",
    body: JSON.stringify({ content }),
  });

export interface ConvDevice {
  device_id: number;
  username: string;
  public_key: string;
  has_key: boolean;
}

export interface WrapEntry {
  device_id: number;
  wrapped_key: string;
  nonce: string;
  wrapper_pub: string;
}

export const registerDevice = (publicKey: string, name: string) =>
  api<{ id: number }>("/api/devices", {
    method: "POST",
    body: JSON.stringify({ public_key: publicKey, name }),
  });

export const conversationDevices = (conversationId: number) =>
  api<{ devices: ConvDevice[] }>(`/api/conversations/${conversationId}/devices`);

export const getConversationKey = (conversationId: number, deviceId: number) =>
  api<{ wrapped_key: string; nonce: string; wrapper_pub: string }>(
    `/api/conversations/${conversationId}/keys?device_id=${deviceId}`,
  );

export const postConversationKeys = (
  conversationId: number,
  initial: boolean,
  entries: WrapEntry[],
) =>
  api<unknown>(`/api/conversations/${conversationId}/keys`, {
    method: "POST",
    body: JSON.stringify({ initial, entries }),
  });
