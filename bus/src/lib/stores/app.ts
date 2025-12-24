import { writable, derived } from "svelte/store";
import type { Session, Message, EventLogEntry } from "../types";

// Daemon state
export const daemonRunning = writable<boolean>(false);

// Sessions
export const sessions = writable<Map<string, Session>>(new Map());
export const currentSessionId = writable<string | null>(null);

// Messages by session ID
export const messages = writable<Map<string, Message[]>>(new Map());

// Event log
export const eventLog = writable<EventLogEntry[]>([]);

// UI state
export const showEventsLog = writable<boolean>(true);

// Derived stores
export const currentSession = derived(
  [sessions, currentSessionId],
  ([$sessions, $currentSessionId]) => {
    if (!$currentSessionId) return null;
    return $sessions.get($currentSessionId) ?? null;
  },
);

export const currentMessages = derived(
  [messages, currentSessionId],
  ([$messages, $currentSessionId]) => {
    if (!$currentSessionId) return [];
    return $messages.get($currentSessionId) ?? [];
  },
);

export const sessionsList = derived(sessions, ($sessions) => {
  return Array.from($sessions.values());
});

// Helper functions
export function addSession(sessionData: {
  session_id: string;
  is_server?: boolean;
  remote_addr?: string;
}) {
  const id = sessionData.session_id;
  const session: Session = {
    id,
    isServer: sessionData.is_server ?? false,
    remoteAddr: sessionData.remote_addr ?? "",
    createdAt: new Date().toISOString(),
  };

  sessions.update((s) => {
    s.set(id, session);
    return new Map(s);
  });

  // Initialize messages for this session if not exists
  messages.update((m) => {
    if (!m.has(id)) {
      m.set(id, []);
    }
    return new Map(m);
  });
}

export function removeSession(sessionId: string) {
  sessions.update((s) => {
    s.delete(sessionId);
    return new Map(s);
  });

  // Clear current session if it was the one removed
  currentSessionId.update((current) => {
    if (current === sessionId) return null;
    return current;
  });
}

export function addMessage(sessionId: string, message: Omit<Message, "id">) {
  const messageWithId: Message = {
    ...message,
    id: crypto.randomUUID(),
  };

  messages.update((m) => {
    const sessionMessages = m.get(sessionId) ?? [];
    m.set(sessionId, [...sessionMessages, messageWithId]);
    return new Map(m);
  });
}

export function logEvent(type: string, data: unknown) {
  const entry: EventLogEntry = {
    id: crypto.randomUUID(),
    time: new Date().toLocaleTimeString(),
    type: type.toUpperCase(),
    data: typeof data === "object" ? JSON.stringify(data) : String(data),
  };

  eventLog.update((log) => {
    const newLog = [...log, entry];
    // Keep only last 100 entries
    if (newLog.length > 100) {
      return newLog.slice(-100);
    }
    return newLog;
  });
}

export function clearSessions() {
  sessions.set(new Map());
  messages.set(new Map());
  currentSessionId.set(null);
}

export function selectSession(sessionId: string | null) {
  currentSessionId.set(sessionId);
}

// Helper to truncate session IDs for display
export function truncateId(id: string | null): string {
  if (!id) return "";
  if (id.length <= 12) return id;
  return id.substring(0, 6) + "..." + id.substring(id.length - 4);
}
