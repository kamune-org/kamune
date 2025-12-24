import type {
  ApiResult,
  DaemonStatusData,
  SessionsListData,
} from "../types";

// Tauri API wrapper for communicating with the Rust backend
export const api = {
  async invoke<T = unknown>(
    command: string,
    args: Record<string, unknown> = {}
  ): Promise<ApiResult<T>> {
    try {
      // @ts-expect-error - Tauri is injected at runtime
      if (window.__TAURI__) {
        // @ts-expect-error - Tauri is injected at runtime
        const result = await window.__TAURI__.core.invoke(command, args);
        return result as ApiResult<T>;
      } else {
        console.warn("Tauri API not available, running in browser mode");
        return { success: false, error: "Tauri not available" };
      }
    } catch (error) {
      console.error(`API error (${command}):`, error);
      return { success: false, error: String(error) };
    }
  },

  async startDaemon(): Promise<ApiResult> {
    return this.invoke("start_daemon");
  },

  async stopDaemon(): Promise<ApiResult> {
    return this.invoke("stop_daemon");
  },

  async daemonStatus(): Promise<ApiResult<DaemonStatusData>> {
    return this.invoke<DaemonStatusData>("daemon_status");
  },

  async startServer(
    addr: string,
    storagePath: string | null = null,
    noPassphrase: boolean = true
  ): Promise<ApiResult> {
    return this.invoke("start_server", {
      addr,
      storagePath,
      noPassphrase,
    });
  },

  async dial(
    addr: string,
    storagePath: string | null = null,
    noPassphrase: boolean = true
  ): Promise<ApiResult> {
    return this.invoke("dial", {
      addr,
      storagePath,
      noPassphrase,
    });
  },

  async sendMessage(sessionId: string, message: string): Promise<ApiResult> {
    return this.invoke("send_message", {
      sessionId,
      message,
    });
  },

  async listSessions(): Promise<ApiResult<SessionsListData>> {
    return this.invoke<SessionsListData>("list_sessions");
  },

  async closeSession(sessionId: string): Promise<ApiResult> {
    return this.invoke("close_session", {
      sessionId,
    });
  },
};

// Event listener setup for Tauri events
export function setupTauriEvents(handlers: {
  onDaemonEvent?: (evt: string, data: unknown) => void;
  onReady?: (data: unknown) => void;
  onServerStarted?: (data: unknown) => void;
  onSessionStarted?: (data: unknown) => void;
  onSessionClosed?: (data: unknown) => void;
  onMessageReceived?: (data: unknown) => void;
  onMessageSent?: (data: unknown) => void;
  onError?: (data: unknown) => void;
}): () => void {
  // @ts-expect-error - Tauri is injected at runtime
  if (!window.__TAURI__) {
    console.warn("Tauri not available, skipping event listeners");
    return () => {};
  }

  // @ts-expect-error - Tauri is injected at runtime
  const { listen } = window.__TAURI__.event;
  const unlisteners: Array<() => void> = [];

  // General daemon event
  listen("daemon:event", (event: { payload: { evt: string; data: unknown } }) => {
    handlers.onDaemonEvent?.(event.payload.evt, event.payload.data);
  }).then((unlisten: () => void) => unlisteners.push(unlisten));

  // Ready event
  listen("daemon:ready", (event: { payload: { data: unknown } }) => {
    handlers.onReady?.(event.payload.data);
  }).then((unlisten: () => void) => unlisteners.push(unlisten));

  // Server started
  listen("daemon:server_started", (event: { payload: { data: unknown } }) => {
    handlers.onServerStarted?.(event.payload.data);
  }).then((unlisten: () => void) => unlisteners.push(unlisten));

  // Session started
  listen("daemon:session_started", (event: { payload: { data: unknown } }) => {
    handlers.onSessionStarted?.(event.payload.data);
  }).then((unlisten: () => void) => unlisteners.push(unlisten));

  // Session closed
  listen("daemon:session_closed", (event: { payload: { data: unknown } }) => {
    handlers.onSessionClosed?.(event.payload.data);
  }).then((unlisten: () => void) => unlisteners.push(unlisten));

  // Message received
  listen("daemon:message_received", (event: { payload: { data: unknown } }) => {
    handlers.onMessageReceived?.(event.payload.data);
  }).then((unlisten: () => void) => unlisteners.push(unlisten));

  // Message sent
  listen("daemon:message_sent", (event: { payload: { data: unknown } }) => {
    handlers.onMessageSent?.(event.payload.data);
  }).then((unlisten: () => void) => unlisteners.push(unlisten));

  // Error
  listen("daemon:error", (event: { payload: { data: unknown } }) => {
    handlers.onError?.(event.payload.data);
  }).then((unlisten: () => void) => unlisteners.push(unlisten));

  // Return cleanup function
  return () => {
    unlisteners.forEach((unlisten) => unlisten());
  };
}
