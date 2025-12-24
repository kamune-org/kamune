export interface Session {
  id: string;
  isServer: boolean;
  remoteAddr: string;
  createdAt: string;
}

export interface Message {
  id: string;
  text: string;
  timestamp: string;
  sent: boolean;
}

export interface EventLogEntry {
  id: string;
  time: string;
  type: string;
  data: string;
}

export interface DaemonEvent {
  evt: string;
  data: unknown;
}

export interface ApiResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface DaemonStatusData {
  running: boolean;
}

export interface SessionData {
  session_id: string;
  is_server?: boolean;
  remote_addr?: string;
  created_at?: string;
}

export interface SessionsListData {
  sessions: SessionData[];
}

export interface MessageReceivedData {
  session_id: string;
  data_base64: string;
  timestamp?: string;
}

export interface ServerStartedData {
  addr?: string;
}

export interface ErrorData {
  error?: string;
}
