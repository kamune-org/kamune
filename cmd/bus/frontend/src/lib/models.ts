export interface ConnectResult {
  sessionId: string
  errorCode: string
}

export interface HistorySessionInfo {
  id: string
  name: string
  messageCount: number
  firstMessage: string
  lastMessage: string
  loaded: boolean
}

export interface LogEntryInfo {
  timestamp: string
  level: string
  message: string
}

export interface MessageInfo {
  text: string
  timestamp: string
  isLocal: boolean
}

export interface PeerInfo {
  name: string
  publicKeyBase64: string
  firstSeen: string
  lastSeen: string
  fingerprintEmoji: string
}

export interface ServerStatusInfo {
  running: boolean
  transport: string
  addr: string
  relayAddr: string
  name: string
  startedAt?: string
}

export interface SessionInfo {
  id: string
  peerName: string
  isServer: boolean
  msgCount: number
  lastActivity: string
  transportType: string
  remoteVersion: string
  sessionTTL: number
  sessionStartedAt: string
}

export interface ShareRelayInfo {
  address: string
  scheme: string
  token: string
  password: boolean
}

export interface ShareInfo {
  url: string
  transport: string
  address: string
  port: string
  fingerprintEmoji: string
  fingerprintHex: string
  relayInfo?: ShareRelayInfo | null
}

export interface StatusInfo {
  status: string
  message: string
}

export interface P2PToken {
  token: string
  consumed: boolean
  ttl: number
  expiresAt: string
  mode: string
  peerPubB64?: string
}

export interface RelayToken {
  token: string
  consumed: boolean
  ttl: number
  sessionTtl: number
  expiresAt: string
  mode: string
  peerPubB64?: string
}
