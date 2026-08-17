import { derived, writable } from 'svelte/store'
import type { main } from '../../wailsjs/go/models'

export type SidebarTab = 'sessions' | 'peers' | 'history'

export interface ToastInfo {
  message: string
  token?: string
  type: 'error' | 'warning' | 'token' | 'info'
}

export interface VerificationRequest {
  requestID: number
  peerName: string
  known: boolean
  emoji: string
  hex: string
}

export interface FingerprintInfo {
  emoji: string
  b64: string
  hex: string
  sum: string
}

export interface DialogsState {
  showServer: boolean
  showConnect: boolean
  showImport: boolean
  showSessionInfo: main.SessionInfo | null
  showRename: string | null
  showRenameType: 'live' | 'history' | null
  showDelete: string | null
  showShortcuts: boolean
  showAddPeer: boolean
  showIncognitoConfirm: boolean
  peerInfoFor: string | null
}

export const sessions = writable<main.SessionInfo[]>([])
export const historySessions = writable<main.HistorySessionInfo[]>([])
export const sessionMessages = writable<Record<string, main.MessageInfo[]>>({})
export const status = writable<main.StatusInfo>({
  status: 'disconnected',
  message: 'Not connected',
})
export const fingerprint = writable<FingerprintInfo>({
  emoji: '',
  b64: '',
  hex: '',
  sum: '',
})
export const dbPath = writable('')
export const logEntries = writable<main.LogEntryInfo[]>([])

const levelOrder = ['DEBUG', 'INFO', 'WARN', 'ERROR']
export const logLevel = writable('INFO')
export const filteredLogEntries = derived(
  [logEntries, logLevel],
  ([$logEntries, $logLevel]) => {
    const min = levelOrder.indexOf($logLevel)
    return $logEntries.filter((e) => levelOrder.indexOf(e.level) >= min)
  }
)

export const verificationMode = writable(1)
export const incognito = writable(false)
export const appVersion = writable('2.0.0')
export const libraryVersion = writable('')
export const myName = writable('')
export const theme = writable('')

export const activeSessionId = writable<string | null>(null)
export const sidebarTab = writable<SidebarTab>('sessions')
export const logPanelOpen = writable(false)
export const showWelcome = derived(sessions, ($sessions) => $sessions.length === 0)

export const peers = writable<main.PeerInfo[]>([])

export const activeSession = derived(
  [sessions, activeSessionId],
  ([$sessions, $activeSessionId]) => {
    if ($activeSessionId === null) return null
    return $sessions.find((s) => s.id === $activeSessionId) || null
  }
)

export const toast = writable<ToastInfo | null>(null)
export const relayToken = writable('')
export const relayTokens = writable<main.relayToken[]>([])
export const p2pTokens = writable<main.p2pToken[]>([])

export const verificationDialog = writable<VerificationRequest | null>(null)
export const shareDialog = writable<main.ShareInfo | null>(null)
export const versionWarnings = writable<Record<string, string>>({})
export const dialogs = writable<DialogsState>({
  showServer: false,
  showConnect: false,
  showImport: false,
  showSessionInfo: null,
  showRename: null,
  showRenameType: null,
  showDelete: null,
  showShortcuts: false,
  showAddPeer: false,
  showIncognitoConfirm: false,
  peerInfoFor: null,
})