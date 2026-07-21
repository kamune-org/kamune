import { writable, derived } from 'svelte/store'

export const sessions = writable([])
export const historySessions = writable([])
export const sessionMessages = writable({})
export const status = writable({ status: 'disconnected', message: 'Not connected' })
export const fingerprint = writable({ emoji: '', b64: '', hex: '', sum: '' })
export const dbPath = writable('')
export const logEntries = writable([])

const levelOrder = ['DEBUG', 'INFO', 'WARN', 'ERROR']
export const logLevel = writable('INFO')
export const filteredLogEntries = derived(
  [logEntries, logLevel],
  ([$logEntries, $logLevel]) => {
    const min = levelOrder.indexOf($logLevel)
    return $logEntries.filter(e => levelOrder.indexOf(e.level) >= min)
  }
)

export const verificationMode = writable(1)
export const incognito = writable(false)
export const appVersion = writable('2.0.0')
export const libraryVersion = writable('')
export const myName = writable('')
export const theme = writable('')

export const activeSessionId = writable(null)
export const sidebarTab = writable('sessions') // 'sessions' | 'peers' | 'history'
export const logPanelOpen = writable(false)
export const showWelcome = derived(sessions, $sessions => $sessions.length === 0)

export const peers = writable([])

export const activeSession = derived(
  [sessions, activeSessionId],
  ([$sessions, $activeSessionId]) => {
    if ($activeSessionId === null) return null
    return $sessions.find(s => s.id === $activeSessionId) || null
  }
)

export const toast = writable(null) // { message, type: 'error'|'info'|'token' }
export const relayToken = writable('')
export const relayTokens = writable([])
export const p2pTokens = writable([])

export const verificationDialog = writable(null)
export const shareDialog = writable(null)
export const versionWarnings = writable({})
export const dialogs = writable({
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
