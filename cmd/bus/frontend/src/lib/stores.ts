import { derived, writable } from 'svelte/store';
import type {
  HistorySessionInfo,
  LogEntryInfo,
  MessageInfo,
  PeerInfo,
  SessionInfo,
  ShareInfo,
  StatusInfo,
  P2PToken,
  RelayToken,
} from './models';

export type SidebarTab = 'sessions' | 'peers' | 'history';

export interface ToastInfo {
  message: string;
  token?: string;
  type: 'error' | 'warning' | 'token' | 'info';
}

export interface VerificationRequest {
  requestID: number;
  // peerName is the stored name for a saved key and a key-derived label
  // otherwise; claimedName is the name the peer introduced itself with.
  peerName: string;
  claimedName: string;
  known: boolean;
  nameMismatch: boolean;
  nameConflict: boolean;
  emoji: string;
  hex: string;
}

export interface FingerprintInfo {
  emoji: string;
  b64: string;
  hex: string;
  sum: string;
}

export interface DialogsState {
  showServer: boolean;
  showConnect: boolean;
  showImport: boolean;
  showSessionInfo: SessionInfo | null;
  showRename: string | null;
  showRenameType: 'live' | 'history' | null;
  showDelete: string | null;
  showShortcuts: boolean;
  showAddPeer: boolean;
  showIncognitoConfirm: boolean;
  peerInfoFor: string | null;
}

export const sessions = writable<SessionInfo[]>([]);
export const historySessions = writable<HistorySessionInfo[]>([]);
export const sessionMessages = writable<Record<string, MessageInfo[]>>({});
export const status = writable<StatusInfo>({
  status: 'disconnected',
  message: 'Not connected',
});
export const fingerprint = writable<FingerprintInfo>({
  emoji: '',
  b64: '',
  hex: '',
  sum: '',
});
export const dbPath = writable('');
// dbNoPassphrase is set while the open database has no passphrase.
export const dbNoPassphrase = writable(false);
export const logEntries = writable<LogEntryInfo[]>([]);

const levelOrder = ['DEBUG', 'INFO', 'WARN', 'ERROR'];
export const logLevel = writable('INFO');
export const filteredLogEntries = derived([logEntries, logLevel], ([$logEntries, $logLevel]) => {
  const min = levelOrder.indexOf($logLevel);
  return $logEntries.filter((e) => levelOrder.indexOf(e.level) >= min);
});

export const verificationMode = writable(1);
export const incognito = writable(false);
export const appVersion = writable('2.0.0');
export const libraryVersion = writable('');
export const myName = writable('');
export const theme = writable('');

export const activeSessionId = writable<string | null>(null);
export const sidebarTab = writable<SidebarTab>('sessions');
export const logPanelOpen = writable(false);
export const showWelcome = derived(sessions, ($sessions) => $sessions.length === 0);

export const peers = writable<PeerInfo[]>([]);

export const activeSession = derived(
  [sessions, activeSessionId],
  ([$sessions, $activeSessionId]) => {
    if ($activeSessionId === null) return null;
    return $sessions.find((s) => s.id === $activeSessionId) || null;
  }
);

export const toast = writable<ToastInfo | null>(null);
export const relayToken = writable('');
export const relayTokens = writable<RelayToken[]>([]);
export const p2pTokens = writable<P2PToken[]>([]);

// verificationQueue holds the open verification requests, oldest first.
// The dialog shows the first one; a new request joins the end and never
// replaces the request the user is looking at.
export const verificationQueue = writable<VerificationRequest[]>([]);
export const shareDialog = writable<ShareInfo | null>(null);
export const versionWarnings = writable<Record<string, string>>({});
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
});
