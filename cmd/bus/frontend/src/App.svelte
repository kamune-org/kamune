<script>
  import { onMount, onDestroy } from 'svelte'
  import {
    GetSessions, GetHistorySessions, GetFingerprint, GetDBPath,
    GetLogEntries, GetVersion, GetStatus, GetVerificationMode,
    StartServer, ConnectToServer, StopServer, DisconnectSession,
    SendMessage, RefreshHistory, SetVerificationMode,
    ClearLogs, RenameSession, RenameHistorySession, DeleteHistorySession,
    SetActiveSession, GetStorageReady,
  } from '../wailsjs/go/main/App.js'
  import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime.js'

  import {
    sessions, historySessions, sessionMessages, status, fingerprint,
    dbPath, logEntries, verificationMode, appVersion, activeSessionId,
    sidebarTab, logPanelOpen, verificationDialog, dialogs, toast,
  } from './lib/stores.js'
  import { K, isMac } from './lib/keyboard.js'

  import Sidebar from './lib/Sidebar.svelte'
  import ChatPanel from './lib/ChatPanel.svelte'
  import StatusBar from './lib/StatusBar.svelte'
  import LogViewer from './lib/LogViewer.svelte'
  import VerifyDialog from './lib/VerifyDialog.svelte'
  import RenameDialog from './lib/RenameDialog.svelte'
  import PassphraseDialog from './lib/PassphraseDialog.svelte'

  $: serverActive = $status.status === 'connected' || $status.status === 'connecting'

  const TRANSPORTS = ['tcp', 'udp', 'relay']

  const LABELS = {
    type: 'Type',
    peerName: 'Peer Name',
    sessionID: 'Session ID',
    messageCount: 'Messages',
    lastActivity: 'Last Activity',
    isServer: 'Is Server',
    name: 'Name',
  }

  let connectServerAddr = ':8443'
  let connectServerAddr2 = ''
  let serverTransport = 'tcp'
  let connectTransport = 'tcp'
  let serverRelayAddr = ''
  let connectRelayAddr = ''
  let connectPeerKey = ''
  let serverLoading = false
  let connectLoading = false
  let showPassphraseDialog = true
  let passphraseDismissable = false

  onMount(async () => {
    const v = await GetVersion()
    appVersion.set(v)

    const s = await GetStatus()
    status.set(s)

    const fp = await GetFingerprint()
    fingerprint.set({ emoji: fp.emoji, b64: fp.b64 })

    const p = await GetDBPath()
    dbPath.set(p)

    const vm = await GetVerificationMode()
    verificationMode.set(vm)

    await loadSessions()
    await loadHistory()

    EventsOn('status-changed', (data) => status.set(data))
    EventsOn('session-new', async (data) => {
      await loadSessions()
      activeSessionId.set(data.id)
    })
    EventsOn('session-closed', async (data) => { await loadSessions() })
    EventsOn('session-updated', async (data) => { await loadSessions() })
    EventsOn('history-updated', async (data) => { await loadHistory() })
    EventsOn('session-messages', (sessionID, messages) => {
      sessionMessages.update(m => ({ ...m, [sessionID]: messages }))
    })
    EventsOn('message-sent', (sessionID, msg) => {
      sessionMessages.update(m => {
        const msgs = m[sessionID] || []
        return { ...m, [sessionID]: [...msgs, msg] }
      })
    })
    EventsOn('message-received', (sessionID, msg) => {
      sessionMessages.update(m => {
        const msgs = m[sessionID] || []
        return { ...m, [sessionID]: [...msgs, msg] }
      })
    })
    EventsOn('verify-peer', (data) => {
      verificationDialog.set(data)
    })
    EventsOn('log-entry', (entry) => {
      logEntries.update(e => {
        const next = [...e, entry]
        return next.length > 200 ? next.slice(-200) : next
      })
    })
    EventsOn('notification', (title, message) => {
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, { body: message })
      }
    })
    const ready = await GetStorageReady()
    showPassphraseDialog = !ready

    EventsOn('storage-ready', () => {
      showPassphraseDialog = false
    })
    EventsOn('request-passphrase', () => {
      showPassphraseDialog = true
      passphraseDismissable = false
    })
    EventsOn('verification-mode-changed', (mode) => {
      verificationMode.set(mode)
    })
    EventsOn('fingerprint-changed', (emoji, b64) => {
      fingerprint.set({ emoji, b64 })
    })

    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission()
    }
  })

  onDestroy(() => {
    EventsOff('status-changed')
    EventsOff('session-new')
    EventsOff('session-closed')
    EventsOff('session-updated')
    EventsOff('history-updated')
    EventsOff('session-messages')
    EventsOff('message-sent')
    EventsOff('message-received')
    EventsOff('verify-peer')
    EventsOff('log-entry')
    EventsOff('notification')
    EventsOff('storage-ready')
    EventsOff('request-passphrase')
    EventsOff('verification-mode-changed')
    EventsOff('fingerprint-changed')
  })

  async function loadSessions() {
    const s = await GetSessions()
    sessions.set(s)
  }

  async function loadHistory() {
    const h = await GetHistorySessions()
    historySessions.set(h)
  }

  async function handleStartServer() {
    if (serverTransport === 'relay' && !serverRelayAddr.trim()) {
      alert('Relay server address is required')
      return
    }
    closeAllDialogs()
    serverLoading = true
    try {
      const addr = serverTransport === 'relay' ? '' : (connectServerAddr.trim() || ':8443')
      const relayAddr = serverTransport === 'relay' ? serverRelayAddr.trim() : ''
      const fp = await StartServer(addr, serverTransport, relayAddr)
      await loadSessions()
    } catch (e) {
      alert('Failed to start server: ' + e)
    } finally {
      serverLoading = false
    }
  }

  async function handleStopServer() {
    try {
      await StopServer()
      await loadSessions()
    } catch (e) {
      console.error('Stop server error:', e)
    }
  }

  async function handleConnect() {
    if (connectTransport === 'relay') {
      if (!connectRelayAddr.trim()) {
        alert('Relay server address is required')
        return
      }
      if (!connectPeerKey.trim()) {
        alert('Peer public key is required')
        return
      }
    }
    connectLoading = true
    try {
      const addr = connectTransport === 'relay' ? '' : (connectServerAddr2.trim() || 'localhost:8443')
      const relayAddr = connectTransport === 'relay' ? connectRelayAddr.trim() : ''
      const peerKey = connectTransport === 'relay' ? connectPeerKey.trim() : ''
      const sessionId = await ConnectToServer(addr, connectTransport, relayAddr, peerKey)
      await loadSessions()
      activeSessionId.set(sessionId)
      closeAllDialogs()
    } catch (e) {
      alert('Failed to connect: ' + e)
    } finally {
      connectLoading = false
    }
  }

  async function handleDisconnect(sessionId) {
    try {
      await DisconnectSession(sessionId)
    } catch (e) {
      console.error('Disconnect error:', e)
    }
    await handleRefreshHistory()
    sidebarTab.set('history')
    activeSessionId.set(sessionId)
    await handleLoadHistoryMessages(sessionId)
  }

  async function handleSendMessage(sessionId, text) {
    if (!text.trim()) return
    try {
      await SendMessage(sessionId, text)
    } catch (e) {
      console.error('Send error:', e)
      toast.set({ message: 'Failed to send message: ' + (e.message || e), type: 'error' })
      setTimeout(() => toast.set(null), 4000)
    }
  }

  async function getSessionMessages(sessionId) {
    const { GetSessionMessages } = await import('../wailsjs/go/main/App.js')
    return await GetSessionMessages(sessionId) || []
  }

  async function handleLoadHistoryMessages(sessionId) {
    const { LoadHistoryMessages, GetHistoryMessages } = await import('../wailsjs/go/main/App.js')
    await LoadHistoryMessages(sessionId)
    const msgs = await GetHistoryMessages(sessionId) || []
    sessionMessages.update(m => ({ ...m, [sessionId]: msgs }))
  }

  async function handleRefreshHistory() {
    await RefreshHistory()
  }

  async function handleSelectTab(sessionId) {
    activeSessionId.set(sessionId)
    SetActiveSession(sessionId || '')
    if (sessionId) {
      const existing = $sessionMessages[sessionId]
      if (!existing || existing.length === 0) {
        const msgs = await getSessionMessages(sessionId)
        if (msgs.length > 0) {
          sessionMessages.update(m => ({ ...m, [sessionId]: msgs }))
        }
      }
    }
  }

  function closeAllDialogs() {
    dialogs.update(d => ({
      ...d,
      showServer: false,
      showConnect: false,
      showSessionInfo: null,
      showRename: null,
      showRenameType: null,
      showDelete: null,
      showShortcuts: false,
    }))
  }

  function handleOverlayKeydown(e) {
    if (e.key === 'Escape') closeAllDialogs()
  }

  function noopPropagationKeydown(e) {
    e.stopPropagation()
  }

  async function handleDisconnectAll() {
    const currentSessions = await GetSessions()
    for (const s of currentSessions) {
      await DisconnectSession(s.id)
    }
    activeSessionId.set(null)
    SetActiveSession('')
    await loadSessions()
  }

  function handleKeydown(e) {
    if (isMac ? e.metaKey : e.ctrlKey) {
      switch (e.key) {
        case 'l':
          e.preventDefault()
          logPanelOpen.update(v => !v)
          break
        case 'n':
          e.preventDefault()
          connectTransport = 'tcp'
          connectRelayAddr = ''
          connectPeerKey = ''
          dialogs.update(d => ({ ...d, showConnect: true }))
          break
        case 's':
          e.preventDefault()
          if (serverActive) {
            handleStopServer()
          } else {
            connectServerAddr = ':8443'
            serverTransport = 'tcp'
            serverRelayAddr = ''
            dialogs.update(d => ({ ...d, showServer: true }))
          }
          break
        case 'h':
          e.preventDefault()
          sidebarTab.set('history')
          handleRefreshHistory()
          break
        case 'w':
          e.preventDefault()
          if (e.shiftKey) {
            handleDisconnectAll()
          } else if ($activeSessionId) {
            handleDisconnect($activeSessionId)
          }
          break
        case 'r':
          e.preventDefault()
          handleRefreshHistory()
          break
      }
    }
    if (e.key === 'Escape') {
      closeAllDialogs()
      logPanelOpen.set(false)
    }
  }
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="app-layout">
  {#if showPassphraseDialog}
    <PassphraseDialog dismissable={passphraseDismissable} on:close={() => showPassphraseDialog = false} />
  {/if}

  {#if $verificationDialog}
    <VerifyDialog
      data={$verificationDialog}
      on:close={() => verificationDialog.set(null)}
    />
  {/if}

  <!-- Dialogs -->
  {#if $dialogs.showServer}
    <div class="dialog-overlay" on:click={closeAllDialogs} on:keydown={handleOverlayKeydown}>
      <div class="dialog" on:click|stopPropagation on:keydown={noopPropagationKeydown}>
        <div class="dialog-header">
          <div class="dialog-icon">
            <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
              <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd" />
            </svg>
          </div>
          <h3>Start Server</h3>
        </div>
        <div class="dialog-body">
          <div class="transport-pills">
            <span class="transport-label">Transport</span>
            <div class="pill-group">
              {#each TRANSPORTS as t}
                <button
                  class="pill-btn"
                  class:pill-active={serverTransport === t}
                  on:click={() => serverTransport = t}
                >{t.toUpperCase()}</button>
              {/each}
            </div>
          </div>

          {#if serverTransport !== 'relay'}
            <input
              bind:value={connectServerAddr}
              placeholder="Listen address (e.g. :8443)"
              class="dialog-input"
            />
            <p class="dialog-hint">Leave empty for default :8443</p>
          {:else}
            <input
              bind:value={serverRelayAddr}
              placeholder="Relay server address (e.g. 127.0.0.1:8888)"
              class="dialog-input"
            />
            <p class="dialog-hint">Address of the relay server</p>
          {/if}
        </div>
        <div class="dialog-actions">
          <button class="dialog-btn dialog-btn-secondary" on:click={closeAllDialogs}>Cancel</button>
          <button class="dialog-btn dialog-btn-primary" on:click={handleStartServer} disabled={serverLoading}>
            {serverLoading ? 'Starting…' : 'Start Server'}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if $dialogs.showConnect}
    <div class="dialog-overlay" on:click={closeAllDialogs} on:keydown={handleOverlayKeydown}>
      <div class="dialog" on:click|stopPropagation on:keydown={noopPropagationKeydown}>
        <div class="dialog-header">
          <div class="dialog-icon">
            <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
              <path d="M11 3a1 1 0 100 2h2.586l-6.293 6.293a1 1 0 101.414 1.414L15 6.414V9a1 1 0 102 0V4a1 1 0 00-1-1h-5z" />
              <path d="M5 5a2 2 0 00-2 2v8a2 2 0 002 2h8a2 2 0 002-2v-3a1 1 0 10-2 0v3H5V7h3a1 1 0 000-2H5z" />
            </svg>
          </div>
          <h3>Connect to Peer</h3>
        </div>
        <div class="dialog-body">
          <div class="transport-pills">
            <span class="transport-label">Transport</span>
            <div class="pill-group">
              {#each TRANSPORTS as t}
                <button
                  class="pill-btn"
                  class:pill-active={connectTransport === t}
                  on:click={() => connectTransport = t}
                >{t.toUpperCase()}</button>
              {/each}
            </div>
          </div>

          {#if connectTransport !== 'relay'}
            <input
              bind:value={connectServerAddr2}
              placeholder="Peer address (e.g. 192.168.1.100:8443)"
              class="dialog-input"
            />
            <p class="dialog-hint">Leave empty for default localhost:8443</p>
          {:else}
            <input
              bind:value={connectRelayAddr}
              placeholder="Relay server address (e.g. 127.0.0.1:8888)"
              class="dialog-input"
            />
            <p class="dialog-hint">Address of the relay server</p>

            <input
              bind:value={connectPeerKey}
              placeholder="Peer's base64 public key"
              class="dialog-input"
            />
            <p class="dialog-hint">Paste the peer's public key from their fingerprint</p>
          {/if}
        </div>
        <div class="dialog-actions">
          <button class="dialog-btn dialog-btn-secondary" on:click={closeAllDialogs}>Cancel</button>
          <button class="dialog-btn dialog-btn-primary" on:click={handleConnect} disabled={connectLoading}>
            {connectLoading ? 'Connecting…' : 'Connect'}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if $dialogs.showSessionInfo}
    <div class="dialog-overlay" on:click={closeAllDialogs} on:keydown={handleOverlayKeydown}>
      <div class="dialog" on:click|stopPropagation on:keydown={noopPropagationKeydown}>
        <div class="dialog-header">
          <div class="dialog-icon">
            <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
              <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
            </svg>
          </div>
          <h3>Session Info</h3>
        </div>
        <div class="dialog-body">
          <div class="info-rows">
            {#each Object.entries($dialogs.showSessionInfo) as [key, val]}
              <div class="info-row">
                <span class="info-key">{LABELS[key] || key}</span>
                <span class="info-val">
                  {#if key === 'sessionID'}
                    <code class="session-id">{val}</code>
                  {:else if key === 'lastActivity'}
                    {new Date(val).toLocaleString()}
                  {:else if key === 'isServer'}
                    {val ? 'Yes' : 'No'}
                  {:else}
                    {val}
                  {/if}
                </span>
              </div>
            {/each}
          </div>
        </div>
        <div class="dialog-actions">
          <button class="dialog-btn dialog-btn-primary" on:click={closeAllDialogs}>Close</button>
        </div>
      </div>
    </div>
  {/if}

  {#if $dialogs.showRename}
    <RenameDialog
      sessionId={$dialogs.showRename}
      isHistory={$dialogs.showRenameType === 'history'}
      on:close={closeAllDialogs}
      on:renamed={async () => { await loadSessions(); await loadHistory(); closeAllDialogs() }}
    />
  {/if}

  {#if $dialogs.showDelete}
    <div class="dialog-overlay" on:click={closeAllDialogs} on:keydown={handleOverlayKeydown}>
      <div class="dialog dialog-danger" on:click|stopPropagation on:keydown={noopPropagationKeydown}>
        <div class="dialog-header">
          <div class="dialog-icon dialog-icon-danger">
            <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
              <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
            </svg>
          </div>
          <h3>Delete Session</h3>
        </div>
        <div class="dialog-body">
          <p>Are you sure you want to permanently delete this session's history? This cannot be undone.</p>
        </div>
        <div class="dialog-actions">
          <button class="dialog-btn dialog-btn-secondary" on:click={closeAllDialogs}>Cancel</button>
          <button class="dialog-btn dialog-btn-danger" on:click={async () => {
            await DeleteHistorySession($dialogs.showDelete)
            await loadHistory()
            closeAllDialogs()
          }}>Delete</button>
        </div>
      </div>
    </div>
  {/if}

  {#if $dialogs.showShortcuts}
    <div class="dialog-overlay" on:click={closeAllDialogs} on:keydown={handleOverlayKeydown}>
      <div class="dialog dialog-wide" on:click|stopPropagation on:keydown={noopPropagationKeydown}>
        <div class="dialog-header">
          <div class="dialog-icon">
            <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
              <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd" />
            </svg>
          </div>
          <h3>Keyboard Shortcuts</h3>
        </div>
        <div class="dialog-body">
          <div class="shortcuts-grid">
            <span><kbd>{K('N')}</kbd></span><span>Connect to server</span>
            <span><kbd>{K('S')}</kbd></span><span>Toggle server</span>
            <span><kbd>{K('H')}</kbd></span><span>History tab</span>
            <span><kbd>{K('R')}</kbd></span><span>Refresh history</span>
            <span><kbd>{K('L')}</kbd></span><span>Toggle log panel</span>
            <span><kbd>{K('W')}</kbd></span><span>Close active tab</span>
            <span><kbd>{K('W+shift')}</kbd></span><span>Close all tabs</span>
            <span><kbd>Esc</kbd></span><span>Close dialog or log panel</span>
          </div>
        </div>
        <div class="dialog-actions">
          <button class="dialog-btn dialog-btn-primary" on:click={closeAllDialogs}>Close</button>
        </div>
      </div>
    </div>
  {/if}

  <div class="app-body">
    <Sidebar
      {serverActive}
      on:startServer={() => { connectServerAddr = ':8443'; serverTransport = 'tcp'; serverRelayAddr = ''; dialogs.update(d => ({ ...d, showServer: true })) }}
      on:stopServer={handleStopServer}
      on:connect={() => { connectTransport = 'tcp'; connectRelayAddr = ''; connectPeerKey = ''; dialogs.update(d => ({ ...d, showConnect: true })) }}
      on:refreshHistory={handleRefreshHistory}
      on:selectSession={(e) => {
        handleSelectTab(e.detail)
      }}
      on:selectHistory={async (e) => {
        handleSelectTab(e.detail)
        await handleLoadHistoryMessages(e.detail)
        sidebarTab.set('history')
      }}
      on:disconnect={async (e) => {
        await handleDisconnect(e.detail)
      }}
      on:showInfo={async (e) => {
        const { GetSessionInfo } = await import('../wailsjs/go/main/App.js')
        const info = await GetSessionInfo(e.detail)
        dialogs.update(d => ({ ...d, showSessionInfo: info }))
      }}
      on:rename={(e) => {
        dialogs.update(d => ({ ...d, showRename: e.detail, showRenameType: 'live' }))
      }}
      on:renameHistory={(e) => {
        dialogs.update(d => ({ ...d, showRename: e.detail, showRenameType: 'history' }))
      }}
      on:deleteHistory={(e) => {
        dialogs.update(d => ({ ...d, showDelete: e.detail }))
      }}
      on:changeDBPath={() => {
        showPassphraseDialog = true
        passphraseDismissable = true
      }}
    />

    <div class="main-content">
      <ChatPanel
        on:sendMessage={(e) => handleSendMessage(e.detail.sessionId, e.detail.text)}
        on:disconnect={(e) => handleDisconnect(e.detail)}
        on:loadHistory={async (e) => await handleLoadHistoryMessages(e.detail)}
        on:showInfo={async (e) => {
          const { GetSessionInfo } = await import('../wailsjs/go/main/App.js')
          const info = await GetSessionInfo(e.detail)
          dialogs.update(d => ({ ...d, showSessionInfo: info }))
        }}
        on:closePanel={() => activeSessionId.set(null)}
      />

      {#if $logPanelOpen}
        <LogViewer />
      {/if}
    </div>
  </div>

  <StatusBar
    on:toggleLogs={() => logPanelOpen.update(v => !v)}
    on:showShortcuts={() => dialogs.update(d => ({ ...d, showShortcuts: true }))}
  />
</div>

{#if $toast}
  <div class="toast" class:toast-error={$toast.type === 'error'} on:click={() => toast.set(null)}>
    {$toast.message}
  </div>
{/if}

<style>
  .app-layout {
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
  }
  .app-body {
    display: flex;
    flex-direction: row;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }
  .main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-height: 0;
  }

  /* ── Dialog Base ── */
  .dialog-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.65);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    animation: fadeIn 0.15s ease-out;
  }
  .dialog {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-xl);
    padding: 0;
    min-width: 400px;
    max-width: 480px;
    box-shadow: var(--shadow-lg);
    animation: fadeInScale 0.15s ease-out;
    overflow: hidden;
  }
  .dialog-danger {
    border-color: rgba(239, 68, 68, 0.3);
  }
  .dialog-wide {
    min-width: 480px;
    max-width: 520px;
  }

  .dialog-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 18px 20px 0;
  }
  .dialog-icon {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: var(--accent-primary-dim);
    color: var(--accent-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .dialog-icon-danger {
    background: var(--danger-dim);
    color: var(--danger);
  }
  .dialog-header h3 {
    font-size: 16px;
    font-weight: 700;
    color: var(--text-primary);
  }

  .dialog-body {
    padding: 16px 20px 4px;
  }
  .dialog-body p {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.5;
    margin-bottom: 14px;
  }

  .dialog-input {
    width: 100%;
    padding: 10px 14px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 13px;
    transition: border-color 0.2s;
  }
  .dialog-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
  }
  .dialog-input-wide {
    font-size: 14px;
    padding: 12px 16px;
    font-family: var(--font-mono);
  }

  .dialog-hint {
    margin-top: 8px;
    font-size: 11px;
    color: var(--text-timestamp);
  }

  /* ── Transport Pills ── */
  .transport-pills {
    margin-bottom: 14px;
  }
  .transport-label {
    display: block;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin-bottom: 6px;
  }
  .pill-group {
    display: flex;
    gap: 4px;
  }
  .pill-btn {
    flex: 1;
    padding: 7px 10px;
    border-radius: var(--border-radius);
    font-size: 12px;
    font-weight: 600;
    background: var(--bg-hover);
    color: var(--text-muted);
    border: 1px solid var(--border-color);
    transition: all 0.15s;
  }
  .pill-btn:hover {
    color: var(--text-secondary);
    border-color: var(--border-light);
  }
  .pill-btn.pill-active {
    background: var(--accent-primary);
    color: #fff;
    border-color: var(--accent-primary);
  }
  .pill-btn.pill-active:hover {
    background: var(--accent-primary-hover);
  }

  .dialog-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    padding: 16px 20px 18px;
  }
  .dialog-btn {
    padding: 8px 18px;
    border-radius: var(--border-radius);
    font-size: 13px;
    font-weight: 600;
    transition: all 0.15s;
  }
  .dialog-btn-primary {
    background: var(--accent-primary);
    color: #fff;
  }
  .dialog-btn-primary:hover {
    background: var(--accent-primary-hover);
  }
  .dialog-btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .dialog-btn-primary:disabled:hover {
    background: var(--accent-primary);
  }
  .dialog-btn-secondary {
    background: var(--bg-hover);
    color: var(--text-secondary);
  }
  .dialog-btn-secondary:hover {
    background: var(--border-color);
    color: var(--text-primary);
  }
  .dialog-btn-secondary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .dialog-btn-danger {
    background: var(--danger);
    color: #fff;
  }
  .dialog-btn-danger:hover {
    background: var(--danger-hover);
  }
  .dialog-btn-danger:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* ── Info Rows ── */
  .info-rows {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .info-row {
    display: flex;
    gap: 12px;
    padding: 6px 0;
    font-size: 13px;
    border-bottom: 1px solid var(--border-color);
  }
  .info-row:last-child {
    border-bottom: none;
  }
  .info-key {
    color: var(--text-muted);
    min-width: 110px;
    font-weight: 500;
  }
  .info-val {
    color: var(--text-primary);
    word-break: break-all;
  }
  .info-val .session-id {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    background: var(--bg-surface);
    padding: 2px 6px;
    border-radius: 4px;
    word-break: break-all;
  }

  /* ── Shortcuts ── */
  .shortcuts-grid {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 10px 28px;
    padding: 12px 24px;
    align-items: center;
    max-width: 360px;
    margin: 0 auto;
  }
  .shortcuts-grid kbd {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 600;
    color: var(--text-primary);
    background: var(--bg-input);
    padding: 3px 8px;
    border-radius: 5px;
    display: inline-block;
    border: 1px solid var(--border-color);
    border-bottom-width: 2px;
    min-width: 28px;
    text-align: center;
    letter-spacing: 0.3px;
  }
  .shortcuts-grid span:nth-child(even) {
    color: var(--text-secondary);
    font-size: 13px;
    display: flex;
    align-items: center;
    text-align: left;
  }

  .toast {
    position: fixed;
    bottom: 48px;
    left: 50%;
    transform: translateX(-50%);
    padding: 10px 20px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 500;
    z-index: 1000;
    cursor: pointer;
    animation: slideUp 0.2s ease-out;
    max-width: 80%;
    text-align: center;
    background: var(--bg-surface);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
  }
  .toast.toast-error {
    border-color: var(--danger);
    color: var(--danger);
  }
</style>
