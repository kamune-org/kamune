<script>
  import { createEventDispatcher } from 'svelte'
  import {
    sessions, historySessions, activeSessionId, fingerprint,
    status, sidebarTab, dbPath, myName, relayTokens, toast,
  } from './stores.js'
  import { CopyToClipboard, SetMyName, GenerateRelayToken, RemoveRelayToken, RenameSession, RenameHistorySession } from '../../wailsjs/go/main/App.js'

  function truncateToken(t) {
    if (t.length <= 20) return t
    return t.slice(0, 8) + '…' + t.slice(-6)
  }

  function formatExpiry(rt) {
    if (rt.consumed || !rt.expiresAt) return ''
    const remaining = new Date(rt.expiresAt).getTime() - Date.now()
    if (remaining <= 0) return 'expired'
    if (remaining < 60000) return Math.ceil(remaining / 1000) + 's'
    if (remaining < 3600000) return Math.ceil(remaining / 60000) + 'm'
    return Math.ceil(remaining / 3600000) + 'h'
  }

  function formatSessionTTL(rt) {
    if (!rt.sessionTtl || rt.sessionTtl <= 0) return ''
    const d = rt.sessionTtl / 1000000000
    if (d < 60) return Math.round(d) + 's'
    if (d < 3600) return Math.round(d / 60) + 'm'
    return Math.round(d / 3600) + 'h'
  }

  const dispatch = createEventDispatcher()
  export let serverActive = false
  export let runningServerTransport = ''
  export let serverLoading = false
  export let connectLoading = false

  let copied = false
  let tokensExpanded = true
  let editingName = false
  let editName = ''
  let ctxMenu = null

  function openCtx(e, id, isHistory, name) {
    e.preventDefault()
    ctxMenu = { x: e.clientX, y: e.clientY, id, isHistory, name }
  }

  function closeCtx() {
    ctxMenu = null
  }

  let editingSessionId = null
  let editSessionName = ''
  let editingIsHistory = false

  function startRename(id, name, isHistory) {
    editingSessionId = id
    editSessionName = name
    editingIsHistory = isHistory
  }

  async function saveRename() {
    const trimmed = editSessionName.trim()
    if (trimmed && editingSessionId) {
      try {
        if (editingIsHistory) {
          await RenameHistorySession(editingSessionId, trimmed)
        } else {
          await RenameSession(editingSessionId, trimmed)
        }
        dispatch('renamed')
      } catch (e) {
        console.error('Rename error:', e)
      }
    }
    editingSessionId = null
    editSessionName = ''
  }

  function cancelRename() {
    editingSessionId = null
    editSessionName = ''
  }

  function focusInput(node) {
    node.focus()
    node.select()
  }

  function startEdit() {
    editName = $myName
    editingName = true
  }

  async function saveName() {
    const trimmed = editName.trim()
    if (trimmed && trimmed !== $myName) {
      await SetMyName(trimmed)
    }
    editingName = false
  }

  function cancelEdit() {
    editingName = false
  }

  function toggleTab(tab) {
    sidebarTab.set(tab)
    activeSessionId.set(null)
  }

  function handleItemKeydown(e, handler) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handler()
    }
  }

  function timeAgo(t) {
    if (!t) return ''
    const diff = Date.now() - new Date(t).getTime()
    const seconds = Math.floor(diff / 1000)
    if (seconds < 10) return 'just now'
    if (seconds < 60) return `${seconds}s ago`
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    if (days < 30) return `${days}d ago`
    return new Date(t).toLocaleDateString()
  }

  async function copyFingerprint() {
    if (!$fingerprint.emoji) return
    try {
      const text = $fingerprint.emoji.replace(/ • /g, ' ')
      await CopyToClipboard(text)
      copied = true
      setTimeout(() => copied = false, 1500)
    } catch (e) {
      console.error('Copy failed:', e)
    }
  }

  async function handleCopyToken(token) {
    await CopyToClipboard(token)
    toast.set({ message: 'Copied!', type: 'info' })
    setTimeout(() => toast.set(null), 2000)
  }
</script>

<div class="sidebar">
  <div class="sidebar-header">
    <div class="brand">
      <svg class="brand-icon" viewBox="0 0 20 20" fill="currentColor" width="18" height="18"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" /></svg>
      <span class="brand-text">Kamune</span>
      {#if editingName}
        <input
          class="name-input"
          type="text"
          bind:value={editName}
          maxlength="32"
          on:blur={saveName}
          on:keydown={(e) => { if (e.key === 'Enter') saveName(); if (e.key === 'Escape') cancelEdit() }}
          use:focusInput
        >
      {:else if $myName}
        <span class="brand-name" on:click={startEdit} on:keydown={(e) => e.key === 'Enter' && startEdit()} tabindex="0" role="button">{ $myName }</span>
      {/if}
    </div>
  </div>

  <div class="sidebar-tabs">
    <button
      class="tab-btn"
      class:active={$sidebarTab === 'sessions'}
      on:click={() => toggleTab('sessions')}
    >
      <svg class="tab-icon" viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
        <path d="M10 2a6 6 0 00-6 6v3.586l-.707.707A1 1 0 004 14h12a1 1 0 00.707-1.707L16 11.586V8a6 6 0 00-6-6z" />
        <path d="M7 14a3 3 0 006 0H7z" />
      </svg>
      Sessions
      {#if $sessions.length > 0}
        <span class="tab-count">{$sessions.length}</span>
      {/if}
    </button>
    <button
      class="tab-btn"
      class:active={$sidebarTab === 'history'}
      on:click={() => toggleTab('history')}
    >
      <svg class="tab-icon" viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
      </svg>
      History
      {#if $historySessions.length > 0}
        <span class="tab-count">{$historySessions.length}</span>
      {/if}
        </button>
      </div>

  <div class="sidebar-content">
    {#if $sidebarTab === 'sessions'}
      <div class="sidebar-actions">
        {#if serverLoading || connectLoading}
          <button class="action-btn action-danger" on:click={() => dispatch('cancel')}>
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
              <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
            Cancel
          </button>
        {:else}
          <button class="action-btn" class:action-primary={!serverActive} class:action-danger={serverActive} on:click={() => dispatch(serverActive ? 'stopServer' : 'startServer')}>
            {#if serverActive}
              <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8 7a1 1 0 00-1 1v4a1 1 0 001 1h4a1 1 0 001-1V8a1 1 0 00-1-1H8z" clip-rule="evenodd" />
              </svg>
              Stop Server
            {:else}
              <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd" />
              </svg>
              Start Server
            {/if}
          </button>
          <button class="action-btn action-secondary" on:click={() => dispatch('connect')}>
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
              <path d="M11 3a1 1 0 100 2h2.586l-6.293 6.293a1 1 0 101.414 1.414L15 6.414V9a1 1 0 102 0V4a1 1 0 00-1-1h-5z" />
              <path d="M5 5a2 2 0 00-2 2v8a2 2 0 002 2h8a2 2 0 002-2v-3a1 1 0 10-2 0v3H5V7h3a1 1 0 000-2H5z" />
            </svg>
            Connect
          </button>
        {/if}
      </div>

      {#if $relayTokens.length > 0 || (serverActive && runningServerTransport === 'relay')}
        <div class="relay-tokens-section">
          <div class="rt-header" on:click={() => tokensExpanded = !tokensExpanded} on:keydown={(e) => { if (e.key === 'Enter') tokensExpanded = !tokensExpanded }} role="button" tabindex="0">
            <svg class="rt-chevron" class:collapsed={!tokensExpanded} viewBox="0 0 20 20" fill="currentColor" width="10" height="10">
              <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
            <span class="rt-header-label">Relay Tokens</span>
            <span class="rt-count">{$relayTokens.length}</span>
            <button class="rt-gen-btn" on:click|stopPropagation={async () => {
              try {
                const token = await GenerateRelayToken()
                if (token) {
                  toast.set({ message: `Generated token: ${token}`, token, type: 'token' })
                  setTimeout(() => toast.set(null), 4000)
                }
              } catch (e) {
                toast.set({ message: String(e), type: 'error' })
                setTimeout(() => toast.set(null), 3000)
              }
            }}>
              <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
                <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" />
              </svg>
              Generate
            </button>
          </div>
          {#if tokensExpanded}
            <div class="rt-list">
              {#each $relayTokens as rt}
                {@const expiry = formatExpiry(rt)}
                {@const sessionTTL = formatSessionTTL(rt)}
                <div class="rt-item" class:consumed={rt.consumed}>
                  <span class="rt-dot" class:filled={rt.consumed}></span>
                  <span class="rt-item-token" role="button" tabindex="0" on:click={() => handleCopyToken(rt.token)} on:keydown={(e) => { if (e.key === 'Enter') handleCopyToken(rt.token) }}>{truncateToken(rt.token)}</span>
                  {#if expiry}
                    <span class="rt-expiry" class:expired={expiry === 'expired'}>{expiry}</span>
                  {/if}
                  {#if sessionTTL}
                    <span class="rt-session-ttl">session {sessionTTL}</span>
                  {/if}
                  <button class="rt-rm-btn" title="Remove token" on:click|stopPropagation={async () => {
                    try {
                      await RemoveRelayToken(rt.token)
                    } catch (e) {
                      console.error('Remove token failed:', e)
                    }
                  }}>
                    <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
                      <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                    </svg>
                  </button>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/if}

      <div class="list">
        {#if $sessions.length === 0}
          <div class="empty-state">
            <div class="empty-icon-wrap">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="32" height="32" stroke-width="1.5">
                <path d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
            </div>
            <p class="empty-title">No active sessions</p>
            <p class="empty-hint">Start a server or connect to a peer</p>
          </div>
        {:else}
          {#each $sessions as session}
            <div
              class="session-item"
              class:active={$activeSessionId === session.id}
              role="button"
              tabindex="0"
              on:click={() => dispatch('selectSession', session.id)}
              on:keydown={(e) => handleItemKeydown(e, () => dispatch('selectSession', session.id))}
               on:contextmenu|preventDefault={(e) => openCtx(e, session.id, false, session.peerName)}
            >
              <div class="session-indicator"></div>
              <div class="session-avatar">
                <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
                  <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
                </svg>
              </div>
              <div class="session-info">
                {#if editingSessionId === session.id}
                  <input
                    class="session-name-input"
                    type="text"
                    bind:value={editSessionName}
                    use:focusInput
                    on:blur={saveRename}
                    on:keydown|stopPropagation={(e) => { if (e.key === 'Enter') saveRename(); if (e.key === 'Escape') cancelRename() }}
                  />
                {:else}
                  <div class="session-name">{session.peerName}</div>
                {/if}
                <div class="session-meta">
                  <span class="meta-msgs">{session.msgCount} msgs</span>
                  <span class="meta-dot">·</span>
                  <span class="meta-time">{timeAgo(session.lastActivity)}</span>
                  <span class="meta-dot">·</span>
                  <span class="transport-badge" class:transport-relay={session.transportType === 'relay'} class:transport-udp={session.transportType === 'udp'}>{session.transportType}</span>
                  {#if session.remoteVersion}
                    <span class="meta-dot">·</span>
                    <span class="meta-version">v{session.remoteVersion}</span>
                  {/if}
                </div>
              </div>
            </div>
          {/each}
        {/if}
      </div>
    {:else}
      <div class="sidebar-actions">
        <button class="action-btn action-secondary" on:click={() => dispatch('refreshHistory')}>
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
            <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd" />
          </svg>
          Refresh
        </button>
      </div>

      <div class="list">
        {#if $historySessions.length === 0}
          <div class="empty-state">
            <div class="empty-icon-wrap">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="32" height="32" stroke-width="1.5">
                <path d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
            </div>
            <p class="empty-title">No history yet</p>
            <p class="empty-hint">Messages are stored when you chat</p>
          </div>
        {:else}
          {#each $historySessions as hs}
            <div
              class="session-item"
              class:active={$activeSessionId === hs.id}
              role="button"
              tabindex="0"
              on:click={() => dispatch('selectHistory', hs.id)}
              on:keydown={(e) => handleItemKeydown(e, () => dispatch('selectHistory', hs.id))}
               on:contextmenu|preventDefault={(e) => openCtx(e, hs.id, true, hs.name || hs.id.slice(0, 16))}
            >
              <div class="session-indicator"></div>
              <div class="session-avatar history">
                <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
                  <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
                </svg>
              </div>
              <div class="session-info">
                {#if editingSessionId === hs.id}
                  <input
                    class="session-name-input"
                    type="text"
                    bind:value={editSessionName}
                    use:focusInput
                    on:blur={saveRename}
                    on:keydown|stopPropagation={(e) => { if (e.key === 'Enter') saveRename(); if (e.key === 'Escape') cancelRename() }}
                  />
                {:else}
                  <div class="session-name">{hs.name || hs.id.slice(0, 16)}</div>
                {/if}
                <div class="session-meta">
                  <span class="meta-msgs">{hs.messageCount || '?'} msgs</span>
                  {#if hs.lastMessage}
                    <span class="meta-dot">·</span>
                    <span class="meta-time">{timeAgo(hs.lastMessage)}</span>
                  {/if}
                </div>
              </div>
            </div>
          {/each}
        {/if}
      </div>
    {/if}
  </div>

  {#if ctxMenu}
    <div class="ctx-overlay" on:click={closeCtx} on:contextmenu|preventDefault={closeCtx}></div>
    <div class="ctx-menu" style="left: {ctxMenu.x}px; top: {ctxMenu.y}px;">
      {#if ctxMenu.isHistory}
        <button class="ctx-item" on:click={() => { startRename(ctxMenu.id, ctxMenu.name, true); closeCtx() }}>
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"><path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" /></svg>
          Rename
        </button>
        <button class="ctx-item ctx-danger" on:click={() => { dispatch('deleteHistory', ctxMenu.id); closeCtx() }}>
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"><path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" /></svg>
          Delete
        </button>
      {:else}
        <button class="ctx-item" on:click={() => { startRename(ctxMenu.id, ctxMenu.name, false); closeCtx() }}>
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"><path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" /></svg>
          Rename
        </button>
        <button class="ctx-item ctx-danger" on:click={() => { dispatch('disconnect', ctxMenu.id); closeCtx() }}>
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"><path fill-rule="evenodd" d="M10 2a1 1 0 011 1v6a1 1 0 11-2 0V3a1 1 0 011-1z" clip-rule="evenodd" /><path fill-rule="evenodd" d="M4.903 4.903a1 1 0 01.085 1.413A6 6 0 1015.012 6.32a1 1 0 111.328-1.498 8 8 0 11-13.35 5.178 8 8 0 012.412-5.912 1 1 0 011.413-.085z" clip-rule="evenodd" /></svg>
          Disconnect
        </button>
      {/if}
      <div class="ctx-divider"></div>
      <button class="ctx-item" on:click={() => { dispatch('showInfo', ctxMenu.id); closeCtx() }}>
        <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" /></svg>
        Session Info
      </button>
    </div>
  {/if}

  <div class="sidebar-footer">
    <div class="fingerprint-card" class:clickable={!!$fingerprint.emoji} role="button" tabindex="0" on:click={copyFingerprint} on:keydown={(e) => handleItemKeydown(e, copyFingerprint)} title={$fingerprint.emoji ? 'Click to copy fingerprint' : ''}>
      <div class="fp-header">
        <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
          <path fill-rule="evenodd" d="M6.625 2.655A9 9 0 0119 11a1 1 0 11-2 0 7 7 0 00-9.625-6.492 1 1 0 11-.75-1.853zM4.662 4.959A1 1 0 014.75 6.37 6.97 6.97 0 003 11a1 1 0 11-2 0 8.97 8.97 0 012.25-5.953 1 1 0 011.412-.088z" clip-rule="evenodd" />
          <path fill-rule="evenodd" d="M5 11a5 5 0 1110 0 1 1 0 11-2 0 3 3 0 10-6 0c0 1.677-.345 3.276-.968 4.729a1 1 0 11-1.838-.789A9.964 9.964 0 005 11zm8.921 2.012a1 1 0 01.831 1.145 19.86 19.86 0 01-.545 2.436 1 1 0 11-1.92-.558c.207-.713.371-1.445.49-2.192a1 1 0 011.144-.83z" clip-rule="evenodd" />
          <path fill-rule="evenodd" d="M10 8a3 3 0 00-3 3c0 1.29-.326 2.51-.882 3.57a1 1 0 01-1.764-.944A6.96 6.96 0 007 11a1 1 0 012 0c0 .859-.144 1.685-.41 2.452a1 1 0 01-1.908-.602A4.97 4.97 0 0010 11a1 1 0 012 0 6.96 6.96 0 01-.647 2.878 1 1 0 01-1.78-.91A4.97 4.97 0 0011 11a1 1 0 012 0c0 1.556-.372 3.027-1.03 4.34a1 1 0 01-1.775-.922A6.95 6.95 0 0010 11z" clip-rule="evenodd" />
        </svg>
        <span class="fp-label">Fingerprint</span>
        {#if copied}
          <span class="fp-copied">Copied!</span>
        {/if}
      </div>
      {#if $fingerprint.emoji}
        <div class="fp-emojis">
          {#each $fingerprint.emoji.split(' • ') as emojiChar}
            <span class="fp-emoji-tile">{emojiChar}</span>
          {/each}
        </div>
      {:else}
        <div class="fp-empty">
          <span class="fp-empty-text">Start a server to generate your identity fingerprint</span>
        </div>
      {/if}
    </div>
    <div class="db-card" role="button" tabindex="0" on:click={() => dispatch('changeDBPath')} on:keydown={(e) => handleItemKeydown(e, () => dispatch('changeDBPath'))} title="Click to change database path">
      <div class="db-header">
        <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
          <path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" />
          <path d="M3 7v3c0 1.657 3.134 3 7 3s7-1.343 7-3V7c0 1.657-3.134 3-7 3S3 8.657 3 7z" />
          <path d="M17 5c0 1.657-3.134 3-7 3S3 6.657 3 5s3.134-3 7-3 7 1.343 7 3z" />
        </svg>
        <span class="db-label">Database Path</span>
        <svg class="db-edit-icon" viewBox="0 0 20 20" fill="currentColor" width="10" height="10">
          <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" />
        </svg>
      </div>
      <span class="db-path">{$dbPath}</span>
      <span class="db-hint">Click to change</span>
    </div>
  </div>
</div>

<style>
  .sidebar {
    width: var(--sidebar-width);
    min-width: var(--sidebar-width);
    background: var(--bg-sidebar);
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border-color);
  }

  .sidebar-header {
    padding: 16px 16px 12px;
    border-bottom: 1px solid var(--border-color);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .brand-icon {
    display: flex;
    color: var(--accent-primary);
  }
  .brand-text {
    font-size: 15px;
    font-weight: 700;
    letter-spacing: -0.3px;
    color: var(--text-primary);
  }
  .brand-name {
    font-size: 13px;
    color: var(--text-secondary);
    cursor: pointer;
    padding: 2px 6px;
    border-radius: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 180px;
    margin-left: auto;
  }
  .brand-name:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .name-input {
    font-size: 13px;
    padding: 2px 6px;
    border: 1px solid var(--accent-primary);
    border-radius: 4px;
    background: var(--bg-surface);
    color: var(--text-primary);
    outline: none;
    width: 180px;
    margin-left: auto;
  }

  .sidebar-tabs {
    display: flex;
    gap: 2px;
    padding: 8px 10px 0;
  }
  .tab-btn {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 8px 10px;
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-radius: var(--border-radius) var(--border-radius) 0 0;
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
  }
  .tab-btn:hover {
    color: var(--text-secondary);
    background: var(--bg-hover);
  }
  .tab-btn.active {
    color: var(--accent-primary);
    border-bottom-color: var(--accent-primary);
    background: var(--accent-primary-dim);
  }
  .tab-icon {
    flex-shrink: 0;
  }
  .tab-count {
    background: var(--bg-hover);
    color: var(--text-muted);
    font-size: 9px;
    font-weight: 700;
    padding: 1px 5px;
    border-radius: 8px;
    margin-left: 2px;
  }
  .tab-btn.active .tab-count {
    background: var(--accent-primary-dim);
    color: var(--accent-primary);
  }

  .sidebar-content {
    flex: 1;
    overflow-y: auto;
  }

  .sidebar-actions {
    display: flex;
    gap: 6px;
    padding: 10px 12px;
  }
  .action-btn {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 9px 8px;
    border-radius: var(--border-radius);
    font-size: 12px;
    font-weight: 600;
    transition: all 0.2s;
  }
  .action-primary {
    background: var(--accent-primary);
    color: #fff;
  }
  .action-primary:hover:not(:disabled) {
    background: var(--accent-primary-hover);
    box-shadow: var(--shadow-glow);
  }
  .action-primary:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }
  .action-danger {
    background: rgba(239, 68, 68, 0.12);
    color: var(--danger);
    border: 1px solid rgba(239, 68, 68, 0.25);
  }
  .action-danger:hover {
    background: rgba(239, 68, 68, 0.2);
  }
  .action-secondary {
    background: var(--bg-surface);
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
  }
  .action-secondary:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
    border-color: var(--border-light);
  }

  .list {
    padding: 2px 8px 4px;
  }

  .session-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border-radius: var(--border-radius);
    cursor: pointer;
    transition: all 0.15s;
    position: relative;
    margin-bottom: 2px;
  }
  .session-item:hover {
    background: var(--bg-hover);
  }
  .session-item.active {
    background: var(--session-active-bg);
    box-shadow: inset 2px 0 0 var(--accent-primary);
  }

  .session-indicator {
    width: 3px;
    height: 20px;
    border-radius: 2px;
    background: transparent;
    flex-shrink: 0;
  }
  .session-item.active .session-indicator {
    background: var(--accent-primary);
  }

  .session-avatar {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    background: var(--accent-primary-dim);
    color: var(--accent-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .session-avatar.history {
    background: rgba(139, 92, 246, 0.12);
    color: var(--accent-secondary);
  }

  .session-info {
    flex: 1;
    min-width: 0;
  }
  .session-name {
    font-size: 13px;
    font-weight: 500;
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    line-height: 1.3;
  }
  .session-name-input {
    font-size: 13px;
    font-weight: 500;
    color: var(--text-primary);
    background: var(--bg-input);
    border: 1px solid var(--accent-primary);
    border-radius: 4px;
    padding: 1px 4px;
    outline: none;
    width: auto;
    min-width: 40px;
    max-width: 100%;
  }
  .session-meta {
    font-size: 11px;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    gap: 4px;
    margin-top: 1px;
  }
  .meta-dot {
    color: var(--border-color);
  }
  .meta-time {
    color: var(--text-timestamp);
  }
  .transport-badge {
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    padding: 1px 5px;
    border-radius: 4px;
    background: rgba(99, 102, 241, 0.1);
    color: var(--accent-primary);
  }
  .transport-badge.transport-relay {
    background: rgba(139, 92, 246, 0.1);
    color: var(--accent-secondary);
  }
  .transport-badge.transport-udp {
    background: rgba(34, 211, 238, 0.1);
    color: #22d3ee;
  }
  .meta-version {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-timestamp);
  }

  .empty-state {
    text-align: center;
    padding: 36px 16px;
  }
  .empty-icon-wrap {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 48px;
    height: 48px;
    border-radius: 12px;
    background: var(--bg-surface);
    color: var(--text-muted);
    margin-bottom: 12px;
  }
  .empty-title {
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 500;
    margin-bottom: 4px;
  }
  .empty-hint {
    font-size: 11px;
    color: var(--text-muted);
  }

  .sidebar-footer {
    padding: 10px 12px;
    border-top: 1px solid var(--border-color);
  }

  .fingerprint-card {
    padding: 10px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    margin-bottom: 8px;
    transition: border-color 0.15s;
  }
  .fingerprint-card.clickable {
    cursor: pointer;
  }
  .fingerprint-card.clickable:hover {
    border-color: var(--accent-primary);
    background: var(--bg-hover);
  }
  .fp-header {
    display: flex;
    align-items: center;
    gap: 5px;
    margin-bottom: 8px;
  }
  .fp-label {
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    flex: 1;
  }
  .fp-copied {
    font-size: 9px;
    font-weight: 600;
    color: var(--accent-primary);
    animation: fadeIn 0.15s ease-out;
  }
  .fp-emojis {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .fp-emoji-tile {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    font-size: 16px;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    transition: all 0.15s;
  }
  .fingerprint-card.clickable:hover .fp-emoji-tile {
    border-color: var(--accent-primary);
    background: var(--accent-primary-dim);
  }
  .fp-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 30px;
  }
  .fp-empty-text {
    font-size: 10px;
    color: var(--text-muted);
    text-align: center;
    line-height: 1.4;
  }
  .db-card {
    padding: 10px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    cursor: pointer;
    transition: all 0.15s;
  }
  .db-card:hover {
    border-color: var(--accent-primary);
    background: var(--bg-hover);
  }
  .db-header {
    display: flex;
    align-items: center;
    gap: 5px;
    margin-bottom: 4px;
    color: var(--text-muted);
  }
  .db-label {
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex: 1;
  }
  .db-edit-icon {
    opacity: 0;
    color: var(--accent-primary);
    transition: opacity 0.15s;
  }
  .db-card:hover .db-edit-icon {
    opacity: 1;
  }
  .db-path {
    display: block;
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-secondary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    line-height: 1.4;
  }
  .db-hint {
    display: block;
    font-size: 9px;
    color: var(--text-timestamp);
    margin-top: 2px;
  }

  .relay-tokens-section {
    margin: 4px 10px;
    background: var(--bg-card);
    border: 1px solid var(--accent-primary-dim);
    border-radius: var(--border-radius);
    overflow: hidden;
  }
  .rt-header {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border-color);
    cursor: pointer;
    user-select: none;
    transition: background 0.12s;
  }
  .rt-header:hover {
    background: var(--bg-hover);
  }
  .rt-chevron {
    color: var(--text-muted);
    flex-shrink: 0;
    transition: transform 0.15s;
  }
  .rt-chevron.collapsed {
    transform: rotate(-90deg);
  }
  .rt-header-label {
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--accent-primary);
  }
  .rt-count {
    font-size: 9px;
    font-weight: 600;
    color: var(--text-muted);
    background: var(--bg-hover);
    border-radius: 8px;
    padding: 0 5px;
    line-height: 14px;
  }
  .rt-gen-btn {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 3px;
    padding: 3px 7px;
    font-size: 10px;
    font-weight: 600;
    border-radius: 5px;
    background: var(--accent-primary);
    color: #fff;
    border: none;
    cursor: pointer;
    transition: background 0.15s;
  }
  .rt-gen-btn:hover {
    background: var(--accent-primary-hover);
  }
  .rt-list {
    max-height: 140px;
    overflow-y: auto;
  }
  .rt-item {
    display: flex;
    align-items: center;
    padding: 4px 8px;
    gap: 4px;
    border-bottom: 1px solid var(--border-color);
  }
  .rt-item:last-child {
    border-bottom: none;
  }
  .rt-item.consumed {
    opacity: 0.5;
  }
  .rt-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    border: 1.5px solid var(--text-muted);
    flex-shrink: 0;
  }
  .rt-dot.filled {
    background: var(--text-muted);
    border-color: var(--text-muted);
  }
  .rt-item-token {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    cursor: pointer;
    transition: color 0.12s;
    flex: 1;
  }
  .rt-item-token:hover {
    color: var(--accent-primary);
  }
  .rt-expiry {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
    margin-left: 6px;
    flex-shrink: 0;
  }
  .rt-expiry.expired {
    color: var(--danger);
  }
  .rt-session-ttl {
    font-family: var(--font-mono);
    font-size: 9px;
    color: var(--accent-secondary);
    margin-left: 4px;
    flex-shrink: 0;
  }
  .rt-rm-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    border-radius: 3px;
    background: transparent;
    color: var(--text-muted);
    border: none;
    cursor: pointer;
    transition: all 0.12s;
    flex-shrink: 0;
  }
  .rt-rm-btn:hover {
    background: var(--danger-dim);
    color: var(--danger);
  }
  .ctx-overlay {
    position: fixed;
    inset: 0;
    z-index: 999;
  }
  .ctx-menu {
    position: fixed;
    z-index: 1000;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    box-shadow: var(--shadow-lg);
    min-width: 170px;
    padding: 4px;
    animation: fadeIn 0.1s ease-out;
  }
  .ctx-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 7px 10px;
    font-size: 12px;
    font-weight: 500;
    color: var(--text-primary);
    background: none;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    text-align: left;
    transition: background 0.1s;
  }
  .ctx-item:hover {
    background: var(--bg-hover);
  }
  .ctx-item svg {
    flex-shrink: 0;
    opacity: 0.6;
  }
  .ctx-danger {
    color: var(--danger);
  }
  .ctx-danger:hover {
    background: var(--danger-dim);
  }
  .ctx-divider {
    height: 1px;
    background: var(--border-color);
    margin: 3px 6px;
  }
</style>
