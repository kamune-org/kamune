<script>
  import { createEventDispatcher, afterUpdate, onDestroy } from 'svelte'
  import {
    sessions, historySessions, activeSessionId, sessionMessages, sidebarTab, showWelcome,
    versionWarnings,
  } from './stores.js'
  import { CopyToClipboard, RenameSession, RenameHistorySession } from '../../wailsjs/go/main/App.js'
  import { K } from './keyboard.js'

  const dispatch = createEventDispatcher()

  let messageText = ''
  let messagesEl
  let copiedId = null
  let editingName = false
  let editName = ''

  $: activeSession = $sessions.find(s => s.id === $activeSessionId) || $historySessions.find(s => s.id === $activeSessionId) || null
  $: isHistory = $sidebarTab === 'history'
  $: activeMsgs = $activeSessionId
    ? ($sessionMessages[$activeSessionId] || [])
    : []

  let countdownNow = Date.now()
  let countdownTimer

  function stopCountdown() {
    clearInterval(countdownTimer)
  }

  $: if ($activeSessionId && !isHistory && activeSession?.sessionTTL && activeSession?.sessionStartedAt) {
    clearInterval(countdownTimer)
    countdownNow = Date.now()
    countdownTimer = setInterval(() => { countdownNow = Date.now() }, 1000)
  } else {
    clearInterval(countdownTimer)
  }

  $: remainingMs = (activeSession?.sessionTTL && activeSession?.sessionStartedAt)
    ? (new Date(activeSession.sessionStartedAt).getTime() + activeSession.sessionTTL / 1000000 - countdownNow)
    : 0

  $: countdownLabel = remainingMs > 0
    ? (() => { const s = Math.ceil(remainingMs / 1000); const m = Math.floor(s / 60); return m > 0 ? `${m}m ${s % 60}s` : `${s}s` })()
    : 'expired'

  onDestroy(() => clearInterval(countdownTimer))

  function startEdit() {
    editName = activeSession?.peerName || activeSession?.name || $activeSessionId?.slice(0, 16) || ''
    editingName = true
  }

  function selectOnMount(node) {
    node.select()
  }

  async function saveName() {
    const trimmed = editName.trim()
    if (trimmed && activeSession) {
      try {
        if (isHistory) {
          await RenameHistorySession($activeSessionId, trimmed)
        } else {
          await RenameSession($activeSessionId, trimmed)
        }
        dispatch('renamed')
      } catch (e) {
        console.error('Rename error:', e)
      }
    }
    editingName = false
  }

  function cancelEdit() {
    editingName = false
  }

  function handleSend() {
    const text = messageText.trim()
    if (!text || !$activeSessionId) return
    dispatch('sendMessage', { sessionId: $activeSessionId, text })
    messageText = ''
  }

  async function handleCopy(text, index) {
    try {
      await CopyToClipboard(text)
      copiedId = index
      setTimeout(() => { copiedId = null }, 1500)
    } catch (e) {
      console.error('Copy failed:', e)
    }
  }

  function formatTime(ts) {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  afterUpdate(() => {
    if (messagesEl) {
      messagesEl.scrollTop = messagesEl.scrollHeight
    }
  })
</script>

<div class="chat-panel">
  {#if $activeSessionId}
    <div class="info-bar">
      <div class="info-left">
        <div class="info-avatar" class:history={isHistory}>
          {#if isHistory}
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
            </svg>
          {:else}
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clip-rule="evenodd" />
            </svg>
          {/if}
        </div>
        <div class="info-details">
          {#if editingName}
            <input
              class="info-name-input"
              type="text"
              bind:value={editName}
              use:selectOnMount
              on:blur={saveName}
              on:keydown={(e) => { if (e.key === 'Enter') saveName(); if (e.key === 'Escape') cancelEdit() }}
            />
          {:else}
            <div class="info-name" role="button" tabindex="0" on:click={startEdit} on:keydown={(e) => { if (e.key === 'Enter') startEdit() }}>{activeSession?.peerName || activeSession?.name || $activeSessionId?.slice(0, 16)}</div>
          {/if}
          <div class="info-sub">
            <span class="badge-type" class:live={!isHistory} class:history={isHistory}>
              {isHistory ? 'HISTORY' : 'LIVE'}
            </span>
            {#if !isHistory}
              <span class="info-meta">{activeSession?.msgCount} messages</span>
              {#if activeSession?.sessionTTL > 0}
                <span class="countdown-sep">·</span>
                <span class="countdown-ttl" class:expired={remainingMs <= 0}>
                  {#if remainingMs > 0}
                    expires {countdownLabel}
                  {:else}
                    expired
                  {/if}
                </span>
              {/if}
            {/if}
          </div>
        </div>
      </div>
      <div class="info-actions">
        <button class="info-btn" title="Session Info" on:click={() => dispatch('showInfo', $activeSessionId)}>
          <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
          </svg>
        </button>
        {#if isHistory}
          <button class="info-btn info-btn-danger" title="Delete" on:click={() => dispatch('deleteHistory', $activeSessionId)}>
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
            </svg>
          </button>
        {:else}
          <button class="info-btn info-btn-danger" title="Disconnect" on:click={() => dispatch('disconnect', $activeSessionId)}>
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M10 2a1 1 0 011 1v6a1 1 0 11-2 0V3a1 1 0 011-1z" clip-rule="evenodd" />
              <path fill-rule="evenodd" d="M4.903 4.903a1 1 0 01.085 1.413A6 6 0 1015.012 6.32a1 1 0 111.328-1.498 8 8 0 11-13.35 5.178 8 8 0 012.412-5.912 1 1 0 011.413-.085z" clip-rule="evenodd" />
            </svg>
          </button>
        {/if}
        <button class="info-btn" title="Close" on:click={() => dispatch('closePanel')}>
          <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
            <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
          </svg>
        </button>
      </div>
    </div>
  {/if}

  {#if $activeSessionId && $versionWarnings[$activeSessionId]}
    <div class="version-warning">
      <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
      </svg>
      <span>{$versionWarnings[$activeSessionId]}</span>
      <button class="warn-dismiss" on:click={() => versionWarnings.update(w => { const n = { ...w }; delete n[$activeSessionId]; return n })}>
        <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
          <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
        </svg>
      </button>
    </div>
  {/if}

  <div class="messages" bind:this={messagesEl}>
    {#if (!$activeSessionId) || ($showWelcome && !isHistory)}
      <div class="welcome">
        <div class="welcome-icon-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="48" height="48" stroke-width="1.2">
            <path d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
          </svg>
        </div>
        <h2 class="welcome-title">Bus — Kamune Chat</h2>
        <p class="welcome-sub">Secure, end-to-end encrypted messaging</p>
        <div class="welcome-shortcuts">
          <span class="shortcut-chip">
            <kbd>{K('N')}</kbd>
            <span>Connect</span>
          </span>
          <span class="shortcut-chip">
            <kbd>{K('S')}</kbd>
            <span>Toggle Server</span>
          </span>
          <span class="shortcut-chip">
            <kbd>{K('L')}</kbd>
            <span>Toggle Logs</span>
          </span>
        </div>
      </div>
    {:else if activeMsgs.length === 0}
      <div class="empty-msgs">
        <div class="empty-msgs-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="32" height="32" stroke-width="1.5">
            <path d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
          </svg>
        </div>
        <p>No messages yet</p>
        {#if isHistory}
          <p class="readonly-hint">Viewing session history (read-only)</p>
        {:else}
          <p class="start-hint">Send a message to start the conversation</p>
        {/if}
      </div>
    {:else}
      {#each activeMsgs as msg, i}
        <div class="msg-row" class:local={msg.isLocal} class:peer={!msg.isLocal} style="animation: slideUp 0.2s ease-out">
          <div class="msg-bubble" on:click={() => handleCopy(msg.text, i)}>
            <div class="bubble-header">
              <span class="bubble-sender">{msg.isLocal ? 'You' : 'Peer'}</span>
              <span class="bubble-time">{formatTime(msg.timestamp)}</span>
            </div>
            <div class="bubble-text">{msg.text}</div>
            {#if copiedId === i}
              <div class="copied-indicator">Copied</div>
            {/if}
          </div>
        </div>
      {/each}
    {/if}
  </div>

  {#if $activeSessionId && !isHistory}
    <div class="input-area">
      <div class="input-wrapper">
        <input
          type="text"
          bind:value={messageText}
          placeholder="Type a message..."
          on:keydown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
        />
        <button
          class="send-btn"
          on:click={handleSend}
          disabled={!messageText.trim()}
        >
          <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
            <path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd" />
          </svg>
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .chat-panel {
    flex: 1;
    display: flex;
    flex-direction: column;
    background: var(--bg-primary);
    overflow: hidden;
  }

  .info-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-color);
    flex-shrink: 0;
    animation: fadeIn 0.15s ease-out;
  }
  .info-left {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .info-avatar {
    width: 34px;
    height: 34px;
    border-radius: 8px;
    background: rgba(16, 185, 129, 0.12);
    color: var(--status-connected);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .info-avatar.history {
    background: var(--accent-primary-dim);
    color: var(--accent-primary);
  }
  .info-details {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .info-name {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    cursor: pointer;
    padding: 1px 3px;
    border-radius: 4px;
    transition: background 0.12s;
  }
  .info-name:hover {
    background: var(--bg-hover);
  }
  .info-name-input {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    background: var(--bg-input);
    border: 1px solid var(--accent-primary);
    border-radius: 4px;
    padding: 1px 4px;
    outline: none;
    width: 100%;
  }
  .info-sub {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .badge-type {
    font-size: 9px;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }
  .badge-type.live {
    background: var(--accent-primary-dim);
    color: var(--accent-primary);
  }
  .badge-type.history {
    background: rgba(139, 92, 246, 0.12);
    color: var(--accent-secondary);
  }
  .info-meta {
    font-size: 11px;
    color: var(--text-muted);
  }
  .countdown-sep {
    color: var(--border-color);
    font-size: 11px;
  }
  .countdown-ttl {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--accent-secondary);
  }
  .countdown-ttl.expired {
    color: var(--danger);
  }
  .info-actions {
    display: flex;
    gap: 4px;
  }
  .info-btn {
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    color: var(--text-muted);
    border-radius: 6px;
    transition: all 0.15s;
  }
  .info-btn:hover {
    background: var(--bg-hover);
    color: var(--text-secondary);
  }
  .info-btn-info-btn-danger:hover {
    background: var(--danger-dim);
    color: var(--danger);
  }

  .messages {
    flex: 1;
    overflow-y: auto;
    padding: 16px 20px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .msg-row {
    display: flex;
    animation: slideUp 0.2s ease-out;
  }
  .msg-row.local {
    justify-content: flex-end;
  }
  .msg-row.peer {
    justify-content: flex-start;
  }

  .msg-bubble {
    max-width: 72%;
    padding: 10px 14px;
    border-radius: 14px;
    cursor: pointer;
    position: relative;
    transition: box-shadow 0.15s;
  }
  .msg-bubble:hover {
    box-shadow: 0 0 0 1px var(--border-light);
  }
  .msg-row.local .msg-bubble {
    background: var(--bubble-local-bg);
    border-bottom-right-radius: 4px;
  }
  .msg-row.peer .msg-bubble {
    background: var(--bubble-peer-bg);
    border: 1px solid var(--border-color);
    border-bottom-left-radius: 4px;
  }

  .bubble-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 3px;
    gap: 12px;
  }
  .bubble-sender {
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    color: var(--accent-primary);
    opacity: 0.9;
  }
  .msg-row.local .bubble-sender {
    color: rgba(255, 255, 255, 0.8);
  }
  .bubble-time {
    font-size: 9px;
    color: var(--text-timestamp);
    opacity: 0.7;
    white-space: nowrap;
  }
  .msg-row.local .bubble-time {
    color: rgba(255, 255, 255, 0.5);
  }

  .bubble-text {
    font-size: 14px;
    line-height: 1.45;
    word-wrap: break-word;
    color: var(--text-primary);
  }

  .copied-indicator {
    position: absolute;
    bottom: -18px;
    right: 4px;
    font-size: 9px;
    font-weight: 600;
    color: var(--accent-primary);
    background: var(--bg-surface);
    padding: 1px 6px;
    border-radius: 4px;
    border: 1px solid var(--border-color);
    animation: fadeIn 0.15s ease-out;
  }

  .welcome {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 8px;
    text-align: center;
    padding: 40px;
  }
  .welcome-icon-wrap {
    width: 72px;
    height: 72px;
    border-radius: 16px;
    background: var(--accent-primary-dim);
    color: var(--accent-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 8px;
  }
  .welcome-title {
    font-size: 20px;
    font-weight: 700;
    letter-spacing: -0.3px;
    color: var(--text-primary);
  }
  .welcome-sub {
    font-size: 13px;
    color: var(--text-muted);
    margin-bottom: 8px;
  }
  .welcome-shortcuts {
    display: flex;
    gap: 8px;
    margin-top: 4px;
  }
  .shortcut-chip {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .shortcut-chip kbd {
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 600;
    padding: 2px 6px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-bottom-width: 2px;
    border-radius: 5px;
    letter-spacing: 0.3px;
    min-width: 24px;
    text-align: center;
  }

  .empty-msgs {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 8px;
  }
  .empty-msgs-icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    background: var(--bg-surface);
    color: var(--text-muted);
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 4px;
  }
  .empty-msgs p {
    color: var(--text-muted);
    font-size: 13px;
  }
  .readonly-hint {
    color: var(--warning) !important;
    font-size: 11px !important;
    padding: 2px 8px;
    background: var(--warning-dim);
    border-radius: 4px;
  }
  .start-hint {
    font-size: 11px !important;
    color: var(--text-timestamp) !important;
  }

  .input-area {
    padding: 10px 16px;
    border-top: 1px solid var(--border-color);
    background: var(--bg-surface);
    flex-shrink: 0;
  }
  .input-wrapper {
    display: flex;
    gap: 8px;
    align-items: center;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: 24px;
    padding: 2px;
    transition: border-color 0.2s;
  }
  .input-wrapper:focus-within {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
  }
  .input-wrapper input {
    flex: 1;
    padding: 10px 14px;
    background: transparent;
    border: none;
    color: var(--text-primary);
    font-size: 14px;
  }
  .input-wrapper input::placeholder {
    color: var(--text-muted);
  }
  .send-btn {
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--accent-primary);
    color: #fff;
    border-radius: 50%;
    margin-right: 2px;
    transition: all 0.2s;
    flex-shrink: 0;
  }
  .send-btn:hover:not(:disabled) {
    background: var(--accent-primary-hover);
    box-shadow: 0 0 12px var(--accent-glow);
  }
  .send-btn:disabled {
    opacity: 0.3;
    cursor: default;
  }

  .version-warning {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: rgba(245, 158, 11, 0.12);
    border-bottom: 1px solid rgba(245, 158, 11, 0.25);
    color: #f59e0b;
    font-size: 12px;
    font-weight: 500;
    flex-shrink: 0;
  }
  .version-warning span {
    flex: 1;
  }
  .warn-dismiss {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    background: transparent;
    color: rgba(245, 158, 11, 0.6);
    border-radius: 4px;
    flex-shrink: 0;
    transition: all 0.15s;
  }
  .warn-dismiss:hover {
    background: rgba(245, 158, 11, 0.2);
    color: #f59e0b;
  }
</style>
