<script>
  import { createEventDispatcher, afterUpdate } from 'svelte'
  import {
    sessions, activeSessionId, sessionMessages, sidebarTab, showWelcome,
  } from './stores.js'
  import { CopyToClipboard } from '../../wailsjs/go/main/App.js'
  import { K } from './keyboard.js'

  const dispatch = createEventDispatcher()

  let messageText = ''
  let messagesEl
  let copiedId = null

  $: activeSession = $sessions.find(s => s.id === $activeSessionId) || null
  $: isHistory = $sidebarTab === 'history'
  $: activeMsgs = $activeSessionId
    ? ($sessionMessages[$activeSessionId] || [])
    : []

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
        <div class="info-avatar" class:is-server={activeSession?.isServer}>
          <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
            {#if activeSession?.isServer}
              <path fill-rule="evenodd" d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4zm3 1h10v2H7V5zm0 3h10v2H7V8zm0 3h10v2H7v-2z" clip-rule="evenodd" />
            {:else}
              <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
            {/if}
          </svg>
        </div>
        <div class="info-details">
          <div class="info-name">{activeSession?.peerName || $activeSessionId?.slice(0, 16)}</div>
          <div class="info-sub">
            <span class="badge-type" class:live={!isHistory} class:history={isHistory}>
              {isHistory ? 'HISTORY' : 'LIVE'}
            </span>
            {#if !isHistory}
              <span class="info-meta">{activeSession?.msgCount} messages</span>
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
        {#if !isHistory}
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
          <button class="shortcut-chip" on:click={() => dispatch('openConnect')}>
            <kbd>{K('N')}</kbd>
            <span>Connect</span>
          </button>
          <button class="shortcut-chip" on:click={() => dispatch('startServer')}>
            <kbd>{K('S')}</kbd>
            <span>Start Server</span>
          </button>
          <button class="shortcut-chip" on:click={() => dispatch('toggleLogs')}>
            <kbd>{K('L')}</kbd>
            <span>Toggle Logs</span>
          </button>
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
    background: var(--accent-primary-dim);
    color: var(--accent-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .info-avatar.is-server {
    background: rgba(16, 185, 129, 0.12);
    color: var(--status-connected);
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
    cursor: pointer;
    transition: all 0.15s;
  }
  .shortcut-chip:hover {
    background: var(--bg-hover);
    border-color: var(--accent-primary);
    color: var(--text-primary);
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
</style>
