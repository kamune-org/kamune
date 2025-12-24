<script lang="ts">
  import {
    currentSession,
    currentSessionId,
    currentMessages,
    addMessage,
    removeSession,
    selectSession,
    truncateId,
    logEvent,
  } from "../stores/app";
  import { api } from "../api/tauri";
  import { tick } from "svelte";

  let messageInput = $state("");
  let isSending = $state(false);
  let isClosing = $state(false);
  let messagesContainer: HTMLDivElement | null = $state(null);

  // Auto-scroll to bottom when messages change
  $effect(() => {
    if ($currentMessages.length > 0 && messagesContainer) {
      tick().then(() => {
        if (messagesContainer) {
          messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
      });
    }
  });

  async function handleSendMessage() {
    const message = messageInput.trim();
    if (!message || !$currentSessionId || isSending) return;

    messageInput = "";
    isSending = true;

    // Optimistic update
    addMessage($currentSessionId, {
      text: message,
      timestamp: new Date().toISOString(),
      sent: true,
    });

    const result = await api.sendMessage($currentSessionId, message);

    if (!result.success) {
      logEvent("error", result.error || "Failed to send message");
    }

    isSending = false;
  }

  async function handleCloseSession() {
    if (!$currentSessionId || isClosing) return;

    const sessionId = $currentSessionId;
    isClosing = true;
    logEvent("info", `Closing session ${truncateId(sessionId)}...`);

    const result = await api.closeSession(sessionId);

    if (result.success) {
      removeSession(sessionId);
      logEvent("info", "Session closed");
    } else {
      logEvent("error", result.error || "Failed to close session");
    }

    isClosing = false;
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  }

  function formatTime(timestamp: string): string {
    return new Date(timestamp).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  }
</script>

<div class="chat-area">
  <!-- Chat Header -->
  <header class="chat-header">
    {#if $currentSession}
      <div class="header-info">
        <div class="avatar" class:server={$currentSession.isServer}>
          {#if $currentSession.isServer}
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <rect x="2" y="2" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2" />
              <rect x="2" y="14" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2" />
            </svg>
          {:else}
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" stroke="currentColor" stroke-width="2" />
              <circle cx="12" cy="7" r="4" stroke="currentColor" stroke-width="2" />
            </svg>
          {/if}
        </div>
        <div class="header-text">
          <h2 class="session-title">{truncateId($currentSession.id)}</h2>
          <span class="session-subtitle">
            {$currentSession.isServer ? "Server" : "Client"} •
            {$currentSession.remoteAddr || "Local connection"}
          </span>
        </div>
      </div>
      <button
        class="btn btn-danger btn-sm"
        onclick={handleCloseSession}
        disabled={isClosing}
      >
        {#if isClosing}
          <span class="spinner"></span>
        {:else}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
            <line x1="18" y1="6" x2="6" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
            <line x1="6" y1="6" x2="18" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
          </svg>
        {/if}
        Close
      </button>
    {:else}
      <div class="header-info">
        <h2 class="session-title muted">Select a session</h2>
      </div>
    {/if}
  </header>

  <!-- Messages Container -->
  <div class="messages-container" bind:this={messagesContainer}>
    {#if !$currentSession}
      <div class="empty-state">
        <div class="empty-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none">
            <path
              d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
        </div>
        <h3>No Session Selected</h3>
        <p>Select a session from the sidebar to start messaging</p>
      </div>
    {:else if $currentMessages.length === 0}
      <div class="empty-state">
        <div class="empty-icon wave">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none">
            <path
              d="M7 11v-1a5 5 0 0 1 10 0v1"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
            />
            <path
              d="M12 16v.01"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
            />
            <rect
              x="4"
              y="11"
              width="16"
              height="10"
              rx="2"
              stroke="currentColor"
              stroke-width="1.5"
            />
          </svg>
        </div>
        <h3>Say Hello!</h3>
        <p>Start the conversation by sending a message</p>
      </div>
    {:else}
      <div class="messages">
        {#each $currentMessages as message (message.id)}
          <div class="message" class:sent={message.sent} class:received={!message.sent}>
            <div class="message-bubble">
              <p class="message-text">{message.text}</p>
              <span class="message-time">{formatTime(message.timestamp)}</span>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Message Input -->
  <footer class="message-input-area">
    <div class="input-wrapper">
      <input
        type="text"
        bind:value={messageInput}
        placeholder={$currentSession ? "Type a message..." : "Select a session to start"}
        disabled={!$currentSession || isSending}
        onkeydown={handleKeyDown}
      />
      <button
        class="send-btn"
        onclick={handleSendMessage}
        disabled={!$currentSession || !messageInput.trim() || isSending}
      >
        {#if isSending}
          <span class="spinner"></span>
        {:else}
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <line x1="22" y1="2" x2="11" y2="13" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
            <polygon points="22 2 15 22 11 13 2 9 22 2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="currentColor" fill-opacity="0.1" />
          </svg>
        {/if}
      </button>
    </div>
  </footer>
</div>

<style>
  .chat-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    background: var(--color-bg-primary);
    overflow: hidden;
  }

  /* Header */
  .chat-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--spacing-md) var(--spacing-lg);
    background: var(--color-bg-secondary);
    border-bottom: 1px solid var(--color-border);
    min-height: 64px;
  }

  .header-info {
    display: flex;
    align-items: center;
    gap: var(--spacing-md);
  }

  .avatar {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: var(--radius-lg);
    background: var(--color-bg-tertiary);
    color: var(--color-text-secondary);
  }

  .avatar.server {
    background: var(--color-success-subtle);
    color: var(--color-success);
  }

  .header-text {
    display: flex;
    flex-direction: column;
  }

  .session-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--color-text-primary);
    margin: 0;
  }

  .session-title.muted {
    color: var(--color-text-muted);
  }

  .session-subtitle {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
  }

  .btn {
    display: inline-flex;
    align-items: center;
    gap: var(--spacing-xs);
    padding: 6px 12px;
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    font-weight: 500;
    transition: all var(--transition-fast);
  }

  .btn-danger {
    background: var(--color-error-subtle);
    color: var(--color-error);
  }

  .btn-danger:hover:not(:disabled) {
    background: var(--color-error);
    color: white;
  }

  .btn-sm {
    padding: 6px 10px;
    font-size: var(--text-xs);
  }

  /* Messages Container */
  .messages-container {
    flex: 1;
    overflow-y: auto;
    padding: var(--spacing-lg);
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    text-align: center;
    color: var(--color-text-muted);
    padding: var(--spacing-xl);
  }

  .empty-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background: var(--color-bg-elevated);
    margin-bottom: var(--spacing-lg);
    color: var(--color-text-muted);
  }

  .empty-icon.wave {
    animation: wave 2s ease-in-out infinite;
  }

  @keyframes wave {
    0%, 100% {
      transform: rotate(0deg);
    }
    25% {
      transform: rotate(-10deg);
    }
    75% {
      transform: rotate(10deg);
    }
  }

  .empty-state h3 {
    font-size: var(--text-lg);
    font-weight: 600;
    color: var(--color-text-secondary);
    margin: 0 0 var(--spacing-sm) 0;
  }

  .empty-state p {
    font-size: var(--text-sm);
    margin: 0;
    max-width: 250px;
  }

  /* Messages */
  .messages {
    display: flex;
    flex-direction: column;
    gap: var(--spacing-sm);
  }

  .message {
    display: flex;
    animation: slideIn var(--transition-normal) ease-out;
  }

  .message.sent {
    justify-content: flex-end;
  }

  .message.received {
    justify-content: flex-start;
  }

  .message-bubble {
    max-width: 70%;
    padding: var(--spacing-sm) var(--spacing-md);
    border-radius: var(--radius-lg);
    position: relative;
  }

  .message.sent .message-bubble {
    background: var(--gradient-accent);
    color: white;
    border-bottom-right-radius: var(--radius-sm);
  }

  .message.received .message-bubble {
    background: var(--color-bg-elevated);
    color: var(--color-text-primary);
    border-bottom-left-radius: var(--radius-sm);
  }

  .message-text {
    margin: 0;
    font-size: var(--text-sm);
    line-height: 1.5;
    word-wrap: break-word;
  }

  .message-time {
    display: block;
    font-size: 10px;
    opacity: 0.7;
    margin-top: var(--spacing-xs);
    text-align: right;
  }

  /* Message Input Area */
  .message-input-area {
    padding: var(--spacing-md) var(--spacing-lg);
    background: var(--color-bg-secondary);
    border-top: 1px solid var(--color-border);
  }

  .input-wrapper {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
    padding: var(--spacing-xs);
    background: var(--color-bg-primary);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-xl);
    transition: all var(--transition-fast);
  }

  .input-wrapper:focus-within {
    border-color: var(--color-accent);
    box-shadow: 0 0 0 3px var(--color-accent-subtle);
  }

  .input-wrapper input {
    flex: 1;
    padding: var(--spacing-sm) var(--spacing-md);
    font-size: var(--text-sm);
  }

  .send-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: var(--gradient-accent);
    color: white;
    transition: all var(--transition-fast);
    flex-shrink: 0;
  }

  .send-btn:hover:not(:disabled) {
    box-shadow: var(--shadow-glow);
    transform: scale(1.05);
  }

  .send-btn:disabled {
    background: var(--color-bg-elevated);
    color: var(--color-text-muted);
    cursor: not-allowed;
    opacity: 0.5;
  }

  .spinner {
    width: 14px;
    height: 14px;
    border: 2px solid transparent;
    border-top-color: currentColor;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateY(10px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }
</style>
