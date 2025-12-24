<script lang="ts">
  import {
    daemonRunning,
    sessions,
    currentSessionId,
    sessionsList,
    selectSession,
    clearSessions,
    addSession,
    logEvent,
    truncateId,
  } from "../stores/app";
  import { api } from "../api/tauri";

  let serverAddr = $state("127.0.0.1:9000");
  let dialAddr = $state("");
  let isStartingDaemon = $state(false);
  let isStoppingDaemon = $state(false);
  let isStartingServer = $state(false);
  let isDialing = $state(false);

  async function handleStartDaemon() {
    if (isStartingDaemon) return;
    isStartingDaemon = true;
    logEvent("info", "Starting daemon...");

    const result = await api.startDaemon();

    if (result.success) {
      daemonRunning.set(true);
      logEvent("info", "Daemon started");
    } else {
      logEvent("error", result.error || "Failed to start daemon");
    }

    isStartingDaemon = false;
  }

  async function handleStopDaemon() {
    if (isStoppingDaemon) return;
    isStoppingDaemon = true;
    logEvent("info", "Stopping daemon...");

    const result = await api.stopDaemon();

    if (result.success) {
      daemonRunning.set(false);
      clearSessions();
      logEvent("info", "Daemon stopped");
    } else {
      logEvent("error", result.error || "Failed to stop daemon");
    }

    isStoppingDaemon = false;
  }

  async function handleStartServer() {
    if (isStartingServer || !$daemonRunning) return;
    const addr = serverAddr.trim() || "127.0.0.1:9000";
    isStartingServer = true;
    logEvent("info", `Starting server on ${addr}...`);

    const result = await api.startServer(addr);

    if (!result.success) {
      logEvent("error", result.error || "Failed to start server");
    }

    isStartingServer = false;
  }

  async function handleDial() {
    if (isDialing || !$daemonRunning) return;
    const addr = dialAddr.trim();

    if (!addr) {
      logEvent("error", "Please enter a remote address");
      return;
    }

    isDialing = true;
    logEvent("info", `Dialing ${addr}...`);

    const result = await api.dial(addr);

    if (!result.success) {
      logEvent("error", result.error || "Failed to dial");
    } else {
      dialAddr = "";
    }

    isDialing = false;
  }

  async function handleRefreshSessions() {
    logEvent("info", "Refreshing sessions...");
    const result = await api.listSessions();

    if (result.success && result.data?.sessions) {
      sessions.set(new Map());
      for (const session of result.data.sessions) {
        addSession(session);
      }
      logEvent("info", `Found ${result.data.sessions.length} sessions`);
    } else {
      logEvent("error", result.error || "Failed to list sessions");
    }
  }

  function handleSessionClick(sessionId: string) {
    selectSession(sessionId);
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleDial();
    }
  }
</script>

<aside class="sidebar">
  <!-- Daemon Control -->
  <div class="section">
    <h3 class="section-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2" />
        <path
          d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
        />
      </svg>
      Daemon Control
    </h3>
    <div class="button-group">
      <button
        class="btn btn-primary"
        onclick={handleStartDaemon}
        disabled={$daemonRunning || isStartingDaemon}
      >
        {#if isStartingDaemon}
          <span class="spinner"></span>
        {:else}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
            <polygon points="5 3 19 12 5 21 5 3" fill="currentColor" />
          </svg>
        {/if}
        Start
      </button>
      <button
        class="btn btn-danger"
        onclick={handleStopDaemon}
        disabled={!$daemonRunning || isStoppingDaemon}
      >
        {#if isStoppingDaemon}
          <span class="spinner"></span>
        {:else}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
            <rect x="4" y="4" width="16" height="16" rx="2" fill="currentColor" />
          </svg>
        {/if}
        Stop
      </button>
    </div>
  </div>

  <!-- Server -->
  <div class="section">
    <h3 class="section-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
        <rect
          x="2"
          y="2"
          width="20"
          height="8"
          rx="2"
          stroke="currentColor"
          stroke-width="2"
        />
        <rect
          x="2"
          y="14"
          width="20"
          height="8"
          rx="2"
          stroke="currentColor"
          stroke-width="2"
        />
        <circle cx="6" cy="6" r="1" fill="currentColor" />
        <circle cx="6" cy="18" r="1" fill="currentColor" />
      </svg>
      Server
    </h3>
    <div class="input-group">
      <label for="server-addr">Bind Address</label>
      <input
        type="text"
        id="server-addr"
        bind:value={serverAddr}
        placeholder="127.0.0.1:9000"
        disabled={!$daemonRunning}
      />
    </div>
    <button
      class="btn btn-secondary btn-block"
      onclick={handleStartServer}
      disabled={!$daemonRunning || isStartingServer}
    >
      {#if isStartingServer}
        <span class="spinner"></span>
        Starting...
      {:else}
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
          <path
            d="M22 12h-4l-3 9L9 3l-3 9H2"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
        Start Server
      {/if}
    </button>
  </div>

  <!-- Connect -->
  <div class="section">
    <h3 class="section-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
        <path
          d="M15 7h3a5 5 0 0 1 5 5 5 5 0 0 1-5 5h-3m-6 0H6a5 5 0 0 1-5-5 5 5 0 0 1 5-5h3"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
        />
        <line
          x1="8"
          y1="12"
          x2="16"
          y2="12"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
        />
      </svg>
      Connect
    </h3>
    <div class="input-group">
      <label for="dial-addr">Remote Address</label>
      <input
        type="text"
        id="dial-addr"
        bind:value={dialAddr}
        placeholder="192.168.1.10:9000"
        disabled={!$daemonRunning}
        onkeydown={handleKeyDown}
      />
    </div>
    <button
      class="btn btn-primary btn-block"
      onclick={handleDial}
      disabled={!$daemonRunning || isDialing || !dialAddr.trim()}
    >
      {#if isDialing}
        <span class="spinner"></span>
        Connecting...
      {:else}
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
          <path
            d="M5 12h14M12 5l7 7-7 7"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
        Connect
      {/if}
    </button>
  </div>

  <!-- Sessions -->
  <div class="section sessions-section">
    <div class="section-header">
      <h3 class="section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
          <path
            d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
          />
          <circle cx="9" cy="7" r="4" stroke="currentColor" stroke-width="2" />
          <path
            d="M23 21v-2a4 4 0 0 0-3-3.87"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
          />
          <path
            d="M16 3.13a4 4 0 0 1 0 7.75"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
          />
        </svg>
        Sessions
        {#if $sessionsList.length > 0}
          <span class="badge">{$sessionsList.length}</span>
        {/if}
      </h3>
      <button
        class="btn-icon"
        onclick={handleRefreshSessions}
        disabled={!$daemonRunning}
        title="Refresh Sessions"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
          <path
            d="M23 4v6h-6M1 20v-6h6"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
          <path
            d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </button>
    </div>

    <div class="sessions-list">
      {#if $sessionsList.length === 0}
        <div class="empty-state">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" />
            <path
              d="M8 15h8M9 9h.01M15 9h.01"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
            />
          </svg>
          <p>No active sessions</p>
        </div>
      {:else}
        {#each $sessionsList as session (session.id)}
          <button
            class="session-item"
            class:active={$currentSessionId === session.id}
            onclick={() => handleSessionClick(session.id)}
          >
            <div class="session-avatar" class:server={session.isServer}>
              {#if session.isServer}
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                  <rect
                    x="2"
                    y="2"
                    width="20"
                    height="8"
                    rx="2"
                    stroke="currentColor"
                    stroke-width="2"
                  />
                  <rect
                    x="2"
                    y="14"
                    width="20"
                    height="8"
                    rx="2"
                    stroke="currentColor"
                    stroke-width="2"
                  />
                </svg>
              {:else}
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                  <path
                    d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"
                    stroke="currentColor"
                    stroke-width="2"
                  />
                  <circle cx="12" cy="7" r="4" stroke="currentColor" stroke-width="2" />
                </svg>
              {/if}
            </div>
            <div class="session-info">
              <span class="session-id">{truncateId(session.id)}</span>
              <span class="session-meta">
                {session.isServer ? "Server" : "Client"} • {session.remoteAddr || "Local"}
              </span>
            </div>
            <div class="session-indicator"></div>
          </button>
        {/each}
      {/if}
    </div>
  </div>
</aside>

<style>
  .sidebar {
    width: 280px;
    min-width: 280px;
    background: var(--color-bg-secondary);
    border-right: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .section {
    padding: var(--spacing-md);
    border-bottom: 1px solid var(--color-border);
  }

  .section-title {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: var(--spacing-md);
  }

  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--spacing-sm);
  }

  .section-header .section-title {
    margin-bottom: 0;
  }

  .badge {
    background: var(--color-accent-subtle);
    color: var(--color-accent);
    padding: 2px 6px;
    border-radius: var(--radius-full);
    font-size: 10px;
    margin-left: var(--spacing-xs);
  }

  .button-group {
    display: flex;
    gap: var(--spacing-sm);
  }

  .button-group .btn {
    flex: 1;
  }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--spacing-sm);
    padding: 8px 12px;
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    font-weight: 500;
    transition: all var(--transition-fast);
  }

  .btn-primary {
    background: var(--gradient-accent);
    color: white;
    box-shadow: var(--shadow-sm);
  }

  .btn-primary:hover:not(:disabled) {
    box-shadow: var(--shadow-glow);
    transform: translateY(-1px);
  }

  .btn-secondary {
    background: var(--color-bg-elevated);
    color: var(--color-text-primary);
    border: 1px solid var(--color-border);
  }

  .btn-secondary:hover:not(:disabled) {
    background: var(--color-bg-hover);
    border-color: var(--color-text-muted);
  }

  .btn-danger {
    background: var(--color-error-subtle);
    color: var(--color-error);
  }

  .btn-danger:hover:not(:disabled) {
    background: var(--color-error);
    color: white;
  }

  .btn-block {
    width: 100%;
  }

  .btn-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: var(--radius-md);
    color: var(--color-text-muted);
    transition: all var(--transition-fast);
  }

  .btn-icon:hover:not(:disabled) {
    background: var(--color-bg-elevated);
    color: var(--color-text-primary);
  }

  .input-group {
    margin-bottom: var(--spacing-sm);
  }

  .input-group label {
    display: block;
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    margin-bottom: var(--spacing-xs);
  }

  .input-group input {
    width: 100%;
    padding: 8px 12px;
    background: var(--color-bg-primary);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    transition: all var(--transition-fast);
  }

  .input-group input:focus {
    border-color: var(--color-accent);
    box-shadow: 0 0 0 3px var(--color-accent-subtle);
  }

  .input-group input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .sessions-section {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border-bottom: none;
    padding-bottom: 0;
  }

  .sessions-list {
    flex: 1;
    overflow-y: auto;
    padding: var(--spacing-xs) 0;
    margin: 0 calc(-1 * var(--spacing-md));
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: var(--spacing-xl);
    color: var(--color-text-muted);
    text-align: center;
    gap: var(--spacing-sm);
  }

  .empty-state p {
    font-size: var(--text-sm);
  }

  .session-item {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
    width: 100%;
    padding: var(--spacing-sm) var(--spacing-md);
    text-align: left;
    transition: all var(--transition-fast);
    position: relative;
  }

  .session-item:hover {
    background: var(--color-bg-elevated);
  }

  .session-item.active {
    background: var(--color-accent-subtle);
  }

  .session-item.active::before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 3px;
    background: var(--color-accent);
    border-radius: 0 2px 2px 0;
  }

  .session-avatar {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    background: var(--color-bg-tertiary);
    color: var(--color-text-secondary);
    flex-shrink: 0;
  }

  .session-avatar.server {
    background: var(--color-success-subtle);
    color: var(--color-success);
  }

  .session-info {
    flex: 1;
    min-width: 0;
  }

  .session-id {
    display: block;
    font-size: var(--text-sm);
    font-weight: 500;
    color: var(--color-text-primary);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .session-meta {
    display: block;
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .session-item.active .session-id,
  .session-item.active .session-meta {
    color: var(--color-accent);
  }

  .session-indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-success);
    flex-shrink: 0;
    animation: pulse 2s infinite;
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

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }
</style>
