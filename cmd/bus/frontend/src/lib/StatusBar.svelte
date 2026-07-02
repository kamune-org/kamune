<script>
  import { createEventDispatcher } from 'svelte'
  import { status, appVersion, libraryVersion, logPanelOpen, verificationMode, incognito } from './stores.js'

  const dispatch = createEventDispatcher()

  const modeLabels = ['Strict', 'Quick', 'Auto-Accept']

  $: indicatorColor = {
    disconnected: '#5b677d',
    connecting: '#f59e0b',
    connected: '#10b981',
    error: '#ef4444',
    verifying: '#8b5cf6',
  }[$status.status] || '#5b677d'

  $: indicatorText = $status.message || 'Not connected'
  $: isConnecting = $status.status === 'connecting' || $status.status === 'verifying'
</script>

<div class="statusbar">
  <div class="status-left">
    <span
      class="dot"
      class:connecting={isConnecting}
      class:verifying={$status.status === 'verifying'}
      style="background:{indicatorColor}"
    ></span>
    <span class="status-msg">{indicatorText}</span>
    <span class="sep">·</span>
    <span class="version" title="Bus v{$appVersion} • kamune v{$libraryVersion}">
      v{$appVersion} <span class="lib-part">(kamune v{$libraryVersion})</span>
    </span>
  </div>
  <div class="status-right">
    <span class="mode-badge" title="Verification mode — change from Connection menu">
      {modeLabels[$verificationMode] || 'Unknown'}
    </span>
    {#if $incognito}
      <span class="mode-badge incognito-badge" title="Incognito mode — new messages not saved">
        Incognito
      </span>
    {/if}
    <button
      class="status-btn logs-btn"
      class:active={$logPanelOpen}
      on:click={() => dispatch('toggleLogs')}
    >
      <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
        <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd" />
      </svg>
      Logs
    </button>
    <button class="status-btn shortcuts-btn" title="Keyboard shortcuts" on:click={() => dispatch('showShortcuts')}>
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="14" height="14">
        <rect x="2" y="4" width="16" height="12" rx="1.5" />
        <line x1="6" y1="8" x2="6" y2="8" stroke-width="2.5" />
        <line x1="10" y1="8" x2="10" y2="8" stroke-width="2.5" />
        <line x1="14" y1="8" x2="14" y2="8" stroke-width="2.5" />
        <line x1="6" y1="12" x2="6" y2="12" stroke-width="2.5" />
        <line x1="10" y1="12" x2="10" y2="12" stroke-width="2.5" />
        <line x1="14" y1="12" x2="14" y2="12" stroke-width="2.5" />
      </svg>
    </button>
  </div>
</div>

<style>
  .statusbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: calc(var(--statusbar-height) + 6px);
    padding: 0 14px;
    background: var(--bg-surface);
    border-top: 1px solid var(--border-color);
    font-size: 13px;
    flex-shrink: 0;
  }
  .status-left {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    flex-shrink: 0;
    box-shadow: 0 0 5px currentColor;
  }
  .dot.connecting {
    animation: pulse-dot 1.2s ease-in-out infinite;
  }
  .dot.verifying {
    animation: pulse-dot 1.2s ease-in-out infinite;
    box-shadow: 0 0 8px #8b5cf6;
  }
  .status-msg {
    color: var(--text-secondary);
    font-size: 13px;
  }
  .status-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .sep {
    color: var(--text-timestamp);
    opacity: 0.3;
    font-size: 13px;
  }
  .version {
    color: var(--text-timestamp);
    font-family: var(--font-mono);
    font-size: 11px;
  }
  .lib-part {
    opacity: 0.7;
  }
  .mode-badge {
    display: inline-flex;
    align-items: center;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--accent-primary);
    background: var(--accent-primary-dim);
    padding: 3px 10px;
    border-radius: 5px;
    line-height: 1;
  }
  .incognito-badge {
    color: #f59e0b;
    background: rgba(245, 158, 11, 0.15);
  }
  .status-btn {
    display: flex;
    align-items: center;
    gap: 5px;
    background: transparent;
    font-size: 12px;
    padding: 5px 12px;
    border-radius: 5px;
    transition: all 0.15s;
  }
  .status-btn.logs-btn {
    color: var(--text-secondary);
    background: var(--bg-hover);
  }
  .status-btn.logs-btn:hover {
    color: var(--text-primary);
    background: var(--border-color);
  }
  .status-btn.logs-btn.active {
    color: var(--accent-primary);
    background: var(--accent-primary-dim);
  }
  .status-btn.shortcuts-btn {
    color: var(--text-timestamp);
    border: 1px solid var(--border-color);
    background: transparent;
    padding: 4px 7px;
    border-radius: 5px;
  }
  .status-btn.shortcuts-btn:hover {
    color: var(--text-secondary);
    border-color: var(--border-light);
    background: var(--bg-hover);
  }
</style>
