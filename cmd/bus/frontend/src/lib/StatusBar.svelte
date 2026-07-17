<script>
  import { createEventDispatcher } from 'svelte'
  import { status, appVersion, libraryVersion, logPanelOpen, verificationMode, incognito } from './stores.js'

  const dispatch = createEventDispatcher()

  const modeLabels = ['Strict', 'Quick', 'Auto-Accept']

  let isDark = document.documentElement.classList.contains('dark')

  function toggleTheme() {
    isDark = !isDark
    document.documentElement.classList.toggle('dark', isDark)
    localStorage.setItem('kamune:theme', isDark ? 'dark' : 'light')
  }

  $: indicatorText = $status.message || 'Not connected'
</script>

<div class="statusbar">
  <div class="status-left">
    <span
      class="dot"
      class:connecting={$status.status === 'connecting'}
      class:verifying={$status.status === 'verifying'}
      class:connected={$status.status === 'connected'}
      class:error={$status.status === 'error'}
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
    <button class="status-btn theme-btn" title="Toggle theme" on:click={toggleTheme}>
      {#if isDark}
        <svg viewBox="0 0 20 20" fill="currentColor" width="13" height="13">
          <path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd" />
        </svg>
      {:else}
        <svg viewBox="0 0 20 20" fill="currentColor" width="13" height="13">
          <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
        </svg>
      {/if}
    </button>
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
    background: var(--status-disconnected);
  }
  .dot.connecting {
    animation: pulse-dot 1.2s ease-in-out infinite;
    background: var(--status-connecting);
  }
  .dot.verifying {
    animation: pulse-dot 1.2s ease-in-out infinite;
    box-shadow: 0 0 8px var(--accent-secondary);
    background: var(--accent-secondary);
  }
  .dot.connected {
    background: var(--status-connected);
  }
  .dot.error {
    background: var(--status-error);
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
    color: var(--warning);
    background: var(--warning-dim);
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
  .status-btn.theme-btn {
    color: var(--text-timestamp);
    background: transparent;
    padding: 5px 7px;
    border-radius: 5px;
  }
  .status-btn.theme-btn:hover {
    color: var(--accent-primary);
    background: var(--accent-primary-dim);
  }
</style>
