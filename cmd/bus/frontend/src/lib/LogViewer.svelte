<script>
  import { afterUpdate } from 'svelte'
  import { logEntries, toast } from './stores.js'
  import { ClearLogs, ExportLogsToFile } from '../../wailsjs/go/main/App.js'

  let autoScroll = true
  let listEl

  afterUpdate(() => {
    if (autoScroll && listEl) {
      listEl.scrollTop = listEl.scrollHeight
    }
  })

  function levelColor(level) {
    return {
      INFO: 'var(--log-info)',
      WARN: 'var(--log-warn)',
      ERROR: 'var(--log-error)',
      DEBUG: 'var(--log-debug)',
    }[level] || 'var(--log-debug)'
  }

  async function clearLogs() {
    await ClearLogs()
    logEntries.set([])
  }

  async function exportLogs() {
    try {
      await ExportLogsToFile()
    } catch (e) {
      toast.set({ message: String(e), type: 'error' })
      setTimeout(() => toast.set(null), 3000)
    }
  }
</script>

<div class="log-panel">
  <div class="log-header">
    <div class="log-header-left">
      <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
        <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
      </svg>
      <span>Logs</span>
      <span class="log-count">{$logEntries.length}</span>
    </div>
    <div class="log-header-right">
      <label class="auto-scroll">
        <input type="checkbox" bind:checked={autoScroll} />
        Auto
      </label>
      <button class="log-btn" on:click={clearLogs}>
        <svg viewBox="0 0 20 20" fill="currentColor" width="10" height="10">
          <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
        </svg>
        Clear
      </button>
      <button class="log-btn" on:click={exportLogs}>
        <svg viewBox="0 0 20 20" fill="currentColor" width="10" height="10">
          <path d="M10 1a1 1 0 011 1v9.586l2.293-2.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 11.586V2a1 1 0 011-1z"/>
          <path d="M2 17a1 1 0 011 1h14a1 1 0 011-1H2z" opacity=".5"/>
        </svg>
        Export
      </button>
    </div>
  </div>
  <div class="log-entries" bind:this={listEl}>
    {#each $logEntries as entry, i}
      <div class="log-entry">
        <span class="log-time">
          {new Date(entry.timestamp).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}
        </span>
        <span class="log-level" style="color:{levelColor(entry.level)}">
          {entry.level}
        </span>
        <span class="log-msg">{entry.message}</span>
      </div>
    {/each}
  </div>
</div>

<style>
  .log-panel {
    height: 180px;
    border-top: 1px solid var(--border-color);
    background: var(--bg-sidebar);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    animation: slideUp 0.15s ease-out;
  }
  .log-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 5px 12px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-color);
    font-size: 10px;
    flex-shrink: 0;
  }
  .log-header-left {
    display: flex;
    align-items: center;
    gap: 5px;
    color: var(--text-muted);
    font-weight: 600;
  }
  .log-count {
    background: var(--bg-hover);
    color: var(--text-timestamp);
    font-size: 9px;
    font-weight: 700;
    padding: 1px 5px;
    border-radius: 6px;
  }
  .log-header-right {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .auto-scroll {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 10px;
    color: var(--text-muted);
    cursor: pointer;
  }
  .auto-scroll input {
    accent-color: var(--accent-primary);
    width: 11px;
    height: 11px;
  }
  .log-btn {
    display: flex;
    align-items: center;
    gap: 3px;
    background: transparent;
    color: var(--text-muted);
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 4px;
    transition: all 0.15s;
  }
  .log-btn:hover {
    color: var(--text-secondary);
    background: var(--bg-hover);
  }
  .log-entries {
    flex: 1;
    overflow-y: auto;
    padding: 3px 8px;
    font-family: var(--font-mono);
    font-size: 10px;
    line-height: 1.7;
  }
  .log-entry {
    display: flex;
    gap: 8px;
    padding: 1px 0;
  }
  .log-entry:hover {
    background: var(--bg-hover);
    border-radius: 3px;
  }
  .log-time {
    color: var(--text-timestamp);
    white-space: nowrap;
    flex-shrink: 0;
    font-size: 9px;
    opacity: 0.6;
  }
  .log-level {
    font-weight: 700;
    min-width: 36px;
    flex-shrink: 0;
    font-size: 9px;
  }
  .log-msg {
    color: var(--text-secondary);
    word-break: break-all;
  }
</style>
