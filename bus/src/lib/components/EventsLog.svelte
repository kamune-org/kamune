<script lang="ts">
  import { eventLog } from "../stores/app";
  import { tick } from "svelte";

  let logContainer: HTMLDivElement | null = $state(null);

  // Auto-scroll to bottom when new events come in
  $effect(() => {
    if ($eventLog.length > 0 && logContainer) {
      tick().then(() => {
        if (logContainer) {
          logContainer.scrollTop = logContainer.scrollHeight;
        }
      });
    }
  });

  function getTypeColor(type: string): string {
    switch (type.toLowerCase()) {
      case "error":
        return "var(--color-error)";
      case "warning":
        return "var(--color-warning)";
      case "ready":
      case "success":
        return "var(--color-success)";
      case "info":
        return "var(--color-accent)";
      default:
        return "var(--color-text-muted)";
    }
  }
</script>

<div class="events-log">
  <header class="log-header">
    <div class="header-content">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
        <polyline
          points="4 17 10 11 4 5"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
        <line
          x1="12"
          y1="19"
          x2="20"
          y2="19"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
        />
      </svg>
      <span>Events Log</span>
      <span class="event-count">{$eventLog.length}</span>
    </div>
  </header>

  <div class="log-content" bind:this={logContainer}>
    {#if $eventLog.length === 0}
      <div class="empty">
        <span>Waiting for events...</span>
      </div>
    {:else}
      {#each $eventLog as entry (entry.id)}
        <div class="log-entry">
          <span class="entry-time">{entry.time}</span>
          <span class="entry-type" style="color: {getTypeColor(entry.type)}">{entry.type}</span>
          <span class="entry-data">{entry.data}</span>
        </div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .events-log {
    background: var(--color-bg-secondary);
    border-top: 1px solid var(--color-border);
    display: flex;
    flex-direction: column;
    max-height: 180px;
    min-height: 100px;
  }

  .log-header {
    padding: var(--spacing-sm) var(--spacing-md);
    border-bottom: 1px solid var(--color-border);
    flex-shrink: 0;
  }

  .header-content {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .event-count {
    background: var(--color-bg-elevated);
    padding: 2px 6px;
    border-radius: var(--radius-full);
    font-size: 10px;
    color: var(--color-text-muted);
  }

  .log-content {
    flex: 1;
    overflow-y: auto;
    font-family: "Monaco", "Menlo", "Consolas", monospace;
    font-size: 11px;
  }

  .empty {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--color-text-muted);
    font-family: inherit;
    font-size: var(--text-xs);
  }

  .log-entry {
    display: flex;
    gap: var(--spacing-md);
    padding: var(--spacing-xs) var(--spacing-md);
    border-bottom: 1px solid var(--color-border-subtle);
    line-height: 1.5;
  }

  .log-entry:hover {
    background: var(--color-bg-elevated);
  }

  .entry-time {
    color: var(--color-text-muted);
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }

  .entry-type {
    flex-shrink: 0;
    min-width: 80px;
    font-weight: 500;
  }

  .entry-data {
    color: var(--color-text-secondary);
    word-break: break-all;
    flex: 1;
  }
</style>
