<script lang="ts">
  import { daemonRunning, showEventsLog } from "../stores/app";
</script>

<header class="header">
  <div class="brand">
    <div class="logo">
      <svg
        width="24"
        height="24"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M12 2L2 7L12 12L22 7L12 2Z"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
        <path
          d="M2 17L12 22L22 17"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
        <path
          d="M2 12L12 17L22 12"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </svg>
    </div>
    <h1 class="title">Kamune</h1>
    <span class="subtitle">Secure P2P</span>
  </div>

  <div class="actions">
    <button
      class="toggle-logs"
      class:active={$showEventsLog}
      onclick={() => showEventsLog.update((v) => !v)}
      title="Toggle Events Log"
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
        <polyline
          points="14 2 14 8 20 8"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
        <line
          x1="16"
          y1="13"
          x2="8"
          y2="13"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
        <line
          x1="16"
          y1="17"
          x2="8"
          y2="17"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </svg>
    </button>

    <div class="status-badge" class:running={$daemonRunning}>
      <span class="status-dot"></span>
      <span class="status-text">{$daemonRunning ? "Running" : "Stopped"}</span>
    </div>
  </div>
</header>

<style>
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: var(--spacing-sm) var(--spacing-lg);
    background: var(--color-bg-secondary);
    border-bottom: 1px solid var(--color-border);
    height: 56px;
    flex-shrink: 0;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
  }

  .logo {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    background: var(--gradient-accent);
    color: white;
  }

  .title {
    font-size: var(--text-lg);
    font-weight: 600;
    color: var(--color-text-primary);
    letter-spacing: -0.02em;
  }

  .subtitle {
    font-size: var(--text-xs);
    color: var(--color-text-muted);
    background: var(--color-bg-elevated);
    padding: 2px 8px;
    border-radius: var(--radius-full);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 500;
  }

  .actions {
    display: flex;
    align-items: center;
    gap: var(--spacing-md);
  }

  .toggle-logs {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    color: var(--color-text-muted);
    transition: all var(--transition-fast);
  }

  .toggle-logs:hover {
    background: var(--color-bg-elevated);
    color: var(--color-text-primary);
  }

  .toggle-logs.active {
    background: var(--color-accent-subtle);
    color: var(--color-accent);
  }

  .status-badge {
    display: flex;
    align-items: center;
    gap: var(--spacing-sm);
    padding: 6px 12px;
    border-radius: var(--radius-full);
    background: var(--color-error-subtle);
    font-size: var(--text-xs);
    font-weight: 500;
    transition: all var(--transition-normal);
  }

  .status-badge.running {
    background: var(--color-success-subtle);
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-error);
    transition: background var(--transition-normal);
  }

  .status-badge.running .status-dot {
    background: var(--color-success);
    animation: pulse 2s infinite;
  }

  .status-text {
    color: var(--color-error);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .status-badge.running .status-text {
    color: var(--color-success);
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
