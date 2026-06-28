<script>
  import { peers } from './stores.js'
  import { dialogs } from './stores.js'

  function timeAgo(t) {
    if (!t) return ''
    const diff = Date.now() - new Date(t).getTime()
    const seconds = Math.floor(diff / 1000)
    if (seconds < 60) return 'just now'
    const minutes = Math.floor(seconds / 60)
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    if (days < 30) return `${days}d ago`
    return new Date(t).toLocaleDateString()
  }

  function handleSelect(publicKeyB64) {
    dialogs.update((d) => ({ ...d, peerInfoFor: publicKeyB64 }))
  }
</script>

<div class="peers-panel">
  <div class="peers-actions">
    <button class="action-btn action-primary" on:click={() => dialogs.update((d) => ({ ...d, showAddPeer: true }))}>
      <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
        <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" />
      </svg>
      Add Peer
    </button>
  </div>

  <div class="peers-list">
    {#if $peers.length === 0}
      <div class="empty-state">
        <div class="empty-icon-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="32" height="32" stroke-width="1.5">
            <path d="M17 20h5v-2a4 4 0 00-3-3.87M9 20H4v-2a4 4 0 013-3.87m6-2.13a4 4 0 100-7.75 4 4 0 000 7.75zm6 0a4 4 0 100-7.75 4 4 0 000 7.75z" />
          </svg>
        </div>
        <p class="empty-title">No known peers</p>
        <p class="empty-hint">Accept a verification or add a peer manually</p>
      </div>
    {:else}
      {#each $peers as peer (peer.publicKeyBase64)}
        <div
          class="peer-item"
          role="button"
          tabindex="0"
          on:click={() => handleSelect(peer.publicKeyBase64)}
          on:keydown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              handleSelect(peer.publicKeyBase64)
            }
          }}
        >
          <div class="peer-avatar">
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
              <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd" />
            </svg>
          </div>
          <div class="peer-info">
            <div class="peer-name" title={peer.name}>{peer.name}</div>
            <div class="peer-meta">
              <span class="peer-fp">{peer.fingerprintEmoji}</span>
              <span class="meta-dot">·</span>
              <span class="peer-time">{timeAgo(peer.lastSeen)}</span>
            </div>
          </div>
        </div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .peers-panel {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
  }
  .peers-actions {
    padding: 12px 14px;
    border-bottom: 1px solid var(--border-color);
  }
  .action-btn {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 8px 12px;
    border-radius: var(--border-radius);
    font-size: 13px;
    font-weight: 600;
    border: 1px solid transparent;
    cursor: pointer;
    transition: all 0.15s;
  }
  .action-primary {
    background: var(--accent-primary);
    color: #fff;
  }
  .action-primary:hover {
    background: var(--accent-primary-hover);
  }
  .peers-list {
    flex: 1;
    overflow-y: auto;
    padding: 8px 8px;
  }
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 48px 20px;
    color: var(--text-muted);
  }
  .empty-icon-wrap {
    margin-bottom: 12px;
    opacity: 0.5;
  }
  .empty-title {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 4px;
  }
  .empty-hint {
    font-size: 12px;
    opacity: 0.7;
  }
  .peer-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    border-radius: var(--border-radius);
    margin-bottom: 2px;
    transition: background 0.15s;
    cursor: pointer;
    outline: none;
  }
  .peer-item:hover,
  .peer-item:focus-visible {
    background: var(--bg-hover);
  }
  .peer-item:focus-visible {
    box-shadow: 0 0 0 1px var(--accent-primary);
  }
  .peer-avatar {
    width: 24px;
    height: 24px;
    border-radius: 8px;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .peer-info {
    min-width: 0;
    flex: 1;
  }
  .peer-name {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .peer-meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 6px;
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 2px;
  }
  .peer-fp {
    word-break: break-all;
    flex: 0 1 auto;
  }
  .meta-dot {
    opacity: 0.5;
  }
  .peer-time {
    flex-shrink: 0;
  }
</style>
