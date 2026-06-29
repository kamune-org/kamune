<script>
  import {
    GenerateP2PToken, RemoveP2PToken, CopyToClipboard,
  } from '../../wailsjs/go/main/App.js'
  import { p2pTokens, toast } from './stores.js'

  let brokerAddr = ''
  let expanded = true
  let generating = false

  async function handleGenerate() {
    if (generating) return
    const trimmed = brokerAddr.trim()
    if (!trimmed) {
      toast.set({ message: 'Broker address is required', type: 'error' })
      setTimeout(() => toast.set(null), 3000)
      return
    }
    generating = true
    try {
      const token = await GenerateP2PToken(trimmed)
      if (token) {
        toast.set({ message: `Token: ${token}`, token, type: 'token' })
        setTimeout(() => toast.set(null), 4000)
      }
    } catch (e) {
      toast.set({ message: String(e), type: 'error' })
      setTimeout(() => toast.set(null), 3000)
    } finally {
      generating = false
    }
  }

  async function handleRemove(token) {
    try {
      await RemoveP2PToken(token)
    } catch (e) {
      console.error('Remove p2p token failed:', e)
    }
  }

  function handleCopyToken(token) {
    CopyToClipboard(token)
      .then(() => {
        toast.set({ message: 'Copied to clipboard', type: 'info' })
        setTimeout(() => toast.set(null), 1500)
      })
      .catch((e) => console.error('Copy failed:', e))
  }

  function truncateToken(t) {
    if (!t) return ''
    if (t.length <= 16) return t
    return t.slice(0, 8) + '…' + t.slice(-8)
  }

  function formatExpiry(token) {
    if (!token.expiresAt) return ''
    const ms = new Date(token.expiresAt).getTime() - Date.now()
    if (ms <= 0) return 'expired'
    const s = Math.floor(ms / 1000)
    if (s < 60) return `${s}s`
    const m = Math.floor(s / 60)
    return `${m}m ${s % 60}s`
  }
</script>

<div class="signaling-tokens-section">
  <div class="st-header" on:click={() => expanded = !expanded}
       on:keydown={(e) => { if (e.key === 'Enter') expanded = !expanded }}
       role="button" tabindex="0">
    <svg class="st-chevron" class:collapsed={!expanded} viewBox="0 0 20 20" fill="currentColor" width="10" height="10">
      <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
    </svg>
    <span class="st-header-label">Signaling Tokens</span>
    <span class="st-count">{$p2pTokens.length}</span>
  </div>

  {#if expanded}
    <div class="st-body">
      <div class="st-broker-row">
        <input
          class="st-broker-input"
          type="text"
          placeholder="broker host:port"
          bind:value={brokerAddr}
          on:keydown={(e) => { if (e.key === 'Enter') handleGenerate() }}
        />
        <button
          class="st-gen-btn"
          on:click={handleGenerate}
          disabled={generating}
        >
          <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
            <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" />
          </svg>
          Generate
        </button>
      </div>

      {#if $p2pTokens.length === 0}
        <p class="st-hint">Enter a broker address and click Generate to create a signaling token.</p>
      {:else}
        <div class="st-list">
          {#each $p2pTokens as pt (pt.token)}
            {@const expiry = formatExpiry(pt)}
            <div class="st-item" class:consumed={pt.consumed}>
              <span class="st-dot" class:filled={pt.consumed}></span>
              <span class="st-item-token" role="button" tabindex="0"
                    on:click={() => handleCopyToken(pt.token)}
                    on:keydown={(e) => { if (e.key === 'Enter') handleCopyToken(pt.token) }}>
                {truncateToken(pt.token)}
              </span>
              {#if expiry}
                <span class="st-expiry" class:expired={expiry === 'expired'}>{expiry}</span>
              {/if}
              <button class="st-rm-btn" title="Remove token" on:click|stopPropagation={() => handleRemove(pt.token)}>
                <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .signaling-tokens-section {
    margin: 0 0 8px;
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    background: var(--bg-input);
  }
  .st-header {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 8px;
    cursor: pointer;
    user-select: none;
  }
  .st-header:hover {
    background: var(--bg-hover);
  }
  .st-chevron {
    flex-shrink: 0;
    transition: transform 0.15s;
  }
  .st-chevron.collapsed {
    transform: rotate(-90deg);
  }
  .st-header-label {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-primary);
    flex: 1;
  }
  .st-count {
    font-size: 10px;
    color: var(--text-muted);
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 1px 6px;
  }
  .st-body {
    padding: 0 8px 8px;
  }
  .st-broker-row {
    display: flex;
    gap: 4px;
    margin-bottom: 6px;
  }
  .st-broker-input {
    flex: 1;
    min-width: 0;
    padding: 4px 8px;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 11px;
  }
  .st-broker-input:focus {
    outline: none;
    border-color: var(--accent-primary);
  }
  .st-gen-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 4px 8px;
    background: var(--bg-hover);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-secondary);
    font-size: 10px;
    font-weight: 600;
    cursor: pointer;
  }
  .st-gen-btn:hover:not(:disabled) {
    background: var(--border-color);
    color: var(--text-primary);
  }
  .st-gen-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .st-hint {
    font-size: 10px;
    color: var(--text-muted);
    line-height: 1.4;
    margin: 4px 0 0;
  }
  .st-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .st-item {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 6px;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    font-size: 11px;
  }
  .st-item.consumed {
    opacity: 0.6;
  }
  .st-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: transparent;
    border: 1px solid var(--text-muted);
    flex-shrink: 0;
  }
  .st-dot.filled {
    background: var(--text-muted);
  }
  .st-item-token {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-primary);
    flex: 1;
    cursor: pointer;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .st-expiry {
    font-size: 10px;
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }
  .st-expiry.expired {
    color: var(--danger);
  }
  .st-rm-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    padding: 2px;
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .st-rm-btn:hover {
    background: var(--bg-hover);
    color: var(--danger);
  }
</style>
