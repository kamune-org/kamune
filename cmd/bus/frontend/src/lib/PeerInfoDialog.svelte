<script>
  import { onMount } from 'svelte'
  import { get } from 'svelte/store'
  import {
    GetPeer, RenamePeer, DeletePeer, CopyToClipboard,
  } from '../../wailsjs/go/main/App.js'
  import { dialogs, toast } from './stores.js'

  let peer = null
  let name = ''
  let originalName = ''
  let loading = true
  let saving = false
  let removing = false
  let confirmingRemove = false
  let error = ''
  let copiedField = null
  let copyResetTimer = null

  function close() {
    dialogs.update((d) => ({ ...d, peerInfoFor: null }))
  }

  function startConfirmRemove() {
    if (!peer || removing) return
    confirmingRemove = true
    error = ''
  }

  function cancelConfirmRemove() {
    if (removing) return
    confirmingRemove = false
  }

  async function performRemove() {
    if (!peer || removing) return
    removing = true
    error = ''
    try {
      await DeletePeer(peer.publicKeyBase64)
      toast.set({ message: 'Peer removed', type: 'info' })
      setTimeout(() => toast.set(null), 2000)
      close()
    } catch (e) {
      error = String(e)
      removing = false
      confirmingRemove = false
    }
  }

  function handleSave() {
    if (!peer || saving) return
    const trimmed = name.trim()
    if (trimmed === originalName) {
      close()
      return
    }
    if (!trimmed) {
      error = 'Name is required'
      return
    }
    saving = true
    error = ''
    RenamePeer(peer.publicKeyBase64, trimmed)
      .then(() => {
        toast.set({ message: 'Peer renamed', type: 'info' })
        setTimeout(() => toast.set(null), 2000)
        close()
      })
      .catch((e) => {
        error = String(e)
        saving = false
      })
  }

  function copy(value, field) {
    if (!value) return
    CopyToClipboard(value)
      .then(() => {
        copiedField = field
        if (copyResetTimer) clearTimeout(copyResetTimer)
        copyResetTimer = setTimeout(() => { copiedField = null }, 1500)
      })
      .catch((e) => {
        console.error('Copy failed:', e)
      })
  }

  function formatDateTime(t) {
    if (!t) return '—'
    const d = new Date(t)
    if (isNaN(d.getTime())) return '—'
    return d.toLocaleString()
  }

  onMount(async () => {
    const publicKeyB64 = get(dialogs).peerInfoFor
    if (!publicKeyB64) {
      loading = false
      return
    }
    try {
      const p = await GetPeer(publicKeyB64)
      peer = p
      name = p.name
      originalName = p.name
    } catch (e) {
      error = String(e)
    } finally {
      loading = false
    }
  })

  $: dirty = peer && name.trim() !== originalName
</script>

<div class="overlay" on:click={close}>
  <div class="dialog" on:click|stopPropagation>
    <div class="dialog-header">
      <div class="dialog-icon">
        <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
          <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd" />
        </svg>
      </div>
      <h3>Peer Details</h3>
    </div>

    <div class="dialog-body">
      {#if loading}
        <p class="dialog-hint">Loading…</p>
      {:else if !peer}
        <p class="dialog-error">Peer not found.</p>
      {:else}
        <label class="field-label">Name</label>
        <input
          type="text"
          bind:value={name}
          placeholder="Peer name"
          class="dialog-input"
          maxlength="32"
          on:keydown={(e) => { if (e.key === 'Enter') handleSave() }}
        />

        <label class="field-label">Public Key</label>
        <div class="copy-row">
          <code class="mono-block" title={peer.publicKeyBase64}>{peer.publicKeyBase64}</code>
          <button class="copy-btn" type="button" on:click={() => copy(peer.publicKeyBase64, 'pk')}>
            {copiedField === 'pk' ? 'Copied' : 'Copy'}
          </button>
        </div>

        <label class="field-label">Fingerprint</label>
        <div class="copy-row">
          <span class="plain-block emoji">{peer.fingerprintEmoji}</span>
          <button class="copy-btn" type="button" on:click={() => copy(peer.fingerprintEmoji, 'fp')}>
            {copiedField === 'fp' ? 'Copied' : 'Copy'}
          </button>
        </div>

        <div class="meta-grid">
          <div>
            <div class="meta-key">First seen</div>
            <div class="meta-val">{formatDateTime(peer.firstSeen)}</div>
          </div>
          <div>
            <div class="meta-key">Last seen</div>
            <div class="meta-val">{formatDateTime(peer.lastSeen)}</div>
          </div>
        </div>

        {#if error}
          <p class="dialog-error">{error}</p>
        {/if}
      {/if}
    </div>

    <div class="dialog-actions">
      {#if confirmingRemove}
        <span class="confirm-text">Remove <strong>{peer?.name}</strong>?</span>
        <div class="spacer"></div>
        <button class="dialog-btn dialog-btn-secondary" type="button" on:click={cancelConfirmRemove} disabled={removing}>Cancel</button>
        <button
          class="dialog-btn dialog-btn-danger dialog-btn-danger-solid"
          type="button"
          on:click={performRemove}
          disabled={removing}
        >
          {removing ? 'Removing…' : 'Remove'}
        </button>
      {:else}
        <button
          class="dialog-btn dialog-btn-danger"
          type="button"
          on:click={startConfirmRemove}
          disabled={!peer || removing || saving}
        >
          Remove
        </button>
        <div class="spacer"></div>
        <button class="dialog-btn dialog-btn-secondary" type="button" on:click={close} disabled={saving}>Cancel</button>
        <button
          class="dialog-btn dialog-btn-primary"
          type="button"
          on:click={handleSave}
          disabled={!peer || !dirty || saving}
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
      {/if}
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.65);
    backdrop-filter: blur(4px);
    -webkit-backdrop-filter: blur(4px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    animation: fadeIn 0.15s ease-out;
  }
  .dialog {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-xl);
    min-width: 480px;
    max-width: 560px;
    box-shadow: var(--shadow-lg);
    animation: fadeInScale 0.15s ease-out;
    overflow: hidden;
  }
  .dialog-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 18px 20px 0;
  }
  .dialog-icon {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: var(--accent-primary-dim);
    color: var(--accent-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .dialog-header h3 {
    font-size: 16px;
    font-weight: 700;
  }
  .dialog-body {
    padding: 16px 20px 4px;
  }
  .dialog-hint {
    font-size: 12px;
    color: var(--text-muted);
  }
  .field-label {
    display: block;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin: 12px 0 6px;
  }
  .field-label:first-of-type {
    margin-top: 0;
  }
  .dialog-input {
    width: 100%;
    padding: 10px 14px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 13px;
    box-sizing: border-box;
  }
  .dialog-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
    outline: none;
  }
  .copy-row {
    display: flex;
    align-items: stretch;
    gap: 6px;
  }
  .mono-block {
    flex: 1;
    min-width: 0;
    padding: 8px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.4;
    overflow-x: auto;
    white-space: nowrap;
    user-select: all;
  }
  .plain-block {
    flex: 1;
    min-width: 0;
    padding: 8px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 13px;
    line-height: 1.4;
    overflow-x: auto;
    white-space: nowrap;
    user-select: all;
  }
  .plain-block.emoji {
    font-size: 15px;
    letter-spacing: 0.5px;
  }
  .copy-btn {
    padding: 8px 12px;
    background: var(--bg-hover);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
    transition: all 0.15s;
  }
  .copy-btn:hover:not(:disabled) {
    background: var(--border-color);
    color: var(--text-primary);
  }
  .copy-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .copy-btn.small {
    margin-top: 6px;
    font-size: 11px;
    padding: 5px 10px;
  }
  .fp-tiles {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 4px;
  }
  .fp-emoji-tile {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    font-size: 16px;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 8px;
  }
  .meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-top: 12px;
    padding: 10px 12px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
  }
  .meta-key {
    font-size: 10px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }
  .meta-val {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 2px;
  }
  .dialog-error {
    margin-top: 10px;
    padding: 8px 10px;
    font-size: 11px;
    color: var(--danger);
    background: var(--danger-dim);
    border-radius: var(--border-radius, 6px);
    font-weight: 500;
    line-height: 1.4;
  }
  .dialog-actions {
    display: flex;
    gap: 8px;
    align-items: center;
    padding: 16px 20px 18px;
  }
  .spacer {
    flex: 1;
  }
  .dialog-btn {
    padding: 8px 18px;
    border-radius: var(--border-radius);
    font-size: 13px;
    font-weight: 600;
    border: none;
    cursor: pointer;
    transition: all 0.15s;
  }
  .dialog-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .dialog-btn-primary {
    background: var(--accent-primary);
    color: #fff;
  }
  .dialog-btn-primary:hover:not(:disabled) {
    background: var(--accent-primary-hover);
  }
  .dialog-btn-secondary {
    background: var(--bg-hover);
    color: var(--text-secondary);
  }
  .dialog-btn-secondary:hover:not(:disabled) {
    background: var(--border-color);
    color: var(--text-primary);
  }
  .dialog-btn-danger {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--danger);
  }
  .dialog-btn-danger:hover:not(:disabled) {
    background: var(--danger-dim);
  }
  .dialog-btn-danger-solid {
    background: var(--danger);
    color: #fff;
  }
  .dialog-btn-danger-solid:hover:not(:disabled) {
    filter: brightness(1.1);
  }
  .confirm-text {
    font-size: 13px;
    color: var(--text-secondary);
  }
  .confirm-text strong {
    color: var(--text-primary);
    font-weight: 600;
  }
</style>
