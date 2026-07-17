<script>
  import { AddPeer } from '../../wailsjs/go/main/App.js'
  import { dialogs } from './stores.js'

  let publicKeyB64 = ''
  let name = ''
  let error = ''
  let saving = false

  function close() {
    publicKeyB64 = ''
    name = ''
    error = ''
    saving = false
    dialogs.update((d) => ({ ...d, showAddPeer: false }))
  }

  // Ed25519 public keys in SPKI form are 44 bytes. Raw URL-safe
  // base64 of 44 bytes = 59 chars (no padding). The bus accepts
  // only that one format.
  $: cleanKey = publicKeyB64.replace(/\s+/g, '')
  $: keyLength = cleanKey.length
  $: isValidB64 = /^[A-Za-z0-9_-]+$/.test(cleanKey)
  $: keyLooksOk = isValidB64 && keyLength === 59

  async function handleSave() {
    if (saving) return
    error = ''
    if (keyLength === 0) {
      error = 'Public key is required'
      return
    }
    if (!isValidB64) {
      error = 'Public key must be base64 (A-Z, a-z, 0-9, _, -)'
      return
    }
    if (!keyLooksOk) {
      error = 'Public key must be 59 base64 chars (PKIX ed25519)'
      return
    }
    saving = true
    try {
      await AddPeer(cleanKey, name.trim())
      close()
    } catch (e) {
      error = String(e)
      saving = false
    }
  }
</script>

<div class="overlay" on:click={close}>
  <div class="dialog" on:click|stopPropagation>
    <div class="dialog-header">
      <div class="dialog-icon">
        <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
          <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd" />
        </svg>
      </div>
      <h3>Add Peer</h3>
    </div>
    <div class="dialog-body">
      <label class="field-label">Public key (base64)</label>
      <input
        type="text"
        bind:value={publicKeyB64}
        placeholder="Raw URL-safe base64 (no padding)"
        class="dialog-input mono"
        spellcheck="false"
        autocomplete="off"
        autocapitalize="off"
        autocorrect="off"
        on:keydown={(e) => { if (e.key === 'Enter') handleSave() }}
      />
      <p class="field-hint">{keyLength} chars</p>

      <label class="field-label">Name (optional)</label>
      <input
        type="text"
        bind:value={name}
        placeholder="Defaults to fingerprint pseudonym"
        class="dialog-input"
        maxlength="32"
        on:keydown={(e) => { if (e.key === 'Enter') handleSave() }}
      />

      {#if error}
        <p class="dialog-error">{error}</p>
      {/if}
    </div>
    <div class="dialog-actions">
      <button class="dialog-btn dialog-btn-secondary" on:click={close} disabled={saving}>Cancel</button>
      <button class="dialog-btn dialog-btn-primary" on:click={handleSave} disabled={saving || !keyLooksOk}>
        {saving ? 'Saving…' : 'Save'}
      </button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
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
    min-width: 440px;
    max-width: 520px;
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
  .field-label {
    display: block;
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin-bottom: 6px;
  }
  .field-label + .dialog-input {
    margin-bottom: 6px;
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
  .dialog-input.mono {
    font-family: var(--font-mono);
    font-size: 12px;
  }
  .dialog-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
    outline: none;
  }
  .field-hint {
    font-size: 11px;
    color: var(--text-timestamp);
    margin-bottom: 14px;
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
    justify-content: flex-end;
    padding: 16px 20px 18px;
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
    color: var(--text-on-accent);
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
</style>
