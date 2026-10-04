<script>
  import { onMount } from 'svelte';
  import { ChangePassphrase, HasKeychainPassphrase } from './go.js';
  import { dbNoPassphrase, dbPath, toast } from './stores';

  /**
   * @typedef {Object} Props
   * @property {() => void} [onClose]
   */

  /** @type {Props} */
  let { onClose } = $props();

  let current = $state('');
  let next = $state('');
  let repeat = $state('');
  let showPass = $state(false);
  let saveToKeychain = $state(false);
  let loading = $state(false);
  let error = $state('');

  onMount(async () => {
    // Keep a saved passphrase saved: the backend replaces it with the
    // new one, or removes it when this is unticked.
    saveToKeychain = await HasKeychainPassphrase();
  });

  async function submit() {
    error = '';
    if (next !== repeat) {
      error = 'The new passphrases do not match';
      return;
    }
    loading = true;
    try {
      // Removing the passphrase (an empty new one) is confirmed in a
      // native dialog first; false means the user declined.
      const changed = await ChangePassphrase(current, next, saveToKeychain);
      if (changed) {
        toast.set({
          message: next ? 'Passphrase changed' : 'Passphrase removed',
          type: next ? 'info' : 'warning',
        });
        setTimeout(() => toast.set(null), 3000);
        onClose?.();
      }
    } catch (e) {
      error = e?.message || String(e) || 'Could not change the passphrase';
    }
    loading = false;
  }

  function handleKeydown(e) {
    if (e.key === 'Enter') {
      submit();
    } else if (e.key === 'Escape') {
      onClose?.();
    }
  }
</script>

<div
  class="overlay"
  role="presentation"
  onclick={() => !loading && onClose?.()}
  onkeydown={(e) => {
    if (e.key === 'Enter' || e.key === ' ') e.stopPropagation();
  }}
>
  <div
    class="dialog"
    role="dialog"
    aria-modal="true"
    aria-labelledby="change-passphrase-title"
    tabindex="-1"
    onclick={(e) => e.stopPropagation()}
    onkeydown={handleKeydown}
  >
    <div class="dialog-header">
      <div class="dialog-icon">
        <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
          <path
            fill-rule="evenodd"
            d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z"
            clip-rule="evenodd"
          />
        </svg>
      </div>
      <h3 id="change-passphrase-title">
        {$dbNoPassphrase ? 'Set a Passphrase' : 'Change Passphrase'}
      </h3>
    </div>

    <div class="dialog-body">
      <p class="dialog-desc">
        The database is encrypted again under a new key, so the old passphrase no longer opens it.
        Copies of the file made before, such as backups, still open with the old one.
      </p>
      <p class="dialog-path">{$dbPath}</p>

      {#if !$dbNoPassphrase}
        <input
          type={showPass ? 'text' : 'password'}
          value={current}
          oninput={(e) => (current = e.target.value)}
          placeholder="Current passphrase"
          class="pass-input"
          disabled={loading}
        />
      {/if}
      <input
        type={showPass ? 'text' : 'password'}
        value={next}
        oninput={(e) => (next = e.target.value)}
        placeholder={$dbNoPassphrase ? 'New passphrase' : 'New passphrase (empty to remove it)'}
        class="pass-input"
        disabled={loading}
      />
      <input
        type={showPass ? 'text' : 'password'}
        value={repeat}
        oninput={(e) => (repeat = e.target.value)}
        placeholder="New passphrase again"
        class="pass-input"
        disabled={loading}
      />

      <label class="checkbox-row">
        <input type="checkbox" bind:checked={showPass} disabled={loading} />
        <span>Show passphrases</span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" bind:checked={saveToKeychain} disabled={loading} />
        <span>Remember the new passphrase in the system keychain</span>
      </label>

      {#if error}
        <div class="error-msg">{error}</div>
      {/if}
    </div>

    <div class="dialog-actions">
      <button class="dialog-btn dialog-btn-ghost" onclick={() => onClose?.()} disabled={loading}>
        Cancel
      </button>
      <button class="dialog-btn dialog-btn-primary" onclick={submit} disabled={loading}>
        {loading ? 'Changing…' : $dbNoPassphrase ? 'Set Passphrase' : 'Change Passphrase'}
      </button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    backdrop-filter: blur(6px);
    -webkit-backdrop-filter: blur(6px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
    animation: fadeIn 0.2s ease-out;
  }
  .dialog {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-xl);
    min-width: 420px;
    max-width: 460px;
    box-shadow: var(--shadow-lg);
    animation: fadeInScale 0.2s ease-out;
    overflow: hidden;
  }
  .dialog-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 20px 20px 0;
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
    color: var(--text-primary);
  }
  .dialog-body {
    padding: 16px 20px 4px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .dialog-desc {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.5;
  }
  .dialog-path {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
    overflow-wrap: anywhere;
  }
  .pass-input {
    width: 100%;
    padding: 11px 14px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 13px;
    font-family: var(--font-mono);
    transition: border-color 0.2s;
  }
  .pass-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
    outline: none;
  }
  .pass-input:disabled {
    opacity: 0.6;
  }
  .checkbox-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .checkbox-row input {
    width: 15px;
    height: 15px;
    accent-color: var(--accent-primary);
    cursor: pointer;
  }
  .error-msg {
    font-size: 12px;
    color: var(--danger);
    background: var(--danger-dim);
    padding: 10px 12px;
    border-radius: var(--border-radius);
    line-height: 1.4;
  }
  .dialog-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    padding: 16px 20px 20px;
  }
  .dialog-btn {
    padding: 9px 18px;
    border-radius: var(--border-radius);
    font-size: 13px;
    font-weight: 600;
    transition: all 0.15s;
  }
  .dialog-btn-primary {
    background: var(--accent-primary);
    color: var(--text-on-accent);
  }
  .dialog-btn-primary:hover:not(:disabled) {
    background: var(--accent-primary-hover);
  }
  .dialog-btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  .dialog-btn-ghost {
    background: transparent;
    color: var(--text-muted);
    font-weight: 500;
  }
  .dialog-btn-ghost:hover:not(:disabled) {
    color: var(--text-secondary);
    background: var(--bg-hover);
  }
  .dialog-btn-ghost:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
</style>
