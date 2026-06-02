<script>
  import { onMount, createEventDispatcher } from 'svelte'
  import {
    SubmitPassphrase, HasKeychainPassphrase, GetDBPath,
    SetDBPath, OpenFileDialog,
  } from '../../wailsjs/go/main/App.js'

  export let dismissable = false
  const dispatch = createEventDispatcher()

  let passphrase = ''
  let showPass = false
  let saveToKeychain = false
  let loading = false
  let error = ''
  let hasKeychain = false
  let dbPath = ''

  onMount(async () => {
    hasKeychain = await HasKeychainPassphrase()
    dbPath = await GetDBPath()
  })

  async function submit() {
    loading = true
    error = ''
    try {
      const currentPath = await GetDBPath()
      if (dbPath !== currentPath) {
        await SetDBPath(dbPath)
      }
      await SubmitPassphrase(passphrase, saveToKeychain)
    } catch (e) {
      error = e.message || e || 'Wrong passphrase or corrupted database'
      loading = false
    }
  }

  async function skipPassphrase() {
    passphrase = ''
    saveToKeychain = true
    await submit()
  }

  async function browsePath() {
    try {
      const file = await OpenFileDialog()
      if (file) {
        dbPath = file
      }
    } catch (e) {
      console.error('Failed to open file dialog:', e)
    }
  }

  function handleKeydown(e) {
    if (e.key === 'Enter') {
      submit()
    } else if (e.key === 'Escape' && dismissable) {
      dispatch('close')
    }
  }
</script>

<div class="overlay" on:click={dismissable ? () => dispatch('close') : undefined} on:keydown={dismissable ? (e) => { if (e.key === 'Enter' || e.key === ' ') e.stopPropagation() } : undefined}>
  <div class="dialog" on:click|stopPropagation on:keydown={handleKeydown}>
    <div class="dialog-header">
      <div class="dialog-icon">
        <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
          <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
        </svg>
      </div>
      <h3>Database Passphrase</h3>
    </div>

    <div class="dialog-body">
      <p class="dialog-desc">
        Enter your database passphrase to unlock your identity and chat history.
        The database is encrypted at rest.
      </p>

      <div class="path-field">
        <input
          type="text"
          bind:value={dbPath}
          class="path-input"
          placeholder="Path to database"
          disabled={loading}
        />
        <button class="path-browse-btn" on:click={browsePath} disabled={loading} title="Browse for file">
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
            <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
          </svg>
        </button>
      </div>

      <div class="pass-field">
        <input
          type={showPass ? 'text' : 'password'}
          value={passphrase}
          on:input={(e) => passphrase = e.target.value}
          placeholder="Enter passphrase"
          class="pass-input"
          disabled={loading}
        />
        <button
          class="toggle-vis"
          on:click={() => showPass = !showPass}
          tabindex="-1"
          title={showPass ? 'Hide' : 'Show'}
        >
          {#if showPass}
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
              <path fill-rule="evenodd" d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-1.473-1.473A10.014 10.014 0 0019.542 10C18.268 5.943 14.478 3 10 3a9.958 9.958 0 00-4.512 1.074l-1.78-1.781zm4.261 4.26l1.514 1.515a2.003 2.003 0 012.45 2.45l1.514 1.514a4 4 0 00-5.478-5.478z" clip-rule="evenodd" />
              <path d="M12.454 16.697L9.75 13.992a4 4 0 01-3.742-3.741L2.335 6.578A9.98 9.98 0 00.458 10c1.274 4.057 5.065 7 9.542 7 .847 0 1.669-.105 2.454-.303z" />
            </svg>
          {:else}
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
              <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
              <path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd" />
            </svg>
          {/if}
        </button>
      </div>

      <label class="checkbox-row">
        <input type="checkbox" bind:checked={saveToKeychain} disabled={loading || hasKeychain} />
        <span>Remember in system keychain</span>
      </label>

      {#if error}
        <div class="error-msg">
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
          </svg>
          {error}
        </div>
      {/if}
    </div>

    <div class="dialog-actions">
      <button class="dialog-btn dialog-btn-ghost" on:click={skipPassphrase} disabled={loading}>
        Use without password
      </button>
      <button class="dialog-btn dialog-btn-primary" on:click={submit} disabled={loading}>
        {loading ? 'Unlocking…' : 'Unlock'}
      </button>
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
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
  }
  .dialog-desc {
    font-size: 13px;
    color: var(--text-secondary);
    line-height: 1.5;
    margin-bottom: 14px;
  }

  .path-field {
    position: relative;
    display: flex;
    align-items: center;
    margin-bottom: 10px;
  }
  .path-input {
    width: 100%;
    padding: 11px 40px 11px 14px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 13px;
    transition: border-color 0.2s;
  }
  .path-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
    outline: none;
  }
  .path-input:disabled {
    opacity: 0.6;
  }
  .path-browse-btn {
    position: absolute;
    right: 6px;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-timestamp);
    border-radius: 6px;
    transition: all 0.15s;
  }
  .path-browse-btn:hover:not(:disabled) {
    color: var(--accent-primary);
    background: var(--accent-primary-dim);
  }
  .path-browse-btn:disabled {
    opacity: 0.4;
  }

  .pass-field {
    position: relative;
    display: flex;
    align-items: center;
  }
  .pass-input {
    width: 100%;
    padding: 11px 40px 11px 14px;
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
  .toggle-vis {
    position: absolute;
    right: 6px;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-timestamp);
    border-radius: 6px;
    transition: all 0.15s;
  }
  .toggle-vis:hover {
    color: var(--text-secondary);
    background: var(--bg-hover);
  }

  .checkbox-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 14px;
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
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 12px;
    color: var(--danger);
    background: var(--danger-dim);
    padding: 10px 12px;
    border-radius: var(--border-radius);
    margin-top: 14px;
    line-height: 1.4;
  }
  .error-msg svg {
    flex-shrink: 0;
    margin-top: 1px;
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
    color: #fff;
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
