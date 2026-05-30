<script>
  import { onMount } from 'svelte'
  import { SubmitPassphrase, HasKeychainPassphrase, GetDBPath, SetDBPath } from '../../wailsjs/go/main/App.js'

  export let pathChangeMode = false

  let passphrase = ''
  let showPass = false
  let saveToKeychain = true
  let loading = false
  let error = ''
  let hasKeychain = false
  let dbPath = ''
  let editingPath = false
  let newDbPath = ''

  onMount(async () => {
    hasKeychain = await HasKeychainPassphrase()
    dbPath = await GetDBPath()
    newDbPath = dbPath
  })

  function startEditPath() {
    newDbPath = dbPath
    editingPath = true
  }

  function cancelEditPath() {
    newDbPath = dbPath
    editingPath = false
  }

  async function submit() {
    loading = true
    error = ''
    try {
      if (editingPath) {
        editingPath = false
        dbPath = newDbPath
      }
      if (dbPath !== await GetDBPath()) {
        await SetDBPath(dbPath)
      } else if (pathChangeMode) {
        error = 'Database path not changed'
        loading = false
        return
      }
      await SubmitPassphrase(passphrase, saveToKeychain)
    } catch (e) {
      error = e.message || e || 'Wrong passphrase or corrupted database'
      loading = false
    }
  }

  async function skipPassphrase() {
    passphrase = ''
    saveToKeychain = false
    await submit()
  }

  function handleKeydown(e) {
    if (e.key === 'Enter') {
      if (editingPath) {
        editingPath = false
        dbPath = newDbPath
        return
      }
      submit()
    }
  }
</script>

<div class="overlay">
  <div class="dialog" on:keydown={handleKeydown}>
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

      <div class="dbpath-field">
        {#if editingPath}
          <input
            type="text"
            bind:value={newDbPath}
            class="dbpath-input"
            disabled={loading}
            autofocus
            on:keydown={(e) => { if (e.key === 'Escape') cancelEditPath() }}
          />
          <button class="dbpath-btn dbpath-btn-cancel" on:click={cancelEditPath} disabled={loading} title="Cancel">
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
              <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
          </button>
          <button class="dbpath-btn dbpath-btn-confirm" on:click={() => { editingPath = false; dbPath = newDbPath }} disabled={loading} title="Confirm">
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
              <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
            </svg>
          </button>
        {:else}
          <span class="dbpath-value" title={dbPath}>{dbPath}</span>
          <button class="dbpath-edit-btn" on:click={startEditPath} disabled={loading} title="Change database path">
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
              <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" />
            </svg>
          </button>
        {/if}
      </div>

      <div class="pass-field">
        <input
          type={showPass ? 'text' : 'password'}
          value={passphrase}
          on:input={(e) => passphrase = e.target.value}
          placeholder="Enter passphrase"
          class="pass-input"
          disabled={loading}
          autofocus
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

  .dbpath-field {
    position: relative;
    display: flex;
    align-items: center;
    margin-bottom: 10px;
  }
  .dbpath-value {
    width: 100%;
    padding: 11px 40px 11px 14px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-timestamp);
    font-family: var(--font-mono);
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    cursor: pointer;
    transition: border-color 0.2s;
  }
  .dbpath-value:hover {
    border-color: var(--text-timestamp);
  }
  .dbpath-edit-btn {
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
  .dbpath-edit-btn:hover:not(:disabled) {
    color: var(--text-secondary);
    background: var(--bg-hover);
  }
  .dbpath-edit-btn:disabled {
    opacity: 0.4;
  }
  .dbpath-input {
    width: 100%;
    padding: 11px 68px 11px 14px;
    background: var(--bg-input);
    border: 1px solid var(--accent-primary);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 12px;
    outline: none;
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
  }
  .dbpath-btn {
    position: absolute;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-timestamp);
    border-radius: 6px;
    transition: all 0.15s;
  }
  .dbpath-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-secondary);
  }
  .dbpath-btn:disabled {
    opacity: 0.4;
  }
  .dbpath-btn-cancel {
    right: 38px;
  }
  .dbpath-btn-confirm {
    right: 6px;
  }
  .dbpath-btn-confirm:hover:not(:disabled) {
    color: var(--accent-primary);
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
    font-size: 14px;
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
