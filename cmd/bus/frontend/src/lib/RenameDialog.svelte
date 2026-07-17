<script>
  import { createEventDispatcher } from 'svelte'
  import {
    RenameSession, RenameHistorySession,
  } from '../../wailsjs/go/main/App.js'

  export let sessionId = ''
  export let isHistory = false

  const dispatch = createEventDispatcher()
  let name = ''

  async function handleRename() {
    if (!name.trim()) return
    try {
      if (isHistory) {
        await RenameHistorySession(sessionId, name.trim())
      } else {
        await RenameSession(sessionId, name.trim())
      }
      dispatch('renamed')
    } catch (e) {
      console.error('Rename error:', e)
    }
  }
</script>

<div class="overlay" on:click={() => dispatch('close')}>
  <div class="dialog" on:click|stopPropagation>
    <div class="dialog-header">
      <div class="dialog-icon">
        <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
          <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z" />
        </svg>
      </div>
      <h3>Rename Session</h3>
    </div>
    <div class="dialog-body">
      <p>Give this session a memorable name.</p>
      <input
        type="text"
        bind:value={name}
        placeholder="Enter new name..."
        class="dialog-input"
        on:keydown={(e) => { if (e.key === 'Enter') handleRename() }}
      />
    </div>
    <div class="dialog-actions">
      <button class="dialog-btn dialog-btn-secondary" on:click={() => dispatch('close')}>Cancel</button>
      <button class="dialog-btn dialog-btn-primary" on:click={handleRename}>Rename</button>
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
    min-width: 380px;
    max-width: 440px;
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
  .dialog-body p {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 12px;
  }
  .dialog-input {
    width: 100%;
    padding: 10px 14px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 13px;
    transition: border-color 0.2s;
  }
  .dialog-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
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
    transition: all 0.15s;
  }
  .dialog-btn-primary {
    background: var(--accent-primary);
    color: var(--text-on-accent);
  }
  .dialog-btn-primary:hover {
    background: var(--accent-primary-hover);
  }
  .dialog-btn-secondary {
    background: var(--bg-hover);
    color: var(--text-secondary);
  }
  .dialog-btn-secondary:hover {
    background: var(--border-color);
    color: var(--text-primary);
  }
</style>
