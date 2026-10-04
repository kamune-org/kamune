<script>
  import { VerifyResponse, CopyToClipboard } from './go.js';
  import { fingerprint } from './stores';

  // data is one verification request; App keys this component by its
  // requestID, so a new request always mounts a fresh dialog. waiting is
  // how many more requests are queued behind it.
  let { data, waiting = 0, onClose } = $props();

  // Accept stays disabled for a moment after the dialog appears, so a
  // click meant for the previous request cannot accept this one.
  const ARM_DELAY_MS = 1000;
  let armed = $state(false);
  let busy = $state(false);

  $effect(() => {
    const timer = setTimeout(() => (armed = true), ARM_DELAY_MS);
    return () => clearTimeout(timer);
  });

  async function answer(accepted) {
    if (busy || (accepted && !armed)) return;
    busy = true;
    try {
      await VerifyResponse(data.requestID, accepted);
    } finally {
      onClose?.(data.requestID);
    }
  }

  const accept = () => answer(true);
  const reject = () => answer(false);

  // The numeric fingerprint is eight groups of five digits, shown four
  // to a row so that people can read it out group by group.
  const groups = $derived((data.numeric || '').split(' ').filter(Boolean));

  let copiedField = $state('');
  async function copy(text, field) {
    try {
      await CopyToClipboard(text);
      copiedField = field;
      setTimeout(() => {
        if (copiedField === field) copiedField = '';
      }, 1500);
    } catch (e) {}
  }
</script>

<div class="overlay" onclick={reject}>
  <div class="dialog" onclick={(e) => e.stopPropagation()}>
    <div class="dialog-header">
      <div class="dialog-icon">
        <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
          <path
            fill-rule="evenodd"
            d="M6.625 2.655A9 9 0 0119 11a1 1 0 11-2 0 7 7 0 00-9.625-6.492 1 1 0 11-.75-1.853zM4.662 4.959A1 1 0 014.75 6.37 6.97 6.97 0 003 11a1 1 0 11-2 0 8.97 8.97 0 012.25-5.953 1 1 0 011.412-.088z"
            clip-rule="evenodd"
          />
          <path
            fill-rule="evenodd"
            d="M5 11a5 5 0 1110 0 1 1 0 11-2 0 3 3 0 10-6 0c0 1.677-.345 3.276-.968 4.729a1 1 0 11-1.838-.789A9.964 9.964 0 005 11zm8.921 2.012a1 1 0 01.831 1.145 19.86 19.86 0 01-.545 2.436 1 1 0 11-1.92-.558c.207-.713.371-1.445.49-2.192a1 1 0 011.144-.83z"
            clip-rule="evenodd"
          />
          <path
            fill-rule="evenodd"
            d="M10 8a3 3 0 00-3 3c0 1.29-.326 2.51-.882 3.57a1 1 0 01-1.764-.944A6.96 6.96 0 007 11a1 1 0 012 0c0 .859-.144 1.685-.41 2.452a1 1 0 01-1.908-.602A4.97 4.97 0 0010 11a1 1 0 012 0 6.96 6.96 0 01-.647 2.878 1 1 0 01-1.78-.91A4.97 4.97 0 0011 11a1 1 0 012 0c0 1.556-.372 3.027-1.03 4.34a1 1 0 01-1.775-.922A6.95 6.95 0 0010 11z"
            clip-rule="evenodd"
          />
        </svg>
      </div>
      <h3>Verify Peer</h3>
      {#if waiting > 0}
        <span class="verify-queue" title="More verification requests are waiting">
          {waiting} more waiting
        </span>
      {/if}
    </div>

    <div class="dialog-body">
      <div class="verify-peer-info">
        <div class="verify-label">
          {data.known ? 'Saved peer' : 'Connection request'}
        </div>
        <div class="verify-peer-name">{data.peerName}</div>
        <div class="verify-claim">
          Introduces itself as
          <span class="verify-claimed-name">“{data.claimedName || 'no name'}”</span>
        </div>
        <div class="verify-status" class:known={data.known} class:unknown={!data.known}>
          {#if data.known}
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"
              ><path
                fill-rule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                clip-rule="evenodd"
              /></svg
            >
            <span>Key is saved</span>
          {:else}
            <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14"
              ><path
                fill-rule="evenodd"
                d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                clip-rule="evenodd"
              /></svg
            >
            <span>Key is not saved</span>
          {/if}
        </div>
        <p class="verify-hint">
          {data.known
            ? 'This key is in your peer list under the name shown above. The name it introduces itself with is its own claim.'
            : 'This key is not in your peer list. The name it introduces itself with is its own claim and proves nothing.'}
        </p>
        {#if data.nameConflict}
          <div class="verify-warning verify-danger">
            Another saved peer has the name this peer uses, but a different key. This peer may be
            impersonating them. Compare the numeric fingerprint with them before accepting.
          </div>
        {:else if data.nameMismatch}
          <div class="verify-warning">
            This key is saved as “{data.peerName}”, but the peer introduces itself as “{data.claimedName}”.
          </div>
        {/if}
      </div>

      <div class="verify-section">
        <div class="verify-section-title">Numeric fingerprint</div>
        <div class="verify-numeric-row">
          <div class="verify-numeric" aria-label={data.numeric}>
            {#each groups as group}
              <span class="verify-numeric-group">{group}</span>
            {/each}
          </div>
          <button class="verify-copy-btn" onclick={() => copy(data.numeric, 'numeric')}>
            {copiedField === 'numeric' ? 'Copied' : 'Copy'}
          </button>
        </div>
        {#if $fingerprint.numeric}
          <div class="verify-own">
            Yours: <span class="verify-own-numeric">{$fingerprint.numeric}</span>
          </div>
        {/if}
        <p class="verify-hint">
          Over a channel you trust, ask the peer to read out the numeric fingerprint of its own key
          and check it against the number above. If their app shows no numeric fingerprint, compare
          the hex fingerprint below instead.
        </p>
      </div>

      <div class="verify-section">
        <div class="verify-section-title">Emoji fingerprint</div>
        <div class="verify-emoji">{data.emoji}</div>
        <p class="verify-hint">
          A quick visual check only: another key can be found with the same emojis.
        </p>
      </div>

      <details class="verify-section">
        <summary class="verify-section-title verify-summary">Hex fingerprint</summary>
        <div class="verify-hex-row">
          <input type="text" readonly value={data.hex} class="verify-hex-input" />
          <button class="verify-copy-btn" onclick={() => copy(data.hex, 'hex')}>
            {copiedField === 'hex' ? 'Copied' : 'Copy'}
          </button>
        </div>
      </details>

      {#if !data.known}
        <div class="verify-warning">
          <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
            <path
              fill-rule="evenodd"
              d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
              clip-rule="evenodd"
            />
          </svg>
          This peer is not in your trusted list. Compare its numeric fingerprint with the peer over a
          channel you trust before accepting.
        </div>
      {/if}
    </div>

    <div class="dialog-actions">
      <button class="dialog-btn dialog-btn-secondary" onclick={reject}>Reject</button>
      <button class="dialog-btn dialog-btn-primary" onclick={accept} disabled={!armed || busy}
        >Accept</button
      >
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
    z-index: 2000;
    animation: fadeIn 0.15s ease-out;
  }
  .dialog {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius-xl);
    min-width: 440px;
    max-width: 500px;
    /* Keep the actions on screen whatever the body holds. */
    max-height: calc(100vh - 32px);
    display: flex;
    flex-direction: column;
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
  .verify-queue {
    margin-left: auto;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 6px;
    color: var(--warning);
    background: var(--warning-dim);
  }
  .dialog-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .dialog-header h3 {
    font-size: 16px;
    font-weight: 700;
  }
  .dialog-body {
    padding: 16px 20px 4px;
    min-height: 0;
    overflow-y: auto;
  }
  .dialog-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    padding: 16px 20px 18px;
  }
  .dialog-btn {
    padding: 9px 22px;
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
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
  }
  .dialog-btn-secondary:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .verify-peer-info {
    margin-bottom: 16px;
  }
  .verify-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    font-weight: 600;
    margin-bottom: 6px;
  }
  .verify-peer-name,
  .verify-claim {
    overflow-wrap: anywhere;
  }
  .verify-peer-name {
    font-size: 15px;
    font-weight: 600;
    margin-bottom: 6px;
  }
  .verify-claim {
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 8px;
  }
  .verify-claimed-name {
    font-style: italic;
  }
  .verify-status {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 6px;
    margin-bottom: 8px;
  }
  .verify-status.known {
    color: var(--status-connected);
    background: var(--success-dim);
  }
  .verify-status.unknown {
    color: var(--warning);
    background: var(--warning-dim);
  }
  .verify-hint {
    font-size: 12px;
    color: var(--text-muted);
    line-height: 1.5;
  }

  .verify-section {
    margin-bottom: 14px;
  }
  .verify-section-title {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    font-weight: 600;
    margin-bottom: 6px;
  }
  .verify-emoji {
    font-size: 18px;
    letter-spacing: 4px;
    padding: 8px 12px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    text-align: center;
    color: var(--text-primary);
  }
  .verify-numeric-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .verify-numeric {
    flex: 1;
    display: grid;
    grid-template-columns: repeat(4, auto);
    justify-content: space-around;
    gap: 4px 12px;
    padding: 8px 12px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    font-family: var(--font-mono);
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 1px;
    color: var(--text-primary);
    user-select: all;
  }
  .verify-own {
    margin-top: 6px;
    font-size: 11px;
    color: var(--text-muted);
  }
  .verify-own-numeric {
    font-family: var(--font-mono);
    color: var(--text-secondary);
    user-select: all;
  }
  .verify-section .verify-hint {
    margin-top: 6px;
  }
  .verify-summary {
    cursor: pointer;
  }
  .verify-hex-row {
    display: flex;
    gap: 6px;
  }
  .verify-hex-input {
    flex: 1;
    padding: 8px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-size: 10px;
  }
  .verify-copy-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 8px 12px;
    background: var(--bg-hover);
    color: var(--text-secondary);
    border-radius: var(--border-radius);
    font-size: 11px;
    font-weight: 500;
    transition: all 0.15s;
  }
  .verify-copy-btn:hover {
    background: var(--border-color);
    color: var(--text-primary);
  }

  .verify-warning {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 11px;
    color: var(--warning);
    line-height: 1.5;
    padding: 10px;
    background: var(--warning-dim);
    border-radius: var(--border-radius);
    margin-bottom: 4px;
  }
  .verify-peer-info .verify-warning {
    margin-top: 8px;
  }
  .verify-danger {
    color: var(--danger);
    background: var(--danger-dim);
    font-weight: 600;
  }
  .verify-warning svg {
    flex-shrink: 0;
    margin-top: 1px;
  }
</style>
