<script>
  import { VerifyResponse, CopyToClipboard } from './go.js';

  // data is one verification request; App keys this component by its
  // requestID, so a new request always mounts a fresh dialog.
  let { data, onClose } = $props();

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

  function groups(code) {
    return (code || '').split(' ').filter(Boolean);
  }

  const ownGroups = $derived(groups(data.ownCode));
  const peerGroups = $derived(groups(data.peerCode));
  const showClaim = $derived(
    data.role === 'responder' && !!data.peerName
  );
  const showReached = $derived(
    data.mode === 'quick' &&
      data.role === 'initiator' &&
      !data.pinned &&
      data.known &&
      !!data.storedName
  );

  let copied = $state(false);
  async function copySafetyNumber() {
    try {
      await CopyToClipboard(data.safetyNumber);
      copied = true;
      setTimeout(() => {
        copied = false;
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
    </div>

    <div class="dialog-body">
      {#if data.resumed}
        <div class="verify-banner">
          Reconnecting session {data.sessionID}
        </div>
      {/if}

      <div class="verify-peer-info">
        <div class="verify-label">
          {data.known ? 'Saved peer' : 'Connection request'}
        </div>
        {#if data.nickname}
          <div class="verify-peer-name">Nickname: {data.nickname}</div>
        {/if}
        {#if showClaim}
          <div class="verify-peer-name">Name it gives itself: {data.peerName}</div>
        {/if}
        {#if showReached}
          <div class="verify-peer-name">You reached {data.storedName}.</div>
        {/if}
        <div class="verify-status" class:known={data.known} class:unknown={!data.known}>
          {#if data.known}
            <span>Key is saved</span>
          {:else}
            <span>Key is not saved</span>
          {/if}
        </div>
        {#if data.nameCollision}
          <div class="verify-warning verify-danger">
            A NEW key is using the name of your contact {data.storedName}.
            Compare both codes with them before accepting.
          </div>
          {#if data.storedCode}
            <div class="verify-code-line">
              <div class="verify-code-label">Saved contact's code:</div>
              <div class="verify-numeric" aria-label={data.storedCode}>
                {#each groups(data.storedCode) as group}
                  <span class="verify-numeric-group">{group}</span>
                {/each}
              </div>
            </div>
          {/if}
        {/if}
      </div>

      <div class="verify-section">
        <div class="verify-code-block">
          <div class="verify-code-line">
            <div class="verify-code-label">Your code:</div>
            <div class="verify-numeric" aria-label={data.ownCode}>
              {#each ownGroups as group}
                <span class="verify-numeric-group">{group}</span>
              {/each}
            </div>
          </div>
          <div class="verify-code-line">
            <div class="verify-code-label">Peer's code:</div>
            <div class="verify-numeric" aria-label={data.peerCode}>
              {#each peerGroups as group}
                <span class="verify-numeric-group">{group}</span>
              {/each}
            </div>
          </div>
        </div>
        <div class="verify-numeric-row">
          <p class="verify-hint">
            Read your code to your contact and have them read theirs. Every digit
            of both codes must match.
          </p>
          <button class="verify-copy-btn" onclick={copySafetyNumber}>
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>
    </div>

    <div class="dialog-actions">
      {#if data.nameCollision}
        <button class="dialog-btn dialog-btn-primary" onclick={reject} autofocus
          >Reject</button
        >
        <button class="dialog-btn dialog-btn-secondary" onclick={accept} disabled={!armed || busy}
          >Accept</button
        >
      {:else}
        <button class="dialog-btn dialog-btn-secondary" onclick={reject}>Reject</button>
        <button class="dialog-btn dialog-btn-primary" onclick={accept} disabled={!armed || busy}
          >Accept</button
        >
      {/if}
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
    max-width: 520px;
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

  .verify-banner {
    font-size: 12px;
    font-weight: 600;
    padding: 8px 10px;
    margin-bottom: 12px;
    border-radius: var(--border-radius);
    color: var(--accent-primary);
    background: var(--accent-primary-dim);
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
  .verify-peer-name {
    overflow-wrap: anywhere;
    font-size: 15px;
    font-weight: 600;
    margin-bottom: 6px;
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
    flex: 1;
  }

  .verify-section {
    margin-bottom: 14px;
  }
  .verify-code-block {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .verify-code-line {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .verify-code-label {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-secondary);
  }
  .verify-numeric-row {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    margin-top: 10px;
  }
  .verify-numeric {
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
    flex-shrink: 0;
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
</style>
