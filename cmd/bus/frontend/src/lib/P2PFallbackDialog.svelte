<script>
  // @ts-check
  // (svelte-check then reports names this script uses but never declares)
  import { CancelConnect, ConnectToServer, DisconnectSession } from './go.js';
  import { newConnectAttemptId } from './attempts';
  import { insecureWarning, isTLSRelayScheme, pinPlaceholder, relayAddress } from './relayaddr';

  /**
   * @typedef {Object} Props
   * @property {boolean} [open]
   * @property {any} [context]
   * @property {any} [onClose]
   */

  /** @type {Props} */
  let { open = $bindable(false), context = null, onClose = () => {} } = $props();

  let useRelayAddr = $state('');
  let useRelayToken = $state('');
  let useRelayPassword = $state('');
  // TLS by default, so the relay password and token are not sent in
  // the clear.
  let useRelayScheme = $state('wss');
  const relaySchemes = ['tcp', 'tls', 'ws', 'wss'];
  let useRelayInsecure = $state(false);
  let useRelayPin = $state('');
  let loading = $state(false);
  // attempt is the attempt ID of the connect in progress, which Cancel
  // cancels.
  let attempt = '';

  /**
   * connect runs dial, a ConnectToServer call with the attempt ID that it
   * is given, as the connect in progress. It returns null once Cancel has
   * cancelled it.
   * @param {(id: string) => Promise<any>} dial
   */
  async function connect(dial) {
    const id = newConnectAttemptId();
    attempt = id;
    loading = true;
    try {
      const result = await dial(id);
      if (id === attempt) return result;
      // Cancelled, but the session was established first.
      if (result.sessionId) await DisconnectSession(result.sessionId);
      return null;
    } catch (e) {
      if (id === attempt) throw e;
      return null;
    } finally {
      if (id === attempt) {
        attempt = '';
        loading = false;
      }
    }
  }

  async function cancel() {
    const id = attempt;
    attempt = '';
    loading = false;
    close();
    if (!id) return;
    try {
      await CancelConnect(id);
    } catch (e) {
      console.error('Cancel connect error:', e);
    }
  }

  async function retryP2P() {
    if (!context) return;
    const ctx = context;
    try {
      const result = await connect((id) =>
        ConnectToServer(
          ctx.addr,
          ctx.transport,
          ctx.relayAddr,
          '',
          ctx.name || '',
          '',
          ctx.brokerAddr,
          ctx.peerPubB64,
          ctx.p2pToken,
          ctx.useP2P,
          ctx.useBroker,
          id
        )
      );
      if (!result) return;
      if (result.errorCode) {
        if (result.errorCode === 'hole_punch_failed') {
          // Stay open for another attempt.
          return;
        }
        alert('Failed to connect: ' + result.errorCode);
        close();
      } else {
        close();
      }
    } catch (e) {
      alert('Retry failed: ' + e);
    }
  }

  async function useRelay() {
    if (!context || !useRelayAddr.trim()) {
      alert('Enter a relay address to fall back to');
      return;
    }
    // Without a token, the relay token is derived from the peer that the
    // P2P attempt was for. With one, the backend dials the token and
    // still pins that peer's key, so nobody else can answer on it.
    const peer = context.peerPubB64 || '';
    if (!useRelayToken.trim() && !peer) {
      alert('Enter the relay token from the share card');
      return;
    }
    // A pasted address may carry its scheme: use it rather than put the
    // chosen one in front of it.
    let host = useRelayAddr.trim();
    const typed = /^([a-z][a-z0-9+.-]*):\/\//i.exec(host);
    if (typed) {
      const scheme = (typed[1] || '').toLowerCase();
      if (!relaySchemes.includes(scheme)) {
        alert('Unsupported relay scheme: ' + scheme);
        return;
      }
      useRelayScheme = scheme;
      host = host.slice(typed[0].length);
    }
    const relayAddr = relayAddress(useRelayScheme, host, useRelayInsecure, useRelayPin);
    const token = useRelayToken.trim();
    const name = context.name || '';
    const password = useRelayPassword;
    try {
      const result = await connect((id) =>
        ConnectToServer(
          '',
          'relay',
          relayAddr,
          token,
          name,
          password,
          '',
          peer,
          '',
          false,
          false,
          id
        )
      );
      if (!result) return;
      if (result.errorCode) {
        alert('Relay fallback failed: ' + result.errorCode);
      } else {
        close();
      }
    } catch (e) {
      alert('Relay fallback failed: ' + e);
    }
  }

  function close() {
    open = false;
    useRelayAddr = '';
    useRelayToken = '';
    useRelayPassword = '';
    useRelayInsecure = false;
    useRelayPin = '';
    onClose();
  }
</script>

{#if open}
  <!-- While a connect runs, a click outside does not close the dialog:
       Cancel cancels the connect and closes it. -->
  <div class="dialog-overlay" onclick={() => !loading && close()}>
    <div class="dialog" onclick={(e) => e.stopPropagation()}>
      <h2>P2P hole-punch failed</h2>
      <p class="message">
        The direct connection could not be established. You can retry, fall back to a relay, or
        cancel.
      </p>
      <div class="actions">
        <button class="primary" onclick={retryP2P} disabled={loading}> Retry P2P </button>
        <div class="relay-fallback">
          <div class="relay-fields">
            <div class="scheme-pills">
              {#each relaySchemes as s}
                <button
                  class="scheme-btn"
                  class:active={useRelayScheme === s}
                  disabled={loading}
                  onclick={() => (useRelayScheme = s)}>{s}</button
                >
              {/each}
            </div>
            <input
              type="text"
              placeholder="Relay address (host:port)"
              bind:value={useRelayAddr}
              disabled={loading}
            />
            <input
              type="text"
              placeholder={context?.peerPubB64
                ? 'Relay token (optional, for a random token)'
                : 'Relay token (from share card)'}
              bind:value={useRelayToken}
              disabled={loading}
            />
            <input
              type="password"
              placeholder="Relay password (if required)"
              bind:value={useRelayPassword}
              disabled={loading}
            />
            {#if isTLSRelayScheme(useRelayScheme)}
              <input
                type="text"
                placeholder={pinPlaceholder}
                bind:value={useRelayPin}
                disabled={loading}
                spellcheck="false"
              />
              <label class="insecure-option">
                <input
                  type="checkbox"
                  bind:checked={useRelayInsecure}
                  disabled={loading || !!useRelayPin.trim()}
                />
                Skip TLS verification
              </label>
              {#if useRelayInsecure && !useRelayPin.trim()}
                <p class="insecure-warning">{insecureWarning}</p>
              {/if}
            {/if}
          </div>
          <button onclick={useRelay} disabled={loading || !useRelayAddr.trim()}> Use relay </button>
        </div>
        <button onclick={cancel}>Cancel</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .dialog-overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }
  .dialog {
    background: var(--bg-surface);
    color: var(--text-primary);
    border-radius: var(--border-radius);
    padding: 1.5rem;
    max-width: 480px;
    width: 90%;
    box-shadow: var(--shadow-lg);
  }
  h2 {
    margin: 0 0 0.5rem;
    color: var(--text-primary);
  }
  .message {
    margin: 0 0 1rem;
    color: var(--text-muted);
  }
  .actions {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .relay-fallback {
    display: flex;
    gap: 0.5rem;
    align-items: flex-start;
  }
  .relay-fields {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }
  .relay-fields input {
    padding: 0.4rem 0.6rem;
    border: 1px solid var(--border-color);
    background: var(--bg-input);
    color: var(--text-primary);
    border-radius: var(--border-radius);
    width: 100%;
    box-sizing: border-box;
  }
  .relay-fallback button {
    flex-shrink: 0;
  }
  .scheme-pills {
    display: flex;
    gap: 0.25rem;
  }
  .relay-fallback .scheme-btn {
    flex: 1;
    padding: 0.2rem 0.4rem;
    font-size: 0.75rem;
  }
  .relay-fallback .scheme-btn.active {
    background: var(--accent-primary);
    border-color: var(--accent-primary);
    color: var(--text-on-accent);
  }
  .insecure-option {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--text-muted);
  }
  .relay-fields .insecure-option input {
    width: auto;
  }
  .insecure-warning {
    margin: 0;
    font-size: 0.75rem;
    color: var(--warning);
  }
  button {
    padding: 0.4rem 0.8rem;
    border: 1px solid var(--border-color);
    background: var(--bg-surface);
    color: var(--text-primary);
    border-radius: var(--border-radius);
    cursor: pointer;
    transition: all 0.15s;
  }
  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  button.primary {
    background: var(--accent-primary);
    border-color: var(--accent-primary);
    color: var(--text-on-accent);
  }
  button.primary:hover:not(:disabled) {
    background: var(--accent-primary-hover);
  }
</style>
