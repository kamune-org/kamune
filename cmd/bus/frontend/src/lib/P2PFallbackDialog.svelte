<script>
    import { ConnectToServer } from "../../wailsjs/go/main/App.js";

    export let open = false;
    export let context = null;
    export let onClose = () => {};

    let useRelayAddr = "";
    let useRelayToken = "";
    let loading = false;

    async function retryP2P() {
        if (!context) return;
        loading = true;
        try {
            const result = await ConnectToServer(
                context.addr,
                context.transport,
                context.relayAddr,
                context.peerKey,
                "",
                "",
                context.brokerAddr,
                context.peerPubB64,
                context.p2pToken,
                context.useP2P,
                context.useBroker,
            );
            if (result.errorCode) {
                if (result.errorCode === "hole_punch_failed") {
                    // Stay open for another attempt.
                    return;
                }
                alert("Failed to connect: " + result.errorCode);
                close();
            } else {
                close();
            }
        } catch (e) {
            alert("Retry failed: " + e);
        } finally {
            loading = false;
        }
    }

    async function useRelay() {
        if (!context || !useRelayAddr.trim()) {
            alert("Enter a relay address to fall back to");
            return;
        }
        loading = true;
        try {
            const result = await ConnectToServer(
                useRelayAddr.trim(),
                "relay",
                useRelayAddr.trim(),
                useRelayToken.trim(),
                "",
                "",
                "",
                "",
                "",
                false,
                false,
            );
            if (result.errorCode) {
                alert("Relay fallback failed: " + result.errorCode);
            } else {
                close();
            }
        } catch (e) {
            alert("Relay fallback failed: " + e);
        } finally {
            loading = false;
        }
    }

    function close() {
        open = false;
        useRelayAddr = "";
        useRelayToken = "";
        onClose();
    }
</script>

{#if open}
    <div class="dialog-overlay" on:click={close}>
        <div class="dialog" on:click|stopPropagation>
            <h2>P2P hole-punch failed</h2>
            <p class="message">
                The direct connection could not be established. You can retry,
                fall back to a relay, or cancel.
            </p>
            <div class="actions">
                <button class="primary" on:click={retryP2P} disabled={loading}>
                    Retry P2P
                </button>
                <div class="relay-fallback">
                    <div class="relay-fields">
                        <input
                            type="text"
                            placeholder="Relay address (host:port)"
                            bind:value={useRelayAddr}
                            disabled={loading}
                        />
                        <input
                            type="text"
                            placeholder="Relay token (from share card)"
                            bind:value={useRelayToken}
                            disabled={loading}
                        />
                    </div>
                    <button on:click={useRelay} disabled={loading || !useRelayAddr.trim()}>
                        Use relay
                    </button>
                </div>
                <button on:click={close} disabled={loading}>Cancel</button>
            </div>
        </div>
    </div>
{/if}

<style>
    .dialog-overlay {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
    }
    .dialog {
        background: var(--bg, #1a1a1a);
        color: var(--fg, #fff);
        border-radius: 8px;
        padding: 1.5rem;
        max-width: 480px;
        width: 90%;
    }
    h2 {
        margin: 0 0 0.5rem;
    }
    .message {
        margin: 0 0 1rem;
        color: var(--fg-muted, #aaa);
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
        border: 1px solid var(--border, #444);
        background: var(--bg-input, #222);
        color: inherit;
        border-radius: 4px;
        width: 100%;
        box-sizing: border-box;
    }
    .relay-fallback button {
        flex-shrink: 0;
    }
    button {
        padding: 0.4rem 0.8rem;
        border: 1px solid var(--border, #444);
        background: var(--bg-button, #2a2a2a);
        color: inherit;
        border-radius: 4px;
        cursor: pointer;
    }
    button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    button.primary {
        background: var(--accent, #4a9eff);
        border-color: var(--accent, #4a9eff);
    }
</style>
