<script>
    import { onMount, onDestroy } from "svelte";
    import {
        GetSessions,
        GetHistorySessions,
        GetFingerprint,
        GetDBPath,
        GetVersion,
        GetLibraryVersion,
        GetMyName,
        GetStatus,
        GetVerificationMode,
		GetServerRunning,
		GetServerTransport,
		StartServer,
        ConnectToServer,
        StopServer,
        ConfirmStopServer,
        DisconnectSession,
        SendMessage,
        RefreshHistory,
        DeleteHistorySession,
        SetActiveSession,
        GetStorageReady,
        GetLogEntries,
        CancelStartServer,
        ListKnownPeers,
    } from "../wailsjs/go/main/App.js";
    import { EventsOn, EventsOff } from "../wailsjs/runtime/runtime.js";

    import {
        sessions,
        historySessions,
        sessionMessages,
        status,
        fingerprint,
        dbPath,
        logEntries,
        verificationMode,
        appVersion,
        activeSessionId,
        sidebarTab,
        logPanelOpen,
        verificationDialog,
        shareDialog,
        dialogs,
        toast,
        versionWarnings,
        libraryVersion,
        myName,
        relayToken,
        relayTokens,
        peers,
    } from "./lib/stores.js";
    import { K, isMac } from "./lib/keyboard.js";

    import Sidebar from "./lib/Sidebar.svelte";
    import ChatPanel from "./lib/ChatPanel.svelte";
    import StatusBar from "./lib/StatusBar.svelte";
    import LogViewer from "./lib/LogViewer.svelte";
    import VerifyDialog from "./lib/VerifyDialog.svelte";
    import RenameDialog from "./lib/RenameDialog.svelte";
    import PassphraseDialog from "./lib/PassphraseDialog.svelte";
    import ShareDialog from "./lib/ShareDialog.svelte";
    import ImportDialog from "./lib/ImportDialog.svelte";
    import AddPeerDialog from "./lib/AddPeerDialog.svelte";
    import PeerInfoDialog from "./lib/PeerInfoDialog.svelte";
    import Resizer from "./lib/Resizer.svelte";

	let serverActive = false;
	let runningServerTransport = '';

    const SIDEBAR_MIN_WIDTH = 240;
    const SIDEBAR_MAX_WIDTH = 500;
    const SIDEBAR_DEFAULT_WIDTH = 320;
    const SIDEBAR_WIDTH_KEY = 'kamune:sidebar-width';

    function clampSidebarWidth(w) {
        if (!Number.isFinite(w)) return SIDEBAR_DEFAULT_WIDTH;
        if (w < SIDEBAR_MIN_WIDTH) return SIDEBAR_MIN_WIDTH;
        if (w > SIDEBAR_MAX_WIDTH) return SIDEBAR_MAX_WIDTH;
        return w;
    }

    function applySidebarWidth(w) {
        document.documentElement.style.setProperty(
            '--sidebar-width', w + 'px',
        );
    }

    function loadSidebarWidth() {
        try {
            const raw = localStorage.getItem(SIDEBAR_WIDTH_KEY);
            if (!raw) return SIDEBAR_DEFAULT_WIDTH;
            return clampSidebarWidth(parseInt(raw, 10));
        } catch {
            return SIDEBAR_DEFAULT_WIDTH;
        }
    }

    function saveSidebarWidth(w) {
        try {
            localStorage.setItem(SIDEBAR_WIDTH_KEY, String(w));
        } catch {
            // ignore quota / private-mode failures
        }
    }

    applySidebarWidth(loadSidebarWidth());

    function handleSidebarResize(e) {
        const w = clampSidebarWidth(e.detail);
        applySidebarWidth(w);
        saveSidebarWidth(w);
    }

	const TRANSPORTS = ["tcp", "udp", "relay"];

    const LABELS = {
        type: "Type",
        peerName: "Peer Name",
        sessionID: "Session ID",
        messageCount: "Messages",
        lastActivity: "Last Activity",
        isServer: "Is Server",
        name: "Name",
        firstMessage: "First Message",
        lastMessage: "Last Message",
        remoteVersion: "Remote Version",
        transportType: "Transport",
    };

    const INFO_ORDER = [
        "name",
        "type",
        "peerName",
        "sessionID",
        "messageCount",
        "firstMessage",
        "lastMessage",
        "lastActivity",
        "isServer",
        "remoteVersion",
        "transportType",
    ];

    let connectServerAddr = "";
    let connectServerAddr2 = "";
    let serverTransport = "tcp";
    let connectTransport = "tcp";
    let serverRelayAddr = "";
    let serverRelayScheme = "tcp";
    let serverRelayPassword = "";
    let serverRelayInsecure = false;
    let connectRelayAddr = "";
    let connectRelayScheme = "tcp";
    let connectRelayPassword = "";
    let connectPeerKey = "";
    let connectRelayInsecure = false;
    let serverError = "";
    let connectError = "";

    let serverLoading = false;
    let connectLoading = false;
    let showPassphraseDialog = true;
    let passphraseDismissable = false;

    onMount(() => {
        // 1) Cleanup stale handlers — sync, before any async work
        //    (Wails EventsOn adds without dedup — if onMount ran before,
        //     handlers accumulate and events fire 2×)
        EventsOff("status-changed");
        EventsOff("session-new");
        EventsOff("session-closed");
        EventsOff("session-updated");
        EventsOff("history-updated");
        EventsOff("session-messages");
        EventsOff("message-sent");
        EventsOff("message-received");
        EventsOff("verify-peer");
        EventsOff("log-entry");
        EventsOff("notification");
        EventsOff("storage-ready");
        EventsOff("request-passphrase");
        EventsOff("server-running");
        EventsOff("version-warning");
        EventsOff("verification-mode-changed");
        EventsOff("fingerprint-changed");
        EventsOff("relay-token");
        EventsOff("local-name-changed");
        EventsOff("relay-tokens");
        EventsOff("toast");
        EventsOff("show-share-card");
        EventsOff("show-import-url");
        EventsOff("import-from-clipboard");
        EventsOff("peers-updated");

        // 2) Register handlers — sync, before any async work
        EventsOn("status-changed", (data) => status.set(data));
        EventsOn("session-new", async (data) => {
            await loadSessions();
            activeSessionId.set(data.id);
        });
        EventsOn("session-closed", async (data) => {
            await loadSessions();
            await loadHistory();
            activeSessionId.update(id => {
                const s = $sessions;
                return s.find(ses => ses.id === data) ? id : null;
            });
            versionWarnings.update((w) => {
                const n = { ...w };
                delete n[data];
                return n;
            });
        });
        EventsOn("session-updated", async (data) => {
            await loadSessions();
        });
        EventsOn("history-updated", async (data) => {
            await loadHistory();
        });
        EventsOn("session-messages", (sessionID, messages) => {
            sessionMessages.update((m) => ({ ...m, [sessionID]: messages }));
        });
        EventsOn("message-sent", (sessionID, msg) => {
            sessionMessages.update((m) => {
                const msgs = m[sessionID] || [];
                return { ...m, [sessionID]: [...msgs, msg] };
            });
        });
        EventsOn("message-received", (sessionID, msg) => {
            sessionMessages.update((m) => {
                const msgs = m[sessionID] || [];
                return { ...m, [sessionID]: [...msgs, msg] };
            });
        });
        EventsOn("verify-peer", (data) => {
            verificationDialog.set(data);
        });
        EventsOn("log-entry", (entry) => {
            logEntries.update((e) => {
                const next = [...e, entry];
                return next.length > 200 ? next.slice(-200) : next;
            });
        });
        EventsOn("notification", (title, message) => {
            if (
                "Notification" in window &&
                Notification.permission === "granted"
            ) {
                new Notification(title, { body: message });
            }
        });
        EventsOn("storage-ready", () => {
            showPassphraseDialog = false;
        });
        EventsOn("request-passphrase", () => {
            showPassphraseDialog = true;
            passphraseDismissable = false;
        });
        EventsOn("verification-mode-changed", (mode) => {
            verificationMode.set(mode);
        });
        EventsOn("fingerprint-changed", (emoji, b64, hex, sum) => {
            fingerprint.set({ emoji, b64, hex, sum });
        });
        EventsOn("local-name-changed", (name) => {
            myName.set(name);
        });
        EventsOn("server-running", (running, transportType) => {
            serverActive = running;
            runningServerTransport = running ? (transportType || '') : '';
            if (!running) {
                relayToken.set("");
                relayTokens.set([]);
            }
        });
        EventsOn("relay-token", (token) => {
            relayToken.set(token);
            toast.set({
                message: `Relay token: ${token}`,
                token,
                type: "token",
            });
            setTimeout(() => toast.set(null), 4000);
        });
        EventsOn("relay-tokens", (tokens) => {
            relayTokens.set(tokens || []);
        });
        EventsOn("version-warning", (sessionId, msg) => {
            versionWarnings.update((w) => ({ ...w, [sessionId]: msg }));
        });
        EventsOn("toast", (message, type) => {
            toast.set({ message, type: type || "info" });
            setTimeout(() => toast.set(null), 2000);
        });

        EventsOn("show-share-card", async () => {
            const { GetShareInfo } = await import("../wailsjs/go/main/App.js");
            try {
                const info = await GetShareInfo();
                shareDialog.set(info);
            } catch (e) {
                toast.set({
                    message: "Start a server first to share a connection card",
                    type: "warning",
                });
                setTimeout(() => toast.set(null), 4000);
            }
        });

        EventsOn("show-import-url", () => {
            dialogs.update((d) => ({ ...d, showImport: true }));
        });

        EventsOn("import-from-clipboard", (urlStr) => {
            try {
                const url = new URL(urlStr);
                const transport = url.protocol.slice(0, -1);
                if (!transport) throw new Error('Unknown transport');
                connectTransport = transport;
                if (transport === "relay") {
                    connectRelayAddr = url.host;
                    connectRelayScheme = url.searchParams.get('scheme') || 'ws';
                    connectPeerKey = url.searchParams.get('token') || '';
                    connectRelayInsecure = url.searchParams.get('insecure') === 'true';
                } else {
                    connectServerAddr2 = url.host;
                }
                dialogs.update((d) => ({ ...d, showConnect: true }));
            } catch {
                toast.set({ message: "Invalid connection URL in clipboard", type: "error" });
                setTimeout(() => toast.set(null), 3000);
            }
        });

        EventsOn("peers-updated", async () => {
            await loadPeers();
        });

        // 3) Async init — deferred, no race between cleanup and registration
        (async () => {
            const v = await GetVersion();
            appVersion.set(v);

            const lv = await GetLibraryVersion();
            libraryVersion.set(lv);

            const mn = await GetMyName();
            myName.set(mn);

            const s = await GetStatus();
            status.set(s);

            const fp = await GetFingerprint();
            fingerprint.set({
                emoji: fp.emoji,
                b64: fp.b64,
                hex: fp.hex,
                sum: fp.sum,
            });

            const p = await GetDBPath();
            dbPath.set(p);

            const vm = await GetVerificationMode();
            verificationMode.set(vm);

            serverActive = await GetServerRunning();
            runningServerTransport = serverActive ? await GetServerTransport() : '';

            await loadSessions();
            await loadHistory();
            await loadPeers();

            const existingLogs = await GetLogEntries();
            logEntries.set(existingLogs);

            const ready = await GetStorageReady();
            showPassphraseDialog = !ready;

            // Request notification permission
            if ("Notification" in window && Notification.permission === "default") {
                Notification.requestPermission();
            }
        })();
    });

    onDestroy(() => {
        EventsOff("status-changed");
        EventsOff("session-new");
        EventsOff("session-closed");
        EventsOff("session-updated");
        EventsOff("history-updated");
        EventsOff("session-messages");
        EventsOff("message-sent");
        EventsOff("message-received");
        EventsOff("verify-peer");
        EventsOff("log-entry");
        EventsOff("notification");
        EventsOff("storage-ready");
        EventsOff("request-passphrase");
        EventsOff("server-running");
        EventsOff("version-warning");
        EventsOff("verification-mode-changed");
        EventsOff("fingerprint-changed");
        EventsOff("local-name-changed");
        EventsOff("relay-token");
        EventsOff("relay-tokens");
        EventsOff("toast");
        EventsOff("show-share-card");
        EventsOff("show-import-url");
        EventsOff("import-from-clipboard");
        EventsOff("peers-updated");
    });

    async function loadSessions() {
        const s = await GetSessions();
        sessions.set(s);
    }

    async function loadHistory() {
        const h = await GetHistorySessions();
        historySessions.set(h);
    }

    async function loadPeers() {
        const p = await ListKnownPeers();
        peers.set(p || []);
    }

    async function handleStartServer() {
        if (serverTransport === "relay") {
            if (!serverRelayAddr.trim()) {
                serverError = "Relay address is required";
                return;
            }
        } else if (!connectServerAddr.trim()) {
            serverError = "Listen address is required";
            return;
        }
        closeAllDialogs();
        serverLoading = true;
        try {
            const addr =
                serverTransport === "relay" ? "" : connectServerAddr.trim();
            const relayAddr =
                serverTransport === "relay"
                    ? `${serverRelayScheme}://${serverRelayAddr.trim()}${serverRelayInsecure ? '?insecure=true' : ''}`
                    : "";
            const relayPw =
                serverTransport === "relay" ? serverRelayPassword : "";
            const [fp, token] = await StartServer(
                addr,
                serverTransport,
                relayAddr,
                $myName,
                relayPw,
            );
            await loadSessions();
            if (token) {
                toast.set({
                    message: `Relay token: ${token}`,
                    token,
                    type: "token",
                });
                setTimeout(() => toast.set(null), 4000);
            }
        } catch (e) {
            alert("Failed to start server: " + e);
        } finally {
            serverLoading = false;
        }
    }

    async function handleStopServer() {
        if (!(await ConfirmStopServer())) {
            return;
        }
        try {
            await StopServer();
            await loadSessions();
        } catch (e) {
            console.error("Stop server error:", e);
        } finally {
            serverLoading = false;
        }
    }

    async function handleCancel() {
        if (serverLoading) {
            try {
                await CancelStartServer();
            } catch (e) {
                console.error("Cancel server error:", e);
            } finally {
                serverLoading = false;
            }
        } else if (connectLoading) {
            connectLoading = false;
        }
    }

    async function handleConnect() {
        if (connectTransport === "relay") {
            if (!connectRelayAddr.trim()) {
                connectError = "Relay address is required";
                return;
            }
            if (!connectPeerKey.trim()) {
                connectError = "Relay token is required";
                return;
            }
        } else if (!connectServerAddr2.trim()) {
            connectError = "Peer address is required";
            return;
        }
        closeAllDialogs();
        connectLoading = true;
        try {
            const addr =
                connectTransport === "relay" ? "" : connectServerAddr2.trim();
            const relayAddr =
                connectTransport === "relay"
                    ? `${connectRelayScheme}://${connectRelayAddr.trim()}${connectRelayInsecure ? '?insecure=true' : ''}`
                    : "";
            const peerKey =
                connectTransport === "relay" ? connectPeerKey.trim() : "";
            const pw = connectTransport === "relay" ? connectRelayPassword : "";
            const sessionId = await ConnectToServer(
                addr,
                connectTransport,
                relayAddr,
                peerKey,
                $myName,
                pw,
            );
            await loadSessions();
            activeSessionId.set(sessionId);
        } catch (e) {
            alert("Failed to connect: " + e);
        } finally {
            connectLoading = false;
        }
    }

    async function handleDisconnect(sessionId) {
        try {
            await DisconnectSession(sessionId);
        } catch (e) {
            console.error("Disconnect error:", e);
        }
        await handleRefreshHistory();
        sidebarTab.set("history");
        activeSessionId.set(sessionId);
        await handleLoadHistoryMessages(sessionId);
    }

    async function handleSendMessage(sessionId, text) {
        if (!text.trim()) return;
        try {
            await SendMessage(sessionId, text);
        } catch (e) {
            console.error("Send error:", e);
            toast.set({
                message: "Failed to send message: " + (e.message || e),
                type: "error",
            });
            setTimeout(() => toast.set(null), 4000);
        }
    }

    async function getSessionMessages(sessionId) {
        const { GetSessionMessages } =
            await import("../wailsjs/go/main/App.js");
        return (await GetSessionMessages(sessionId)) || [];
    }

    async function handleLoadHistoryMessages(sessionId) {
        const { LoadHistoryMessages, GetHistoryMessages } =
            await import("../wailsjs/go/main/App.js");
        await LoadHistoryMessages(sessionId);
        const msgs = (await GetHistoryMessages(sessionId)) || [];
        sessionMessages.update((m) => ({ ...m, [sessionId]: msgs }));
    }

    async function handleRefreshHistory() {
        await RefreshHistory();
    }

    async function handleSelectTab(sessionId) {
        activeSessionId.set(sessionId);
        SetActiveSession(sessionId || "");
        if (sessionId) {
            const existing = $sessionMessages[sessionId];
            if (!existing || existing.length === 0) {
                const msgs = await getSessionMessages(sessionId);
                if (msgs.length > 0) {
                    sessionMessages.update((m) => ({
                        ...m,
                        [sessionId]: msgs,
                    }));
                }
            }
        }
    }

    function closeAllDialogs() {
        serverError = "";
        connectError = "";
        dialogs.update((d) => ({
            ...d,
            showServer: false,
            showConnect: false,
            showImport: false,
            showSessionInfo: null,
            showRename: null,
            showRenameType: null,
            showDelete: null,
            showShortcuts: false,
            showAddPeer: false,
            peerInfoFor: null,
        }));
    }

    function handleOverlayKeydown(e) {
        if (e.key === "Escape") closeAllDialogs();
    }

    function noopPropagationKeydown(e) {
        e.stopPropagation();
    }

    async function handleDisconnectAll() {
        const currentSessions = await GetSessions();
        for (const s of currentSessions) {
            await DisconnectSession(s.id);
        }
        activeSessionId.set(null);
        SetActiveSession("");
        await loadSessions();
    }

    function handleKeydown(e) {
        if (isMac ? e.metaKey : e.ctrlKey) {
            switch (e.key) {
                case "l":
                    e.preventDefault();
                    logPanelOpen.update((v) => !v);
                    break;
                case "n":
                    e.preventDefault();
                    dialogs.update((d) => ({ ...d, showConnect: true }));
                    break;
                case "s":
                    e.preventDefault();
                    if (serverActive) {
                        handleStopServer();
                    } else {
                        dialogs.update((d) => ({ ...d, showServer: true }));
                    }
                    break;
                case "h":
                    e.preventDefault();
                    activeSessionId.set(null);
                    sidebarTab.set("history");
                    handleRefreshHistory();
                    break;
                case "w":
                    e.preventDefault();
                    if (e.shiftKey) {
                        handleDisconnectAll();
                    } else if ($activeSessionId) {
                        handleDisconnect($activeSessionId);
                    }
                    break;
                case "r":
                    e.preventDefault();
                    handleRefreshHistory();
                    break;
            }
        }
        if (e.key === "Escape") {
            closeAllDialogs();
            logPanelOpen.set(false);
        }
    }
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="app-layout">
    {#if showPassphraseDialog}
        <PassphraseDialog
            dismissable={passphraseDismissable}
            on:close={async () => {
                showPassphraseDialog = false;
                const p = await GetDBPath();
                dbPath.set(p);
            }}
        />
    {/if}

    {#if $verificationDialog}
        <VerifyDialog
            data={$verificationDialog}
            on:close={() => verificationDialog.set(null)}
        />
    {/if}

    <!-- Dialogs -->
    {#if $dialogs.showServer}
        <div
            class="dialog-overlay"
            on:click={closeAllDialogs}
            on:keydown={handleOverlayKeydown}
        >
            <div
                class="dialog"
                on:click|stopPropagation
                on:keydown={noopPropagationKeydown}
            >
                <div class="dialog-header">
                    <div class="dialog-icon">
                        <svg
                            viewBox="0 0 20 20"
                            fill="currentColor"
                            width="18"
                            height="18"
                        >
                            <path
                                fill-rule="evenodd"
                                d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z"
                                clip-rule="evenodd"
                            />
                        </svg>
                    </div>
                    <h3>Start Server</h3>
                </div>
                <div class="dialog-body">
                    <div class="transport-pills">
                        <span class="transport-label">Transport</span>
                        <div class="pill-group">
                            {#each TRANSPORTS as t}
                                <button
                                    class="pill-btn"
                                    class:pill-active={serverTransport === t}
                                    on:click={() => {
                                        serverTransport = t;
                                        serverError = "";
                                    }}>{t.toUpperCase()}</button
                                >
                            {/each}
                        </div>
                    </div>

                    {#if serverTransport !== "relay"}
                        <input
                            bind:value={connectServerAddr}
                            placeholder="Listen address (e.g. :8443)"
                            class="dialog-input"
                        />
                    {:else}
                        <div class="relay-addr-row">
                            <div class="scheme-pills">
                                {#each ["tcp", "tls", "ws", "wss"] as s}
                                    <button
                                        class="scheme-btn"
                                        class:active={serverRelayScheme === s}
                                        on:click={() => {
                                            serverRelayScheme = s;
                                            serverError = "";
                                        }}>{s}</button
                                    >
                                {/each}
                            </div>
                            <span class="scheme-sep">://</span>
                            <input
                                bind:value={serverRelayAddr}
                                placeholder="relay.example.com:8888"
                                class="dialog-input"
                            />
                        </div>

                        <input
                            bind:value={serverRelayPassword}
                            type="password"
                            placeholder="Relay password (if required)"
                            class="dialog-input"
                        />
                        {#if serverRelayScheme === 'wss' || serverRelayScheme === 'tls'}
                            <label class="insecure-option">
                                <input type="checkbox" bind:checked={serverRelayInsecure} />
                                Skip TLS verification
                            </label>
                        {/if}
                    {/if}
                    {#if serverError}
                        <p class="dialog-error">{serverError}</p>
                    {/if}
                </div>
                <div class="dialog-actions">
                    <button
                        class="dialog-btn dialog-btn-secondary"
                        on:click={closeAllDialogs}>Cancel</button
                    >
                    <button
                        class="dialog-btn dialog-btn-primary"
                        on:click={handleStartServer}
                        disabled={serverLoading}
                    >
                        {serverLoading ? "Starting…" : "Start Server"}
                    </button>
                </div>
            </div>
        </div>
    {/if}

    {#if $dialogs.showConnect}
        <div
            class="dialog-overlay"
            on:click={closeAllDialogs}
            on:keydown={handleOverlayKeydown}
        >
            <div
                class="dialog"
                on:click|stopPropagation
                on:keydown={noopPropagationKeydown}
            >
                <div class="dialog-header">
                    <div class="dialog-icon">
                        <svg
                            viewBox="0 0 20 20"
                            fill="currentColor"
                            width="18"
                            height="18"
                        >
                            <path
                                d="M11 3a1 1 0 100 2h2.586l-6.293 6.293a1 1 0 101.414 1.414L15 6.414V9a1 1 0 102 0V4a1 1 0 00-1-1h-5z"
                            />
                            <path
                                d="M5 5a2 2 0 00-2 2v8a2 2 0 002 2h8a2 2 0 002-2v-3a1 1 0 10-2 0v3H5V7h3a1 1 0 000-2H5z"
                            />
                        </svg>
                    </div>
                    <h3>Connect to Peer</h3>
                </div>
                <div class="dialog-body">
                    <div class="transport-pills">
                        <span class="transport-label">Transport</span>
                        <div class="pill-group">
                            {#each TRANSPORTS as t}
                                <button
                                    class="pill-btn"
                                    class:pill-active={connectTransport === t}
                                    on:click={() => {
                                        connectTransport = t;
                                        connectError = "";
                                    }}>{t.toUpperCase()}</button
                                >
                            {/each}
                        </div>
                    </div>

                    {#if connectTransport !== "relay"}
                        <input
                            bind:value={connectServerAddr2}
                            placeholder="Peer address (e.g. 192.168.1.100:8443)"
                            class="dialog-input"
                        />
                    {:else}
                        <div class="relay-addr-row">
                            <div class="scheme-pills">
                                {#each ["tcp", "tls", "ws", "wss"] as s}
                                    <button
                                        class="scheme-btn"
                                        class:active={connectRelayScheme === s}
                                        on:click={() => {
                                            connectRelayScheme = s;
                                            connectError = "";
                                        }}>{s}</button
                                    >
                                {/each}
                            </div>
                            <span class="scheme-sep">://</span>
                            <input
                                bind:value={connectRelayAddr}
                                placeholder="relay.example.com:8888"
                                class="dialog-input"
                            />
                        </div>

                        <input
                            bind:value={connectPeerKey}
                            placeholder="Relay token (hex)"
                            class="dialog-input"
                        />

                        <input
                            bind:value={connectRelayPassword}
                            type="password"
                            placeholder="Relay password (if required)"
                            class="dialog-input"
                        />
                        {#if connectRelayScheme === 'wss' || connectRelayScheme === 'tls'}
                            <label class="insecure-option">
                                <input type="checkbox" bind:checked={connectRelayInsecure} />
                                Skip TLS verification
                            </label>
                        {/if}
                    {/if}
                    {#if connectError}
                        <p class="dialog-error">{connectError}</p>
                    {/if}
                </div>
                <div class="dialog-actions">
                    <button
                        class="dialog-btn dialog-btn-secondary"
                        on:click={closeAllDialogs}>Cancel</button
                    >
                    <button
                        class="dialog-btn dialog-btn-primary"
                        on:click={handleConnect}
                        disabled={connectLoading}
                    >
                        {connectLoading ? "Connecting…" : "Connect"}
                    </button>
                </div>
            </div>
        </div>
    {/if}

    {#if $dialogs.showSessionInfo}
        <div
            class="dialog-overlay"
            on:click={closeAllDialogs}
            on:keydown={handleOverlayKeydown}
        >
            <div
                class="dialog"
                on:click|stopPropagation
                on:keydown={noopPropagationKeydown}
            >
                <div class="dialog-header">
                    <div class="dialog-icon">
                        <svg
                            viewBox="0 0 20 20"
                            fill="currentColor"
                            width="18"
                            height="18"
                        >
                            <path
                                fill-rule="evenodd"
                                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                                clip-rule="evenodd"
                            />
                        </svg>
                    </div>
                    <h3>Session Info</h3>
                </div>
                <div class="dialog-body">
                    <div class="info-rows">
                        {#each INFO_ORDER as key}
                            {@const val = $dialogs.showSessionInfo[key]}
                            {#if val !== undefined && val !== null && val !== ""}
                                <div class="info-row">
                                    <span class="info-key">{LABELS[key] || key}</span>
                                    <span class="info-val">
                                        {#if key === "sessionID"}
                                            {val}
                                        {:else if key === "lastActivity" || key === "lastMessage" || key === "firstMessage"}
                                            {new Date(val).toLocaleString()}
                                        {:else if key === "isServer"}
                                            {val ? "Yes" : "No"}
                                        {:else}
                                            {val}
                                        {/if}
                                    </span>
                                </div>
                            {/if}
                        {/each}
                    </div>
                </div>
                <div class="dialog-actions">
                    <button
                        class="dialog-btn dialog-btn-primary"
                        on:click={closeAllDialogs}>Close</button
                    >
                </div>
            </div>
        </div>
    {/if}

    {#if $dialogs.showRename}
        <RenameDialog
            sessionId={$dialogs.showRename}
            isHistory={$dialogs.showRenameType === "history"}
            on:close={closeAllDialogs}
            on:renamed={async () => {
                await loadSessions();
                await loadHistory();
                closeAllDialogs();
            }}
        />
    {/if}

    {#if $dialogs.showDelete}
        <div
            class="dialog-overlay"
            on:click={closeAllDialogs}
            on:keydown={handleOverlayKeydown}
        >
            <div
                class="dialog dialog-danger"
                on:click|stopPropagation
                on:keydown={noopPropagationKeydown}
            >
                <div class="dialog-header">
                    <div class="dialog-icon dialog-icon-danger">
                        <svg
                            viewBox="0 0 20 20"
                            fill="currentColor"
                            width="18"
                            height="18"
                        >
                            <path
                                fill-rule="evenodd"
                                d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z"
                                clip-rule="evenodd"
                            />
                        </svg>
                    </div>
                    <h3>Delete Session</h3>
                </div>
                <div class="dialog-body">
                    <p>
                        Are you sure you want to permanently delete this
                        session's history? This cannot be undone.
                    </p>
                </div>
                <div class="dialog-actions">
                    <button
                        class="dialog-btn dialog-btn-secondary"
                        on:click={closeAllDialogs}>Cancel</button
                    >
                    <button
                        class="dialog-btn dialog-btn-danger"
                        on:click={async () => {
                            await DeleteHistorySession($dialogs.showDelete);
                            await loadHistory();
                            closeAllDialogs();
                        }}>Delete</button
                    >
                </div>
            </div>
        </div>
    {/if}

    {#if $dialogs.showShortcuts}
        <div
            class="dialog-overlay"
            on:click={closeAllDialogs}
            on:keydown={handleOverlayKeydown}
        >
            <div
                class="dialog dialog-wide"
                on:click|stopPropagation
                on:keydown={noopPropagationKeydown}
            >
                <div class="dialog-header">
                    <div class="dialog-icon">
                        <svg
                            viewBox="0 0 20 20"
                            fill="currentColor"
                            width="18"
                            height="18"
                        >
                            <path
                                fill-rule="evenodd"
                                d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z"
                                clip-rule="evenodd"
                            />
                        </svg>
                    </div>
                    <h3>Keyboard Shortcuts</h3>
                </div>
                <div class="dialog-body">
                    <div class="shortcuts-grid">
                        <span><kbd>{K("N")}</kbd></span><span
                            >Connect to server</span
                        >
                        <span><kbd>{K("S")}</kbd></span><span
                            >Toggle server</span
                        >
                        <span><kbd>{K("E")}</kbd></span><span
                            >Share connection</span
                        >
                        <span><kbd>{K("I")}</kbd></span><span
                            >Import connection</span
                        >
                        <span><kbd>{K("I+shift")}</kbd></span><span
                            >Import from clipboard</span
                        >
                        <span><kbd>{K("H")}</kbd></span><span>History tab</span>
                        <span><kbd>{K("R")}</kbd></span><span
                            >Refresh history</span
                        >
                        <span><kbd>{K("L")}</kbd></span><span
                            >Toggle log panel</span
                        >
                        <span><kbd>{K("W")}</kbd></span><span
                            >Close active tab</span
                        >
                        <span><kbd>{K("W+shift")}</kbd></span><span
                            >Close all tabs</span
                        >
                        <span><kbd>Esc</kbd></span><span
                            >Close dialog or log panel</span
                        >
                    </div>
                </div>
                <div class="dialog-actions">
                    <button
                        class="dialog-btn dialog-btn-primary"
                        on:click={closeAllDialogs}>Close</button
                    >
                </div>
            </div>
        </div>
    {/if}

    {#if $shareDialog}
        <ShareDialog
            data={$shareDialog}
            on:close={() => shareDialog.set(null)}
            on:toast={(e) => {
                toast.set(e.detail);
                setTimeout(() => toast.set(null), 2000);
            }}
        />
    {/if}

    {#if $dialogs.showImport}
        <ImportDialog
            on:import={(e) => {
                const { transport, host, scheme, token, insecure } = e.detail;
                connectTransport = transport;
                if (transport === "relay") {
                    connectRelayAddr = host;
                    connectRelayScheme = scheme || "ws";
                    connectPeerKey = token;
                    connectRelayInsecure = insecure || false;
                } else {
                    connectServerAddr2 = host;
                }
                dialogs.update((d) => ({
                    ...d,
                    showImport: false,
                    showConnect: true,
                }));
            }}
            on:close={() =>
                dialogs.update((d) => ({ ...d, showImport: false }))}
        />
    {/if}

    {#if $dialogs.showAddPeer}
        <AddPeerDialog />
    {/if}

    {#if $dialogs.peerInfoFor}
        <PeerInfoDialog />
    {/if}

    <div class="app-body">
		<Sidebar
			{serverActive}
			runningServerTransport={runningServerTransport}
			{serverLoading}
			{connectLoading}
            on:startServer={() => {
                dialogs.update((d) => ({ ...d, showServer: true }));
            }}
            on:stopServer={handleStopServer}
            on:cancel={handleCancel}
            on:connect={() => {
                dialogs.update((d) => ({ ...d, showConnect: true }));
            }}
            on:refreshHistory={handleRefreshHistory}
            on:selectSession={(e) => {
                handleSelectTab(e.detail);
            }}
            on:selectHistory={async (e) => {
                handleSelectTab(e.detail);
                await handleLoadHistoryMessages(e.detail);
                sidebarTab.set("history");
            }}
            on:disconnect={async (e) => {
                await handleDisconnect(e.detail);
            }}
            on:showInfo={async (e) => {
                const { GetSessionInfo } =
                    await import("../wailsjs/go/main/App.js");
                const info = await GetSessionInfo(e.detail);
                dialogs.update((d) => ({ ...d, showSessionInfo: info }));
            }}
            on:rename={(e) => {
                dialogs.update((d) => ({
                    ...d,
                    showRename: e.detail,
                    showRenameType: "live",
                }));
            }}
            on:renameHistory={(e) => {
                dialogs.update((d) => ({
                    ...d,
                    showRename: e.detail,
                    showRenameType: "history",
                }));
            }}
            on:deleteHistory={(e) => {
                dialogs.update((d) => ({ ...d, showDelete: e.detail }));
            }}
            on:changeDBPath={() => {
                showPassphraseDialog = true;
                passphraseDismissable = true;
            }}
        />

        <Resizer
            minWidth={SIDEBAR_MIN_WIDTH}
            maxWidth={SIDEBAR_MAX_WIDTH}
            defaultWidth={SIDEBAR_DEFAULT_WIDTH}
            on:resize={handleSidebarResize}
        />

        <div class="main-content">
            <ChatPanel
                on:sendMessage={(e) =>
                    handleSendMessage(e.detail.sessionId, e.detail.text)}
                on:disconnect={(e) => handleDisconnect(e.detail)}
                on:loadHistory={async (e) =>
                    await handleLoadHistoryMessages(e.detail)}
                on:showInfo={async (e) => {
                    const { GetSessionInfo } =
                        await import("../wailsjs/go/main/App.js");
                    const info = await GetSessionInfo(e.detail);
                    dialogs.update((d) => ({ ...d, showSessionInfo: info }));
                }}
                on:deleteHistory={(e) => {
                    dialogs.update((d) => ({ ...d, showDelete: e.detail }));
                }}
                on:closePanel={() => activeSessionId.set(null)}
                on:renamed={async () => {
                    await loadSessions();
                    await loadHistory();
                }}
            />

            {#if $logPanelOpen}
                <LogViewer />
            {/if}
        </div>
    </div>

    <StatusBar
        on:toggleLogs={() => logPanelOpen.update((v) => !v)}
        on:showShortcuts={() =>
            dialogs.update((d) => ({ ...d, showShortcuts: true }))}
    />
</div>

{#if $toast}
    <div
        class="toast"
        class:toast-error={$toast.type === "error"}
        class:toast-warning={$toast.type === "warning"}
        class:toast-token={$toast.type === "token"}
        class:toast-info={$toast.type === "info"}
        on:click={() => toast.set(null)}
    >
        <span class="toast-msg">{$toast.message}</span>
        {#if $toast.token}
            <button
                class="toast-copy"
                on:click|stopPropagation={async () => {
                    const { CopyToClipboard } =
                        await import("../wailsjs/go/main/App.js");
                    await CopyToClipboard($toast.token);
                    toast.set(null);
                }}>Copy</button
            >
        {/if}
    </div>
{/if}

<style>
    .app-layout {
        display: flex;
        flex-direction: column;
        height: 100vh;
        overflow: hidden;
    }
    .app-body {
        display: flex;
        flex-direction: row;
        flex: 1;
        overflow: hidden;
        min-height: 0;
    }
    .main-content {
        flex: 1;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        min-height: 0;
    }

    /* ── Dialog Base ── */
    .dialog-overlay {
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
        padding: 0;
        min-width: 400px;
        max-width: 480px;
        box-shadow: var(--shadow-lg);
        animation: fadeInScale 0.15s ease-out;
        overflow: hidden;
    }
    .dialog-danger {
        border-color: rgba(239, 68, 68, 0.3);
    }
    .dialog-wide {
        min-width: 480px;
        max-width: 520px;
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
    .dialog-icon-danger {
        background: var(--danger-dim);
        color: var(--danger);
    }
    .dialog-header h3 {
        font-size: 16px;
        font-weight: 700;
        color: var(--text-primary);
    }

    .dialog-body {
        padding: 16px 20px 4px;
    }
    .dialog-body p {
        font-size: 13px;
        color: var(--text-secondary);
        line-height: 1.5;
        margin-bottom: 14px;
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
    .dialog-input-wide {
        font-size: 14px;
        padding: 12px 16px;
        font-family: var(--font-mono);
    }

    .dialog-hint {
        margin-top: 8px;
        font-size: 11px;
        color: var(--text-timestamp);
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

    /* ── Transport Pills ── */
    .transport-pills {
        margin-bottom: 14px;
    }
    .transport-label {
        display: block;
        font-size: 11px;
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.4px;
        margin-bottom: 6px;
    }
    .pill-group {
        display: flex;
        gap: 4px;
    }
    .pill-btn {
        flex: 1;
        padding: 7px 10px;
        border-radius: var(--border-radius);
        font-size: 12px;
        font-weight: 600;
        background: var(--bg-hover);
        color: var(--text-muted);
        border: 1px solid var(--border-color);
        transition: all 0.15s;
    }
    .pill-btn:hover {
        color: var(--text-secondary);
        border-color: var(--border-light);
    }
    .pill-btn.pill-active {
        background: var(--accent-primary);
        color: #fff;
        border-color: var(--accent-primary);
    }
    .pill-btn.pill-active:hover {
        background: var(--accent-primary-hover);
    }

    .relay-addr-row {
        display: flex;
        align-items: center;
        gap: 0;
        margin-bottom: 10px;
    }
    .scheme-pills {
        display: flex;
        gap: 0;
        flex-shrink: 0;
    }
    .scheme-btn {
        padding: 7px 8px;
        font-size: 11px;
        font-weight: 700;
        font-family: var(--font-mono);
        background: var(--bg-hover);
        color: var(--text-muted);
        border: 1px solid var(--border-color);
        border-right: none;
        transition: all 0.1s;
        line-height: 1;
    }
    .scheme-btn:first-child {
        border-radius: var(--border-radius) 0 0 var(--border-radius);
    }
    .scheme-btn:last-child {
        border-radius: 0 var(--border-radius) var(--border-radius) 0;
        border-right: 1px solid var(--border-color);
    }
    .scheme-btn:hover {
        background: var(--bg-surface);
        color: var(--text-secondary);
    }
    .scheme-btn.active {
        background: var(--accent-primary);
        color: #fff;
        border-color: var(--accent-primary);
        border-right-color: var(--accent-primary);
    }
    .scheme-btn.active + .scheme-btn {
        border-left-color: var(--accent-primary);
    }
    .scheme-sep {
        padding: 0 6px;
        font-size: 12px;
        font-weight: 600;
        color: var(--text-muted);
        font-family: var(--font-mono);
        flex-shrink: 0;
    }
    .relay-addr-row .dialog-input {
        flex: 1;
        margin-bottom: 0;
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
        color: #fff;
    }
    .dialog-btn-primary:hover {
        background: var(--accent-primary-hover);
    }
    .dialog-btn-primary:disabled {
        opacity: 0.6;
        cursor: not-allowed;
    }
    .dialog-btn-primary:disabled:hover {
        background: var(--accent-primary);
    }
    .dialog-btn-secondary {
        background: var(--bg-hover);
        color: var(--text-secondary);
    }
    .dialog-btn-secondary:hover {
        background: var(--border-color);
        color: var(--text-primary);
    }
    .dialog-btn-secondary:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    .dialog-btn-danger {
        background: var(--danger);
        color: #fff;
    }
    .dialog-btn-danger:hover {
        background: var(--danger-hover);
    }
    .dialog-btn-danger:disabled {
        opacity: 0.6;
        cursor: not-allowed;
    }

    /* ── Info Rows ── */
    .info-rows {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .info-row {
        display: flex;
        gap: 12px;
        padding: 6px 0;
        font-size: 13px;
        border-bottom: 1px solid var(--border-color);
    }
    .info-row:last-child {
        border-bottom: none;
    }
    .info-key {
        color: var(--text-muted);
        min-width: 110px;
        font-weight: 500;
    }
    .info-val {
        color: var(--text-primary);
        word-break: break-all;
    }

    /* ── Shortcuts ── */
    .shortcuts-grid {
        display: grid;
        grid-template-columns: auto 1fr;
        gap: 10px 28px;
        padding: 12px 24px;
        align-items: center;
        max-width: 360px;
        margin: 0 auto;
    }
    .shortcuts-grid kbd {
        font-family: var(--font-mono);
        font-size: 12px;
        font-weight: 600;
        color: var(--text-primary);
        background: var(--bg-input);
        padding: 3px 8px;
        border-radius: 5px;
        display: inline-block;
        border: 1px solid var(--border-color);
        border-bottom-width: 2px;
        min-width: 28px;
        text-align: center;
        letter-spacing: 0.3px;
    }
    .shortcuts-grid span:nth-child(even) {
        color: var(--text-secondary);
        font-size: 13px;
        display: flex;
        align-items: center;
        text-align: left;
    }

    .toast {
        position: fixed;
        bottom: 48px;
        left: 0;
        right: 0;
        margin: 0 auto;
        width: fit-content;
        padding: 10px 20px;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        z-index: 1000;
        cursor: pointer;
        animation: slideUp 0.2s ease-out;
        max-width: 80%;
        text-align: center;
        background: var(--bg-surface);
        color: var(--text-primary);
        border: 1px solid var(--border-color);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .toast.toast-error {
        border-color: var(--danger);
        color: var(--danger);
    }
    .toast.toast-warning {
        border-color: var(--warning);
        color: var(--warning);
    }
    .toast.toast-token {
        border-color: var(--accent-primary);
        color: var(--text-primary);
        font-family: var(--font-mono);
        font-size: 12px;
        cursor: default;
        word-break: break-all;
    }
    .toast.toast-info {
        border-color: var(--accent-primary);
        color: var(--accent-primary);
    }
    .toast-msg {
        flex: 1;
    }
    .toast-copy {
        flex-shrink: 0;
        padding: 4px 10px;
        border-radius: 5px;
        font-size: 11px;
        font-weight: 600;
        background: var(--accent-primary);
        color: #fff;
        border: none;
        cursor: pointer;
        transition: background 0.15s;
    }
    .toast-copy:hover {
        background: var(--accent-primary-hover);
    }
    .insecure-option {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 12px;
        color: var(--text-secondary);
        cursor: pointer;
        padding: 6px 0;
        width: 100%;
    }
    .insecure-option input {
        accent-color: var(--accent-primary);
    }
</style>
