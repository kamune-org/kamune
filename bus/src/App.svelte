<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import Header from "./lib/components/Header.svelte";
  import Sidebar from "./lib/components/Sidebar.svelte";
  import ChatArea from "./lib/components/ChatArea.svelte";
  import EventsLog from "./lib/components/EventsLog.svelte";
  import { api, setupTauriEvents } from "./lib/api/tauri";
  import {
    daemonRunning,
    addSession,
    removeSession,
    addMessage,
    logEvent,
    showEventsLog,
  } from "./lib/stores/app";
  import type { SessionData, MessageReceivedData, ServerStartedData, ErrorData } from "./lib/types";

  let cleanup: (() => void) | null = null;

  onMount(async () => {
    // Set up Tauri event listeners
    cleanup = setupTauriEvents({
      onDaemonEvent: (evt, data) => {
        logEvent(evt, data);
      },
      onReady: (data) => {
        logEvent("ready", data);
        daemonRunning.set(true);
      },
      onServerStarted: (data) => {
        const serverData = data as ServerStartedData;
        logEvent("server_started", data);
        logEvent("info", `Server started on ${serverData.addr || "unknown address"}`);
      },
      onSessionStarted: (data) => {
        const sessionData = data as SessionData;
        logEvent("session_started", data);
        addSession(sessionData);
      },
      onSessionClosed: (data) => {
        const sessionData = data as SessionData;
        logEvent("session_closed", data);
        removeSession(sessionData.session_id);
      },
      onMessageReceived: (data) => {
        const msgData = data as MessageReceivedData;
        logEvent("message_received", { session_id: msgData.session_id });
        handleMessageReceived(msgData);
      },
      onMessageSent: (data) => {
        logEvent("message_sent", data);
      },
      onError: (data) => {
        const errorData = data as ErrorData;
        logEvent("error", data);
        logEvent("error", `Error: ${errorData.error || "Unknown error"}`);
      },
    });

    // Check initial daemon status
    const result = await api.daemonStatus();
    if (result.success && result.data) {
      daemonRunning.set(result.data.running);
    }

    logEvent("info", "Kamune Desktop initialized");
  });

  onDestroy(() => {
    if (cleanup) {
      cleanup();
    }
  });

  function handleMessageReceived(data: MessageReceivedData) {
    let text: string;
    try {
      text = atob(data.data_base64);
    } catch {
      text = "[Unable to decode message]";
    }

    addMessage(data.session_id, {
      text,
      timestamp: data.timestamp || new Date().toISOString(),
      sent: false,
    });
  }
</script>

<div class="app">
  <Header />
  <main class="main">
    <Sidebar />
    <div class="content">
      <ChatArea />
      {#if $showEventsLog}
        <EventsLog />
      {/if}
    </div>
  </main>
</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: var(--color-bg-primary);
  }

  .main {
    flex: 1;
    display: flex;
    overflow: hidden;
  }

  .content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
</style>
