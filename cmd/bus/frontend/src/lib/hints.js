export const welcomeTips = [
  { text: "Open the Connect dialog with", key: "N" },
  "Start a server to let peers find you",
  "UDP hole punching lets you connect directly — no port forwarding needed",
  "Relay mode works through firewalls — no setup required",
  "Static tokens are linked to your identity — random tokens are one-time and unlinkable.",
  "Check the Peers tab to manage your contacts",
  { text: "Toggle the server on/off with", key: "S" },
  "Use the Share Card to send your connection info to a peer",
  "Choose how you verify peers: Strict asks every time, Quick trusts known ones, Auto-Accept says yes to all",
  "Your fingerprint emoji is your identity — peers see it when they connect",
  "Database holds your keys and chat history — keep your password safe",
  "Messages are end-to-end encrypted — only you and your peer can read them",
  "Press the keyboard icon in the bottom-right for all shortcuts",
  "Open the Logs panel for connection details and debugging",
];

export const contextHints = {
  tcp: "Best for local networks — simple and dependable",
  udp: "Faster, supports hole punching for direct connections",
  relay: "Routes through a server — works even behind strict firewalls",
  p2p: "Both peers send packets simultaneously to open NAT holes — requires both sides online at the same time",
  broker: "Helps peers find each other's addresses so they can hole punch",
};
