// isTLSRelayScheme reports whether a relay scheme runs over TLS, where
// the relay's certificate can be checked or pinned.
export function isTLSRelayScheme(scheme: string): boolean {
  return scheme === 'wss' || scheme === 'tls';
}

// relayAddress builds the relay address that the backend parses:
// scheme://host, then pin=<sha256> or insecure=true as a query. Both only
// apply to a TLS scheme. With a pin, the backend trusts exactly the
// relay certificate whose SHA-256 fingerprint it is, so a relay with a
// self-signed certificate can be checked without skipping verification;
// a pin also makes insecure moot, so it is left out. host may already
// carry a query, such as one the user typed.
export function relayAddress(scheme: string, host: string, insecure: boolean, pin: string): string {
  const h = host.trim();
  const params = new URLSearchParams();
  if (isTLSRelayScheme(scheme)) {
    const p = pin.trim();
    if (p) params.set('pin', p);
    else if (insecure && !h.includes('insecure=')) params.set('insecure', 'true');
  }
  const query = params.toString();
  if (!query) return `${scheme}://${h}`;
  return `${scheme}://${h}${h.includes('?') ? '&' : '?'}${query}`;
}

// insecureWarning is shown while a relay's TLS verification is skipped.
export const insecureWarning =
  "Anyone on the path can pose as the relay and read its password and your token. Pin the relay's certificate instead: the relay logs its SHA-256 fingerprint when it starts.";

// pinPlaceholder is the hint in a relay certificate pin field.
export const pinPlaceholder = 'Relay certificate SHA-256 pin (optional)';
