// Relay schemes the connect form offers.
export const relaySchemes = ['tcp', 'tls', 'ws', 'wss'];

// importedRelayScheme returns the relay scheme named by the scheme
// parameter of an imported connection URL, or wss, which checks the
// relay's certificate, when the URL names none or one the form does not
// offer.
export function importedRelayScheme(param: string | null): string {
  return param && relaySchemes.includes(param) ? param : 'wss';
}

// insecureIgnored is shown when an imported URL asks to skip TLS
// verification. Whoever made or altered the URL cannot turn that on: it
// would let anyone on the path pose as the relay.
export const insecureIgnored =
  'The imported URL asked to skip TLS verification. That was ignored; ' +
  'turn it on yourself only for a relay you trust.';
