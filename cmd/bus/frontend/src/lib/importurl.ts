import { isTLSRelayScheme } from './relayaddr';

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

// importedRelayPin returns the relay certificate pin named by the pin
// parameter of an imported connection URL, such as a daemon's share card
// carries, or '' when the URL names none or its scheme does not use TLS.
// With a pin, Bus trusts exactly the relay certificate whose SHA-256
// fingerprint it is, in place of the certificate authorities, so a relay
// with a self-signed certificate is checked without skipping
// verification. Whoever made the URL chose the relay already, so its pin
// gives them nothing more. The Connect dialog shows the pin before the
// user connects.
export function importedRelayPin(param: string | null, scheme: string): string {
  return isTLSRelayScheme(scheme) ? (param || '').trim() : '';
}

// pinImported is shown when an imported URL pins the relay's
// certificate.
export const pinImported =
  "The imported URL pins the relay's certificate; the Connect dialog " +
  'shows the pin. Clear it to use the usual certificate checks.';

// pinnedRelayHint is shown under a relay certificate pin that is set.
export const pinnedRelayHint =
  'Only the relay certificate with this SHA-256 fingerprint is trusted, ' +
  'not the usual certificate authorities.';
