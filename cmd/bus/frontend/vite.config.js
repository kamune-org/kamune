import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import wails from '@wailsio/runtime/plugins/vite';

// own lists the sources of the page's own files. The window loads the
// page from wails://localhost on Linux and macOS and from
// http://wails.localhost on Windows. The wails: scheme is named besides
// 'self' in case a webview does not count a custom scheme's URLs as the
// page's own; only the app's asset server answers wails: URLs.
const own = "'self' wails:";

// csp is the Content Security Policy of the built page, which can call
// every bound Go method: only the page's own files may run as script, so
// text from a peer can never run even if it reaches an HTML sink. The
// Wails runtime only fetches from the page's own origin. Styles may be
// inline, as Svelte sets style attributes, and images may be data: or
// blob: URLs, for the share card and an imported QR code.
const csp = [
  `default-src ${own}`,
  `script-src ${own}`,
  `style-src ${own} 'unsafe-inline'`,
  `img-src ${own} data: blob:`,
  `connect-src ${own}`,
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

// contentSecurityPolicy puts csp first in the head of the built page. The
// dev server's page goes without it, so that Vite's hot reload works.
function contentSecurityPolicy() {
  return {
    name: 'bus-content-security-policy',
    apply: 'build',
    transformIndexHtml() {
      return [
        {
          tag: 'meta',
          attrs: { 'http-equiv': 'Content-Security-Policy', content: csp },
          injectTo: 'head-prepend',
        },
      ];
    },
  };
}

export default defineConfig({
  server: {
    host: '127.0.0.1',
    port: Number(process.env.WAILS_VITE_PORT) || 9245,
    strictPort: true,
  },
  plugins: [svelte(), wails('./bindings'), contentSecurityPolicy()],
});
