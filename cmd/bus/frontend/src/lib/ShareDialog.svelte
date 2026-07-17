<script>
  import { createEventDispatcher } from 'svelte'
  import { toCanvas } from 'qrcode'

  export let data

  const dispatch = createEventDispatcher()

  let address = data.address || ''
  let url = data.url
  let qrCanvas

  function buildURL() {
    if (data.transport === 'relay') {
      url = data.url
    } else {
      url = address ? `${data.transport}://${address}:${data.port}` : data.url
    }
  }

  function redrawQR() {
    buildURL()
    if (!qrCanvas || !url) return
    const ctx = qrCanvas.getContext('2d')
    if (ctx) ctx.clearRect(0, 0, qrCanvas.width, qrCanvas.height)
    const s = getComputedStyle(document.documentElement)
    const qrDark = s.getPropertyValue('--export-qr-dark').trim() || '#1a1d27'
    toCanvas(qrCanvas, url, {
      width: 220,
      margin: 2,
      color: {
        dark: qrDark,
        light: '#00000000',
      },
    })
  }

  $: if (data && qrCanvas) redrawQR()

  async function handleRefresh() {
    const { GetShareInfo } = await import('../../wailsjs/go/main/App.js')
    try {
      const info = await GetShareInfo()
      data = info
      address = info.address || ''
      url = info.url
    } catch (e) {
      console.error('Failed to refresh share info:', e)
    }
  }

  async function handleCopyURL() {
    const { CopyToClipboard } = await import('../../wailsjs/go/main/App.js')
    try {
      await CopyToClipboard(url)
      dispatch('toast', { message: 'Copied!', type: 'info' })
    } catch (e) {
      dispatch('toast', { message: 'Copy failed', type: 'error' })
    }
  }

  async function handleSavePNG() {
    // TODO: investigate low quality of emoji/text in saved PNG — canvas fillText renders
    // differently from CSS (no subpixel AA, emoji metrics vary by glyph). Possible paths:
    // SVG foreignObject, html2canvas, or Wails-specific screenshot API.
    // Layout measurements (in pixels)
    const margin = 20
    const qrSize = 220
    const titleY = 30
    const qrY = 70
    const emojiGap = 24
    const tileSize = 34
    const tileGap = 4
    const sectionGap = 16
    const rowHeight = 20
    const bottomPad = 20

    // Calculate emoji rows
    const emojis = data.fingerprintEmoji.split(' • ')
    const baseW = 400
    const maxRowWidth = baseW - margin * 2
    const perRow = Math.max(1, Math.floor((maxRowWidth + tileGap) / (tileSize + tileGap)))
    const emojiRows = Math.ceil(emojis.length / perRow)

    // Calculate total height
    let contentEnd = qrY + qrSize + emojiGap + emojiRows * (tileSize + tileGap) + sectionGap + rowHeight + rowHeight + bottomPad

    if (data.transport === 'relay') {
      const relayRows = data.relayInfo.password ? 4 : 3
      contentEnd += relayRows * (rowHeight + 4) + 8
    }

    const w = baseW
    const h = Math.max(contentEnd, 400)

    const offscreen = document.createElement('canvas')
    offscreen.width = w
    offscreen.height = h
    offscreen.style.position = 'fixed'
    offscreen.style.left = '-9999px'
    offscreen.style.top = '-9999px'
    document.body.appendChild(offscreen)
    const ctx = offscreen.getContext('2d')

    const s = getComputedStyle(document.documentElement);
    const cv = (name) => s.getPropertyValue(name).trim();
    const bgColor = cv('--export-bg') || '#f8f9fb';
    const textColor = cv('--export-text') || '#1a1d27';
    const mutedColor = cv('--export-muted') || '#64748b';
    const surfaceColor = cv('--export-surface') || '#e8eaed';
    const borderColor = cv('--export-border') || '#d1d5db';
    const qrDark = cv('--export-qr-dark') || '#1a1d27';
    const warningColor = cv('--warning') || '#d97706';

    // Background
    ctx.fillStyle = bgColor
    ctx.fillRect(0, 0, w, h)

    // Title
    ctx.fillStyle = textColor
    ctx.font = 'bold 18px -apple-system, BlinkMacSystemFont, sans-serif'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    ctx.fillText('Kamune — Connection Card', w / 2, titleY)

    // QR code — temp canvas to not affect display
    const qrTemp = document.createElement('canvas')
    try {
      await toCanvas(qrTemp, url, {
        width: qrSize,
        margin: 2,
        color: { dark: qrDark, light: '#00000000' },
      })
    } catch (err) {
      console.error('QR error:', err)
      document.body.removeChild(offscreen)
      return
    }
    ctx.drawImage(qrTemp, (w - qrSize) / 2, qrY, qrSize, qrSize)

    // Emoji tiles
    for (let ri = 0; ri < emojiRows; ri++) {
      const row = emojis.slice(ri * perRow, (ri + 1) * perRow)
      const rowW = row.length * (tileSize + tileGap) - tileGap
      let x = (w - rowW) / 2
      const y = qrY + qrSize + emojiGap + ri * (tileSize + tileGap)
      for (const emoji of row) {
        ctx.fillStyle = surfaceColor
        roundRect(ctx, x, y, tileSize, tileSize, 8)
        ctx.fill()
        ctx.strokeStyle = borderColor
        ctx.lineWidth = 1
        ctx.stroke()
        ctx.fillStyle = textColor
        ctx.font = '15px -apple-system, BlinkMacSystemFont, sans-serif'
        ctx.textAlign = 'left'
        ctx.textBaseline = 'middle'
        const m = ctx.measureText(emoji)
        ctx.fillText(emoji, x + (tileSize - m.width) / 2, y + tileSize / 2)
        x += tileSize + tileGap
      }
    }

    let nextY = qrY + qrSize + emojiGap + emojiRows * (tileSize + tileGap) + sectionGap

    // Transport info
    ctx.fillStyle = mutedColor
    ctx.font = '12px Menlo, Monaco, monospace'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    ctx.fillText(data.transport.toUpperCase(), w / 2, nextY)
    nextY += rowHeight

    // Relay details
    if (data.transport === 'relay') {
      ctx.textAlign = 'left'
      const labelX = margin
      const valueX = w / 2

      function drawRow(label, value) {
        ctx.fillStyle = mutedColor
        ctx.font = '11px -apple-system, BlinkMacSystemFont, sans-serif'
        ctx.textBaseline = 'top'
        ctx.fillText(label, labelX, nextY)
        ctx.fillStyle = textColor
        ctx.font = '11px Menlo, Monaco, monospace'
        ctx.fillText(value, valueX, nextY)
        nextY += rowHeight + 4
      }

      drawRow('Relay', data.relayInfo.address)
      drawRow('Scheme', data.relayInfo.scheme.toUpperCase())
      drawRow('Token', data.relayInfo.token)
      if (data.relayInfo.password) {
        ctx.fillStyle = mutedColor
        ctx.font = '11px -apple-system, BlinkMacSystemFont, sans-serif'
        ctx.textBaseline = 'top'
        ctx.fillText('Password', labelX, nextY)
        ctx.fillStyle = warningColor
        ctx.font = '11px -apple-system, BlinkMacSystemFont, sans-serif'
        ctx.fillText('Required', valueX, nextY)
        nextY += rowHeight + 4
      }

      nextY += 8
      ctx.textAlign = 'center'
    }

    // Scan to connect
    ctx.fillStyle = mutedColor
    ctx.font = '11px -apple-system, BlinkMacSystemFont, sans-serif'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    ctx.fillText('Scan to connect', w / 2, nextY)

    const dataUrl = offscreen.toDataURL('image/png')
    document.body.removeChild(offscreen)

    const { SaveCardPNG } = await import('../../wailsjs/go/main/App.js')
    try {
      await SaveCardPNG(dataUrl)
    } catch (err) {
      console.error('Save failed:', err)
    }
  }

  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath()
    ctx.moveTo(x + r, y)
    ctx.lineTo(x + w - r, y)
    ctx.quadraticCurveTo(x + w, y, x + w, y + r)
    ctx.lineTo(x + w, y + h - r)
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h)
    ctx.lineTo(x + r, y + h)
    ctx.quadraticCurveTo(x, y + h, x, y + h - r)
    ctx.lineTo(x, y + r)
    ctx.quadraticCurveTo(x, y, x + r, y)
    ctx.closePath()
  }
</script>

<div class="dialog-overlay" on:click={() => dispatch('close')}>
  <div class="dialog dialog-share" on:click|stopPropagation>
    <div class="dialog-header">
      <div class="dialog-icon">
        <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
          <path d="M15 8a3 3 0 10-2.977-2.633l-6.94 3.47a3 3 0 100 4.326l6.94 3.47a3 3 0 10.895-1.789l-6.94-3.47a3.027 3.027 0 000-.748l6.94-3.47A3 3 0 0015 8z" />
        </svg>
      </div>
      <h3>Share Connection</h3>
      <button class="close-btn" on:click={() => dispatch('close')}>✕</button>
    </div>

    <div class="dialog-body share-body">
      <div class="qr-section">
        <canvas bind:this={qrCanvas} class="qr-canvas"></canvas>
      </div>

      <div class="fingerprint-section">
        <div class="fp-emojis">
          {#each data.fingerprintEmoji.split(' • ') as emojiChar}
            <span class="fp-emoji-tile">{emojiChar}</span>
          {/each}
        </div>
      </div>

      {#if data.transport === 'relay'}
        <div class="relay-details">
          <div class="detail-row">
            <span class="detail-label">Relay</span>
            <span class="detail-value mono">{data.relayInfo.address}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Scheme</span>
            <span class="detail-value mono">{data.relayInfo.scheme}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Token</span>
            <span class="detail-value mono token-value">{data.relayInfo.token}</span>
          </div>
          {#if data.relayInfo.password}
            <div class="detail-row">
              <span class="detail-label">Password</span>
              <span class="detail-value">Required</span>
            </div>
          {/if}
          <button class="refresh-token-btn" on:click={handleRefresh}>Regenerate Token</button>
        </div>
      {:else}
        <div class="direct-details">
          <div class="detail-row">
            <span class="detail-label">Address</span>
            <div class="addr-group">
              <input bind:value={address} class="detail-input mono" placeholder="IP address" />
              <span class="port-sep">:</span>
              <span class="port-display mono">{data.port}</span>
            </div>
          </div>
        </div>
      {/if}
    </div>

    <div class="dialog-actions share-actions">
      <button class="dialog-btn dialog-btn-secondary" on:click={handleSavePNG}>Save Card as PNG</button>
      <button class="dialog-btn dialog-btn-primary" on:click={handleCopyURL}>Copy URL</button>
    </div>
  </div>
</div>

<style>
  .dialog-overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
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
    box-shadow: var(--shadow-lg);
    animation: fadeInScale 0.15s ease-out;
    overflow: hidden;
  }

  .dialog-share {
    min-width: 420px;
    max-width: 480px;
  }

  .dialog-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 18px 20px 0;
  }

  .dialog-header h3 {
    flex: 1;
    font-size: 16px;
    font-weight: 700;
    color: var(--text-primary);
  }

  .close-btn {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 18px;
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 6px;
    line-height: 1;
  }
  .close-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
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

  .share-body {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    padding: 16px 20px 4px;
  }

  .qr-section {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .qr-canvas {
    width: 160px;
    height: 160px;
    image-rendering: pixelated;
  }

  .fingerprint-section {
    text-align: center;
  }

  .fp-emojis {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 4px;
  }
  .fp-emoji-tile {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 34px;
    height: 34px;
    font-size: 18px;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 8px;
  }

  .direct-details,
  .relay-details {
    width: 100%;
  }

  .detail-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
  }

  .addr-group {
    display: flex;
    align-items: center;
    gap: 4px;
    flex: 1;
  }

  .detail-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    min-width: 60px;
    flex-shrink: 0;
  }

  .detail-value {
    font-size: 13px;
    color: var(--text-primary);
    word-break: break-all;
  }

  .detail-value.mono,
  .detail-input.mono {
    font-family: Menlo, Monaco, monospace;
    font-size: 12px;
  }

  .token-value {
    font-size: 11px;
  }

  .detail-input {
    flex: 1;
    padding: 6px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 12px;
    font-family: Menlo, Monaco, monospace;
  }
  .detail-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
    outline: none;
  }

  .port-sep {
    color: var(--text-muted);
    font-family: Menlo, Monaco, monospace;
    font-size: 12px;
    flex-shrink: 0;
  }

  .port-display {
    color: var(--text-secondary);
    font-size: 12px;
    font-family: Menlo, Monaco, monospace;
    user-select: all;
    cursor: default;
    flex-shrink: 0;
    padding: 6px 0;
  }

  .refresh-token-btn {
    width: 100%;
    margin-top: 4px;
    padding: 7px 14px;
    border-radius: var(--border-radius);
    font-size: 12px;
    font-weight: 600;
    background: var(--bg-hover);
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
    cursor: pointer;
    transition: all 0.15s;
  }
  .refresh-token-btn:hover {
    background: var(--border-color);
    color: var(--text-primary);
  }

  .share-actions {
    display: flex;
    gap: 8px;
    justify-content: center;
    padding: 16px 20px 18px;
  }

  .dialog-btn {
    padding: 8px 18px;
    border-radius: var(--border-radius);
    font-size: 13px;
    font-weight: 600;
    border: none;
    cursor: pointer;
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
    background: var(--bg-hover);
    color: var(--text-secondary);
  }
  .dialog-btn-secondary:hover {
    background: var(--border-color);
    color: var(--text-primary);
  }
</style>
