<script>
  import { createEventDispatcher } from 'svelte'
  import jsQR from 'jsqr'

  const dispatch = createEventDispatcher()

  let importURL = ''
  let error = ''
  let scanMode = 'idle'
  let videoEl
  let canvasEl
  let fileInput
  let stream = null
  let animationId = null

  function fillConnect(urlStr) {
    try {
      const url = new URL(urlStr)
      const transport = url.protocol.slice(0, -1)
      if (!transport) throw new Error('Unknown transport')
      stopCamera()
      dispatch('import', {
        transport,
        host: url.host,
        scheme: url.searchParams.get('scheme') || '',
        token: url.searchParams.get('token') || '',
      })
    } catch {
      error = 'Invalid connection URL'
    }
  }

  function handlePaste() {
    error = ''
    fillConnect(importURL.trim())
  }

  function handleFileSelect(e) {
    error = ''
    const file = e.target.files?.[0]
    if (!file) return
    const ctx = canvasEl.getContext('2d')
    const img = new Image()
    img.onload = () => {
      canvasEl.width = img.width
      canvasEl.height = img.height
      ctx.drawImage(img, 0, 0)
      const imageData = ctx.getImageData(0, 0, canvasEl.width, canvasEl.height)
      const code = jsQR(imageData.data, imageData.width, imageData.height)
      if (code) {
        fillConnect(code.data)
        return
      }
      error = 'No QR code found in image'
    }
    img.src = URL.createObjectURL(file)
  }

  async function startCamera() {
    error = ''
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      })
      videoEl.srcObject = stream
      scanMode = 'camera'
      scanFrame()
    } catch {
      error = 'Camera access denied or unavailable'
    }
  }

  function scanFrame() {
    if (scanMode !== 'camera') return
    if (videoEl.readyState === videoEl.HAVE_ENOUGH_DATA) {
      canvasEl.width = videoEl.videoWidth
      canvasEl.height = videoEl.videoHeight
      canvasEl.getContext('2d').drawImage(videoEl, 0, 0)
      const imageData = canvasEl
        .getContext('2d')
        .getImageData(0, 0, canvasEl.width, canvasEl.height)
      const code = jsQR(imageData.data, imageData.width, imageData.height)
      if (code) {
        stopCamera()
        fillConnect(code.data)
        return
      }
    }
    animationId = requestAnimationFrame(scanFrame)
  }

  function stopCamera() {
    scanMode = 'idle'
    if (animationId) {
      cancelAnimationFrame(animationId)
      animationId = null
    }
    if (stream) {
      stream.getTracks().forEach((t) => t.stop())
      stream = null
    }
  }

  function handleClose() {
    stopCamera()
    dispatch('close')
  }
</script>

<div class="dialog-overlay" on:click={handleClose}>
  <div class="dialog dialog-narrow" on:click|stopPropagation>
    <div class="dialog-header">
      <div class="dialog-icon">
        <svg viewBox="0 0 20 20" fill="currentColor" width="18" height="18">
          <path d="M4 4a2 2 0 00-2 2v1h2V6h1V4H4zM16 4h-1v2h1v1h2V6a2 2 0 00-2-2zM4 16H4v-1H2v1a2 2 0 002 2h1v-2H4zM16 16h-1v2h1a2 2 0 002-2v-1h-2v1zM5 7a1 1 0 011-1h8a1 1 0 011 1v6a1 1 0 01-1 1H6a1 1 0 01-1-1V7z" />
        </svg>
      </div>
      <h3>Import URL</h3>
      <button class="close-btn" on:click={handleClose}>✕</button>
    </div>

    {#if scanMode === 'camera'}
      <div class="dialog-body">
        <video bind:this={videoEl} autoplay class="camera-preview"></video>
        <p class="dialog-hint">Point camera at QR code</p>
      </div>
      <div class="dialog-actions">
        <button
          class="dialog-btn dialog-btn-secondary"
          on:click={stopCamera}>Cancel Scan</button
        >
      </div>
    {:else}
      <div class="dialog-body">
        <div class="import-paste-row">
          <input
            bind:value={importURL}
            placeholder="Paste connection URL…"
            class="dialog-input"
          />
          <button
            class="dialog-btn dialog-btn-primary import-btn"
            on:click={handlePaste}>Import</button
          >
        </div>

        <div class="import-divider">— or —</div>

        <input
          type="file"
          accept="image/*"
          bind:this={fileInput}
          on:change={handleFileSelect}
          hidden
        />
        <button class="import-action" on:click={() => fileInput.click()}>
          <svg
            viewBox="0 0 20 20"
            fill="currentColor"
            width="16"
            height="16"
          >
            <path
              fill-rule="evenodd"
              d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z"
              clip-rule="evenodd"
            />
          </svg>
          Select QR Image
        </button>
        <button class="import-action" on:click={startCamera}>
          <svg
            viewBox="0 0 20 20"
            fill="currentColor"
            width="16"
            height="16"
          >
            <path
              fill-rule="evenodd"
              d="M4 5a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V7a2 2 0 00-2-2h-1.586a1 1 0 01-.707-.293l-1.121-1.121A2 2 0 0011.172 3H8.828a2 2 0 00-1.414.586L6.293 4.707A1 1 0 015.586 5H4zm6 9a3 3 0 100-6 3 3 0 000 6z"
              clip-rule="evenodd"
            />
          </svg>
          Scan with Camera
        </button>

        {#if error}
          <p class="dialog-error">{error}</p>
        {/if}
      </div>
      <div class="dialog-actions">
        <button
          class="dialog-btn dialog-btn-secondary"
          on:click={handleClose}>Cancel</button
        >
      </div>
    {/if}

    <canvas bind:this={canvasEl} hidden></canvas>
  </div>
</div>

<style>
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
  .dialog-narrow {
    min-width: 360px;
    max-width: 400px;
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
  .dialog-body {
    padding: 16px 20px 4px;
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
    box-sizing: border-box;
  }
  .dialog-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px var(--accent-primary-dim);
    outline: none;
  }
  .dialog-hint {
    margin-top: 8px;
    font-size: 11px;
    color: var(--text-timestamp);
    text-align: center;
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
    border: none;
    cursor: pointer;
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
  .dialog-btn-secondary {
    background: var(--bg-hover);
    color: var(--text-secondary);
  }
  .dialog-btn-secondary:hover {
    background: var(--border-color);
    color: var(--text-primary);
  }

  .import-paste-row {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .import-paste-row .dialog-input {
    flex: 1;
  }
  .import-btn {
    flex-shrink: 0;
    white-space: nowrap;
  }

  .import-divider {
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
    margin: 14px 0;
    position: relative;
  }
  .import-divider::before,
  .import-divider::after {
    content: '';
    position: absolute;
    top: 50%;
    width: calc(50% - 24px);
    height: 1px;
    background: var(--border-color);
  }
  .import-divider::before {
    left: 0;
  }
  .import-divider::after {
    right: 0;
  }

  .import-action {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 10px 14px;
    background: var(--bg-hover);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
    margin-bottom: 6px;
  }
  .import-action:hover {
    background: var(--border-color);
    color: var(--text-primary);
  }
  .import-action svg {
    flex-shrink: 0;
    opacity: 0.6;
  }

  .camera-preview {
    width: 100%;
    border-radius: var(--border-radius);
    background: #000;
  }
</style>
