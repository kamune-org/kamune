<script lang="ts">
  import { onMount } from 'svelte'

  let {
    minWidth = 240,
    maxWidth = 500,
    defaultWidth = 320,
    onResize,
  }: {
    minWidth?: number
    maxWidth?: number
    defaultWidth?: number
    onResize?: (width: number) => void
  } = $props()

  let dragging = false
  let startX = 0
  let startWidth = 0

  function clamp(w: number) {
    if (w < minWidth) return minWidth
    if (w > maxWidth) return maxWidth
    return w
  }

  function currentWidth() {
    const v = getComputedStyle(document.documentElement)
      .getPropertyValue('--sidebar-width')
      .trim()
    const n = parseInt(v, 10)
    return Number.isFinite(n) ? n : defaultWidth
  }

  function onPointerDown(e: PointerEvent) {
    if (e.button !== undefined && e.button !== 0) return
    dragging = true
    startX = e.clientX
    startWidth = currentWidth()
    const target = e.currentTarget as HTMLElement | null
    target?.setPointerCapture?.(e.pointerId)
    document.body.classList.add('is-resizing')
  }

  function onPointerMove(e: PointerEvent) {
    if (!dragging) return
    const next = clamp(startWidth + (e.clientX - startX))
    onResize?.(next)
  }

  function onPointerUp(e: PointerEvent) {
    if (!dragging) return
    dragging = false
    const target = e.currentTarget as HTMLElement | null
    target?.releasePointerCapture?.(e.pointerId)
    document.body.classList.remove('is-resizing')
  }

  function onDblClick() {
    onResize?.(defaultWidth)
  }

  function onKeydown(e: KeyboardEvent) {
    const w = currentWidth()
    let next: number | null = null
    if (e.key === 'ArrowLeft') next = clamp(w - 16)
    else if (e.key === 'ArrowRight') next = clamp(w + 16)
    else if (e.key === 'Home') next = minWidth
    else if (e.key === 'End') next = maxWidth
    if (next !== null) {
      e.preventDefault()
      onResize?.(next)
    }
  }

  onMount(() => () => {
    document.body.classList.remove('is-resizing')
  })
</script>

<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div
  class="resizer"
  role="separator"
  aria-orientation="vertical"
  aria-label="Resize sidebar (drag or use arrow keys)"
  aria-valuemin={minWidth}
  aria-valuemax={maxWidth}
  aria-valuenow={240}
  tabindex="0"
  onpointerdown={onPointerDown}
  onpointermove={onPointerMove}
  onpointerup={onPointerUp}
  onpointercancel={onPointerUp}
  ondblclick={onDblClick}
  onkeydown={onKeydown}
></div>

<style>
  .resizer {
    width: 4px;
    flex-shrink: 0;
    cursor: col-resize;
    background: transparent;
    position: relative;
    z-index: 1;
  }
  .resizer::before {
    content: '';
    position: absolute;
    inset: 0 -2px 0 -2px;
  }
  .resizer:hover,
  .resizer:focus {
    background: var(--accent-primary-dim);
    outline: none;
  }
  .resizer:focus-visible {
    background: var(--accent-primary);
  }
</style>
