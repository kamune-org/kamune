<script>
  import { createEventDispatcher, onMount } from 'svelte'

  export let minWidth = 240
  export let maxWidth = 500
  export let defaultWidth = 320

  const dispatch = createEventDispatcher()

  let dragging = false
  let startX = 0
  let startWidth = 0

  function clamp(w) {
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

  function onPointerDown(e) {
    if (e.button !== undefined && e.button !== 0) return
    dragging = true
    startX = e.clientX
    startWidth = currentWidth()
    e.currentTarget.setPointerCapture?.(e.pointerId)
    document.body.classList.add('is-resizing')
  }

  function onPointerMove(e) {
    if (!dragging) return
    const next = clamp(startWidth + (e.clientX - startX))
    dispatch('resize', next)
  }

  function onPointerUp(e) {
    if (!dragging) return
    dragging = false
    e.currentTarget.releasePointerCapture?.(e.pointerId)
    document.body.classList.remove('is-resizing')
  }

  function onDblClick() {
    dispatch('resize', defaultWidth)
  }

  function onKeydown(e) {
    const w = currentWidth()
    let next = null
    if (e.key === 'ArrowLeft') next = clamp(w - 16)
    else if (e.key === 'ArrowRight') next = clamp(w + 16)
    else if (e.key === 'Home') next = minWidth
    else if (e.key === 'End') next = maxWidth
    if (next !== null) {
      e.preventDefault()
      dispatch('resize', next)
    }
  }

  onMount(() => () => {
    document.body.classList.remove('is-resizing')
  })
</script>

<!-- svelte-ignore a11y-no-noninteractive-tabindex -->
<div
  class="resizer"
  role="separator"
  aria-orientation="vertical"
  aria-label="Resize sidebar (drag or use arrow keys)"
  aria-valuemin={minWidth}
  aria-valuemax={maxWidth}
  aria-valuenow={currentWidth()}
  tabindex="0"
  on:pointerdown={onPointerDown}
  on:pointermove={onPointerMove}
  on:pointerup={onPointerUp}
  on:pointercancel={onPointerUp}
  on:dblclick={onDblClick}
  on:keydown={onKeydown}
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
