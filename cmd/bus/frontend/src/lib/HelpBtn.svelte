<script>
  export let text = ''
  let btnEl
  let tipStyle = ''

  function show() {
    if (!btnEl) return
    const r = btnEl.getBoundingClientRect()
    const top = r.top - 8
    tipStyle = `position:fixed; bottom:auto; top:${top}px; left:${r.left + r.width / 2}px; transform:translate(-50%,-100%);`
  }
</script>

<span class="help-btn" bind:this={btnEl} on:mouseenter={show} tabindex="0">
  ?
  <span class="help-tooltip" style={tipStyle}>{text}</span>
</span>

<style>
  .help-btn {
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    border: 1px solid rgba(255,255,255,0.2);
    background: rgba(255,255,255,0.06);
    color: rgba(255,255,255,0.5);
    font-size: 9px;
    font-weight: 700;
    cursor: help;
    margin-left: 2px;
    flex-shrink: 0;
    line-height: 1;
    transition: all 0.15s;
  }
  .help-btn:hover {
    border-color: rgba(255,255,255,0.5);
    color: #fff;
    background: rgba(255,255,255,0.12);
  }
  .help-tooltip {
    position: fixed;
    width: 200px;
    padding: 8px 10px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    box-shadow: var(--shadow-md);
    font-size: 11px;
    font-weight: 400;
    color: var(--text-secondary);
    line-height: 1.4;
    pointer-events: none;
    opacity: 0;
    transition: opacity 0.15s;
    z-index: 1000;
    text-align: left;
  }
  .help-btn:hover .help-tooltip {
    opacity: 1;
  }
</style>
