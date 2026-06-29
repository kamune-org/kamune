<script>
  import { createEventDispatcher, tick } from 'svelte'

  export let value = ''
  export let peers = []
  export let placeholder = 'Select a peer'

  const dispatch = createEventDispatcher()

  let open = false
  let search = ''
  let searchInput
  let rootEl
  let highlightedIdx = 0

  $: selected = peers.find((p) => p.publicKeyBase64 === value) || null

  $: filtered = (() => {
    if (!search.trim()) return peers
    const q = search.trim().toLowerCase()
    return peers.filter((p) => {
      if ((p.name || '').toLowerCase().includes(q)) return true
      if ((p.fingerprintEmoji || '').includes(q)) return true
      if ((p.publicKeyBase64 || '').toLowerCase().includes(q)) return true
      return false
    })
  })()

  $: if (open) {
    highlightedIdx = 0
  }

  async function toggleDropdown() {
    if (open) {
      closeDropdown()
      return
    }
    open = true
    search = ''
    await tick()
    if (searchInput) searchInput.focus()
  }

  function closeDropdown() {
    open = false
    search = ''
    highlightedIdx = 0
  }

  function pick(peer) {
    value = peer.publicKeyBase64
    dispatch('change', peer)
    closeDropdown()
  }

  function clearSelection() {
    value = ''
    dispatch('change', null)
    closeDropdown()
  }

  function onWindowClick(e) {
    if (!open) return
    if (rootEl && !rootEl.contains(e.target)) closeDropdown()
  }

  function onKeydown(e) {
    if (!open) {
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
        e.preventDefault()
        toggleDropdown()
      }
      return
    }
    if (e.key === 'Escape') {
      e.preventDefault()
      closeDropdown()
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      highlightedIdx = Math.min(
        highlightedIdx + 1, Math.max(filtered.length - 1, 0))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      highlightedIdx = Math.max(highlightedIdx - 1, 0)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const pickPeer = filtered[highlightedIdx]
      if (pickPeer) pick(pickPeer)
    }
  }
</script>

<svelte:window on:click={onWindowClick} />

<div
  class="peer-select"
  class:open
  bind:this={rootEl}
  on:keydown={onKeydown}
  role="combobox"
  aria-expanded={open}
  aria-haspopup="listbox"
  tabindex="0"
>
  <button
    type="button"
    class="trigger"
    class:placeholder={!selected}
    on:click={toggleDropdown}
  >
    {#if selected}
      <span class="name">{selected.name || 'Unnamed peer'}</span>
      <span class="emoji">{selected.fingerprintEmoji}</span>
    {:else}
      <span class="name muted">{placeholder}</span>
    {/if}
    <svg
      class="chevron"
      class:rotated={open}
      viewBox="0 0 20 20"
      fill="currentColor"
      width="12"
      height="12"
    >
      <path
        fill-rule="evenodd"
        d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z"
        clip-rule="evenodd"
      />
    </svg>
  </button>

  {#if open}
    <div class="dropdown" role="listbox">
      <div class="search-row">
        <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
          <path
            fill-rule="evenodd"
            d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z"
            clip-rule="evenodd"
          />
        </svg>
        <input
          bind:this={searchInput}
          bind:value={search}
          type="text"
          class="search-input"
          placeholder="Search peers…"
        />
        <button
          type="button"
          class="close-btn"
          title="Close"
          on:click={closeDropdown}
        >×</button>
        {#if value}
          <button
            type="button"
            class="clear-btn"
            title="Clear selection"
            on:click={clearSelection}
          >⊘</button>
        {/if}
      </div>

      <div class="list">
        {#if filtered.length === 0}
          <div class="empty">No peers match "{search}"</div>
        {:else}
          {#each filtered as p, i (p.publicKeyBase64)}
            <button
              type="button"
              class="item"
              class:highlighted={i === highlightedIdx}
              class:selected={p.publicKeyBase64 === value}
              on:click={() => pick(p)}
              on:mouseenter={() => (highlightedIdx = i)}
            >
              <span class="name">{p.name || 'Unnamed peer'}</span>
              <span class="emoji">{p.fingerprintEmoji}</span>
            </button>
          {/each}
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .peer-select {
    position: relative;
    width: 100%;
  }
  .trigger {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    min-height: 36px;
    padding: 8px 12px;
    background: var(--bg-input);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    color: var(--text-primary);
    font-size: 13px;
    cursor: pointer;
    text-align: left;
    transition: border-color 0.15s;
  }
  .trigger:hover,
  .peer-select.open .trigger {
    border-color: var(--accent-primary);
  }
  .trigger.placeholder {
    color: var(--text-muted);
  }
  .trigger .name {
    flex: 1;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .trigger .name.muted {
    font-weight: 400;
  }
  .trigger .emoji {
    font-size: 12px;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }
  .chevron {
    flex-shrink: 0;
    color: var(--text-muted);
    transition: transform 0.15s;
  }
  .chevron.rotated {
    transform: rotate(-180deg);
  }
  .dropdown {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    right: 0;
    z-index: 100;
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: var(--border-radius);
    box-shadow: var(--shadow-md);
    overflow: hidden;
    animation: fadeIn 0.1s ease-out;
  }
  .search-row {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border-color);
    color: var(--text-muted);
  }
  .search-input {
    flex: 1;
    background: transparent;
    border: none;
    outline: none;
    color: var(--text-primary);
    font-size: 12px;
    padding: 2px 0;
  }
  .search-input::placeholder {
    color: var(--text-muted);
  }
  .clear-btn,
  .close-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-size: 16px;
    line-height: 1;
    cursor: pointer;
    padding: 0 4px;
    border-radius: 3px;
  }
  .clear-btn:hover,
  .close-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .list {
    max-height: 220px;
    overflow-y: auto;
  }
  .item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 8px 12px;
    background: transparent;
    border: none;
    color: var(--text-primary);
    font-size: 13px;
    text-align: left;
    cursor: pointer;
    transition: background 0.1s;
  }
  .item.highlighted {
    background: var(--bg-hover);
  }
  .item.selected {
    background: var(--accent-primary-dim);
    padding: 5px 12px;
    font-size: 12px;
    opacity: 0.85;
  }
  .item.selected.highlighted {
    background: var(--accent-primary-dim);
    filter: brightness(1.1);
  }
  .item .name {
    flex: 1;
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .item .emoji {
    font-size: 12px;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }
  .empty {
    padding: 12px;
    font-size: 12px;
    color: var(--text-muted);
    text-align: center;
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: translateY(0); }
  }
</style>
