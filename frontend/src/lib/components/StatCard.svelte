<script>
  /**
   * @type {string} label — metric name shown above the number
   * @type {string|number} value — the big number / main value
   * @type {string} [subtitle] — optional small text below the number
   * @type {boolean} [loading] — show skeleton while loading
   */
  let { label, value, subtitle = '', loading = false } = $props();
</script>

<div class="card">
  <div class="stat-label">{label}</div>
  {#if loading}
    <div class="stat-number" style="color: var(--border);">—</div>
  {:else}
    <div class="stat-number">{value}</div>
  {/if}
  {#if subtitle}
    <div class="stat-subtitle">{subtitle}</div>
  {/if}
</div>
