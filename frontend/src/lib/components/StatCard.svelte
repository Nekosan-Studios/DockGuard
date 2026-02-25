<script>
  import { Card, CardHeader, CardContent } from '$lib/components/ui/card/index.js';

  /**
   * @type {string} label — metric name shown above the number
   * @type {string|number} value — the big number / main value
   * @type {string} [subtitle] — optional small text below the number
   * @type {boolean} [loading] — show skeleton while loading
   */
  let { label, value, subtitle = '', loading = false } = $props();
</script>

<Card>
  <CardHeader>
    <p class="stat-label">{label}</p>
  </CardHeader>
  <CardContent>
    {#if loading}
      <div class="stat-number" style="color: var(--border);">—</div>
    {:else}
      <div class="stat-number">{value}</div>
    {/if}
    {#if subtitle}
      <p class="stat-subtitle">{subtitle}</p>
    {/if}
  </CardContent>
</Card>
