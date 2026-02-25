<script>
  /** @type {string} severity — e.g. "Critical", "High", "Medium", "Low", "Negligible" */
  let { severity } = $props();

  const cls = $derived(() => {
    switch ((severity ?? '').toLowerCase()) {
      case 'critical':   return 'badge badge-critical';
      case 'high':       return 'badge badge-high';
      case 'medium':     return 'badge badge-medium';
      case 'low':        return 'badge badge-low';
      default:           return 'badge badge-negligible';
    }
  });
</script>

<span class={cls()}>{severity ?? 'Unknown'}</span>
