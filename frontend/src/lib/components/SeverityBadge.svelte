<script>
  import { Badge } from '$lib/components/ui/badge/index.js';

  /** @type {string} severity — e.g. "Critical", "High", "Medium", "Low", "Negligible" */
  let { severity } = $props();

  const colorClass = $derived(() => {
    switch ((severity ?? '').toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-700 border-red-200 dark:bg-red-950/80 dark:text-red-400 dark:border-red-900/50';
      case 'high':     return 'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-950/80 dark:text-orange-400 dark:border-orange-900/50';
      case 'medium':   return 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-950/80 dark:text-yellow-300 dark:border-yellow-900/50';
      case 'low':      return 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-950/80 dark:text-blue-400 dark:border-blue-900/50';
      default:         return 'bg-muted text-muted-foreground border-border';
    }
  });
</script>

<Badge variant="outline" class={colorClass()}>{severity ?? 'Unknown'}</Badge>
