<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<div data-slot="card" class="bg-card text-card-foreground rounded-xl border shadow-sm {className}" {...restProps}>
  {@render children?.()}
</div>
