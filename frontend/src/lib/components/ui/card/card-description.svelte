<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<div data-slot="card-description" class="text-muted-foreground text-sm {className}" {...restProps}>
  {@render children?.()}
</div>
