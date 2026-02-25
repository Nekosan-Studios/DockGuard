<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<caption class="text-muted-foreground mt-4 text-sm {className}" {...restProps}>
  {@render children?.()}
</caption>
