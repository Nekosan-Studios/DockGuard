<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<th class="text-muted-foreground h-10 px-2 text-left align-middle font-medium whitespace-nowrap {className}" {...restProps}>
  {@render children?.()}
</th>
