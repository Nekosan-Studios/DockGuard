<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<tr class="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted {className}" {...restProps}>
  {@render children?.()}
</tr>
