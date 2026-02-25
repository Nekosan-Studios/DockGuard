<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<td class="p-2 align-middle {className}" {...restProps}>
  {@render children?.()}
</td>
