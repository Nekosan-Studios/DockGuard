<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<tbody class="[&_tr:last-child]:border-0 {className}" {...restProps}>
  {@render children?.()}
</tbody>
