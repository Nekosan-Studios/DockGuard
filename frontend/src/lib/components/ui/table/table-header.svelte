<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<thead class="[&_tr]:border-b {className}" {...restProps}>
  {@render children?.()}
</thead>
