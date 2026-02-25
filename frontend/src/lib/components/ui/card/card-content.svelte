<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<div data-slot="card-content" class="px-6 pb-6 {className}" {...restProps}>
  {@render children?.()}
</div>
