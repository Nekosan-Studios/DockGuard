<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<div data-slot="card-title" class="font-semibold leading-none {className}" {...restProps}>
  {@render children?.()}
</div>
