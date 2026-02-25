<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<div data-slot="card-header" class="flex flex-col gap-1.5 px-6 pt-6 {className}" {...restProps}>
  {@render children?.()}
</div>
