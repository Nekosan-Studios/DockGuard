<script>
  let { class: className = '', children, ...restProps } = $props();
</script>

<div class="relative w-full overflow-auto">
  <table class="w-full caption-bottom text-sm {className}" {...restProps}>
    {@render children?.()}
  </table>
</div>
