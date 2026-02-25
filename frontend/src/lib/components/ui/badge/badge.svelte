<script>
  import { cn } from '$lib/utils.js';

  let { class: className = '', variant = 'default', children, ...restProps } = $props();

  const variants = {
    default:     'bg-primary text-primary-foreground border-transparent',
    secondary:   'bg-secondary text-secondary-foreground border-transparent',
    destructive: 'bg-destructive text-white border-transparent',
    outline:     'border border-border bg-transparent text-foreground',
  };
</script>

<span
  class={cn(
    'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold tracking-wide whitespace-nowrap border',
    variants[variant] ?? variants.default,
    className
  )}
  {...restProps}
>
  {@render children?.()}
</span>
