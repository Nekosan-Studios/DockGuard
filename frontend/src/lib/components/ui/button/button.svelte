<script>
  import { cn } from '$lib/utils.js';

  let {
    class: className = '',
    variant = 'default',
    size = 'default',
    children,
    ...restProps
  } = $props();

  const variants = {
    default:   'bg-primary text-primary-foreground hover:bg-primary/90',
    outline:   'border border-border bg-transparent hover:bg-accent hover:text-accent-foreground',
    ghost:     'hover:bg-accent hover:text-accent-foreground',
    secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
  };

  const sizes = {
    default: 'h-9 px-4 py-2',
    sm:      'h-8 px-3 text-xs',
    lg:      'h-10 px-8',
  };
</script>

<button
  class={cn(
    'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 cursor-pointer',
    variants[variant] ?? variants.default,
    sizes[size] ?? sizes.default,
    className
  )}
  {...restProps}
>
  {@render children?.()}
</button>
