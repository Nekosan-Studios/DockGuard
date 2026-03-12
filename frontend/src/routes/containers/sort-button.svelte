<script lang="ts">
  import type { ComponentProps } from "svelte";
  import ArrowUpDown from "@lucide/svelte/icons/arrow-up-down";
  import ArrowUp from "@lucide/svelte/icons/arrow-up";
  import ArrowDown from "@lucide/svelte/icons/arrow-down";
  import { Button } from "$lib/components/ui/button/index.js";

  let {
    label,
    sortDirection = false,
    variant = "ghost",
    class: className = "",
    ...restProps
  }: ComponentProps<typeof Button> & {
    label: string;
    sortDirection?: "asc" | "desc" | false;
  } = $props();
</script>

<Button
  {variant}
  class="h-8 px-0 inline-flex items-center gap-1 font-medium text-xs hover:bg-transparent hover:text-foreground {className}"
  {...restProps}
>
  <span class="truncate">{label}</span>
  {#if sortDirection === "asc"}
    <ArrowUp class="h-3 w-3 shrink-0" />
  {:else if sortDirection === "desc"}
    <ArrowDown class="h-3 w-3 shrink-0" />
  {:else}
    <ArrowUpDown class="h-3 w-3 shrink-0 opacity-40" />
  {/if}
</Button>
