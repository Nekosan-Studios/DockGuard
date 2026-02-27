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
        ...restProps
    }: ComponentProps<typeof Button> & {
        label: string;
        sortDirection?: "asc" | "desc" | false;
    } = $props();
</script>

<Button {variant} {...restProps}>
    {label}
    {#if sortDirection === "asc"}
        <ArrowUp class="ms-2 h-4 w-4" />
    {:else if sortDirection === "desc"}
        <ArrowDown class="ms-2 h-4 w-4" />
    {:else}
        <ArrowUpDown class="ms-2 h-4 w-4 opacity-40" />
    {/if}
</Button>
