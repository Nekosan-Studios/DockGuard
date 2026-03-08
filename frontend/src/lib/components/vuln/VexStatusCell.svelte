<script lang="ts">
    import * as Table from "$lib/components/ui/table/index.js";
    import * as Tooltip from "$lib/components/ui/tooltip/index.js";
    import ShieldCheck from "@lucide/svelte/icons/shield-check";
    import ShieldAlert from "@lucide/svelte/icons/shield-alert";
    import Clock from "@lucide/svelte/icons/clock";

    let {
        vexStatus,
        vexJustification,
        vexStatement,
        class: className = "",
    }: {
        vexStatus: string | null;
        vexJustification?: string | null;
        vexStatement?: string | null;
        class?: string;
    } = $props();

    let tooltipText = $derived.by(() => {
        const parts: string[] = [];
        if (vexStatus === "not_affected") parts.push("Supplier declares: Not Affected");
        else if (vexStatus === "affected") parts.push("Supplier declares: Affected");
        else if (vexStatus === "under_investigation") parts.push("Supplier: Under Investigation");
        else if (vexStatus === "fixed") parts.push("Supplier declares: Fixed");
        if (vexJustification) parts.push(`Justification: ${vexJustification}`);
        if (vexStatement) parts.push(vexStatement);
        return parts.join("\n");
    });
</script>

<Table.Cell class="text-center {className}">
    {#if vexStatus === "not_affected"}
        <Tooltip.Root>
            <Tooltip.Trigger class="cursor-default">
                <ShieldCheck
                    class="mx-auto h-4 w-4 text-emerald-600 dark:text-emerald-400"
                />
            </Tooltip.Trigger>
            <Tooltip.Content class="max-w-xs whitespace-pre-line">
                {tooltipText}
            </Tooltip.Content>
        </Tooltip.Root>
    {:else if vexStatus === "affected"}
        <Tooltip.Root>
            <Tooltip.Trigger class="cursor-default">
                <ShieldAlert
                    class="mx-auto h-4 w-4 text-red-600 dark:text-red-400"
                />
            </Tooltip.Trigger>
            <Tooltip.Content class="max-w-xs whitespace-pre-line">
                {tooltipText}
            </Tooltip.Content>
        </Tooltip.Root>
    {:else if vexStatus === "under_investigation"}
        <Tooltip.Root>
            <Tooltip.Trigger class="cursor-default">
                <Clock
                    class="mx-auto h-4 w-4 text-amber-600 dark:text-amber-400"
                />
            </Tooltip.Trigger>
            <Tooltip.Content class="max-w-xs whitespace-pre-line">
                {tooltipText}
            </Tooltip.Content>
        </Tooltip.Root>
    {:else if vexStatus === "fixed"}
        <Tooltip.Root>
            <Tooltip.Trigger class="cursor-default">
                <ShieldCheck
                    class="mx-auto h-4 w-4 text-blue-600 dark:text-blue-400"
                />
            </Tooltip.Trigger>
            <Tooltip.Content class="max-w-xs whitespace-pre-line">
                {tooltipText}
            </Tooltip.Content>
        </Tooltip.Root>
    {:else}
        <span class="text-muted-foreground">—</span>
    {/if}
</Table.Cell>
