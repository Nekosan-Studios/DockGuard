<script lang="ts">
    import * as Table from "$lib/components/ui/table/index.js";
    import * as Tooltip from "$lib/components/ui/tooltip/index.js";
    import { cvssClass, cvssTooltip } from "./utils.js";

    let {
        score,
        class: className = "",
    }: { score: number | null; class?: string } = $props();
</script>

<Table.Cell class="text-center {cvssClass(score)} {className}">
    {#if score != null}
        <Tooltip.Root>
            <Tooltip.Trigger class="cursor-default">
                {score.toFixed(1)}
            </Tooltip.Trigger>
            <Tooltip.Content>{cvssTooltip(score)}</Tooltip.Content>
        </Tooltip.Root>
    {:else}
        —
    {/if}
</Table.Cell>
