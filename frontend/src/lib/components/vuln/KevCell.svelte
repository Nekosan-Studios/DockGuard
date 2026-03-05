<script lang="ts">
    import * as Table from "$lib/components/ui/table/index.js";
    import * as Tooltip from "$lib/components/ui/tooltip/index.js";
    import CircleCheck from "@lucide/svelte/icons/circle-check";

    let { isKev, class: className = "" }: { isKev: boolean; class?: string } =
        $props();
</script>

<Table.Cell class="text-center {className}">
    {#if isKev}
        <Tooltip.Root>
            <Tooltip.Trigger class="cursor-default">
                <CircleCheck
                    class="mx-auto h-4 w-4 text-red-600 dark:text-red-400"
                />
            </Tooltip.Trigger>
            <Tooltip.Content>
                Known Exploited Vulnerability — this CVE is confirmed to be
                actively exploited in the wild by CISA.
            </Tooltip.Content>
        </Tooltip.Root>
    {:else}
        <span class="text-muted-foreground">—</span>
    {/if}
</Table.Cell>
