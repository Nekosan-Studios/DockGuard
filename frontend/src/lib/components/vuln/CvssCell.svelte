<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import { cvssClass, cvssTooltip } from "./utils.js";

  let {
    score,
    class: className = "",
  }: {
    score: number | null;
    class?: string;
  } = $props();
</script>

<Table.Cell class="text-center {cvssClass(score)} {className}">
  {#if score != null}
    <Tooltip.Provider>
      <Tooltip.Root>
        <Tooltip.Trigger class="cursor-default">
          {score.toFixed(1)}
        </Tooltip.Trigger>
        <Tooltip.Content class="max-w-xs">
          <p>{cvssTooltip(score)}</p>
        </Tooltip.Content>
      </Tooltip.Root>
    </Tooltip.Provider>
  {:else}
    —
  {/if}
</Table.Cell>
