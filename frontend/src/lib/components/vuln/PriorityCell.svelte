<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import {
    PRIORITY_CLASSES,
    priorityFromRiskScore,
    priorityTooltip,
  } from "./utils.js";

  let {
    riskScore = null,
    class: className = "",
  }: { riskScore?: number | null; class?: string } = $props();

  let priority = $derived(priorityFromRiskScore(riskScore));
</script>

<Table.Cell class="text-center {className}">
  <Tooltip.Root>
    <Tooltip.Trigger class="cursor-default">
      <span
        class="inline-flex flex-col items-center rounded-full border px-1.5 py-0.5 font-medium {PRIORITY_CLASSES[
          priority
        ]}"
      >
        <span class="leading-tight">{priority}</span>
        {#if riskScore != null}
          <span class="font-mono opacity-60 text-[9px] leading-tight"
            >{riskScore.toFixed(1)}</span
          >
        {/if}
      </span>
    </Tooltip.Trigger>
    <Tooltip.Content>
      <p>{priorityTooltip(riskScore)}</p>
    </Tooltip.Content>
  </Tooltip.Root>
</Table.Cell>
