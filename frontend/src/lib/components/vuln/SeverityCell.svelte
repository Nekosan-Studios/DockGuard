<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import { SEVERITY_CLASSES, riskScoreTooltip } from "./utils.js";

  let {
    severity,
    riskScore = null,
    class: className = "",
  }: { severity: string; riskScore?: number | null; class?: string } = $props();
</script>

<Table.Cell class="text-center {className}">
  {#if riskScore != null}
    <Tooltip.Root>
      <Tooltip.Trigger class="cursor-default">
        <span
          class="inline-flex flex-col items-center rounded-full border px-1.5 py-0.5 font-medium {SEVERITY_CLASSES[
            severity
          ] ?? SEVERITY_CLASSES['Unknown']}"
        >
          <span class="leading-tight">{severity}</span>
          <span class="font-mono opacity-60 text-[9px] leading-tight"
            >{riskScore.toFixed(1)}</span
          >
        </span>
      </Tooltip.Trigger>
      <Tooltip.Content>
        <p>{riskScoreTooltip(riskScore)}</p>
      </Tooltip.Content>
    </Tooltip.Root>
  {:else}
    <span
      class="inline-flex items-center rounded-full border px-1.5 py-0.5 font-medium {SEVERITY_CLASSES[
        severity
      ] ?? SEVERITY_CLASSES['Unknown']}"
    >
      {severity}
    </span>
  {/if}
</Table.Cell>
