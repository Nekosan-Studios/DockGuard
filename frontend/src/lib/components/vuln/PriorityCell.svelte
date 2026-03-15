<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import {
    PRIORITY_CLASSES,
    decodeCvssVector,
    priorityFromRiskScore,
    priorityTooltip,
  } from "./utils.js";

  let {
    riskScore = null,
    cvssVector = null,
    class: className = "",
  }: {
    riskScore?: number | null;
    cvssVector?: string | null;
    class?: string;
  } = $props();

  let vectorComponents = $derived(
    cvssVector ? decodeCvssVector(cvssVector) : null
  );

  let priority = $derived(priorityFromRiskScore(riskScore));
</script>

<Table.Cell class="text-center {className}">
  <Tooltip.Root>
    <Tooltip.Trigger class="cursor-default">
      <span
        class="inline-flex items-center justify-center gap-1 rounded-full border px-2 py-0.5 font-medium min-w-[60px] {PRIORITY_CLASSES[
          priority
        ]}"
      >
        <span class="text-[11px] leading-none">{priority}</span>
        {#if riskScore != null}
          <span class="font-mono opacity-70 text-[9px] leading-none"
            >{riskScore.toFixed(1)}</span
          >
        {/if}
      </span>
    </Tooltip.Trigger>
    <Tooltip.Content class={vectorComponents ? "max-w-xs" : ""}>
      <p class={vectorComponents ? "font-semibold mb-1" : ""}>
        {priorityTooltip(riskScore)}
      </p>
      {#if vectorComponents}
        <div class="mt-1.5 pt-1.5 border-t border-border/60">
          <dl class="grid grid-cols-2 gap-x-3 gap-y-0.5 text-xs">
            {#each vectorComponents as { label, value } (label)}
              <dt class="text-muted-foreground">{label}</dt>
              <dd class="font-medium">{value}</dd>
            {/each}
          </dl>
        </div>
      {/if}
    </Tooltip.Content>
  </Tooltip.Root>
</Table.Cell>
