<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import { epssClass, epssTooltip } from "./utils.js";

  let {
    score,
    percentile,
    class: className = "",
  }: {
    score: number | null;
    percentile: number | null;
    class?: string;
  } = $props();
</script>

<Table.Cell class="text-center {epssClass(score)} {className}">
  {#if score != null}
    <Tooltip.Provider>
      <Tooltip.Root>
        <Tooltip.Trigger class="cursor-default">
          {#if score * 100 >= 1 && score * 100 < 99.5}
            {Math.round(score * 100)}%
          {:else}
            {(score * 100).toFixed(2)}%
          {/if}
        </Tooltip.Trigger>
        <Tooltip.Content>
          <p>{epssTooltip(score)}</p>
          {#if percentile != null}
            {@const pct = Math.round(percentile * 100)}
            <p
              class="mt-1 {pct >= 90
                ? 'font-semibold text-red-400'
                : pct >= 70
                  ? 'text-orange-400'
                  : ''}"
            >
              {#if pct >= 50}
                More likely to be exploited than {pct}% of all other
                vulnerabilities.
              {:else}
                {100 - pct}% of all other vulnerabilities are more likely to be
                exploited.
              {/if}
            </p>
          {/if}
        </Tooltip.Content>
      </Tooltip.Root>
    </Tooltip.Provider>
  {:else}
    —
  {/if}
</Table.Cell>
