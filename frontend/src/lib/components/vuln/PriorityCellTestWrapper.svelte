<script lang="ts">
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import PriorityCell from "./PriorityCell.svelte";

  let { riskScore = null }: { riskScore?: number | null } = $props();
</script>

<Tooltip.Provider>
  <table>
    <tbody>
      <tr>
        <PriorityCell {riskScore} />
      </tr>
    </tbody>
  </table>
</Tooltip.Provider>
