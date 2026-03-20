<script lang="ts">
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import PriorityCell from "./PriorityCell.svelte";

  let {
    riskScore = null,
    cvssVector = null,
  }: { riskScore?: number | null; cvssVector?: string | null } = $props();
</script>

<Tooltip.Provider>
  <table>
    <tbody>
      <tr>
        <PriorityCell {riskScore} {cvssVector} />
      </tr>
    </tbody>
  </table>
</Tooltip.Provider>
