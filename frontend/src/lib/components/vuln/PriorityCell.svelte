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
    cvssVector = null,
    class: className = "",
  }: { riskScore?: number | null; cvssVector?: string | null; class?: string } = $props();

  // Decode a CVSS v3.x vector string into labeled components.
  // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  const AV_LABELS: Record<string, string> = {
    N: "Network",
    A: "Adjacent",
    L: "Local",
    P: "Physical",
  };
  const AC_LABELS: Record<string, string> = { L: "Low", H: "High" };
  const PR_LABELS: Record<string, string> = { N: "None", L: "Low", H: "High" };
  const UI_LABELS: Record<string, string> = { N: "None", R: "Required" };
  const S_LABELS: Record<string, string> = { U: "Unchanged", C: "Changed" };
  const CIA_LABELS: Record<string, string> = { N: "None", L: "Low", H: "High" };

  interface VectorComponent {
    label: string;
    value: string;
  }

  function decodeCvssVector(vector: string): VectorComponent[] | null {
    // Strip the "CVSS:3.x/" prefix then parse key:value pairs
    const raw = vector.replace(/^CVSS:\d+\.\d+\//, "");
    const parts = raw.split("/");
    const map: Record<string, string> = {};
    for (const part of parts) {
      const [k, v] = part.split(":");
      if (k && v) map[k] = v;
    }
    if (!map["AV"]) return null;
    return [
      { label: "Attack Vector", value: AV_LABELS[map["AV"]] ?? map["AV"] },
      { label: "Attack Complexity", value: AC_LABELS[map["AC"]] ?? map["AC"] },
      {
        label: "Privileges Required",
        value: PR_LABELS[map["PR"]] ?? map["PR"],
      },
      { label: "User Interaction", value: UI_LABELS[map["UI"]] ?? map["UI"] },
      { label: "Scope", value: S_LABELS[map["S"]] ?? map["S"] },
      { label: "Confidentiality", value: CIA_LABELS[map["C"]] ?? map["C"] },
      { label: "Integrity", value: CIA_LABELS[map["I"]] ?? map["I"] },
      { label: "Availability", value: CIA_LABELS[map["A"]] ?? map["A"] },
    ];
  }

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
      <p class={vectorComponents ? "font-semibold mb-1" : ""}>{priorityTooltip(riskScore)}</p>
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
