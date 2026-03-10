<script lang="ts">
    import * as Table from "$lib/components/ui/table/index.js";
    import * as Tooltip from "$lib/components/ui/tooltip/index.js";
    import { cvssClass, cvssTooltip } from "./utils.js";

    let {
        score,
        cvssVector = null,
        class: className = "",
    }: { score: number | null; cvssVector?: string | null; class?: string } = $props();

    // Decode a CVSS v3.x vector string into labeled components.
    // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    const AV_LABELS: Record<string, string> = { N: "Network", A: "Adjacent", L: "Local", P: "Physical" };
    const AC_LABELS: Record<string, string> = { L: "Low", H: "High" };
    const PR_LABELS: Record<string, string> = { N: "None", L: "Low", H: "High" };
    const UI_LABELS: Record<string, string> = { N: "None", R: "Required" };
    const S_LABELS:  Record<string, string> = { U: "Unchanged", C: "Changed" };
    const CIA_LABELS: Record<string, string> = { N: "None", L: "Low", H: "High" };

    interface VectorComponent { label: string; value: string }

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
            { label: "Attack Vector",        value: AV_LABELS[map["AV"]]  ?? map["AV"] },
            { label: "Attack Complexity",     value: AC_LABELS[map["AC"]]  ?? map["AC"] },
            { label: "Privileges Required",   value: PR_LABELS[map["PR"]]  ?? map["PR"] },
            { label: "User Interaction",      value: UI_LABELS[map["UI"]]  ?? map["UI"] },
            { label: "Scope",                 value: S_LABELS[map["S"]]    ?? map["S"] },
            { label: "Confidentiality",       value: CIA_LABELS[map["C"]]  ?? map["C"] },
            { label: "Integrity",             value: CIA_LABELS[map["I"]]  ?? map["I"] },
            { label: "Availability",          value: CIA_LABELS[map["A"]]  ?? map["A"] },
        ];
    }

    let vectorComponents = $derived(cvssVector ? decodeCvssVector(cvssVector) : null);
</script>

<Table.Cell class="text-center {cvssClass(score)} {className}">
    {#if score != null}
        <Tooltip.Provider>
            <Tooltip.Root>
                <Tooltip.Trigger class="cursor-default">
                    {score.toFixed(1)}
                </Tooltip.Trigger>
                <Tooltip.Content class="max-w-xs">
                    <p class="font-semibold mb-1">{cvssTooltip(score)}</p>
                    {#if vectorComponents}
                        <div class="mt-1.5 pt-1.5 border-t border-border/60">
                            <dl class="grid grid-cols-2 gap-x-3 gap-y-0.5 text-xs">
                                {#each vectorComponents as { label, value }}
                                    <dt class="text-muted-foreground">{label}</dt>
                                    <dd class="font-medium">{value}</dd>
                                {/each}
                            </dl>
                        </div>
                    {/if}
                </Tooltip.Content>
            </Tooltip.Root>
        </Tooltip.Provider>
    {:else}
        —
    {/if}
</Table.Cell>
