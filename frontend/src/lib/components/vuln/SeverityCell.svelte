<script lang="ts">
    import * as Table from "$lib/components/ui/table/index.js";
    import { SEVERITY_CLASSES } from "./utils.js";

    let {
        severity,
        class: className = "",
    }: { severity: string; class?: string } = $props();
</script>

<Table.Cell class="text-center {className}">
    <span
        class="inline-flex items-center rounded-full border px-1.5 py-0.5 font-medium {SEVERITY_CLASSES[
            severity
        ] ?? SEVERITY_CLASSES['Unknown']}"
    >
        {severity}
    </span>
</Table.Cell>
