<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import ExternalLink from "@lucide/svelte/icons/external-link";
  import { toUtcDate } from "./utils";

  let {
    vulnId,
    dataSource,
    firstSeenAt,
  }: {
    vulnId: string;
    dataSource: string | null;
    firstSeenAt: string | null;
  } = $props();

  function isNew(firstSeenAt: string | null): boolean {
    if (!firstSeenAt) return false;
    const date = toUtcDate(firstSeenAt);
    const hours = (Date.now() - date.getTime()) / (1000 * 60 * 60);
    return hours <= 24;
  }
</script>

<Table.Cell class="pl-4 font-mono">
  <div class="flex flex-wrap items-center gap-1">
    {#if isNew(firstSeenAt)}
      <span
        class="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-100 px-1.5 py-0.5 font-sans text-[10px] font-semibold text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
      >
        NEW
      </span>
    {/if}
    <a
      href={dataSource ?? `https://nvd.nist.gov/vuln/detail/${vulnId}`}
      target="_blank"
      rel="noopener noreferrer"
      class="inline-flex items-center gap-1 text-blue-600 hover:underline dark:text-blue-400"
      title={vulnId}
    >
      {vulnId}
      <ExternalLink class="h-3 w-3 shrink-0" />
    </a>
  </div>
</Table.Cell>
