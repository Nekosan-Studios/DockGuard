<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import ExternalLink from "@lucide/svelte/icons/external-link";
  import ZoomIn from "@lucide/svelte/icons/zoom-in";

  let {
    vulnId,
    dataSource,
    isNew = false,
    onDetailClick,
  }: {
    vulnId: string;
    dataSource: string | null;
    isNew?: boolean;
    onDetailClick?: () => void;
  } = $props();
</script>

<Table.Cell class="pl-4 font-mono whitespace-normal">
  <div class="flex flex-wrap gap-0.5 sm:gap-1 items-center min-w-0">
    <button
      type="button"
      aria-label="View vulnerability details"
      class="cursor-pointer rounded p-0.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
      onclick={(e) => {
        e.stopPropagation();
        onDetailClick?.();
      }}
    >
      <ZoomIn class="h-3.5 w-3.5" />
    </button>
    {#if isNew}
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
      class="inline-flex min-w-0 max-w-full items-center gap-1 whitespace-normal text-blue-600 hover:underline dark:text-blue-400"
      title={vulnId}
    >
      <span>{vulnId}</span>
      <ExternalLink class="h-3 w-3 shrink-0" />
    </a>
  </div>
</Table.Cell>
