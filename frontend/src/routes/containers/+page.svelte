<script lang="ts">
  import type { PageData } from "./$types";
  import * as Card from "$lib/components/ui/card/index.js";
  import { Badge } from "$lib/components/ui/badge/index.js";
  import * as Table from "$lib/components/ui/table/index.js";
  import Container from "@lucide/svelte/icons/container";
  import ShieldAlert from "@lucide/svelte/icons/shield-alert";
  import ScanLine from "@lucide/svelte/icons/scan-line";
  import SortButton from "./sort-button.svelte";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import { Checkbox } from "$lib/components/ui/checkbox/index.js";
  import ContainerRow from "$lib/components/vuln/ContainerRow.svelte";
  import type { ContainerRecord } from "$lib/components/vuln/ContainerRow.svelte";
  import { PRIORITY_ORDER } from "$lib/components/vuln/utils.js";
  import { page } from "$app/stores";
  import { replaceState } from "$app/navigation";
  import PreviewScannerModal from "$lib/components/preview/PreviewScannerModal.svelte";

  let { data }: { data: PageData } = $props();

  let previewScanOpen = $state(false);
  let expandedContainerName = $state<string | null>(null);

  // ── Deep link state ─────────────────────────────────────────────────────
  let activeCve = $derived($page.url.searchParams.get("cve"));

  function handleModalChange(vulnId: string, open: boolean) {
    if (!open) {
      const u = new URL($page.url);
      if (u.searchParams.get("cve") === vulnId) {
        u.searchParams.delete("cve");
        replaceState(u, {});
      }
    }
  }

  function handleToggleContainerExpand(containerName: string | null) {
    expandedContainerName = containerName;
  }

  let hideVexResolved = $state(false);
  let anyContainerHasVex = $derived(
    data.containers.some((c: { has_vex?: boolean }) => c.has_vex)
  );

  // ── Parent table sort ──────────────────────────────────────────────────────
  type ParentSortCol = "container_name" | "vulns" | "scanned_at";
  let parentSortCol = $state<ParentSortCol>("container_name");
  let parentSortDir = $state<"asc" | "desc">("asc");

  function toggleParentSort(col: ParentSortCol) {
    if (parentSortCol === col) {
      parentSortDir = parentSortDir === "asc" ? "desc" : "asc";
    } else {
      parentSortCol = col;
      parentSortDir = "asc";
    }
  }

  let sortedContainers = $derived.by(() => {
    const rows = [...data.containers] as ContainerRecord[];
    const dir = parentSortDir === "asc" ? 1 : -1;
    return rows.sort((a, b) => {
      switch (parentSortCol) {
        case "container_name":
          return dir * a.container_name.localeCompare(b.container_name);
        case "vulns": {
          const mapA = hideVexResolved
            ? a.vulns_by_priority_no_vex
            : a.vulns_by_priority;
          const mapB = hideVexResolved
            ? b.vulns_by_priority_no_vex
            : b.vulns_by_priority;
          for (const pri of PRIORITY_ORDER) {
            const diff = (mapA?.[pri] ?? 0) - (mapB?.[pri] ?? 0);
            if (diff !== 0) return dir * diff;
          }
          return 0;
        }
        case "scanned_at": {
          if (!a.scanned_at && !b.scanned_at) return 0;
          if (!a.scanned_at) return 1;
          if (!b.scanned_at) return -1;
          return (
            dir *
            (a.scanned_at < b.scanned_at
              ? -1
              : a.scanned_at > b.scanned_at
                ? 1
                : 0)
          );
        }
      }
    });
  });
</script>

<div class="container mx-auto py-6 space-y-6">
  <div class="flex items-center gap-4">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">Containers</h1>
      <p class="text-muted-foreground">
        Running containers and their vulnerability status.
      </p>
    </div>
    <button
      onclick={() => (previewScanOpen = true)}
      class="inline-flex items-center gap-2 rounded-md border border-input bg-background px-3 py-2 text-sm font-medium hover:bg-accent hover:text-accent-foreground transition-colors shrink-0"
    >
      <ScanLine class="h-4 w-4" />
      Preview Scan
    </button>
  </div>

  <Card.Root>
    <Card.Header>
      <div class="space-y-1.5 flex flex-row items-center gap-4">
        <div>
          <Card.Title>Running Containers</Card.Title>
          <Card.Description
            >Images currently running, cross-referenced with the latest scan
            results.</Card.Description
          >
        </div>
        {#if anyContainerHasVex}
          <div class="border-l border-border/50 pl-4 ml-2 my-1">
            <label
              class="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer select-none whitespace-nowrap"
            >
              <Checkbox
                checked={hideVexResolved}
                onCheckedChange={(v) => {
                  hideVexResolved = v === true;
                }}
              />
              Hide VEX Resolved
              <Tooltip.Root>
                <Tooltip.Trigger class="cursor-default">
                  <span class="text-muted-foreground/60 text-xs">ⓘ</span>
                </Tooltip.Trigger>
                <Tooltip.Content>
                  Hide vulnerabilities where the supplier has declared them "not
                  affected" or "fixed" via VEX attestations.
                </Tooltip.Content>
              </Tooltip.Root>
            </label>
          </div>
        {/if}
      </div>
    </Card.Header>
    <Card.Content>
      {#if data.apiError}
        <div
          class="rounded-md border border-red-200 bg-red-50 p-4 dark:border-red-900/50 dark:bg-red-900/10 text-red-800 dark:text-red-300 flex items-start gap-4"
        >
          <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0" />
          <div class="flex flex-col gap-1 text-sm">
            <span class="font-medium">Unexpected Error</span>
            <span class="opacity-90"
              >An unexpected error occurred while loading container data. Please
              try again shortly.</span
            >
          </div>
        </div>
      {:else if data.containers.length === 0}
        <div
          class="flex flex-col items-center justify-center gap-2 py-8 text-center"
        >
          <Container class="text-muted-foreground h-10 w-10" />
          <p class="text-muted-foreground text-sm">
            No running containers found.
          </p>
          <Badge variant="outline">Waiting for data</Badge>
        </div>
      {:else}
        <div class="rounded-md border mt-4">
          <Table.Root>
            <Table.Header>
              <Table.Row>
                <Table.Head>
                  <SortButton
                    label="Container"
                    sortDirection={parentSortCol === "container_name"
                      ? parentSortDir
                      : false}
                    onclick={() => toggleParentSort("container_name")}
                  />
                </Table.Head>
                <Table.Head>
                  <SortButton
                    label="Vulnerabilities"
                    sortDirection={parentSortCol === "vulns"
                      ? parentSortDir
                      : false}
                    onclick={() => toggleParentSort("vulns")}
                  />
                </Table.Head>
                <Table.Head class="w-[180px] text-center">
                  <SortButton
                    label="Last Scanned"
                    sortDirection={parentSortCol === "scanned_at"
                      ? parentSortDir
                      : false}
                    onclick={() => toggleParentSort("scanned_at")}
                  />
                </Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each sortedContainers as container (container.container_name)}
                <ContainerRow
                  {container}
                  {hideVexResolved}
                  {activeCve}
                  {expandedContainerName}
                  onToggleExpand={handleToggleContainerExpand}
                  onModalChange={handleModalChange}
                />
              {/each}
            </Table.Body>
          </Table.Root>
        </div>
      {/if}
    </Card.Content>
  </Card.Root>
</div>

<PreviewScannerModal bind:open={previewScanOpen} />
