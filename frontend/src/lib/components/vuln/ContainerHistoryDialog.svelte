<script lang="ts">
  import * as Dialog from "$lib/components/ui/dialog/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import * as Popover from "$lib/components/ui/popover/index.js";
  import { Skeleton } from "$lib/components/ui/skeleton/index.js";
  import ChevronRight from "@lucide/svelte/icons/chevron-right";
  import CircleCheck from "@lucide/svelte/icons/circle-check";
  import ExternalLink from "@lucide/svelte/icons/external-link";
  import { SvelteSet } from "svelte/reactivity";
  import {
    PRIORITY_CLASSES,
    PRIORITY_ORDER,
    priorityFromRiskScore,
    toUtcDate,
  } from "./utils.js";
  import type { ContainerRecord } from "./ContainerRow.svelte";

  let {
    container,
    open = $bindable(false),
  }: {
    container: ContainerRecord;
    open: boolean;
  } = $props();

  interface VulnDiff {
    vuln_id: string;
    package_name: string;
    installed_version: string;
    risk_score: number | null;
    is_kev: boolean;
    data_source: string | null;
  }

  interface GroupedVulnDiff {
    vuln_id: string;
    data_source: string | null;
    risk_score: number | null;
    is_kev: boolean;
    packages: { package_name: string; installed_version: string }[];
  }

  interface ScanEntry {
    scan_id: number;
    scanned_at: string;
    image_name: string;
    total: number;
    is_baseline: boolean;
    image_changed: boolean | null;
    added: VulnDiff[];
    removed: VulnDiff[];
    vulns_by_priority: Record<string, number> | null;
  }

  interface HistoryResponse {
    container_name: string;
    total_scans: number;
    has_more: boolean;
    entries: ScanEntry[];
  }

  let loading = $state(false);
  let error = $state<string | null>(null);
  let history = $state<HistoryResponse | null>(null);
  let loadingMore = $state(false);
  let expandedEntries = new SvelteSet<number>();

  function shortDate(iso: string): string {
    return toUtcDate(iso).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function groupByVulnId(vulns: VulnDiff[]): GroupedVulnDiff[] {
    const map: Record<string, GroupedVulnDiff> = {};
    for (const v of vulns) {
      const existing = map[v.vuln_id];
      if (!existing) {
        map[v.vuln_id] = {
          vuln_id: v.vuln_id,
          data_source: v.data_source,
          risk_score: v.risk_score,
          is_kev: v.is_kev,
          packages: [
            {
              package_name: v.package_name,
              installed_version: v.installed_version,
            },
          ],
        };
      } else {
        if (
          v.risk_score != null &&
          (existing.risk_score == null || v.risk_score > existing.risk_score)
        ) {
          existing.risk_score = v.risk_score;
        }
        if (v.is_kev) existing.is_kev = true;
        existing.packages.push({
          package_name: v.package_name,
          installed_version: v.installed_version,
        });
      }
    }
    return Object.values(map);
  }

  function countByPriority(vulns: VulnDiff[]): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const v of groupByVulnId(vulns)) {
      const pri = priorityFromRiskScore(v.risk_score);
      counts[pri] = (counts[pri] ?? 0) + 1;
    }
    return counts;
  }

  async function loadHistory(offset = 0) {
    if (offset === 0) {
      loading = true;
      error = null;
      history = null;
    } else {
      loadingMore = true;
    }
    try {
      const params = new URLSearchParams({
        offset: String(offset),
        limit: "10",
      });
      const res = await fetch(
        `/api/containers/${encodeURIComponent(container.container_name)}/scan-history?${params}`
      );
      if (!res.ok) {
        error = `Failed to load history (HTTP ${res.status})`;
        return;
      }
      const data: HistoryResponse = await res.json();
      if (offset === 0) {
        history = data;
      } else if (history) {
        history = {
          ...data,
          entries: [...history.entries, ...data.entries],
        };
      }
    } catch (e) {
      error = e instanceof Error ? e.message : "Failed to load history";
    } finally {
      loading = false;
      loadingMore = false;
    }
  }

  function toggleEntry(scanId: number) {
    if (expandedEntries.has(scanId)) {
      expandedEntries.delete(scanId);
    } else {
      expandedEntries.add(scanId);
    }
  }

  $effect(() => {
    if (open && !history && !loading) {
      loadHistory(0);
    }
    if (!open) {
      history = null;
      error = null;
      expandedEntries.clear();
    }
  });
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="max-w-3xl max-h-[85vh] overflow-y-auto">
    <Dialog.Header>
      <Dialog.Title>Scan History — {container.container_name}</Dialog.Title>
      <Dialog.Description class="font-mono text-xs truncate">
        {container.image_name}
      </Dialog.Description>
    </Dialog.Header>

    <div class="mt-2 space-y-2">
      {#if loading}
        {#each [0, 1, 2, 3] as i (i)}
          <Skeleton class="h-14 w-full rounded-md" />
        {/each}
      {:else if error}
        <p class="text-destructive text-sm">{error}</p>
      {:else if history}
        {#if history.entries.length === 0}
          <p class="text-muted-foreground text-sm">No scan history found.</p>
        {:else}
          {#each history.entries as entry (entry.scan_id)}
            {@const isExpanded = expandedEntries.has(entry.scan_id)}
            <div class="rounded-md border">
              <!-- Entry header (always visible) -->
              <button
                class="flex w-full items-center gap-2 px-3 py-2.5 text-left hover:bg-muted/40 transition-colors"
                onclick={() => toggleEntry(entry.scan_id)}
              >
                <ChevronRight
                  class="h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-150 {isExpanded
                    ? 'rotate-90'
                    : ''}"
                />

                {#if entry.is_baseline}
                  <!-- Baseline header -->
                  <div class="flex flex-1 flex-wrap items-center gap-2 min-w-0">
                    <span
                      class="rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground"
                    >
                      Baseline
                    </span>
                    <span class="text-xs text-muted-foreground"
                      >{shortDate(entry.scanned_at)}</span
                    >
                    <div class="flex flex-wrap gap-1">
                      {#each PRIORITY_ORDER as pri (pri)}
                        {#if entry.vulns_by_priority && (entry.vulns_by_priority[pri] ?? 0) > 0}
                          <span
                            class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {PRIORITY_CLASSES[
                              pri
                            ]}"
                          >
                            {entry.vulns_by_priority[pri]}
                            {pri}
                          </span>
                        {/if}
                      {/each}
                    </div>
                  </div>
                {:else}
                  <!-- Diff header -->
                  <div class="flex flex-1 flex-wrap items-center gap-2 min-w-0">
                    <span class="text-xs font-medium"
                      >{shortDate(entry.scanned_at)}</span
                    >
                    {#each PRIORITY_ORDER as pri (pri)}
                      {@const n = countByPriority(entry.added)[pri] ?? 0}
                      {#if n > 0}
                        <span
                          class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium text-green-600 dark:text-green-400 {PRIORITY_CLASSES[
                            pri
                          ]}"
                        >
                          +{n}
                          {pri}
                        </span>
                      {/if}
                    {/each}
                    {#each PRIORITY_ORDER as pri (pri + "-removed")}
                      {@const n = countByPriority(entry.removed)[pri] ?? 0}
                      {#if n > 0}
                        <span
                          class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium text-red-600 dark:text-red-400 {PRIORITY_CLASSES[
                            pri
                          ]}"
                        >
                          -{n}
                          {pri}
                        </span>
                      {/if}
                    {/each}
                    {#if entry.added.length === 0 && entry.removed.length === 0}
                      <span class="text-xs text-muted-foreground/60"
                        >No changes</span
                      >
                    {/if}
                    {#if entry.image_changed}
                      <span
                        class="text-xs italic text-muted-foreground/60 ml-auto"
                        >new image</span
                      >
                    {/if}
                  </div>
                {/if}
              </button>

              <!-- Expanded body -->
              {#if isExpanded}
                <div class="border-t px-3 pb-3 pt-2 space-y-3">
                  {#if entry.is_baseline}
                    <p class="text-xs text-muted-foreground">
                      Baseline scan — {entry.total} total vulnerabilities at first
                      scan.
                    </p>
                  {:else if entry.added.length === 0 && entry.removed.length === 0}
                    <p class="text-xs text-muted-foreground">
                      No vulnerability changes from previous scan.
                    </p>
                  {:else}
                    {#if entry.added.length > 0}
                      {@const groupedAdded = groupByVulnId(entry.added).slice(
                        0,
                        50
                      )}
                      {@const hiddenAddedCount =
                        groupByVulnId(entry.added).length - groupedAdded.length}
                      <div>
                        <p
                          class="mb-1 text-xs font-semibold text-green-700 dark:text-green-400"
                        >
                          Added ({groupByVulnId(entry.added).length})
                        </p>
                        <div class="space-y-0.5">
                          {#each groupedAdded as v (v.vuln_id)}
                            <div class="flex items-center gap-2 text-xs">
                              <span
                                class="inline-flex shrink-0 items-center gap-1 rounded-full border px-1.5 py-0.5 font-medium {PRIORITY_CLASSES[
                                  priorityFromRiskScore(v.risk_score)
                                ]}"
                              >
                                <span class="text-[10px] leading-none"
                                  >{priorityFromRiskScore(v.risk_score)}</span
                                >
                                {#if v.risk_score != null}
                                  <span
                                    class="font-mono text-[9px] leading-none opacity-70"
                                    >{v.risk_score.toFixed(1)}</span
                                  >
                                {/if}
                              </span>
                              <a
                                href={v.data_source ??
                                  `https://nvd.nist.gov/vuln/detail/${v.vuln_id}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                class="inline-flex items-center gap-1 font-mono font-medium text-blue-600 hover:underline dark:text-blue-400"
                              >
                                {v.vuln_id}
                                <ExternalLink class="h-3 w-3 shrink-0" />
                              </a>
                              {#if v.is_kev}
                                <Tooltip.Provider>
                                  <Tooltip.Root>
                                    <Tooltip.Trigger class="cursor-default">
                                      <CircleCheck
                                        class="h-3.5 w-3.5 shrink-0 text-red-600 dark:text-red-400"
                                      />
                                    </Tooltip.Trigger>
                                    <Tooltip.Content>
                                      Known Exploited Vulnerability
                                    </Tooltip.Content>
                                  </Tooltip.Root>
                                </Tooltip.Provider>
                              {/if}
                              <span class="text-muted-foreground"
                                >{v.packages[0].package_name}</span
                              >
                              <span class="text-muted-foreground/60"
                                >{v.packages[0].installed_version}</span
                              >
                              {#if v.packages.length > 1}
                                <Popover.Root>
                                  <Popover.Trigger>
                                    <span
                                      class="inline-flex cursor-pointer items-center rounded border border-indigo-200 bg-indigo-50 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 hover:bg-indigo-100 dark:border-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300"
                                    >
                                      +{v.packages.length - 1} more
                                    </span>
                                  </Popover.Trigger>
                                  <Popover.Content
                                    class="w-72 p-0"
                                    align="start"
                                  >
                                    <div
                                      class="px-3 py-2 border-b border-border"
                                    >
                                      <p class="text-xs font-semibold">
                                        All Affected Packages ({v.packages
                                          .length})
                                      </p>
                                    </div>
                                    <div
                                      class="max-h-40 overflow-y-auto divide-y divide-border"
                                    >
                                      {#each v.packages as pkg, i (i)}
                                        <div
                                          class="px-3 py-2 text-xs font-mono"
                                        >
                                          <span class="font-medium"
                                            >{pkg.package_name}</span
                                          >
                                          <span
                                            class="text-muted-foreground ml-2"
                                            >{pkg.installed_version}</span
                                          >
                                        </div>
                                      {/each}
                                    </div>
                                  </Popover.Content>
                                </Popover.Root>
                              {/if}
                            </div>
                          {/each}
                          {#if hiddenAddedCount > 0}
                            <p
                              class="text-xs text-muted-foreground/50 mt-1 pl-1"
                            >
                              ...and {hiddenAddedCount} more not shown
                            </p>
                          {/if}
                        </div>
                      </div>
                    {/if}
                    {#if entry.removed.length > 0}
                      {@const groupedRemoved = groupByVulnId(
                        entry.removed
                      ).slice(0, 50)}
                      {@const hiddenRemovedCount =
                        groupByVulnId(entry.removed).length -
                        groupedRemoved.length}
                      <div>
                        <p
                          class="mb-1 text-xs font-semibold text-red-700 dark:text-red-400"
                        >
                          Removed ({groupByVulnId(entry.removed).length})
                        </p>
                        <div class="space-y-0.5">
                          {#each groupedRemoved as v (v.vuln_id)}
                            <div
                              class="flex items-center gap-2 text-xs text-muted-foreground"
                            >
                              <span
                                class="inline-flex shrink-0 items-center gap-1 rounded-full border px-1.5 py-0.5 font-medium opacity-60 {PRIORITY_CLASSES[
                                  priorityFromRiskScore(v.risk_score)
                                ]}"
                              >
                                <span class="text-[10px] leading-none"
                                  >{priorityFromRiskScore(v.risk_score)}</span
                                >
                                {#if v.risk_score != null}
                                  <span
                                    class="font-mono text-[9px] leading-none opacity-70"
                                    >{v.risk_score.toFixed(1)}</span
                                  >
                                {/if}
                              </span>
                              <a
                                href={v.data_source ??
                                  `https://nvd.nist.gov/vuln/detail/${v.vuln_id}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                class="inline-flex items-center gap-1 font-mono line-through text-blue-600/60 hover:underline dark:text-blue-400/60"
                              >
                                {v.vuln_id}
                                <ExternalLink class="h-3 w-3 shrink-0" />
                              </a>
                              {#if v.is_kev}
                                <Tooltip.Provider>
                                  <Tooltip.Root>
                                    <Tooltip.Trigger class="cursor-default">
                                      <CircleCheck
                                        class="h-3.5 w-3.5 shrink-0 text-red-600 dark:text-red-400"
                                      />
                                    </Tooltip.Trigger>
                                    <Tooltip.Content>
                                      Known Exploited Vulnerability
                                    </Tooltip.Content>
                                  </Tooltip.Root>
                                </Tooltip.Provider>
                              {/if}
                              <span>{v.packages[0].package_name}</span>
                              <span class="text-muted-foreground/60"
                                >{v.packages[0].installed_version}</span
                              >
                              {#if v.packages.length > 1}
                                <Popover.Root>
                                  <Popover.Trigger>
                                    <span
                                      class="inline-flex cursor-pointer items-center rounded border border-indigo-200 bg-indigo-50 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 hover:bg-indigo-100 dark:border-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300"
                                    >
                                      +{v.packages.length - 1} more
                                    </span>
                                  </Popover.Trigger>
                                  <Popover.Content
                                    class="w-72 p-0"
                                    align="start"
                                  >
                                    <div
                                      class="px-3 py-2 border-b border-border"
                                    >
                                      <p class="text-xs font-semibold">
                                        All Affected Packages ({v.packages
                                          .length})
                                      </p>
                                    </div>
                                    <div
                                      class="max-h-40 overflow-y-auto divide-y divide-border"
                                    >
                                      {#each v.packages as pkg, i (i)}
                                        <div
                                          class="px-3 py-2 text-xs font-mono"
                                        >
                                          <span class="font-medium"
                                            >{pkg.package_name}</span
                                          >
                                          <span
                                            class="text-muted-foreground ml-2"
                                            >{pkg.installed_version}</span
                                          >
                                        </div>
                                      {/each}
                                    </div>
                                  </Popover.Content>
                                </Popover.Root>
                              {/if}
                            </div>
                          {/each}
                          {#if hiddenRemovedCount > 0}
                            <p
                              class="text-xs text-muted-foreground/50 mt-1 pl-1"
                            >
                              ...and {hiddenRemovedCount} more not shown
                            </p>
                          {/if}
                        </div>
                      </div>
                    {/if}
                  {/if}
                </div>
              {/if}
            </div>
          {/each}

          {#if history.has_more}
            <div class="flex justify-center pt-1">
              <button
                onclick={() => loadHistory(history!.entries.length)}
                disabled={loadingMore}
                class="text-xs text-muted-foreground hover:text-foreground underline disabled:opacity-50"
              >
                {loadingMore ? "Loading…" : "Show more"}
              </button>
            </div>
          {/if}

          <p class="text-center text-xs text-muted-foreground/50">
            {history.entries.length} of {history.total_scans} scans
          </p>
        {/if}
      {/if}
    </div>
  </Dialog.Content>
</Dialog.Root>
