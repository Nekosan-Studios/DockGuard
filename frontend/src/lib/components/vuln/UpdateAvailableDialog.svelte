<script lang="ts">
  import * as Dialog from "$lib/components/ui/dialog/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import * as Popover from "$lib/components/ui/popover/index.js";
  import { Skeleton } from "$lib/components/ui/skeleton/index.js";
  import CircleCheck from "@lucide/svelte/icons/circle-check";
  import ExternalLink from "@lucide/svelte/icons/external-link";
  import ChevronRight from "@lucide/svelte/icons/chevron-right";
  import Loader2 from "@lucide/svelte/icons/loader-2";
  import {
    PRIORITY_CLASSES,
    PRIORITY_ORDER,
    priorityFromRiskScore,
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

  interface DiffResponse {
    image_name: string;
    running_digest: string;
    registry_digest: string | null;
    current_scan_id: number | null;
    update_scan_id: number | null;
    added: VulnDiff[];
    removed: VulnDiff[];
    added_count: number;
    removed_count: number;
  }

  let loading = $state(false);
  let error = $state<string | null>(null);
  let diff = $state<DiffResponse | null>(null);
  let addedExpanded = $state(true);
  let removedExpanded = $state(true);

  function shortDigest(d: string | null | undefined): string {
    if (!d) return "—";
    // Strip sha256: prefix if present, then take 12 chars
    const raw = d.startsWith("sha256:") ? d.slice(7) : d;
    return raw.slice(0, 12);
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

  async function loadDiff() {
    if (!container.update_scan_id) return;
    loading = true;
    error = null;
    diff = null;
    try {
      const res = await fetch(
        `/api/update-scans/${container.update_scan_id}/diff`
      );
      if (!res.ok) {
        error = `Failed to load diff (HTTP ${res.status})`;
        return;
      }
      diff = await res.json();
    } catch (e) {
      error = e instanceof Error ? e.message : "Failed to load diff";
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    if (open && !diff && !loading) {
      loadDiff();
    }
    if (!open) {
      diff = null;
      error = null;
    }
  });
</script>

<Dialog.Root bind:open>
  <Dialog.Content class="max-w-2xl max-h-[85vh] overflow-y-auto">
    <Dialog.Header>
      <Dialog.Title>Update Available — {container.image_name}</Dialog.Title>
      <Dialog.Description class="font-mono text-xs truncate">
        {container.image_name}
      </Dialog.Description>
    </Dialog.Header>

    <div class="mt-2 space-y-3">
      {#if !container.update_scan_id}
        <div class="flex items-center gap-2 py-4">
          <Loader2 class="h-4 w-4 animate-spin text-muted-foreground" />
          <span class="text-sm text-muted-foreground">Scan in progress…</span>
        </div>
      {:else if loading}
        {#each [0, 1, 2] as i (i)}
          <Skeleton class="h-12 w-full rounded-md" />
        {/each}
      {:else if error}
        <p class="text-destructive text-sm">{error}</p>
      {:else if diff}
        <!-- Digest comparison -->
        <div
          class="rounded-md border bg-muted/20 px-3 py-2 text-xs font-mono space-y-1"
        >
          <div class="flex items-center gap-2">
            <span class="text-muted-foreground w-24 shrink-0">Running:</span>
            <span>{shortDigest(diff.running_digest)}</span>
          </div>
          <div class="flex items-center gap-2">
            <span class="text-muted-foreground w-24 shrink-0">Registry:</span>
            <span>{shortDigest(diff.registry_digest)}</span>
          </div>
        </div>

        <!-- Summary badges -->
        <div class="flex flex-wrap gap-2">
          {#if diff.added_count > 0}
            <span
              class="inline-flex items-center rounded-full border border-teal-200 bg-teal-100/50 px-2 py-0.5 text-xs font-medium text-teal-700 dark:border-teal-800 dark:bg-teal-900/40 dark:text-teal-300"
            >
              {diff.added_count} vuln{diff.added_count === 1 ? "" : "s"} added
            </span>
          {/if}
          {#if diff.removed_count > 0}
            <span
              class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium text-muted-foreground"
            >
              {diff.removed_count} vuln{diff.removed_count === 1 ? "" : "s"} removed
            </span>
          {/if}
          {#if diff.added_count === 0 && diff.removed_count === 0}
            <span class="text-muted-foreground text-sm"
              >No vulnerability changes in the new image.</span
            >
          {/if}
        </div>

        <!-- Added vulns -->
        {#if diff.added.length > 0}
          {@const groupedAdded = groupByVulnId(diff.added)}
          <div class="rounded-md border">
            <button
              class="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/40 transition-colors"
              onclick={() => (addedExpanded = !addedExpanded)}
            >
              <ChevronRight
                class="h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-150 {addedExpanded
                  ? 'rotate-90'
                  : ''}"
              />
              <span
                class="text-xs font-semibold text-green-700 dark:text-green-400"
              >
                Added ({groupedAdded.length})
              </span>
              <div class="flex flex-wrap gap-1 ml-1">
                {#each PRIORITY_ORDER as pri (pri)}
                  {@const n = countByPriority(diff.added)[pri] ?? 0}
                  {#if n > 0}
                    <span
                      class="inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium {PRIORITY_CLASSES[
                        pri
                      ]}"
                    >
                      +{n}
                      {pri}
                    </span>
                  {/if}
                {/each}
              </div>
            </button>
            {#if addedExpanded}
              <div class="border-t px-3 pb-3 pt-2 space-y-0.5">
                {#each groupedAdded.slice(0, 50) as v (v.vuln_id)}
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
                          <Tooltip.Content
                            >Known Exploited Vulnerability</Tooltip.Content
                          >
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
                        <Popover.Content class="w-72 p-0" align="start">
                          <div class="px-3 py-2 border-b border-border">
                            <p class="text-xs font-semibold">
                              All Affected Packages ({v.packages.length})
                            </p>
                          </div>
                          <div
                            class="max-h-40 overflow-y-auto divide-y divide-border"
                          >
                            {#each v.packages as pkg, i (i)}
                              <div class="px-3 py-2 text-xs font-mono">
                                <span class="font-medium"
                                  >{pkg.package_name}</span
                                >
                                <span class="text-muted-foreground ml-2"
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
                {#if groupedAdded.length > 50}
                  <p class="text-xs text-muted-foreground/50 mt-1 pl-1">
                    ...and {groupedAdded.length - 50} more not shown
                  </p>
                {/if}
              </div>
            {/if}
          </div>
        {/if}

        <!-- Removed vulns -->
        {#if diff.removed.length > 0}
          {@const groupedRemoved = groupByVulnId(diff.removed)}
          <div class="rounded-md border">
            <button
              class="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/40 transition-colors"
              onclick={() => (removedExpanded = !removedExpanded)}
            >
              <ChevronRight
                class="h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-150 {removedExpanded
                  ? 'rotate-90'
                  : ''}"
              />
              <span
                class="text-xs font-semibold text-red-700 dark:text-red-400"
              >
                Removed ({groupedRemoved.length})
              </span>
              <div class="flex flex-wrap gap-1 ml-1">
                {#each PRIORITY_ORDER as pri (pri + "-removed")}
                  {@const n = countByPriority(diff.removed)[pri] ?? 0}
                  {#if n > 0}
                    <span
                      class="inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium opacity-60 {PRIORITY_CLASSES[
                        pri
                      ]}"
                    >
                      -{n}
                      {pri}
                    </span>
                  {/if}
                {/each}
              </div>
            </button>
            {#if removedExpanded}
              <div class="border-t px-3 pb-3 pt-2 space-y-0.5">
                {#each groupedRemoved.slice(0, 50) as v (v.vuln_id)}
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
                          <Tooltip.Content
                            >Known Exploited Vulnerability</Tooltip.Content
                          >
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
                        <Popover.Content class="w-72 p-0" align="start">
                          <div class="px-3 py-2 border-b border-border">
                            <p class="text-xs font-semibold">
                              All Affected Packages ({v.packages.length})
                            </p>
                          </div>
                          <div
                            class="max-h-40 overflow-y-auto divide-y divide-border"
                          >
                            {#each v.packages as pkg, i (i)}
                              <div class="px-3 py-2 text-xs font-mono">
                                <span class="font-medium"
                                  >{pkg.package_name}</span
                                >
                                <span class="text-muted-foreground ml-2"
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
                {#if groupedRemoved.length > 50}
                  <p class="text-xs text-muted-foreground/50 mt-1 pl-1">
                    ...and {groupedRemoved.length - 50} more not shown
                  </p>
                {/if}
              </div>
            {/if}
          </div>
        {/if}
      {/if}
    </div>
  </Dialog.Content>
</Dialog.Root>
