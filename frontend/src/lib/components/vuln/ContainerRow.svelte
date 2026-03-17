<script lang="ts">
  import * as Table from "$lib/components/ui/table/index.js";
  import { Badge } from "$lib/components/ui/badge/index.js";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import ChevronRight from "@lucide/svelte/icons/chevron-right";
  import AlertCircle from "@lucide/svelte/icons/alert-circle";
  import Loader2 from "@lucide/svelte/icons/loader-2";
  import Info from "@lucide/svelte/icons/info";
  import SortButton from "../../../routes/containers/sort-button.svelte";
  import { slide } from "svelte/transition";
  import { formatDistanceToNow } from "date-fns";
  import { SvelteSet, SvelteURLSearchParams } from "svelte/reactivity";
  import { onDestroy, untrack } from "svelte";
  import {
    PRIORITY_CLASSES,
    PRIORITY_ORDER,
    priorityFromRiskScore,
    toUtcDate,
  } from "./utils.js";
  import VulnRow from "./VulnRow.svelte";
  import type { Vulnerability } from "./VulnRow.svelte";
  import History from "@lucide/svelte/icons/history";
  import ArrowUpCircle from "@lucide/svelte/icons/arrow-up-circle";
  import ContainerHistoryDialog from "./ContainerHistoryDialog.svelte";
  import UpdateAvailableDialog from "./UpdateAvailableDialog.svelte";

  // Priority order is imported from utils.ts

  // Constants matches parent logic
  const SUBVIEW_MAX_ROWS = 400;
  const SUBVIEW_PAGE_SIZE = 200;
  const AUTO_FILTER_THRESHOLD = 15;
  const FIRST_SEEN_IN_IMAGE_TOOLTIP =
    "Scan where this vulnerability instance was first seen in this image. Not container specific.";

  export interface ContainerRecord {
    scan_id?: number | null;
    image_name: string;
    container_name: string;
    has_scan: boolean;
    is_distro_eol?: boolean;
    distro_display?: string;
    has_vex?: boolean;
    vex_status?: string | null;
    vex_error?: string | null;
    vulns_by_severity: Record<string, number>;
    vulns_by_priority: Record<string, number>;
    vulns_by_severity_no_vex: Record<string, number>;
    vulns_by_priority_no_vex: Record<string, number>;
    total?: number;
    scanned_at?: string | null;
    has_update?: boolean;
    update_scan_id?: number | null;
    update_status?: string | null;
  }

  let {
    container,
    hideVexResolved = false,
    activeCve = null,
    onModalChange,
  }: {
    container: ContainerRecord;
    hideVexResolved?: boolean;
    activeCve?: string | null;
    onModalChange?: (vulnId: string, open: boolean) => void;
  } = $props();

  // ── Local State (Replaces Parent `SvelteMap`s) ──────────────────────────
  let expanded = $state(false);
  let historyOpen = $state(false);
  let updateOpen = $state(false);

  let vexStatus = $state(container.vex_status);
  let hasVex = $state(container.has_vex);
  let vexError = $state(container.vex_error);
  let vexChecking = $state(false);

  let diffSummary = $state<{ added: number; removed: number } | null>(null);

  $effect(() => {
    const scanId = container.update_scan_id;
    if (!scanId) return;
    fetch(`/api/update-scans/${scanId}/diff`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data)
          diffSummary = {
            added: data.added_count,
            removed: data.removed_count,
          };
      })
      .catch(() => {});
  });

  let updatePillSuffix = $derived.by(() => {
    if (!diffSummary || (diffSummary.added === 0 && diffSummary.removed === 0))
      return "";
    const parts = [
      diffSummary.added > 0 ? `${diffSummary.added} added` : "",
      diffSummary.removed > 0 ? `${diffSummary.removed} removed` : "",
    ]
      .filter(Boolean)
      .join(", ");
    const label =
      diffSummary.added + diffSummary.removed === 1 ? "vuln" : "vulns";
    return ` (${parts} ${label})`;
  });

  async function recheckVex(e: MouseEvent) {
    e.stopPropagation();
    if (!container.scan_id || vexChecking) return;
    vexChecking = true;
    try {
      const res = await fetch(`/api/scans/${container.scan_id}/recheck-vex`, {
        method: "POST",
      });
      if (res.ok) {
        const data = await res.json();
        vexStatus = data.vex_status;
        hasVex = data.has_vex;
        vexError = data.vex_error;
      }
    } finally {
      vexChecking = false;
    }
  }

  let vulns = $state<Vulnerability[]>([]);
  let totalCount = $state(0);
  let currentOffset = $state(0);
  let hasMore = $state(false);
  let loadingMore = $state(false);

  type VulnSortCol =
    | "vuln_id"
    | "severity"
    | "package_name"
    | "cvss_base_score"
    | "epss_score"
    | "is_kev"
    | "first_seen_at";
  let sortCol = $state<VulnSortCol | null>("severity");
  let sortDir = $state<"asc" | "desc">("asc");

  let activeFilters = new SvelteSet<string>();
  // The specific filter fetched if not fetching 'all'
  let partiallyLoadedPriority = $state<string | undefined>(undefined);

  // ── Sentinel & Observer logic ─────────────────────────────────────────────
  let sentinel: HTMLElement | null = $state(null);
  let observer: IntersectionObserver | null = null;

  $effect(() => {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    if (sentinel && hasMore && expanded) {
      observer = new IntersectionObserver(
        (entries) => {
          if (entries[0].isIntersecting && !loadingMore) {
            fetchVulns(
              currentOffset,
              sortCol,
              sortDir,
              partiallyLoadedPriority
            );
          }
        },
        { rootMargin: "100px" }
      );
      observer.observe(sentinel);
    }
    return () => {
      observer?.disconnect();
      observer = null;
    };
  });

  $effect(() => {
    const currentHideVex = hideVexResolved; // register reactivity
    untrack(() => {
      if (typeof currentHideVex !== "undefined" && expanded) {
        fetchVulns(0, sortCol, sortDir, partiallyLoadedPriority);
      }
    });
  });

  onDestroy(() => observer?.disconnect());

  // ── Data Fetching ─────────────────────────────────────────────────────────
  async function fetchVulns(
    offset = 0,
    sCol: VulnSortCol | null = null,
    sDir: "asc" | "desc" = "asc",
    priorityFilter?: string
  ) {
    if (!container.has_scan) return;
    loadingMore = true;

    try {
      const params = new SvelteURLSearchParams({
        image_ref: container.image_name,
        limit: String(SUBVIEW_PAGE_SIZE),
        offset: String(offset),
        sort_by: sCol ?? "severity",
        sort_dir: sDir,
      });
      if (priorityFilter) params.set("priority", priorityFilter);
      if (hideVexResolved) params.set("hide_vex", "true");

      const res = await fetch(`/api/vulnerabilities?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const payload = await res.json();

      const newRows: Vulnerability[] = payload.vulnerabilities ?? [];
      const existing = offset === 0 ? [] : [...vulns];
      vulns = [...existing, ...newRows];

      currentOffset = vulns.length;
      const atSoftCap = currentOffset >= SUBVIEW_MAX_ROWS;

      totalCount = payload.total_count ?? newRows.length;
      hasMore = (payload.has_more ?? false) && !atSoftCap;
      sortCol = sCol;
      sortDir = sDir;
      partiallyLoadedPriority = priorityFilter;
    } catch (err) {
      console.error("Failed to fetch vulns for", container.image_name, err);
      if (offset === 0) vulns = [];
      hasMore = false;
    } finally {
      loadingMore = false;
    }
  }

  // ── Actions ───────────────────────────────────────────────────────────────
  function toggleExpanded() {
    if (!container.has_scan) return;

    expanded = !expanded;

    // If expanding for the first time and we have no vulns loaded
    if (expanded && vulns.length === 0) {
      const total = container.total ?? 0;
      const map = hideVexResolved
        ? container.vulns_by_priority_no_vex
        : container.vulns_by_priority;
      const topPriority =
        total >= AUTO_FILTER_THRESHOLD
          ? PRIORITY_ORDER.find((p) => (map ? (map[p] ?? 0) : 0) > 0)
          : undefined;

      if (topPriority) {
        activeFilters.add(topPriority);
        fetchVulns(0, sortCol, sortDir, topPriority);
      } else {
        fetchVulns(0, sortCol, sortDir, undefined);
      }
    }
  }

  function toggleFilter(priority: string, e: MouseEvent) {
    e.stopPropagation();
    if (activeFilters.has(priority)) {
      activeFilters.delete(priority);
    } else {
      activeFilters.add(priority);
    }

    // Re-fetch from offset 0
    const fetchPri =
      activeFilters.size === 1 ? [...activeFilters][0] : undefined;
    fetchVulns(0, sortCol, sortDir, fetchPri);
  }

  function toggleVulnSort(col: VulnSortCol, e: MouseEvent) {
    e.stopPropagation();
    let newCol: VulnSortCol | null;
    let newDir: "asc" | "desc";
    if (sortCol !== col) {
      newCol = col;
      newDir = "asc";
    } else if (sortDir === "asc") {
      newCol = col;
      newDir = "desc";
    } else {
      newCol = null;
      newDir = "asc";
    }

    fetchVulns(0, newCol, newDir, partiallyLoadedPriority);
  }

  // ── Derived View State ────────────────────────────────────────────────────
  function activePriorities() {
    const map = hideVexResolved
      ? container.vulns_by_priority_no_vex
      : container.vulns_by_priority;
    return map ? PRIORITY_ORDER.filter((p) => (map[p] ?? 0) > 0) : [];
  }

  let visibleVulns = $derived.by(() => {
    let v = [...vulns];
    if (activeFilters.size > 0) {
      v = v.filter((item) =>
        activeFilters.has(priorityFromRiskScore(item.risk_score))
      );
    }
    return v;
  });

  let hasVexData = $derived(vulns.some((v) => v.vex_status));

  function timeAgo(iso: string | null | undefined): string {
    if (!iso) return "—";
    return formatDistanceToNow(toUtcDate(iso), { addSuffix: true });
  }
</script>

<Table.Row
  class={container.has_scan ? "cursor-pointer hover:bg-muted/50" : ""}
  onclick={toggleExpanded}
>
  <Table.Cell>
    <div class="flex items-center gap-2">
      <ChevronRight
        class="text-muted-foreground h-4 w-4 shrink-0 transition-transform duration-200 {expanded
          ? 'rotate-90'
          : ''} {!container.has_scan ? 'opacity-0' : ''}"
      />
      <div>
        <div class="font-medium flex items-center gap-2">
          {container.container_name}
          {#if container.has_scan}
            <button
              onclick={(e) => {
                e.stopPropagation();
                historyOpen = true;
              }}
              class="text-muted-foreground hover:text-foreground ml-1 rounded p-0.5 transition-colors"
              title="View scan history"
            >
              <History class="h-3.5 w-3.5" />
            </button>
          {/if}
          {#if container.is_distro_eol}
            <Badge
              variant="outline"
              class="bg-orange-100/50 text-orange-700 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800"
            >
              EOL OS
            </Badge>
          {/if}
          {#if hasVex}
            <Tooltip.Root>
              <Tooltip.Trigger class="cursor-default">
                <Badge
                  variant="outline"
                  class="bg-blue-100/50 text-blue-700 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800"
                >
                  VEX
                </Badge>
              </Tooltip.Trigger>
              <Tooltip.Content>
                This image includes VEX attestations from the supplier.
              </Tooltip.Content>
            </Tooltip.Root>
          {:else if vexStatus === "error"}
            <Tooltip.Root>
              <Tooltip.Trigger class="cursor-default">
                <button
                  onclick={recheckVex}
                  disabled={vexChecking}
                  class="inline-flex items-center gap-1 rounded-full border border-amber-200 bg-amber-100/50 px-2 py-0.5 text-xs font-medium text-amber-700 transition-opacity hover:opacity-80 disabled:cursor-not-allowed dark:border-amber-800 dark:bg-amber-900/40 dark:text-amber-300"
                >
                  {#if vexChecking}
                    <Loader2 class="h-3 w-3 animate-spin" />
                  {:else}
                    <AlertCircle class="h-3 w-3" />
                  {/if}
                  VEX
                </button>
              </Tooltip.Trigger>
              <Tooltip.Content class="max-w-xs">
                {#if vexChecking}
                  Checking VEX attestations…
                {:else}
                  VEX attestation check failed.{vexError
                    ? ` Error: ${vexError}`
                    : ""} Click to retry.
                {/if}
              </Tooltip.Content>
            </Tooltip.Root>
          {/if}
          {#if container.has_update}
            <button
              onclick={(e) => {
                e.stopPropagation();
                updateOpen = true;
              }}
              class="inline-flex items-center gap-1 rounded-full border border-teal-200 bg-teal-100/50 px-2 py-0.5 text-xs font-medium text-teal-700 transition-opacity hover:opacity-80 dark:border-teal-800 dark:bg-teal-900/40 dark:text-teal-300"
            >
              <ArrowUpCircle class="h-3 w-3" />
              Update Available{updatePillSuffix}
            </button>
          {/if}
        </div>
        <div class="text-muted-foreground font-mono text-xs">
          {container.image_name}
        </div>
      </div>
    </div>
  </Table.Cell>
  <Table.Cell>
    {#if container.has_scan}
      <div class="flex flex-wrap gap-1">
        {#each activePriorities() as pri (pri)}
          {#if expanded}
            <button
              onclick={(e) => toggleFilter(pri, e)}
              class="inline-flex cursor-pointer items-center rounded-full border px-2 py-0.5 text-xs font-medium transition-all {PRIORITY_CLASSES[
                pri
              ]} {activeFilters.has(pri)
                ? 'ring-2 ring-offset-1 ring-current'
                : 'opacity-80 hover:opacity-100'}"
            >
              {hideVexResolved
                ? container.vulns_by_priority_no_vex[pri]
                : container.vulns_by_priority[pri]}
              {pri}
            </button>
          {:else}
            <span
              class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {PRIORITY_CLASSES[
                pri
              ]}"
            >
              {hideVexResolved
                ? container.vulns_by_priority_no_vex[pri]
                : container.vulns_by_priority[pri]}
              {pri}
            </span>
          {/if}
        {/each}
        {#if activePriorities().length === 0}
          <span class="text-muted-foreground text-xs">None found</span>
        {/if}
      </div>
    {:else}
      <span class="text-muted-foreground text-xs">—</span>
    {/if}
  </Table.Cell>
  <Table.Cell class="text-center text-xs">
    {#if container.has_scan}
      <span class="text-muted-foreground">{timeAgo(container.scanned_at)}</span>
    {:else}
      <span
        class="inline-flex items-center rounded-full border border-amber-200 bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 dark:border-amber-800 dark:bg-amber-900/40 dark:text-amber-300"
      >
        Not yet scanned
      </span>
    {/if}
  </Table.Cell>
</Table.Row>

<!-- Expanded detail row -->
{#if expanded}
  <Table.Row>
    <Table.Cell colspan={3} class="p-0 align-middle">
      <div
        transition:slide={{ duration: 200 }}
        class="bg-muted/20 border-muted border-l-4 overflow-hidden"
      >
        {#if loadingMore && vulns.length === 0}
          <div class="flex items-center gap-2 px-6 py-4 text-sm">
            <Loader2 class="text-muted-foreground h-4 w-4 animate-spin" />
            <span class="text-muted-foreground">Loading vulnerabilities…</span>
          </div>
        {:else}
          <svelte:boundary
            onerror={(e) =>
              console.error("[DockGuard] sub-view render error:", e)}
          >
            {#if container.is_distro_eol}
              <div
                class="mx-6 mt-4 mb-2 rounded-md border border-orange-200 bg-orange-50 p-4 dark:border-orange-900/50 dark:bg-orange-900/10 text-orange-800 dark:text-orange-300 flex gap-3 text-sm"
              >
                <span class="font-medium"
                  >End-of-Life OS{container.distro_display
                    ? ` (${container.distro_display})`
                    : ""}:</span
                >
                <span>Vulnerability data may be incomplete or outdated.</span>
              </div>
            {/if}

            {#if visibleVulns.length === 0}
              <p class="text-muted-foreground px-6 py-4 text-sm">
                {activeFilters.size > 0
                  ? "No vulnerabilities match the selected filters."
                  : "No vulnerabilities found for this image."}
              </p>
            {:else}
              <div class="overflow-x-auto">
                <Table.Root class="w-full min-w-[1200px] text-xs">
                  <colgroup>
                    <col class="w-[140px]" />
                    <col class="w-[140px]" />
                    <col class="w-[100px]" />
                    <col class="w-[100px]" />
                    <col class="w-[90px]" />
                    <col class="w-[80px]" />
                    <col class="w-[80px]" />
                    <col class="w-[80px]" />
                    {#if hasVexData}
                      <col class="w-[80px]" />
                    {/if}
                    <col class="w-[100px]" />
                    <col class="w-auto" />
                  </colgroup>
                  <Table.Header>
                    <Table.Row class="bg-muted/30">
                      <Table.Head class="pl-2">
                        <SortButton
                          label="CVE ID"
                          size="sm"
                          sortDirection={sortCol === "vuln_id"
                            ? sortDir
                            : false}
                          onclick={(e: MouseEvent) =>
                            toggleVulnSort("vuln_id", e)}
                        />
                      </Table.Head>
                      <Table.Head>
                        <SortButton
                          label="Package"
                          size="sm"
                          sortDirection={sortCol === "package_name"
                            ? sortDir
                            : false}
                          onclick={(e: MouseEvent) =>
                            toggleVulnSort("package_name", e)}
                        />
                      </Table.Head>
                      <Table.Head class="text-center">Version</Table.Head>
                      <Table.Head class="text-center">Fixed In</Table.Head>
                      <Table.Head class="text-center">
                        <Tooltip.Root>
                          <Tooltip.Trigger>
                            {#snippet child({ props })}
                              <SortButton
                                label="Priority"
                                size="sm"
                                sortDirection={sortCol === "severity"
                                  ? sortDir
                                  : false}
                                {...props}
                                onclick={(e: MouseEvent) =>
                                  toggleVulnSort("severity", e)}
                              />
                            {/snippet}
                          </Tooltip.Trigger>
                          <Tooltip.Content>
                            Priority based on severity and exploitability.
                          </Tooltip.Content>
                        </Tooltip.Root>
                      </Table.Head>
                      <Table.Head class="text-center">
                        <Tooltip.Root>
                          <Tooltip.Trigger>
                            {#snippet child({ props })}
                              <SortButton
                                label="CVSS"
                                size="sm"
                                sortDirection={sortCol === "cvss_base_score"
                                  ? sortDir
                                  : false}
                                {...props}
                                onclick={(e: MouseEvent) =>
                                  toggleVulnSort("cvss_base_score", e)}
                              />
                            {/snippet}
                          </Tooltip.Trigger>
                          <Tooltip.Content>
                            Common Vulnerability Scoring System.
                          </Tooltip.Content>
                        </Tooltip.Root>
                      </Table.Head>
                      <Table.Head class="text-center">
                        <Tooltip.Root>
                          <Tooltip.Trigger>
                            {#snippet child({ props })}
                              <SortButton
                                label="EPSS %"
                                size="sm"
                                sortDirection={sortCol === "epss_score"
                                  ? sortDir
                                  : false}
                                {...props}
                                onclick={(e: MouseEvent) =>
                                  toggleVulnSort("epss_score", e)}
                              />
                            {/snippet}
                          </Tooltip.Trigger>
                          <Tooltip.Content
                            >Exploit Prediction Scoring System.</Tooltip.Content
                          >
                        </Tooltip.Root>
                      </Table.Head>
                      <Table.Head class="text-center">
                        <Tooltip.Root>
                          <Tooltip.Trigger>
                            {#snippet child({ props })}
                              <SortButton
                                label="KEV"
                                size="sm"
                                sortDirection={sortCol === "is_kev"
                                  ? sortDir
                                  : false}
                                {...props}
                                onclick={(e: MouseEvent) =>
                                  toggleVulnSort("is_kev", e)}
                              />
                            {/snippet}
                          </Tooltip.Trigger>
                          <Tooltip.Content
                            >Known Exploited Vulnerabilities catalog.</Tooltip.Content
                          >
                        </Tooltip.Root>
                      </Table.Head>
                      {#if hasVexData}
                        <Table.Head class="text-center">
                          <Tooltip.Root>
                            <Tooltip.Trigger>
                              <span class="text-xs font-medium">VEX</span>
                            </Tooltip.Trigger>
                            <Tooltip.Content
                              >Vulnerability Exploitability eXchange</Tooltip.Content
                            >
                          </Tooltip.Root>
                        </Table.Head>
                      {/if}
                      <Table.Head class="text-center">
                        <Tooltip.Root>
                          <Tooltip.Trigger>
                            {#snippet child({ props })}
                              <SortButton
                                label="First Seen in Image"
                                size="sm"
                                sortDirection={sortCol === "first_seen_at"
                                  ? sortDir
                                  : false}
                                {...props}
                                onclick={(e: MouseEvent) =>
                                  toggleVulnSort("first_seen_at", e)}
                              />
                            {/snippet}
                          </Tooltip.Trigger>
                          <Tooltip.Content
                            >{FIRST_SEEN_IN_IMAGE_TOOLTIP}</Tooltip.Content
                          >
                        </Tooltip.Root>
                      </Table.Head>
                      <Table.Head class="pr-6">
                        <Tooltip.Root>
                          <Tooltip.Trigger
                            class="flex cursor-default items-center gap-1"
                          >
                            <span>Description</span>
                            <Info class="h-3 w-3 text-muted-foreground" />
                          </Tooltip.Trigger>
                          <Tooltip.Content
                            >Click any row to view full vulnerability details</Tooltip.Content
                          >
                        </Tooltip.Root>
                      </Table.Head>
                    </Table.Row>
                  </Table.Header>
                  <Table.Body>
                    {#each visibleVulns as vuln (vuln.vuln_id)}
                      <VulnRow
                        {vuln}
                        hasAnyVex={hasVexData}
                        {activeCve}
                        {onModalChange}
                      />
                    {/each}
                  </Table.Body>
                </Table.Root>
              </div>
            {/if}

            {#snippet failed(error, reset)}
              <div class="flex flex-col items-start gap-3 px-6 py-4">
                <p class="text-sm font-medium text-destructive">
                  Error rendering vulnerabilities: {error instanceof Error
                    ? error.message
                    : String(error)}
                </p>
                <button
                  class="text-xs underline text-muted-foreground"
                  onclick={reset}>Try again</button
                >
              </div>
            {/snippet}
          </svelte:boundary>
        {/if}

        {#if hasMore || loadingMore}
          <div
            bind:this={sentinel}
            class="flex items-center gap-2 border-t px-6 py-2 text-xs text-muted-foreground"
          >
            {#if loadingMore}
              <Loader2 class="h-3 w-3 animate-spin" />
              <span>Loading more vulnerabilities…</span>
            {:else}
              <span class="text-muted-foreground/60">Scroll for more</span>
            {/if}
          </div>
        {:else if totalCount > SUBVIEW_MAX_ROWS && !hasMore && currentOffset >= SUBVIEW_MAX_ROWS}
          <div
            class="border-t px-6 py-3 text-xs text-muted-foreground/80 bg-muted/20"
          >
            Showing {SUBVIEW_MAX_ROWS} of {totalCount.toLocaleString()}
            vulnerabilities — use the severity filters above or sort by CVSS / EPSS
            to prioritize.
          </div>
        {:else if totalCount > 0 && totalCount > SUBVIEW_PAGE_SIZE}
          <div class="border-t px-6 py-2 text-[11px] text-muted-foreground/60">
            Showing {currentOffset} of {totalCount.toLocaleString()}
            vulnerabilities
          </div>
        {/if}
      </div>
    </Table.Cell>
  </Table.Row>
{/if}

<ContainerHistoryDialog bind:open={historyOpen} {container} />
<UpdateAvailableDialog bind:open={updateOpen} {container} />
