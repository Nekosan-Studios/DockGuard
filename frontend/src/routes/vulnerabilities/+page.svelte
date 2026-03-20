<script lang="ts">
  import type { PageData } from "./$types";
  import * as Card from "$lib/components/ui/card/index.js";
  import * as Table from "$lib/components/ui/table/index.js";
  import * as Select from "$lib/components/ui/select/index.js";
  import { Label } from "$lib/components/ui/label/index.js";
  import Shield from "@lucide/svelte/icons/shield";
  import ShieldAlert from "@lucide/svelte/icons/shield-alert";
  import Loader2 from "@lucide/svelte/icons/loader-2";
  import SortButton from "../containers/sort-button.svelte";
  import * as Tooltip from "$lib/components/ui/tooltip/index.js";
  import { Checkbox } from "$lib/components/ui/checkbox/index.js";
  import { goto, replaceState, invalidateAll } from "$app/navigation";
  import VulnRow from "$lib/components/vuln/VulnRow.svelte";
  import type { Vulnerability } from "$lib/components/vuln/VulnRow.svelte";
  import { page } from "$app/stores";
  import { on } from "svelte/events";
  import { onDestroy, tick } from "svelte";

  let { data }: { data: PageData } = $props();

  const firstSeenInImageTooltip =
    "Scan where this vulnerability instance was first seen in this image. Not container specific.";

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

  // ── Infinite scroll state ─────────────────────────────────────────────────
  let rows = $state<Vulnerability[]>([]);
  let totalCount = $state(0);
  let totalInstances = $state(0);
  let hasMore = $state(false);
  let currentOffset = $state(0);
  let loadingMore = $state(false);

  // Reset when server data changes (report or sort navigates)
  $effect(() => {
    rows = data.vulnerabilities || [];
    totalCount = data.total_count ?? 0;
    totalInstances = data.total_instances ?? 0;
    hasMore = data.has_more ?? false;
    currentOffset = data.vulnerabilities?.length ?? 0;
  });

  let hasAnyVex = $derived(data.has_any_vex ?? false);

  const MAX_ROWS = 400;

  async function loadNextPage() {
    if (loadingMore || !hasMore || currentOffset >= MAX_ROWS) return;
    loadingMore = true;
    try {
      const params = new URLSearchParams({
        report: reportValue,
        hide_vex: String(hideVexValue),
        sort_by: sortByValue,
        sort_dir: sortDirValue,
        limit: "100", // PAGE_SIZE
        offset: String(currentOffset),
      });
      const fetchStart = performance.now();
      const res = await fetch(`/api/vulnerabilities-paged?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const payload = await res.json();
      const newRows: Vulnerability[] = payload.vulnerabilities ?? [];
      const fetchMs = performance.now() - fetchStart;
      console.info(
        `[VulnLoad page] infinite-scroll fetch: ${fetchMs.toFixed(1)}ms offset=${currentOffset} returned=${newRows.length}`
      );
      const renderStart = performance.now();
      rows = [...rows, ...newRows];
      currentOffset += newRows.length;
      await tick();
      console.info(
        `[VulnLoad page] DOM render: ${(performance.now() - renderStart).toFixed(1)}ms total_rows=${rows.length}`
      );
      hasMore = (payload.has_more ?? false) && currentOffset < MAX_ROWS;
      totalCount = payload.total_count ?? totalCount;
      totalInstances = payload.total_instances ?? totalInstances;
    } catch (err) {
      console.error("[DG] Failed to load next vulnerability page", err);
    } finally {
      loadingMore = false;
    }
  }

  // ── IntersectionObserver sentinel ─────────────────────────────────────────
  let sentinel: HTMLElement | null = $state(null);
  let observer: IntersectionObserver | null = null;

  $effect(() => {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    if (sentinel && hasMore) {
      observer = new IntersectionObserver(
        (entries) => {
          if (entries[0].isIntersecting) loadNextPage();
        },
        { rootMargin: "200px" }
      );
      observer.observe(sentinel);
    }
    return () => {
      observer?.disconnect();
      observer = null;
    };
  });

  onDestroy(() => observer?.disconnect());

  // 30s background refresh — skip if user has scrolled past page 1 to avoid snap-back
  $effect(() => {
    const refresh = () => {
      if (!document.hidden && currentOffset === 0) invalidateAll();
    };
    const interval = setInterval(refresh, 30_000);
    const cleanup = on(document, "visibilitychange", refresh);
    return () => {
      clearInterval(interval);
      cleanup();
    };
  });

  // ── Reports & sort URL params ─────────────────────────────────────────────
  const reports = [
    { value: "all", label: "All Vulnerabilities" },
    { value: "urgent", label: "Urgent Priority" },
    { value: "kev", label: "Actively Exploited (KEV)" },
    { value: "new", label: "Newly Found" },
    { value: "vex_annotated", label: "VEX Annotated" },
  ];

  let reportValue = $derived($page.url.searchParams.get("report") || "urgent");
  let sortByValue = $derived(
    $page.url.searchParams.get("sort_by") ||
      (reportValue === "new" ? "first_seen_at" : "severity")
  );
  let sortDirValue = $derived(
    (($page.url.searchParams.get("sort_dir") as "asc" | "desc") || null) ??
      (reportValue === "new" ? "desc" : "asc")
  );
  let hideVexValue = $derived(
    $page.url.searchParams.get("hide_vex") === "true"
  );
  let reportLabel = $derived(
    reportValue === "new"
      ? "Newly Found (Since Previous Scan)"
      : reports.find((r) => r.value === reportValue)?.label || "Urgent Priority"
  );

  function handleReportChange(v: string) {
    const u = new URL($page.url);
    u.searchParams.set("report", v);
    if (v === "new") {
      u.searchParams.set("sort_by", "first_seen_at");
      u.searchParams.set("sort_dir", "desc");
    } else {
      u.searchParams.delete("sort_by");
      u.searchParams.delete("sort_dir");
    }
    goto(u.toString());
  }

  type VulnSortCol =
    | "vuln_id"
    | "severity"
    | "package_name"
    | "containers"
    | "vex_status"
    | "cvss_base_score"
    | "epss_score"
    | "is_kev"
    | "first_seen_at";

  function toggleSort(col: VulnSortCol) {
    const u = new URL($page.url);
    if (sortByValue === col) {
      if (sortDirValue === "asc") {
        u.searchParams.set("sort_by", col);
        u.searchParams.set("sort_dir", "desc");
      } else {
        u.searchParams.delete("sort_by");
        u.searchParams.delete("sort_dir");
      }
    } else {
      u.searchParams.set("sort_by", col);
      u.searchParams.set("sort_dir", "asc");
    }
    goto(u.toString());
  }

  function activeSortDir(col: VulnSortCol): "asc" | "desc" | false {
    return sortByValue === col ? sortDirValue : false;
  }

  // ── Utility functions ─────────────────────────────────────────────────────
</script>

<div class="flex flex-col gap-6">
  <div class="flex items-center justify-between">
    <div>
      <h1 class="text-2xl font-bold tracking-tight">Vulnerabilities</h1>
      <p class="text-muted-foreground">
        Detailed view of vulnerabilities across running containers.
      </p>
    </div>
  </div>

  {#if data.eol_images && data.eol_images.length > 0}
    <div
      class="rounded-md border border-orange-200 bg-orange-50 p-4 dark:border-orange-900/50 dark:bg-orange-900/10 text-orange-800 dark:text-orange-300 flex items-start gap-4"
    >
      <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0" />
      <div class="flex flex-col gap-1 text-sm">
        <span class="font-medium">End-of-Life Systems Detected</span>
        <span class="opacity-90">
          One or more running containers are using an end-of-life operating
          system: {data.eol_images
            .map((e) => e.container_name + (e.distro ? ` (${e.distro})` : ""))
            .join(", ")}. Vulnerability data for these systems may be
          incomplete, outdated, or inaccurate.
        </span>
      </div>
    </div>
  {/if}

  <Card.Root>
    <Card.Header
      class="flex flex-col gap-3 pb-3 sm:flex-row sm:items-center sm:justify-between"
    >
      <div class="space-y-1.5 flex flex-row items-start lg:items-center gap-4">
        <div>
          <div class="flex items-center gap-2">
            <ShieldAlert class="h-5 w-5 text-muted-foreground" />
            <Card.Title>{reportLabel}</Card.Title>
          </div>
          <Card.Description class="mt-1.5">
            {#if data.apiError}
              Unable to fetch vulnerabilities. Engine might be offline.
            {:else if rows.length === 0}
              No vulnerabilities found for this filter.
            {:else}
              Showing {rows.length.toLocaleString()} of {totalCount.toLocaleString()}
              unique vulnerabilities ({totalInstances.toLocaleString()}
              total instances) across running containers.
            {/if}
          </Card.Description>
        </div>

        {#if hasAnyVex}
          <div class="border-l border-border/50 pl-4 ml-2 mt-2 lg:mt-0">
            <label
              class="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer select-none whitespace-nowrap"
            >
              <Checkbox
                checked={hideVexValue}
                onCheckedChange={(v) => {
                  const u = new URL($page.url);
                  if (v === true) {
                    u.searchParams.set("hide_vex", "true");
                  } else {
                    u.searchParams.delete("hide_vex");
                  }
                  goto(u.toString());
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

      <div class="flex items-center space-x-2">
        <Label id="report-type" class="text-sm font-medium mr-1">Report:</Label>
        <Select.Root
          type="single"
          value={reportValue}
          onValueChange={handleReportChange}
        >
          <Select.Trigger class="w-full sm:w-[260px]">
            {reportLabel}
          </Select.Trigger>
          <Select.Content>
            <Select.Group>
              {#each reports as report (report.value)}
                <Select.Item value={report.value} label={report.label}>
                  {report.label}
                </Select.Item>
              {/each}
            </Select.Group>
          </Select.Content>
        </Select.Root>
      </div>
    </Card.Header>
    <Card.Content class="p-0 sm:p-6 sm:pt-0">
      {#if data.apiError}
        <div
          class="rounded-md border border-red-200 bg-red-50 p-4 dark:border-red-900/50 dark:bg-red-900/10 text-red-800 dark:text-red-300 flex items-start gap-4 mb-4"
        >
          <ShieldAlert class="mt-0.5 h-5 w-5 shrink-0" />
          <div class="flex flex-col gap-1 text-sm">
            <span class="font-medium">Unexpected Error</span>
            <span class="opacity-90">
              An unexpected error occurred while loading vulnerability data.
              Please try again shortly.
            </span>
          </div>
        </div>
      {:else if rows.length === 0 && !loadingMore}
        <div
          class="flex flex-col items-center justify-center gap-2 py-8 text-center rounded-md border border-dashed border-muted-foreground/30 mx-6 mb-6"
        >
          <Shield class="text-muted-foreground h-10 w-10" />
          <p class="text-muted-foreground text-sm">
            No vulnerabilities found for this report.
          </p>
        </div>
      {:else}
        <div class="rounded-md border">
          <Table.Root class="w-full min-w-[1370px] table-fixed text-xs">
            <colgroup>
              <col class="w-[214px]" />
              <col class="w-[132px]" />
              <col class="w-[206px]" />
              <col class="w-[88px]" />
              <col class="w-[80px]" />
              <col class="w-[80px]" />
              <col class="w-[64px]" />
              {#if hasAnyVex}<col class="w-[96px]" />{/if}
              <col class="w-[152px]" />
              <col class="w-auto" />
            </colgroup>
            <Table.Header>
              <Table.Row class="bg-muted/50">
                <Table.Head class="pl-4">
                  <SortButton
                    label="CVE ID"
                    size="sm"
                    sortDirection={activeSortDir("vuln_id")}
                    onclick={() => toggleSort("vuln_id")}
                  />
                </Table.Head>
                <Table.Head>
                  <SortButton
                    label="Containers"
                    size="sm"
                    sortDirection={activeSortDir("containers")}
                    onclick={() => toggleSort("containers")}
                  />
                </Table.Head>
                <Table.Head>
                  <SortButton
                    label="Package"
                    size="sm"
                    sortDirection={activeSortDir("package_name")}
                    onclick={() => toggleSort("package_name")}
                  />
                </Table.Head>

                <Table.Head class="text-center">
                  <Tooltip.Root>
                    <Tooltip.Trigger>
                      {#snippet child({ props })}
                        <SortButton
                          label="Priority"
                          size="sm"
                          sortDirection={activeSortDir("severity")}
                          {...props}
                          onclick={() => toggleSort("severity")}
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
                          sortDirection={activeSortDir("cvss_base_score")}
                          {...props}
                          onclick={() => toggleSort("cvss_base_score")}
                        />
                      {/snippet}
                    </Tooltip.Trigger>
                    <Tooltip.Content
                      >Common Vulnerability Scoring System.</Tooltip.Content
                    >
                  </Tooltip.Root>
                </Table.Head>
                <Table.Head class="text-center">
                  <Tooltip.Root>
                    <Tooltip.Trigger>
                      {#snippet child({ props })}
                        <SortButton
                          label="EPSS"
                          size="sm"
                          sortDirection={activeSortDir("epss_score")}
                          {...props}
                          onclick={() => toggleSort("epss_score")}
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
                          sortDirection={activeSortDir("is_kev")}
                          {...props}
                          onclick={() => toggleSort("is_kev")}
                        />
                      {/snippet}
                    </Tooltip.Trigger>
                    <Tooltip.Content
                      >Known Exploited Vulnerability catalog.</Tooltip.Content
                    >
                  </Tooltip.Root>
                </Table.Head>
                {#if hasAnyVex}
                  <Table.Head class="text-center">
                    <Tooltip.Root>
                      <Tooltip.Trigger>
                        {#snippet child({ props })}
                          <SortButton
                            label="VEX"
                            size="sm"
                            sortDirection={activeSortDir("vex_status")}
                            {...props}
                            onclick={() => toggleSort("vex_status")}
                          />
                        {/snippet}
                      </Tooltip.Trigger>
                      <Tooltip.Content
                        >Vulnerability Exploitability eXchange — supplier
                        assessment of whether this vulnerability affects the
                        image.</Tooltip.Content
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
                          sortDirection={activeSortDir("first_seen_at")}
                          {...props}
                          onclick={() => toggleSort("first_seen_at")}
                        />
                      {/snippet}
                    </Tooltip.Trigger>
                    <Tooltip.Content>{firstSeenInImageTooltip}</Tooltip.Content>
                  </Tooltip.Root>
                </Table.Head>
                <Table.Head class="pr-6">Description</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {#each rows as vuln (vuln.vuln_id)}
                <VulnRow
                  {vuln}
                  showContainers={true}
                  {hasAnyVex}
                  {activeCve}
                  onModalChange={handleModalChange}
                />
              {/each}
            </Table.Body>
          </Table.Root>

          <!-- Infinite scroll sentinel / loading indicator -->
          {#if hasMore}
            <div
              bind:this={sentinel}
              class="flex items-center justify-center gap-2 border-t px-6 py-4 text-sm text-muted-foreground bg-muted/20"
            >
              {#if loadingMore}
                <Loader2 class="h-4 w-4 animate-spin" />
                <span>Loading more…</span>
              {:else}
                <span class="text-xs text-muted-foreground/60"
                  >Scroll for more</span
                >
              {/if}
            </div>
          {:else if totalCount > MAX_ROWS && currentOffset >= MAX_ROWS}
            <div
              class="border-t px-6 py-3 text-xs text-muted-foreground/80 bg-muted/20 text-center"
            >
              Showing {MAX_ROWS} of {totalCount.toLocaleString()} vulnerabilities
              — use the report filters above or sort by CVSS / EPSS to prioritize.
            </div>
          {/if}
        </div>
      {/if}
    </Card.Content>
  </Card.Root>
</div>
