<script lang="ts">
  import { onMount } from "svelte";
  import type { PageData } from "./$types";
  import * as Card from "$lib/components/ui/card/index.js";
  import { Badge } from "$lib/components/ui/badge/index.js";
  import * as Table from "$lib/components/ui/table/index.js";
  import * as Chart from "$lib/components/ui/chart/index.js";
  import * as Pagination from "$lib/components/ui/pagination";
  import { AreaChart } from "layerchart";
  import { curveMonotoneX } from "d3-shape";
  import Shield from "@lucide/svelte/icons/shield";
  import Container from "@lucide/svelte/icons/container";
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
  import Zap from "@lucide/svelte/icons/zap";
  import CircleCheck from "@lucide/svelte/icons/circle-check";
  import CircleX from "@lucide/svelte/icons/circle-x";
  import LoaderCircle from "@lucide/svelte/icons/loader-circle";

  import { invalidateAll } from "$app/navigation";
  import { formatDistanceToNow, format } from "date-fns";

  let { data }: { data: PageData } = $props();

  // eslint-disable-next-line svelte/prefer-writable-derived
  let summary = $state({ ...data.summary });

  // Sync detached state copy when server data changes (e.g. after invalidateAll)
  $effect(() => {
    summary = { ...data.summary };
  });

  // 30s background refresh with tab-visibility guard
  $effect(() => {
    const refresh = () => {
      if (!document.hidden) invalidateAll();
    };
    const interval = setInterval(refresh, 30_000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      clearInterval(interval);
      document.removeEventListener("visibilitychange", refresh);
    };
  });

  $effect(() => {
    const isActive =
      summary.active_tasks > 0 ||
      summary.queued_tasks > 0 ||
      summary.db_updating;
    if (!isActive) return;
    const controller = new AbortController();
    const interval = setInterval(async () => {
      try {
        const res = await fetch("/api/dashboard/summary", {
          signal: controller.signal,
        });
        if (res.ok) summary = { ...summary, ...(await res.json()) };
      } catch (e) {
        if (e instanceof DOMException && e.name === "AbortError") return;
      }
    }, 3000);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  });

  let activities = $state<
    {
      scan_id: number;
      scanned_at: string;
      image_name: string;
      affected_containers_at_scan: string[];
      affected_container_count_at_scan: number;
      vulns_by_priority: Record<string, number>;
    }[]
  >([]);
  let activityTotal = $state(0);
  let activityPage = $state(1);
  let activityLoading = $state(true);

  async function fetchActivity(page: number) {
    activityLoading = true;
    try {
      const res = await fetch(`/api/activity/recent?page=${page}&page_size=10`);
      if (res.ok) {
        const json = await res.json();
        activities = json.activities ?? [];
        activityTotal = json.total ?? 0;
      }
    } catch (err) {
      console.error("Error fetching activity:", err);
    } finally {
      activityLoading = false;
    }
  }

  onMount(() => {
    fetchActivity(activityPage);
  });

  let _activityPageInit = false;
  $effect(() => {
    const p = activityPage;
    if (!_activityPageInit) {
      _activityPageInit = true;
      return;
    }
    fetchActivity(p);
  });

  import {
    PRIORITY_ORDER,
    PRIORITY_CLASSES,
  } from "$lib/components/vuln/utils.js";

  function timeAgo(iso: string): string {
    return formatDistanceToNow(new Date(iso), { addSuffix: true });
  }

  function activePriorities(vulnsByPriority: Record<string, number>) {
    return PRIORITY_ORDER.filter((p) => (vulnsByPriority[p] ?? 0) > 0);
  }

  // Chart config — fixed semantic colors independent of --chart-N theme tokens
  const chartConfig = {
    urgent: {
      label: "Urgent Priority",
      color: "oklch(0.577 0.245 27.325)", // red (matches --destructive)
    },
    kev: {
      label: "Actively Exploited (KEV)",
      color: "oklch(0.75 0.183 55)", // amber/orange — warning, not green
    },
  } satisfies Chart.ChartConfig;

  // Parse trend dates for display
  const trendData = $derived(
    (summary.trend ?? []).map(
      (d: { date: string; urgent: number; kev: number }) => ({
        ...d,
        label: format(new Date(d.date + "T12:00:00"), "MMM d"),
      })
    )
  );

  const hasTrend = $derived(trendData.length > 0);

  function formatVulnDb(schema: string | null, built: string | null): string {
    if (!schema && !built) return "—";
    const builtStr = built ? built.replace(/\+00:00$/, "Z") : "";
    if (schema && builtStr) return `${schema}(${builtStr})`;
    return schema ?? builtStr;
  }
</script>

<div class="container mx-auto py-6 space-y-6">
  <div>
    <h1 class="text-2xl font-bold tracking-tight">Dashboard</h1>
    <p class="text-muted-foreground">
      Overview of your Docker security posture.
    </p>
  </div>

  <!-- API error banner -->
  {#if data.apiError}
    <div
      class="rounded-md border border-red-200 bg-red-50 p-4 dark:border-red-900/50 dark:bg-red-900/10 text-red-800 dark:text-red-300 flex items-start gap-4"
    >
      <TriangleAlert class="mt-0.5 h-5 w-5 shrink-0" />
      <div class="flex flex-col gap-1 text-sm">
        <span class="font-medium">Unexpected Error</span>
        <span class="opacity-90"
          >An unexpected error occurred while loading dashboard data. Please try
          again shortly.</span
        >
      </div>
    </div>
  {/if}

  <!-- Status bar -->
  <div
    class="bg-muted/50 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg border px-4 py-2.5 text-xs"
  >
    <!-- Docker connectivity -->
    <span class="flex items-center gap-1.5">
      {#if summary.docker_connected}
        <CircleCheck class="h-3.5 w-3.5 text-green-500" />
        <span class="text-foreground font-medium">Docker</span>
        <span class="text-muted-foreground">Connected</span>
      {:else}
        <CircleX class="h-3.5 w-3.5 text-red-500" />
        <span class="text-foreground font-medium">Docker</span>
        <span class="text-red-500">Disconnected</span>
      {/if}
    </span>

    <span class="text-border select-none hidden sm:inline">|</span>

    <!-- Grype version -->
    <span class="flex items-center gap-1.5">
      <span class="text-muted-foreground">Grype</span>
      <span class="text-foreground font-medium"
        >{summary.grype_version ?? "—"}</span
      >
    </span>

    <span class="text-border select-none hidden sm:inline">|</span>

    <!-- Vuln DB built -->
    <span class="flex items-center gap-1.5">
      <span class="text-muted-foreground">Vuln DB</span>
      <span class="text-foreground font-medium"
        >{formatVulnDb(summary.db_schema, summary.db_built)}</span
      >
      {#if summary.db_updating}
        <Badge
          class="gap-1 bg-blue-100/50 text-blue-700 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800 pointer-events-none"
        >
          <LoaderCircle class="animate-spin" />
          Updating
        </Badge>
      {/if}
    </span>

    <span class="text-border select-none hidden sm:inline">|</span>

    <!-- Last DB check -->
    <span class="flex items-center gap-1.5">
      <span class="text-muted-foreground">Last checked</span>
      <span class="text-foreground font-medium">
        {summary.last_db_checked_at ? timeAgo(summary.last_db_checked_at) : "—"}
      </span>
    </span>
  </div>

  <!-- Stat cards -->
  <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
    <!-- Running containers + images scanned -->
    <Card.Root class="transition-colors hover:bg-muted/50">
      <a href="/containers" class="block h-full">
        <Card.Header
          class="flex flex-row items-center justify-between space-y-0 pb-2"
        >
          <Card.Title class="text-sm font-medium">Environment</Card.Title>
          <Container class="text-muted-foreground h-4 w-4" />
        </Card.Header>
        <Card.Content>
          {#if summary.running_containers === null}
            <div class="text-2xl font-bold">—</div>
            <p class="text-muted-foreground text-xs">No data yet</p>
          {:else}
            <div class="text-2xl font-bold">
              {summary.running_containers}
            </div>
            <p class="text-muted-foreground text-xs mb-2">
              running container{summary.running_containers === 1 ? "" : "s"} &middot;
              {summary.unique_running_images} unique image{summary.unique_running_images ===
              1
                ? ""
                : "s"}
            </p>
            {#if summary.active_tasks > 0 || summary.queued_tasks > 0 || summary.eol_count > 0}
              <div class="flex flex-wrap items-center gap-1.5 mt-auto pt-1">
                {#if summary.eol_count > 0}
                  <Badge
                    class="bg-orange-100/50 text-orange-700 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800 hover:bg-orange-100/80 pointer-events-none"
                  >
                    {summary.eol_count} EOL system{summary.eol_count === 1
                      ? ""
                      : "s"}
                  </Badge>
                {/if}
                {#if summary.active_tasks > 0}
                  <Badge
                    class="bg-blue-100/50 text-blue-700 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800 hover:bg-blue-100/80 pointer-events-none"
                  >
                    {summary.active_tasks} scanning
                    <LoaderCircle class="animate-spin" />
                  </Badge>
                {/if}
                {#if summary.queued_tasks > 0}
                  <Badge
                    class="bg-indigo-100/50 text-indigo-700 border-indigo-200 dark:bg-indigo-900/40 dark:text-indigo-300 dark:border-indigo-800 hover:bg-indigo-100/80 pointer-events-none"
                  >
                    {summary.queued_tasks} queued
                  </Badge>
                {/if}
              </div>
            {/if}
          {/if}
        </Card.Content>
      </a>
    </Card.Root>

    <!-- Urgent priority -->
    <Card.Root class="transition-colors hover:bg-muted/50">
      <a href="/vulnerabilities?report=urgent" class="block h-full">
        <Card.Header
          class="flex flex-row items-center justify-between space-y-0 pb-2"
        >
          <Card.Title class="text-sm font-medium">Urgent Priority</Card.Title>
          <TriangleAlert class="text-muted-foreground h-4 w-4" />
        </Card.Header>
        <Card.Content>
          {#if summary.urgent_count === null}
            <div class="text-2xl font-bold">—</div>
            <p class="text-muted-foreground text-xs">No data yet</p>
          {:else}
            <div class="text-2xl font-bold">
              {summary.urgent_count}
            </div>
            <p class="text-muted-foreground text-xs">
              with the highest risk scores across running containers
            </p>
          {/if}
        </Card.Content>
      </a>
    </Card.Root>

    <!-- Actively exploited (KEV) -->
    <Card.Root class="transition-colors hover:bg-muted/50">
      <a href="/vulnerabilities?report=kev" class="block h-full">
        <Card.Header
          class="flex flex-row items-center justify-between space-y-0 pb-2"
        >
          <Card.Title class="text-sm font-medium">Actively Exploited</Card.Title
          >
          <Zap class="text-muted-foreground h-4 w-4" />
        </Card.Header>
        <Card.Content>
          {#if summary.kev_count === null}
            <div class="text-2xl font-bold">—</div>
            <p class="text-muted-foreground text-xs">No data yet</p>
          {:else}
            <div
              class="text-2xl font-bold {summary.kev_count > 0
                ? 'text-red-600 dark:text-red-400'
                : ''}"
            >
              {summary.kev_count}
            </div>
            <p class="text-muted-foreground text-xs">
              known exploited vulnerabilities (KEV)
            </p>
          {/if}
        </Card.Content>
      </a>
    </Card.Root>

    <!-- New findings since previous scan -->
    <Card.Root class="transition-colors hover:bg-muted/50">
      <a href="/vulnerabilities?report=new" class="block h-full">
        <Card.Header
          class="flex flex-row items-center justify-between space-y-0 pb-2"
        >
          <Card.Title class="text-sm font-medium"
            >New (Since Previous Scan)</Card.Title
          >
          <Shield class="text-muted-foreground h-4 w-4" />
        </Card.Header>
        <Card.Content>
          {@const newFindingCount = summary.new_findings ?? 0}
          {#if summary.new_findings === null}
            <div class="text-2xl font-bold">—</div>
            <p class="text-muted-foreground text-xs">No data yet</p>
          {:else}
            <div
              class="text-2xl font-bold {newFindingCount > 0
                ? 'text-amber-600 dark:text-amber-400'
                : ''}"
            >
              {newFindingCount}
            </div>
            <p class="text-muted-foreground text-xs">
              vulnerabilities newly introduced since previous scan
            </p>
          {/if}
        </Card.Content>
      </a>
    </Card.Root>
  </div>

  <!-- Critical vuln trend chart -->
  <Card.Root>
    <Card.Header>
      <Card.Title>30-Day Trend</Card.Title>
      <Card.Description>
        Urgent priority and actively exploited (KEV) vulnerabilities across all
        scanned images per day.
      </Card.Description>
    </Card.Header>
    <Card.Content>
      {#if !hasTrend}
        <div
          class="flex flex-col items-center justify-center gap-2 py-8 text-center"
        >
          <Shield class="text-muted-foreground h-10 w-10" />
          <p class="text-muted-foreground text-sm">
            No scan data yet — trend will appear here.
          </p>
        </div>
      {:else}
        <Chart.Container config={chartConfig} class="h-[200px] w-full">
          <AreaChart
            data={trendData}
            x="label"
            series={[
              {
                key: "urgent",
                label: chartConfig.urgent.label,
                color: chartConfig.urgent.color,
              },
              {
                key: "kev",
                label: chartConfig.kev.label,
                color: chartConfig.kev.color,
                props: { line: { "stroke-dasharray": "5 3" } },
              },
            ]}
            axis={true}
            points={true}
            props={{
              area: {
                fillOpacity: 0.2,
                line: { strokeWidth: 2 },
                curve: curveMonotoneX,
                motion: "tween",
              },
              xAxis: {
                format: (d: string) => d,
              },
              yAxis: {
                format: (d: number) => (Number.isInteger(d) ? String(d) : ""),
                ticks: 4,
              },
            }}
          >
            {#snippet tooltip()}
              <Chart.Tooltip indicator="line" />
            {/snippet}
          </AreaChart>
        </Chart.Container>
        <!-- Legend -->
        <div class="mt-3 flex flex-wrap items-center justify-center gap-4">
          <span class="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span
              class="h-2.5 w-2.5 rounded-full"
              style="background-color: {chartConfig.urgent.color}"
            ></span>
            Urgent Priority
          </span>
          <span class="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span
              class="h-2.5 w-2.5 rounded-full"
              style="background-color: {chartConfig.kev.color}"
            ></span>
            Actively Exploited (KEV)
          </span>
        </div>
      {/if}
    </Card.Content>
  </Card.Root>

  <!-- Recent scans -->
  <Card.Root>
    <Card.Header>
      <Card.Title>Recent Scans</Card.Title>
      <Card.Description
        >Latest scan results and detected changes.</Card.Description
      >
    </Card.Header>
    <Card.Content>
      {#if activityLoading && activities.length === 0}
        <div
          class="flex flex-col items-center justify-center gap-2 py-8 text-center"
        >
          <LoaderCircle class="text-muted-foreground h-8 w-8 animate-spin" />
        </div>
      {:else if activities.length === 0}
        <div
          class="flex flex-col items-center justify-center gap-2 py-8 text-center"
        >
          <Shield class="text-muted-foreground h-10 w-10" />
          <p class="text-muted-foreground text-sm">No scans have run yet.</p>
          <Badge variant="outline">Waiting for data</Badge>
        </div>
      {:else}
        <Table.Root>
          <Table.Header>
            <Table.Row>
              <Table.Head class="w-[130px]">Scanned</Table.Head>
              <Table.Head>Affected Containers</Table.Head>
              <Table.Head>Image</Table.Head>
              <Table.Head>Vulnerabilities</Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {#each activities as activity (activity.scan_id)}
              <Table.Row>
                <Table.Cell class="text-muted-foreground text-xs">
                  {timeAgo(activity.scanned_at)}
                </Table.Cell>
                <Table.Cell class="text-sm">
                  {#if (activity.affected_container_count_at_scan ?? 0) > 0}
                    {#if (activity.affected_container_count_at_scan ?? 0) <= 3}
                      <div class="flex flex-wrap gap-1">
                        {#each activity.affected_containers_at_scan ?? [] as containerName (containerName)}
                          <span
                            class="inline-flex max-w-[120px] truncate items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
                            title={containerName}
                          >
                            {containerName}
                          </span>
                        {/each}
                      </div>
                    {:else}
                      <span
                        class="inline-flex items-center rounded border border-border/60 bg-muted/40 px-2 py-0.5 text-xs"
                        title={(
                          activity.affected_containers_at_scan ?? []
                        ).join(", ")}
                      >
                        {activity.affected_container_count_at_scan}
                      </span>
                    {/if}
                  {:else}
                    <span class="text-muted-foreground">—</span>
                  {/if}
                </Table.Cell>
                <Table.Cell class="font-mono text-sm">
                  {activity.image_name}
                </Table.Cell>
                <Table.Cell>
                  <div class="flex flex-wrap gap-1">
                    {#each activePriorities(activity.vulns_by_priority ?? {}) as pri (pri)}
                      <span
                        class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {PRIORITY_CLASSES[
                          pri
                        ]}"
                      >
                        {activity.vulns_by_priority[pri]}
                        {pri}
                      </span>
                    {/each}
                  </div>
                </Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>

        {#if activityTotal > 10}
          <div class="mt-4">
            <Pagination.Root
              count={activityTotal}
              perPage={10}
              bind:page={activityPage}
            >
              {#snippet children({ pages, currentPage })}
                <Pagination.Content>
                  <Pagination.Item><Pagination.Previous /></Pagination.Item>
                  {#each pages as pageItem (pageItem.key)}
                    <Pagination.Item>
                      {#if pageItem.type === "page"}
                        <Pagination.Link
                          page={pageItem}
                          isActive={currentPage === pageItem.value}
                        />
                      {:else}
                        <Pagination.Ellipsis />
                      {/if}
                    </Pagination.Item>
                  {/each}
                  <Pagination.Item><Pagination.Next /></Pagination.Item>
                </Pagination.Content>
              {/snippet}
            </Pagination.Root>
          </div>
        {/if}
      {/if}
    </Card.Content>
  </Card.Root>
</div>
