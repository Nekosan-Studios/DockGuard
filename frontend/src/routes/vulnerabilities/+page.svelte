<script lang="ts">
    import type { PageData } from "./$types";
    import * as Card from "$lib/components/ui/card/index.js";
    import { Badge } from "$lib/components/ui/badge/index.js";
    import * as Table from "$lib/components/ui/table/index.js";
    import * as Select from "$lib/components/ui/select/index.js";
    import { Label } from "$lib/components/ui/label/index.js";
    import Shield from "@lucide/svelte/icons/shield";
    import ShieldAlert from "@lucide/svelte/icons/shield-alert";
    import ExternalLink from "@lucide/svelte/icons/external-link";
    import CircleCheck from "@lucide/svelte/icons/circle-check";
    import Loader2 from "@lucide/svelte/icons/loader-2";
    import SortButton from "../containers/sort-button.svelte";
    import * as Tooltip from "$lib/components/ui/tooltip/index.js";
    import * as Popover from "$lib/components/ui/popover/index.js";
    import { formatDistanceToNow } from "date-fns";
    import { goto } from "$app/navigation";
    import CvssCell from "$lib/components/vuln/CvssCell.svelte";
    import EpssCell from "$lib/components/vuln/EpssCell.svelte";
    import KevCell from "$lib/components/vuln/KevCell.svelte";
    import SeverityCell from "$lib/components/vuln/SeverityCell.svelte";
    import { SEVERITY_CLASSES, toUtcDate, cvssClass } from "$lib/components/vuln/utils.js";
    import { page } from "$app/stores";
    import { onMount, onDestroy } from "svelte";

    let { data }: { data: PageData } = $props();

    interface ContainerInfo {
        image_name: string;
        container_name: string;
    }

    interface PackageInfo {
        package_name: string;
        installed_version: string;
        fixed_version: string | null;
        package_type: string | null;
        locations: string | null;
        severity: string;
        cvss_base_score: number | null;
    }

    interface Vulnerability {
        vuln_id: string;
        severity: string;
        description: string | null;
        data_source: string | null;
        cvss_base_score: number | null;
        epss_score: number | null;
        is_kev: boolean;
        package_name: string;
        installed_version: string;
        fixed_version: string | null;
        package_type: string | null;
        locations: string | null;
        epss_percentile: number | null;
        first_seen_at: string | null;
        containers: ContainerInfo[];
        packages: PackageInfo[];
    }

    // ── Infinite scroll state ─────────────────────────────────────────────────
    const PAGE_SIZE = 100;

    let rows = $state<Vulnerability[]>([]);
    let totalCount = $state(0);
    let hasMore = $state(false);
    let currentOffset = $state(0);
    let loadingMore = $state(false);

    // Reset when server data changes (report or sort navigates)
    $effect(() => {
        rows = data.vulnerabilities || [];
        totalCount = data.total_count ?? 0;
        hasMore = data.has_more ?? false;
        currentOffset = data.vulnerabilities?.length ?? 0;
    });

    const MAX_ROWS = 400;

    async function loadNextPage() {
        if (loadingMore || !hasMore || currentOffset >= MAX_ROWS) return;
        loadingMore = true;
        try {
            const params = new URLSearchParams({
                report: reportValue,
                sort_by: sortByValue,
                sort_dir: sortDirValue,
                limit: "100", // PAGE_SIZE
                offset: String(currentOffset),
            });
            const res = await fetch(`/api/vulnerabilities-paged?${params}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const payload = await res.json();
            const newRows: Vulnerability[] = payload.vulnerabilities ?? [];
            rows = [...rows, ...newRows];
            currentOffset += newRows.length;
            hasMore = (payload.has_more ?? false) && currentOffset < MAX_ROWS;
            totalCount = payload.total_count ?? totalCount;
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
                { rootMargin: "200px" },
            );
            observer.observe(sentinel);
        }
        return () => {
            observer?.disconnect();
            observer = null;
        };
    });

    onDestroy(() => observer?.disconnect());

    // ── Reports & sort URL params ─────────────────────────────────────────────
    const reports = [
        { value: "all", label: "All Vulnerabilities" },
        { value: "critical", label: "Critical Vulnerabilities" },
        { value: "kev", label: "Actively Exploited (KEV)" },
        { value: "new", label: "Newly Found (Last 24h)" },
    ];

    let reportValue = $derived(
        $page.url.searchParams.get("report") || "critical",
    );
    let sortByValue = $derived(
        $page.url.searchParams.get("sort_by") || "severity",
    );
    let sortDirValue = $derived(
        ($page.url.searchParams.get("sort_dir") as "asc" | "desc") || "asc",
    );
    let reportLabel = $derived(
        reports.find((r) => r.value === reportValue)?.label ||
            "Critical Vulnerabilities",
    );

    function handleReportChange(v: string) {
        const u = new URL($page.url);
        u.searchParams.set("report", v);
        u.searchParams.delete("sort_by");
        u.searchParams.delete("sort_dir");
        goto(u.toString());
    }

    type VulnSortCol =
        | "vuln_id"
        | "severity"
        | "package_name"
        | "containers"
        | "cvss_base_score"
        | "epss_score"
        | "is_kev"
        | "first_seen_at";

    function toggleSort(col: VulnSortCol) {
        if (col === "containers") return; // computed client-side, not server-sortable
        const u = new URL($page.url);
        const currentCol = u.searchParams.get("sort_by") || "severity";
        const currentDir = u.searchParams.get("sort_dir") || "asc";
        if (currentCol === col) {
            if (currentDir === "asc") {
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
        if (col === "containers") return false;
        return sortByValue === col ? sortDirValue : false;
    }

    // ── Utility functions ─────────────────────────────────────────────────────
    function timeAgo(iso: string): string {
        return formatDistanceToNow(toUtcDate(iso), { addSuffix: true });
    }

    function formatDate(iso: string): string {
        return toUtcDate(iso).toLocaleString();
    }

    function truncate(text: string | null, max = 120): string {
        if (!text) return "";
        return text.length > max ? text.slice(0, max) + "…" : text;
    }

    function isNew(firstSeenAt: string | null): boolean {
        if (!firstSeenAt) return false;
        const date = toUtcDate(firstSeenAt);
        const hours = (Date.now() - date.getTime()) / (1000 * 60 * 60);
        return hours <= 24;
    }
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
                    One or more running containers ({data.eol_images.join(
                        ", ",
                    )}) are using an end-of-life operating system. Vulnerability
                    data for these systems may be incomplete, outdated, or
                    inaccurate.
                </span>
            </div>
        </div>
    {/if}

    <Card.Root>
        <Card.Header class="flex flex-row items-center justify-between pb-3">
            <div class="space-y-1.5">
                <div class="flex items-center gap-2">
                    <ShieldAlert class="h-5 w-5 text-muted-foreground" />
                    <Card.Title>{reportLabel}</Card.Title>
                </div>
                <Card.Description>
                    {#if totalCount > 0}
                        Showing {rows.length.toLocaleString()} of {totalCount.toLocaleString()}
                        vulnerabilities across running containers.
                    {:else}
                        No vulnerabilities found for this report.
                    {/if}
                </Card.Description>
            </div>

            <div class="flex items-center space-x-2">
                <Label id="report-type" class="text-sm font-medium mr-1"
                    >Report:</Label
                >
                <Select.Root
                    type="single"
                    value={reportValue}
                    onValueChange={handleReportChange}
                >
                    <Select.Trigger class="w-[260px]">
                        {reportLabel}
                    </Select.Trigger>
                    <Select.Content>
                        <Select.Group>
                            {#each reports as report}
                                <Select.Item
                                    value={report.value}
                                    label={report.label}
                                >
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
                            An unexpected error occurred while loading
                            vulnerability data. Please try again shortly.
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
                <div class="overflow-x-auto rounded-md border">
                    <Table.Root class="w-full table-fixed text-xs">
                        <colgroup>
                            <col style="width:14%" />
                            <col style="width:15%" />
                            <col style="width:7%" />
                            <col style="width:10%" />
                            <col style="width:7%" />
                            <col style="width:7%" />
                            <col style="width:5%" />
                            <col style="width:5%" />
                            <col style="width:4%" />
                            <col style="width:8%" />
                            <col style="width:18%" />
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
                                    <span class="text-xs font-medium">Containers</span>
                                </Table.Head>
                                <Table.Head class="text-center">
                                    <SortButton
                                        label="Severity"
                                        size="sm"
                                        sortDirection={activeSortDir(
                                            "severity",
                                        )}
                                        onclick={() => toggleSort("severity")}
                                    />
                                </Table.Head>
                                <Table.Head>
                                    <SortButton
                                        label="Package"
                                        size="sm"
                                        sortDirection={activeSortDir(
                                            "package_name",
                                        )}
                                        onclick={() =>
                                            toggleSort("package_name")}
                                    />
                                </Table.Head>
                                <Table.Head class="text-center"
                                    >Version</Table.Head
                                >
                                <Table.Head class="text-center"
                                    >Fixed In</Table.Head
                                >
                                <Table.Head class="text-center">
                                    <Tooltip.Root>
                                        <Tooltip.Trigger>
                                            {#snippet child({ props })}
                                                <SortButton
                                                    label="CVSS"
                                                    size="sm"
                                                    sortDirection={activeSortDir(
                                                        "cvss_base_score",
                                                    )}
                                                    {...props}
                                                    onclick={() =>
                                                        toggleSort(
                                                            "cvss_base_score",
                                                        )}
                                                />
                                            {/snippet}
                                        </Tooltip.Trigger>
                                        <Tooltip.Content
                                            >Common Vulnerability Scoring
                                            System.</Tooltip.Content
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
                                                    sortDirection={activeSortDir(
                                                        "epss_score",
                                                    )}
                                                    {...props}
                                                    onclick={() =>
                                                        toggleSort(
                                                            "epss_score",
                                                        )}
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
                                                    sortDirection={activeSortDir(
                                                        "is_kev",
                                                    )}
                                                    {...props}
                                                    onclick={() =>
                                                        toggleSort("is_kev")}
                                                />
                                            {/snippet}
                                        </Tooltip.Trigger>
                                        <Tooltip.Content
                                            >Known Exploited Vulnerability
                                            catalog.</Tooltip.Content
                                        >
                                    </Tooltip.Root>
                                </Table.Head>
                                <Table.Head class="text-center">
                                    <SortButton
                                        label="First Seen"
                                        size="sm"
                                        sortDirection={activeSortDir(
                                            "first_seen_at",
                                        )}
                                        onclick={() =>
                                            toggleSort("first_seen_at")}
                                    />
                                </Table.Head>
                                <Table.Head class="pr-6">Description</Table.Head
                                >
                            </Table.Row>
                        </Table.Header>
                        <Table.Body>
                            {#each rows as vuln (vuln.vuln_id)}
                                {@const rep = vuln.packages?.[0] ?? vuln}
                                {@const extraPkgs = (vuln.packages?.length ?? 1) - 1}
                                <Table.Row class="hover:bg-muted/30">
                                    <Table.Cell class="pl-4 font-mono">
                                        <div
                                            class="flex flex-wrap items-center gap-1"
                                        >
                                            {#if isNew(vuln.first_seen_at)}
                                                <span
                                                    class="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-100 px-1.5 py-0.5 font-sans text-[10px] font-semibold text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
                                                >
                                                    NEW
                                                </span>
                                            {/if}
                                            <a
                                                href={vuln.data_source ??
                                                    `https://nvd.nist.gov/vuln/detail/${vuln.vuln_id}`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                class="inline-flex items-center gap-1 text-blue-600 hover:underline dark:text-blue-400"
                                            >
                                                {vuln.vuln_id}
                                                <ExternalLink
                                                    class="h-3 w-3 shrink-0"
                                                />
                                            </a>
                                        </div>
                                    </Table.Cell>
                                    <Table.Cell class="align-top py-2">
                                        {#if vuln.containers && vuln.containers.length > 0}
                                            <div class="flex flex-wrap gap-1">
                                                {#each vuln.containers as container}
                                                    <Tooltip.Root>
                                                        <Tooltip.Trigger
                                                            class="cursor-default"
                                                        >
                                                            <span
                                                                class="inline-flex max-w-[120px] truncate items-center rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
                                                            >
                                                                {container.container_name}
                                                            </span>
                                                        </Tooltip.Trigger>
                                                        <Tooltip.Content>
                                                            <p
                                                                class="font-medium text-xs mb-0.5"
                                                            >
                                                                Container: {container.container_name}
                                                            </p>
                                                            <p
                                                                class="font-mono text-[10px] text-muted-foreground"
                                                            >
                                                                Image: {container.image_name}
                                                            </p>
                                                        </Tooltip.Content>
                                                    </Tooltip.Root>
                                                {/each}
                                            </div>
                                        {:else}
                                            <span
                                                class="text-muted-foreground text-xs"
                                                >—</span
                                            >
                                        {/if}
                                    </Table.Cell>
                                    <SeverityCell severity={vuln.severity} />
                                    <Table.Cell class="font-mono">
                                        <div class="flex flex-wrap items-baseline gap-x-1.5 gap-y-0.5">
                                            <Tooltip.Root>
                                                <Tooltip.Trigger
                                                    class="cursor-default text-left"
                                                >
                                                    <div class="flex flex-wrap items-baseline gap-x-1.5 gap-y-0.5">
                                                        <span>{rep.package_name}</span>
                                                        {#if rep.package_type}
                                                            <span
                                                                class="inline-flex items-center rounded border border-slate-200 bg-slate-100 px-1 py-0 font-sans text-[10px] text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
                                                            >
                                                                {rep.package_type}
                                                            </span>
                                                        {/if}
                                                    </div>
                                                </Tooltip.Trigger>
                                                <Tooltip.Content class="max-w-sm">
                                                    {@const paths = rep.locations
                                                        ? rep.locations.split("\n")
                                                        : []}
                                                    <p class="mb-1 font-semibold">
                                                        {paths.length === 1
                                                            ? "Location:"
                                                            : "Locations (Sample):"}
                                                    </p>
                                                    {#if paths.length > 0}
                                                        <ul class="space-y-0.5">
                                                            {#each paths as path (path)}
                                                                <li class="flex items-start gap-1 font-mono text-xs">
                                                                    <span class="shrink-0">•</span>
                                                                    <span class="break-all">{path}</span>
                                                                </li>
                                                            {/each}
                                                        </ul>
                                                    {:else}
                                                        <p class="text-xs text-muted-foreground">
                                                            No locations noted.
                                                        </p>
                                                    {/if}
                                                </Tooltip.Content>
                                            </Tooltip.Root>
                                            {#if extraPkgs > 0}
                                                <Popover.Root>
                                                    <Popover.Trigger>
                                                        <span
                                                            class="inline-flex cursor-pointer items-center rounded border border-indigo-200 bg-indigo-50 px-1.5 py-0.5 font-sans text-[10px] font-medium text-indigo-700 hover:bg-indigo-100 dark:border-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300 dark:hover:bg-indigo-900/60"
                                                        >
                                                            +{extraPkgs} more
                                                        </span>
                                                    </Popover.Trigger>
                                                    <Popover.Content class="w-80 p-0" align="start">
                                                        <div class="px-3 py-2 border-b border-border">
                                                            <p class="text-xs font-semibold">All Affected Packages ({vuln.packages.length})</p>
                                                        </div>
                                                        <div class="max-h-48 overflow-y-auto divide-y divide-border">
                                                            {#each vuln.packages as pkg}
                                                                <div class="px-3 py-2 text-xs">
                                                                    <div class="flex items-center justify-between gap-1.5">
                                                                        <div class="flex items-baseline gap-1.5">
                                                                            <span class="font-mono font-medium">{pkg.package_name}</span>
                                                                            {#if pkg.package_type}
                                                                                <span class="inline-flex items-center rounded border border-slate-200 bg-slate-100 px-1 py-0 text-[10px] text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
                                                                                    {pkg.package_type}
                                                                                </span>
                                                                            {/if}
                                                                        </div>
                                                                        <div class="flex items-center gap-1.5 shrink-0">
                                                                            <span class="inline-flex items-center rounded-full border px-1.5 py-0 text-[10px] font-medium {SEVERITY_CLASSES[pkg.severity] ?? SEVERITY_CLASSES['Unknown']}">
                                                                                {pkg.severity}
                                                                            </span>
                                                                            {#if pkg.cvss_base_score != null}
                                                                                <span class="font-mono text-[10px] {cvssClass(pkg.cvss_base_score)}">
                                                                                    {pkg.cvss_base_score.toFixed(1)}
                                                                                </span>
                                                                            {/if}
                                                                        </div>
                                                                    </div>
                                                                    <div class="mt-0.5 flex gap-3 text-muted-foreground font-mono">
                                                                        <span>{pkg.installed_version}</span>
                                                                        <span>→</span>
                                                                        <span class={pkg.fixed_version ? "text-foreground" : ""}>
                                                                            {pkg.fixed_version ?? "No fix"}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                            {/each}
                                                        </div>
                                                    </Popover.Content>
                                                </Popover.Root>
                                            {/if}
                                        </div>
                                    </Table.Cell>
                                    <Table.Cell
                                        class="text-center font-mono text-muted-foreground"
                                        >{rep.installed_version}</Table.Cell
                                    >
                                    <Table.Cell class="text-center font-mono">
                                        {#if rep.fixed_version}
                                            {rep.fixed_version}
                                        {:else}
                                            <span class="text-muted-foreground"
                                                >No fix</span
                                            >
                                        {/if}
                                    </Table.Cell>
                                    <CvssCell score={vuln.cvss_base_score} />
                                    <EpssCell
                                        score={vuln.epss_score}
                                        percentile={vuln.epss_percentile}
                                    />
                                    <KevCell isKev={vuln.is_kev} />
                                    <Table.Cell class="text-center">
                                        {#if vuln.first_seen_at}
                                            <Tooltip.Root>
                                                <Tooltip.Trigger
                                                    class="cursor-default text-xs text-muted-foreground"
                                                >
                                                    {timeAgo(
                                                        vuln.first_seen_at,
                                                    )}
                                                </Tooltip.Trigger>
                                                <Tooltip.Content
                                                    >{formatDate(
                                                        vuln.first_seen_at,
                                                    )}</Tooltip.Content
                                                >
                                            </Tooltip.Root>
                                        {:else}
                                            <span class="text-muted-foreground"
                                                >—</span
                                            >
                                        {/if}
                                    </Table.Cell>

                                    <Table.Cell
                                        class="text-muted-foreground pr-6 text-[11px] leading-snug"
                                    >
                                        <span
                                            title={vuln.description ??
                                                undefined}
                                        >
                                            {truncate(vuln.description, 100)}
                                        </span>
                                    </Table.Cell>
                                </Table.Row>
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
                            — use the report filters above or sort by CVSS / EPSS
                            to prioritize.
                        </div>
                    {/if}
                </div>
            {/if}
        </Card.Content>
    </Card.Root>
</div>
