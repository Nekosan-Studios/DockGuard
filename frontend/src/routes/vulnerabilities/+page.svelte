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
    import { formatDistanceToNow } from "date-fns";
    import { goto } from "$app/navigation";
    import { page } from "$app/stores";
    import { onMount, onDestroy } from "svelte";

    let { data }: { data: PageData } = $props();

    interface ContainerInfo {
        image_name: string;
        container_name: string;
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
    }

    const SEVERITY_CLASSES: Record<string, string> = {
        Critical:
            "bg-red-100 text-red-800 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-800",
        High: "bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800",
        Medium: "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/40 dark:text-amber-300 dark:border-amber-800",
        Low: "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800",
        Negligible:
            "bg-gray-100 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600",
        Unknown:
            "bg-gray-100 text-gray-500 border-gray-300 dark:bg-gray-800 dark:text-gray-500 dark:border-gray-600",
    };

    // ── Infinite scroll state ─────────────────────────────────────────────────
    const PAGE_SIZE = 100;

    let rows = $state<Vulnerability[]>(data.vulnerabilities || []);
    let totalCount = $state(data.total_count ?? 0);
    let hasMore = $state(data.has_more ?? false);
    let currentOffset = $state(data.vulnerabilities?.length ?? 0);
    let loadingMore = $state(false);

    // Reset when server data changes (report or sort navigates)
    $effect(() => {
        rows = data.vulnerabilities || [];
        totalCount = data.total_count ?? 0;
        hasMore = data.has_more ?? false;
        currentOffset = data.vulnerabilities?.length ?? 0;
    });

    async function loadNextPage() {
        if (loadingMore || !hasMore) return;
        loadingMore = true;
        try {
            const params = new URLSearchParams({
                report: reportValue,
                sort_by: sortByValue,
                sort_dir: sortDirValue,
                limit: String(PAGE_SIZE),
                offset: String(currentOffset),
            });
            const res = await fetch(`/api/vulnerabilities-paged?${params}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const payload = await res.json();
            const newRows: Vulnerability[] = payload.vulnerabilities ?? [];
            rows = [...rows, ...newRows];
            currentOffset += newRows.length;
            hasMore = payload.has_more ?? false;
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
    function toUtcDate(iso: string): Date {
        return new Date(
            iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z",
        );
    }

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

    function cvssTooltip(score: number): string {
        if (score >= 9.0) return "Critical severity";
        if (score >= 7.0) return "High severity";
        if (score >= 4.0) return "Medium severity";
        return "Low severity";
    }

    function epssTooltip(score: number): string {
        if (score >= 0.5) return "Very high exploitation risk";
        if (score >= 0.1) return "Elevated exploitation risk";
        if (score >= 0.01) return "Moderate exploitation risk";
        return "Low exploitation risk";
    }

    function cvssClass(score: number | null): string {
        if (score === null) return "text-muted-foreground";
        if (score >= 9.0) return "font-bold text-red-700 dark:text-red-400";
        if (score >= 7.0)
            return "font-semibold text-orange-600 dark:text-orange-400";
        if (score >= 4.0) return "text-amber-600 dark:text-amber-400";
        return "text-muted-foreground";
    }

    function epssClass(score: number | null): string {
        if (score === null) return "text-muted-foreground";
        if (score >= 0.5) return "font-bold text-red-700 dark:text-red-400";
        if (score >= 0.1)
            return "font-semibold text-orange-600 dark:text-orange-400";
        if (score >= 0.01) return "text-amber-600 dark:text-amber-400";
        return "text-muted-foreground";
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

    <Card.Root>
        <Card.Header class="flex flex-row items-center justify-between pb-3">
            <div class="space-y-1.5">
                <div class="flex items-center gap-2">
                    <ShieldAlert class="h-5 w-5 text-muted-foreground" />
                    <Card.Title>{reportLabel}</Card.Title>
                </div>
                <Card.Description>
                    {#if totalCount > 0}
                        Showing {rows.length.toLocaleString()} of {totalCount.toLocaleString()} vulnerabilities across running containers.
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
            {#if rows.length === 0 && !loadingMore}
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
                            <col style="width:12%" />
                            <col style="width:15%" />
                            <col style="width:7%" />
                            <col style="width:10%" />
                            <col style="width:7%" />
                            <col style="width:7%" />
                            <col style="width:5%" />
                            <col style="width:5%" />
                            <col style="width:4%" />
                            <col style="width:8%" />
                            <col style="width:20%" />
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
                                        sortDirection={false}
                                    />
                                </Table.Head>
                                <Table.Head class="text-center">
                                    <SortButton
                                        label="Severity"
                                        size="sm"
                                        sortDirection={activeSortDir("severity")}
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
                                                        toggleSort("epss_score")}
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
                            {#each rows as vuln (vuln.vuln_id + vuln.package_name + vuln.installed_version)}
                                <Table.Row class="hover:bg-muted/30">
                                    <Table.Cell class="pl-4 font-mono">
                                        <div
                                            class="flex flex-wrap items-center gap-1"
                                        >
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
                                            {#if isNew(vuln.first_seen_at)}
                                                <span
                                                    class="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-100 px-1.5 py-0.5 font-sans text-[10px] font-semibold text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
                                                >
                                                    NEW
                                                </span>
                                            {/if}
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
                                    <Table.Cell class="text-center">
                                        <span
                                            class="inline-flex items-center rounded-full border px-1.5 py-0.5 font-medium {SEVERITY_CLASSES[
                                                vuln.severity
                                            ] ?? SEVERITY_CLASSES['Unknown']}"
                                        >
                                            {vuln.severity}
                                        </span>
                                    </Table.Cell>
                                    <Table.Cell class="font-mono">
                                        <Tooltip.Root>
                                            <Tooltip.Trigger
                                                class="cursor-default text-left"
                                            >
                                                <div
                                                    class="flex flex-wrap items-baseline gap-x-1.5 gap-y-0.5"
                                                >
                                                    <span
                                                        >{vuln.package_name}</span
                                                    >
                                                    {#if vuln.package_type}
                                                        <span
                                                            class="inline-flex items-center rounded border border-slate-200 bg-slate-100 px-1 py-0 font-sans text-[10px] text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
                                                        >
                                                            {vuln.package_type}
                                                        </span>
                                                    {/if}
                                                </div>
                                            </Tooltip.Trigger>
                                            <Tooltip.Content class="max-w-sm">
                                                {@const paths = vuln.locations
                                                    ? vuln.locations.split("\n")
                                                    : []}
                                                <p class="mb-1 font-semibold">
                                                    {paths.length === 1
                                                        ? "Location:"
                                                        : "Locations (Sample):"}
                                                </p>
                                                {#if paths.length > 0}
                                                    <ul class="space-y-0.5">
                                                        {#each paths as path (path)}
                                                            <li
                                                                class="flex items-start gap-1 font-mono text-xs"
                                                            >
                                                                <span
                                                                    class="shrink-0"
                                                                    >•</span
                                                                >
                                                                <span
                                                                    class="break-all"
                                                                    >{path}</span
                                                                >
                                                            </li>
                                                        {/each}
                                                    </ul>
                                                {:else}
                                                    <p
                                                        class="text-xs text-muted-foreground"
                                                    >
                                                        No locations noted.
                                                    </p>
                                                {/if}
                                            </Tooltip.Content>
                                        </Tooltip.Root>
                                    </Table.Cell>
                                    <Table.Cell
                                        class="text-center font-mono text-muted-foreground"
                                        >{vuln.installed_version}</Table.Cell
                                    >
                                    <Table.Cell class="text-center font-mono">
                                        {#if vuln.fixed_version}
                                            {vuln.fixed_version}
                                        {:else}
                                            <span class="text-muted-foreground"
                                                >No fix</span
                                            >
                                        {/if}
                                    </Table.Cell>
                                    <Table.Cell
                                        class="text-center {cvssClass(
                                            vuln.cvss_base_score,
                                        )}"
                                    >
                                        {#if vuln.cvss_base_score != null}
                                            <Tooltip.Root>
                                                <Tooltip.Trigger
                                                    class="cursor-default"
                                                >
                                                    {vuln.cvss_base_score.toFixed(
                                                        1,
                                                    )}
                                                </Tooltip.Trigger>
                                                <Tooltip.Content
                                                    >{cvssTooltip(
                                                        vuln.cvss_base_score,
                                                    )}</Tooltip.Content
                                                >
                                            </Tooltip.Root>
                                        {:else}
                                            —
                                        {/if}
                                    </Table.Cell>
                                    <Table.Cell
                                        class="text-center {epssClass(
                                            vuln.epss_score,
                                        )}"
                                    >
                                        {#if vuln.epss_score != null}
                                            <Tooltip.Root>
                                                <Tooltip.Trigger
                                                    class="cursor-default"
                                                >
                                                    {(
                                                        vuln.epss_score * 100
                                                    ).toFixed(1)}%
                                                </Tooltip.Trigger>
                                                <Tooltip.Content>
                                                    <p>
                                                        {epssTooltip(
                                                            vuln.epss_score,
                                                        )}
                                                    </p>
                                                    {#if vuln.epss_percentile != null}
                                                        {@const pct =
                                                            Math.round(
                                                                vuln.epss_percentile *
                                                                    100,
                                                            )}
                                                        <p
                                                            class="mt-1 {pct >=
                                                            90
                                                                ? 'font-semibold text-red-400'
                                                                : pct >= 70
                                                                  ? 'text-orange-400'
                                                                  : ''}"
                                                        >
                                                            In {pct}th
                                                            percentile of
                                                            exploit likelihood.
                                                        </p>
                                                    {/if}
                                                </Tooltip.Content>
                                            </Tooltip.Root>
                                        {:else}
                                            —
                                        {/if}
                                    </Table.Cell>
                                    <Table.Cell class="text-center">
                                        {#if vuln.is_kev}
                                            <Tooltip.Root>
                                                <Tooltip.Trigger
                                                    class="cursor-default"
                                                >
                                                    <CircleCheck
                                                        class="mx-auto h-4 w-4 text-red-600 dark:text-red-400"
                                                    />
                                                </Tooltip.Trigger>
                                                <Tooltip.Content
                                                    >Known Exploited
                                                    Vulnerability</Tooltip.Content
                                                >
                                            </Tooltip.Root>
                                        {:else}
                                            <span class="text-muted-foreground"
                                                >—</span
                                            >
                                        {/if}
                                    </Table.Cell>
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
                                <span class="text-xs text-muted-foreground/60">Scroll for more</span>
                            {/if}
                        </div>
                    {/if}
                </div>
            {/if}
        </Card.Content>
    </Card.Root>
</div>
