<script lang="ts">
    import * as Table from "$lib/components/ui/table/index.js";
    import { Badge } from "$lib/components/ui/badge/index.js";
    import * as Tooltip from "$lib/components/ui/tooltip/index.js";
    import ChevronRight from "@lucide/svelte/icons/chevron-right";
    import Loader2 from "@lucide/svelte/icons/loader-2";
    import SortButton from "../../../routes/containers/sort-button.svelte";
    import { slide } from "svelte/transition";
    import { formatDistanceToNow } from "date-fns";
    import { SvelteSet } from "svelte/reactivity";
    import { onDestroy, onMount } from "svelte";
    import { SEVERITY_CLASSES, toUtcDate } from "./utils.js";
    import VulnRow from "./VulnRow.svelte";
    import type { Vulnerability } from "./VulnRow.svelte";

    const SEVERITY_ORDER = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Negligible",
        "Unknown",
    ];

    // Constants matches parent logic
    const SUBVIEW_MAX_ROWS = 400;
    const SUBVIEW_PAGE_SIZE = 200;
    const AUTO_FILTER_THRESHOLD = 15;

    export interface ContainerRecord {
        image_name: string;
        container_name: string;
        has_scan: boolean;
        is_distro_eol?: boolean;
        distro_display?: string;
        has_vex?: boolean;
        vulns_by_severity: Record<string, number>;
        total?: number;
        scanned_at?: string | null;
    }

    let {
        container,
        hideVexResolved = false,
    }: {
        container: ContainerRecord;
        hideVexResolved?: boolean;
    } = $props();

    // ── Local State (Replaces Parent `SvelteMap`s) ──────────────────────────
    let expanded = $state(false);
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
    let sortCol = $state<VulnSortCol | null>(null);
    let sortDir = $state<"asc" | "desc">("asc");

    let activeFilters = new SvelteSet<string>();
    // The specific filter fetched if not fetching 'all'
    let partiallyLoadedSeverity = $state<string | undefined>(undefined);

    // Track scanned_at explicitly to detect "NEW" vulnerabilities accurately
    let lastScannedAt = $state<string | undefined>(undefined);

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
                            partiallyLoadedSeverity,
                        );
                    }
                },
                { rootMargin: "100px" },
            );
            observer.observe(sentinel);
        }
        return () => {
            observer?.disconnect();
            observer = null;
        };
    });

    onDestroy(() => observer?.disconnect());

    // ── Data Fetching ─────────────────────────────────────────────────────────
    async function fetchVulns(
        offset = 0,
        sCol: VulnSortCol | null = null,
        sDir: "asc" | "desc" = "asc",
        severityFilter?: string,
    ) {
        if (!container.has_scan) return;
        loadingMore = true;

        try {
            const params = new URLSearchParams({
                image_ref: container.image_name,
                limit: String(SUBVIEW_PAGE_SIZE),
                offset: String(offset),
                sort_by: sCol ?? "severity",
                sort_dir: sDir,
            });
            if (severityFilter) params.set("severity", severityFilter);

            const res = await fetch(`/api/vulnerabilities?${params}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const payload = await res.json();

            if (payload.scanned_at) {
                lastScannedAt = payload.scanned_at;
            }

            const newRows: Vulnerability[] = payload.vulnerabilities ?? [];
            const existing = offset === 0 ? [] : [...vulns];
            vulns = [...existing, ...newRows];

            currentOffset = vulns.length;
            const atSoftCap = currentOffset >= SUBVIEW_MAX_ROWS;

            totalCount = payload.total_count ?? newRows.length;
            hasMore = (payload.has_more ?? false) && !atSoftCap;
            sortCol = sCol;
            sortDir = sDir;
            partiallyLoadedSeverity = severityFilter;
        } catch (err) {
            console.error(
                "Failed to fetch vulns for",
                container.image_name,
                err,
            );
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
            const topSeverity =
                total >= AUTO_FILTER_THRESHOLD
                    ? SEVERITY_ORDER.find(
                          (s) => (container.vulns_by_severity[s] ?? 0) > 0,
                      )
                    : undefined;

            if (topSeverity) {
                activeFilters.add(topSeverity);
                fetchVulns(0, null, "asc", topSeverity);
            } else {
                fetchVulns(0, null, "asc", undefined);
            }
        }
    }

    function toggleFilter(severity: string, e: MouseEvent) {
        e.stopPropagation();
        if (activeFilters.has(severity)) {
            activeFilters.delete(severity);
        } else {
            activeFilters.add(severity);
        }

        // Re-fetch from offset 0
        const fetchSev =
            activeFilters.size === 1 ? [...activeFilters][0] : undefined;
        fetchVulns(0, sortCol, sortDir, fetchSev);
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

        fetchVulns(0, newCol, newDir, partiallyLoadedSeverity);
    }

    // ── Derived View State ────────────────────────────────────────────────────
    function activeSeverities() {
        return SEVERITY_ORDER.filter(
            (s) => (container.vulns_by_severity[s] ?? 0) > 0,
        );
    }

    let visibleVulns = $derived.by(() => {
        let v = [...vulns];
        if (activeFilters.size > 0) {
            v = v.filter((item) => activeFilters.has(item.severity));
        }
        if (hideVexResolved) {
            v = v.filter(
                (item) =>
                    item.vex_status !== "not_affected" &&
                    item.vex_status !== "fixed",
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
                    {#if container.is_distro_eol}
                        <Badge
                            variant="outline"
                            class="bg-orange-100/50 text-orange-700 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800"
                        >
                            EOL OS
                        </Badge>
                    {/if}
                    {#if container.has_vex}
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
                                This image includes VEX attestations from the
                                supplier.
                            </Tooltip.Content>
                        </Tooltip.Root>
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
                {#each activeSeverities() as sev (sev)}
                    {#if expanded}
                        <button
                            onclick={(e) => toggleFilter(sev, e)}
                            class="inline-flex cursor-pointer items-center rounded-full border px-2 py-0.5 text-xs font-medium transition-all {SEVERITY_CLASSES[
                                sev
                            ]} {activeFilters.has(sev)
                                ? 'ring-2 ring-offset-1 ring-current'
                                : 'opacity-80 hover:opacity-100'}"
                        >
                            {container.vulns_by_severity[sev]}
                            {sev}
                        </button>
                    {:else}
                        <span
                            class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {SEVERITY_CLASSES[
                                sev
                            ]}"
                        >
                            {container.vulns_by_severity[sev]}
                            {sev}
                        </span>
                    {/if}
                {/each}
                {#if activeSeverities().length === 0}
                    <span class="text-muted-foreground text-xs">None found</span
                    >
                {/if}
            </div>
        {:else}
            <span class="text-muted-foreground text-xs">—</span>
        {/if}
    </Table.Cell>
    <Table.Cell class="text-center text-xs">
        {#if container.has_scan}
            <span class="text-muted-foreground"
                >{timeAgo(container.scanned_at)}</span
            >
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
        <Table.Cell colspan={3} class="p-0">
            <div
                transition:slide={{ duration: 200 }}
                class="bg-muted/20 border-muted border-l-4 overflow-hidden"
            >
                {#if loadingMore && vulns.length === 0}
                    <div class="flex items-center gap-2 px-6 py-4 text-sm">
                        <Loader2
                            class="text-muted-foreground h-4 w-4 animate-spin"
                        />
                        <span class="text-muted-foreground"
                            >Loading vulnerabilities…</span
                        >
                    </div>
                {:else}
                    <svelte:boundary
                        onerror={(e) =>
                            console.error(
                                "[DockGuard] sub-view render error:",
                                e,
                            )}
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
                                <span
                                    >Vulnerability data may be incomplete or
                                    outdated.</span
                                >
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
                                <Table.Root
                                    class="w-full min-w-[1000px] table-fixed text-xs"
                                >
                                    <colgroup>
                                        <col style="width:13%" />
                                        <col style="width:7%" />
                                        <col style="width:12%" />
                                        <col style="width:8%" />
                                        <col style="width:8%" />
                                        <col style="width:5%" />
                                        <col style="width:6%" />
                                        <col style="width:4%" />
                                        {#if hasVexData}
                                            <col style="width:4%" />
                                        {/if}
                                        <col style="width:10%" />
                                        <col
                                            style="width:{hasVexData
                                                ? '23'
                                                : '27'}%"
                                        />
                                    </colgroup>
                                    <Table.Header>
                                        <Table.Row class="bg-muted/30">
                                            <Table.Head class="pl-2">
                                                <SortButton
                                                    label="CVE ID"
                                                    size="sm"
                                                    sortDirection={sortCol ===
                                                    "vuln_id"
                                                        ? sortDir
                                                        : false}
                                                    onclick={(e: MouseEvent) =>
                                                        toggleVulnSort(
                                                            "vuln_id",
                                                            e,
                                                        )}
                                                />
                                            </Table.Head>
                                            <Table.Head class="text-center">
                                                <SortButton
                                                    label="Severity"
                                                    size="sm"
                                                    sortDirection={sortCol ===
                                                    "severity"
                                                        ? sortDir
                                                        : false}
                                                    onclick={(e: MouseEvent) =>
                                                        toggleVulnSort(
                                                            "severity",
                                                            e,
                                                        )}
                                                />
                                            </Table.Head>
                                            <Table.Head>
                                                <SortButton
                                                    label="Package"
                                                    size="sm"
                                                    sortDirection={sortCol ===
                                                    "package_name"
                                                        ? sortDir
                                                        : false}
                                                    onclick={(e: MouseEvent) =>
                                                        toggleVulnSort(
                                                            "package_name",
                                                            e,
                                                        )}
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
                                                        {#snippet child({
                                                            props,
                                                        })}
                                                            <SortButton
                                                                label="CVSS"
                                                                size="sm"
                                                                sortDirection={sortCol ===
                                                                "cvss_base_score"
                                                                    ? sortDir
                                                                    : false}
                                                                {...props}
                                                                onclick={(
                                                                    e: MouseEvent,
                                                                ) =>
                                                                    toggleVulnSort(
                                                                        "cvss_base_score",
                                                                        e,
                                                                    )}
                                                            />
                                                        {/snippet}
                                                    </Tooltip.Trigger>
                                                    <Tooltip.Content>
                                                        Common Vulnerability
                                                        Scoring System.
                                                    </Tooltip.Content>
                                                </Tooltip.Root>
                                            </Table.Head>
                                            <Table.Head class="text-center">
                                                <Tooltip.Root>
                                                    <Tooltip.Trigger>
                                                        {#snippet child({
                                                            props,
                                                        })}
                                                            <SortButton
                                                                label="EPSS %"
                                                                size="sm"
                                                                sortDirection={sortCol ===
                                                                "epss_score"
                                                                    ? sortDir
                                                                    : false}
                                                                {...props}
                                                                onclick={(
                                                                    e: MouseEvent,
                                                                ) =>
                                                                    toggleVulnSort(
                                                                        "epss_score",
                                                                        e,
                                                                    )}
                                                            />
                                                        {/snippet}
                                                    </Tooltip.Trigger>
                                                    <Tooltip.Content
                                                        >Exploit Prediction
                                                        Scoring System.</Tooltip.Content
                                                    >
                                                </Tooltip.Root>
                                            </Table.Head>
                                            <Table.Head class="text-center">
                                                <Tooltip.Root>
                                                    <Tooltip.Trigger>
                                                        {#snippet child({
                                                            props,
                                                        })}
                                                            <SortButton
                                                                label="KEV"
                                                                size="sm"
                                                                sortDirection={sortCol ===
                                                                "is_kev"
                                                                    ? sortDir
                                                                    : false}
                                                                {...props}
                                                                onclick={(
                                                                    e: MouseEvent,
                                                                ) =>
                                                                    toggleVulnSort(
                                                                        "is_kev",
                                                                        e,
                                                                    )}
                                                            />
                                                        {/snippet}
                                                    </Tooltip.Trigger>
                                                    <Tooltip.Content
                                                        >Known Exploited
                                                        Vulnerabilities catalog.</Tooltip.Content
                                                    >
                                                </Tooltip.Root>
                                            </Table.Head>
                                            {#if hasVexData}
                                                <Table.Head class="text-center">
                                                    <Tooltip.Root>
                                                        <Tooltip.Trigger>
                                                            <span
                                                                class="text-xs font-medium"
                                                                >VEX</span
                                                            >
                                                        </Tooltip.Trigger>
                                                        <Tooltip.Content
                                                            >Vulnerability
                                                            Exploitability
                                                            eXchange</Tooltip.Content
                                                        >
                                                    </Tooltip.Root>
                                                </Table.Head>
                                            {/if}
                                            <Table.Head class="text-center">
                                                <SortButton
                                                    label="First Seen"
                                                    size="sm"
                                                    sortDirection={sortCol ===
                                                    "first_seen_at"
                                                        ? sortDir
                                                        : false}
                                                    onclick={(e: MouseEvent) =>
                                                        toggleVulnSort(
                                                            "first_seen_at",
                                                            e,
                                                        )}
                                                />
                                            </Table.Head>
                                            <Table.Head class="pr-6"
                                                >Description</Table.Head
                                            >
                                        </Table.Row>
                                    </Table.Header>
                                    <Table.Body>
                                        {#each visibleVulns as vuln (vuln.vuln_id)}
                                            <VulnRow
                                                {vuln}
                                                hasAnyVex={hasVexData}
                                            />
                                        {/each}
                                    </Table.Body>
                                </Table.Root>
                            </div>
                        {/if}

                        {#snippet failed(error, reset)}
                            <div
                                class="flex flex-col items-start gap-3 px-6 py-4"
                            >
                                <p class="text-sm font-medium text-destructive">
                                    Error rendering vulnerabilities: {error instanceof
                                    Error
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
                            <span class="text-muted-foreground/60"
                                >Scroll for more</span
                            >
                        {/if}
                    </div>
                {:else if totalCount > SUBVIEW_MAX_ROWS && !hasMore && currentOffset >= SUBVIEW_MAX_ROWS}
                    <div
                        class="border-t px-6 py-3 text-xs text-muted-foreground/80 bg-muted/20"
                    >
                        Showing {SUBVIEW_MAX_ROWS} of {totalCount.toLocaleString()}
                        vulnerabilities — use the severity filters above or sort
                        by CVSS / EPSS to prioritize.
                    </div>
                {:else if totalCount > 0 && totalCount > SUBVIEW_PAGE_SIZE}
                    <div
                        class="border-t px-6 py-2 text-[11px] text-muted-foreground/60"
                    >
                        Showing {currentOffset} of {totalCount.toLocaleString()}
                        vulnerabilities
                    </div>
                {/if}
            </div>
        </Table.Cell>
    </Table.Row>
{/if}
