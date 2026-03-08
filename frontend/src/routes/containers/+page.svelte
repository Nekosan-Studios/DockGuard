<script lang="ts">
	import type { PageData } from "./$types";
	import * as Card from "$lib/components/ui/card/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import * as Table from "$lib/components/ui/table/index.js";
	import { SvelteSet, SvelteMap } from "svelte/reactivity";
	import Container from "@lucide/svelte/icons/container";
	import ShieldAlert from "@lucide/svelte/icons/shield-alert";
	import ChevronRight from "@lucide/svelte/icons/chevron-right";
	import ExternalLink from "@lucide/svelte/icons/external-link";
	import CircleCheck from "@lucide/svelte/icons/circle-check";
	import Loader2 from "@lucide/svelte/icons/loader-2";
	import SortButton from "./sort-button.svelte";
	import * as Tooltip from "$lib/components/ui/tooltip/index.js";
	import { formatDistanceToNow } from "date-fns";
	import { slide } from "svelte/transition";
	import { onMount, onDestroy } from "svelte";
	import CvssCell from "$lib/components/vuln/CvssCell.svelte";
	import EpssCell from "$lib/components/vuln/EpssCell.svelte";
	import KevCell from "$lib/components/vuln/KevCell.svelte";
	import VexStatusCell from "$lib/components/vuln/VexStatusCell.svelte";
	import SeverityCell from "$lib/components/vuln/SeverityCell.svelte";
	import { SEVERITY_CLASSES, toUtcDate } from "$lib/components/vuln/utils.js";
	import { Checkbox } from "$lib/components/ui/checkbox/index.js";

	let { data }: { data: PageData } = $props();

	let hideVexResolved = $state(false);
	let anyContainerHasVex = $derived(
		data.containers.some((c: { has_vex?: boolean }) => c.has_vex),
	);

	interface Vulnerability {
		id: number;
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
		vex_status: string | null;
		vex_justification: string | null;
		vex_statement: string | null;
	}

	const SEVERITY_ORDER = [
		"Critical",
		"High",
		"Medium",
		"Low",
		"Negligible",
		"Unknown",
	];

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
		const rows = [...data.containers];
		const dir = parentSortDir === "asc" ? 1 : -1;
		return rows.sort((a, b) => {
			switch (parentSortCol) {
				case "container_name":
					return (
						dir * a.container_name.localeCompare(b.container_name)
					);
				case "vulns": {
					for (const sev of SEVERITY_ORDER) {
						const diff =
							(a.vulns_by_severity[sev] ?? 0) -
							(b.vulns_by_severity[sev] ?? 0);
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

	// ── IntersectionObserver for sub-view sentinel divs ───────────────────────
	// We use a MutationObserver on the document body to detect when sentinel
	// divs (data-sentinel="imageName") appear in the DOM after Svelte renders them.
	// When a sentinel enters the viewport, we load the next page for that image.
	let subviewObservers = new Map<Element, IntersectionObserver>();
	let mutObs: MutationObserver | null = null;

	function attachSentinelIfNeeded(el: Element) {
		const imageName = (el as HTMLElement).dataset.sentinel;
		if (!imageName || subviewObservers.has(el)) return;
		const io = new IntersectionObserver(
			(entries) => {
				if (!entries[0].isIntersecting) return;
				const meta = getMeta(imageName);
				if (meta.hasMore && !meta.loadingMore) {
					const fetchedSev = partiallyLoadedSeverity.get(imageName);
					fetchVulns(
						imageName,
						fetchedSev,
						meta.offset,
						meta.sortCol,
						meta.sortDir,
					);
				}
			},
			{ rootMargin: "100px" },
		);
		io.observe(el);
		subviewObservers.set(el, io);
	}

	onMount(() => {
		// Observe existing and future sentinel divs.
		mutObs = new MutationObserver((mutations) => {
			for (const mut of mutations) {
				for (const node of mut.addedNodes) {
					if (node instanceof Element) {
						if ((node as HTMLElement).dataset.sentinel)
							attachSentinelIfNeeded(node);
						for (const el of node.querySelectorAll(
							"[data-sentinel]",
						))
							attachSentinelIfNeeded(el);
					}
				}
				for (const node of mut.removedNodes) {
					if (node instanceof Element) {
						const io = subviewObservers.get(node);
						if (io) {
							io.disconnect();
							subviewObservers.delete(node);
						}
					}
				}
			}
		});
		mutObs.observe(document.body, { childList: true, subtree: true });
	});

	onDestroy(() => {
		mutObs?.disconnect();
		for (const io of subviewObservers.values()) io.disconnect();
		subviewObservers.clear();
	});

	let expandedContainer = $state<string | null>(null);
	let containerVulns = new SvelteMap<string, Vulnerability[]>();
	let containerScanTimes = new SvelteMap<string, string>(); // imageName -> scanned_at ISO
	let loadingContainers = new SvelteSet<string>();
	let activeFilters = new SvelteMap<string, SvelteSet<string>>();
	// Maps imageName → the single severity that was fetched (e.g. 'Critical').
	// Not reactive — only read inside event handlers.
	const partiallyLoadedSeverity = new Map<string, string>();

	// ── Pagination state ────────────────────────────────────────────────────────
	// Soft cap: stop loading more rows once this many are accumulated.
	const SUBVIEW_MAX_ROWS = 400;
	const SUBVIEW_PAGE_SIZE = 200;

	interface VulnMeta {
		totalCount: number;
		offset: number;
		hasMore: boolean;
		loadingMore: boolean;
		sortCol: VulnSortCol | null;
		sortDir: "asc" | "desc";
	}
	let containerVulnsMeta = new SvelteMap<string, VulnMeta>();

	function getMeta(imageName: string): VulnMeta {
		return (
			containerVulnsMeta.get(imageName) ?? {
				totalCount: 0,
				offset: 0,
				hasMore: false,
				loadingMore: false,
				sortCol: null,
				sortDir: "asc",
			}
		);
	}

	// ── Sub-table sort (per-container) ─────────────────────────────────────────
	type VulnSortCol =
		| "vuln_id"
		| "severity"
		| "package_name"
		| "cvss_base_score"
		| "epss_score"
		| "is_kev"
		| "first_seen_at";

	function getVulnSortCol(imageName: string): VulnSortCol | null {
		return getMeta(imageName).sortCol;
	}

	function getVulnSortDir(imageName: string): "asc" | "desc" {
		return getMeta(imageName).sortDir;
	}

	function vulnSortDir(
		imageName: string,
		col: VulnSortCol,
	): "asc" | "desc" | false {
		const meta = getMeta(imageName);
		return meta.sortCol === col ? meta.sortDir : false;
	}

	function toggleVulnSort(
		imageName: string,
		col: VulnSortCol,
		e: MouseEvent,
	) {
		e.stopPropagation();
		const meta = getMeta(imageName);
		let newCol: VulnSortCol | null;
		let newDir: "asc" | "desc";
		if (meta.sortCol !== col) {
			newCol = col;
			newDir = "asc";
		} else if (meta.sortDir === "asc") {
			newCol = col;
			newDir = "desc";
		} else {
			newCol = null;
			newDir = "asc";
		}
		containerVulnsMeta.set(imageName, {
			...meta,
			sortCol: newCol,
			sortDir: newDir,
		});
		// Re-fetch from offset 0 with new sort
		const fetchedSev = partiallyLoadedSeverity.get(imageName);
		fetchVulns(imageName, fetchedSev, 0, newCol, newDir);
	}

	function timeAgo(iso: string): string {
		return formatDistanceToNow(toUtcDate(iso), { addSuffix: true });
	}

	function activeSeverities(vulnsBySeverity: Record<string, number>) {
		return SEVERITY_ORDER.filter((s) => (vulnsBySeverity[s] ?? 0) > 0);
	}

	async function fetchVulns(
		imageName: string,
		severity?: string,
		offset = 0,
		sortCol: VulnSortCol | null = null,
		sortDir: "asc" | "desc" = "asc",
	) {
		loadingContainers.add(imageName);
		const prevMeta = getMeta(imageName);
		containerVulnsMeta.set(imageName, { ...prevMeta, loadingMore: true });
		document.body.style.cursor = "wait";
		try {
			const params = new URLSearchParams({
				image_ref: imageName,
				limit: String(SUBVIEW_PAGE_SIZE),
				offset: String(offset),
				sort_by: sortCol ?? "severity",
				sort_dir: sortDir,
			});
			if (severity) params.set("severity", severity);
			const t0 = performance.now();
			const res = await fetch(`/api/vulnerabilities?${params}`);
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const payload = await res.json();
			console.log(
				`[DG] vuln fetch ${imageName}${severity ? ` (${severity})` : ""} offset=${offset}: ` +
					`${payload.count}/${payload.total_count} rows, ${(performance.now() - t0).toFixed(0)}ms`,
			);
			if (payload.scanned_at)
				containerScanTimes.set(imageName, payload.scanned_at);
			const newRows: Vulnerability[] = payload.vulnerabilities ?? [];
			const existing =
				offset === 0 ? [] : (containerVulns.get(imageName) ?? []);
			containerVulns.set(imageName, [...existing, ...newRows]);
			const totalLoaded = existing.length + newRows.length;
			const atSoftCap = totalLoaded >= SUBVIEW_MAX_ROWS;
			containerVulnsMeta.set(imageName, {
				totalCount: payload.total_count ?? newRows.length,
				offset: totalLoaded,
				hasMore: (payload.has_more ?? false) && !atSoftCap,
				loadingMore: false,
				sortCol,
				sortDir,
			});
			if (severity) {
				partiallyLoadedSeverity.set(imageName, severity);
			} else {
				partiallyLoadedSeverity.delete(imageName);
			}
		} catch (err) {
			console.error("Failed to fetch vulns for", imageName, err);
			if (offset === 0) containerVulns.set(imageName, []);
			containerVulnsMeta.set(imageName, {
				...getMeta(imageName),
				loadingMore: false,
				hasMore: false,
			});
		} finally {
			loadingContainers.delete(imageName);
			if (loadingContainers.size === 0) document.body.style.cursor = "";
		}
	}

	const AUTO_FILTER_THRESHOLD = 15;

	function toggleExpanded(
		containerName: string,
		imageName: string,
		hasScan: boolean,
		vulnsBySeverity: Record<string, number> = {},
		total = 0,
	) {
		if (!hasScan) return;
		if (expandedContainer === containerName) {
			expandedContainer = null;
		} else {
			expandedContainer = containerName;
			if (!containerVulns.has(imageName)) {
				// First open: auto-filter to highest severity when there are many vulns.
				const topSeverity =
					total >= AUTO_FILTER_THRESHOLD
						? SEVERITY_ORDER.find(
								(s) => (vulnsBySeverity[s] ?? 0) > 0,
							)
						: undefined;
				if (topSeverity) {
					activeFilters.set(imageName, new SvelteSet([topSeverity]));
					fetchVulns(imageName, topSeverity, 0, null, "asc");
				} else {
					fetchVulns(imageName, undefined, 0, null, "asc");
				}
			}
		}
	}

	function toggleFilter(imageName: string, severity: string, e: MouseEvent) {
		e.stopPropagation();
		if (!activeFilters.has(imageName))
			activeFilters.set(imageName, new SvelteSet<string>());
		const filters = activeFilters.get(imageName)!;
		if (filters.has(severity)) filters.delete(severity);
		else filters.add(severity);
		// Determine which severity to fetch based on new filter state.
		// If exactly one severity is selected, fetch only that; otherwise fetch all.
		const meta = getMeta(imageName);
		const fetchSev = filters.size === 1 ? [...filters][0] : undefined;
		// Re-fetch from offset 0 with current sort.
		fetchVulns(imageName, fetchSev, 0, meta.sortCol, meta.sortDir);
		if (fetchSev) {
			partiallyLoadedSeverity.set(imageName, fetchSev);
		} else {
			partiallyLoadedSeverity.delete(imageName);
		}
	}

	function isFilterActive(imageName: string, severity: string): boolean {
		return activeFilters.get(imageName)?.has(severity) ?? false;
	}

	function visibleVulns(imageName: string): Vulnerability[] {
		let vulns = containerVulns.get(imageName) ?? [];
		const filters = activeFilters.get(imageName);
		if (filters && filters.size > 0) {
			vulns = vulns.filter((v) => filters.has(v.severity));
		}
		if (hideVexResolved) {
			vulns = vulns.filter(
				(v) => v.vex_status !== "not_affected" && v.vex_status !== "fixed",
			);
		}
		return vulns;
	}

	function hasVexData(imageName: string): boolean {
		const vulns = containerVulns.get(imageName) ?? [];
		return vulns.some((v) => v.vex_status);
	}

	function isNew(
		vuln: Vulnerability,
		scannedAt: string | undefined,
	): boolean {
		if (!vuln.first_seen_at || !scannedAt) return false;
		// Compare as UTC timestamps to avoid timezone-skewed mismatches
		return (
			toUtcDate(vuln.first_seen_at).getTime() ===
			toUtcDate(scannedAt).getTime()
		);
	}

	function formatDate(iso: string): string {
		return toUtcDate(iso).toLocaleString();
	}
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Containers</h1>
		<p class="text-muted-foreground">
			Running containers and their vulnerability status.
		</p>
	</div>

	<Card.Root>
		<Card.Header class="flex flex-row items-center justify-between">
			<div class="space-y-1.5">
				<Card.Title>Running Containers</Card.Title>
				<Card.Description
					>Images currently running, cross-referenced with the latest scan
					results.</Card.Description
				>
			</div>
			{#if anyContainerHasVex}
				<label
					class="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer select-none"
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
							Hide vulnerabilities where the supplier has declared them
							"not affected" or "fixed" via VEX attestations.
						</Tooltip.Content>
					</Tooltip.Root>
				</label>
			{/if}
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
							>An unexpected error occurred while loading
							container data. Please try again shortly.</span
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
				<Table.Root>
					<Table.Header>
						<Table.Row>
							<Table.Head>
								<SortButton
									label="Container"
									sortDirection={parentSortCol ===
									"container_name"
										? parentSortDir
										: false}
									onclick={() =>
										toggleParentSort("container_name")}
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
									sortDirection={parentSortCol ===
									"scanned_at"
										? parentSortDir
										: false}
									onclick={() =>
										toggleParentSort("scanned_at")}
								/>
							</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each sortedContainers as container (container.container_name)}
							<!-- Parent row -->
							<Table.Row
								class={container.has_scan
									? "cursor-pointer hover:bg-muted/50"
									: ""}
								onclick={() =>
									toggleExpanded(
										container.container_name,
										container.image_name,
										container.has_scan,
										container.vulns_by_severity,
										container.total ?? 0,
									)}
							>
								<Table.Cell>
									<div class="flex items-center gap-2">
										<ChevronRight
											class="text-muted-foreground h-4 w-4 shrink-0 transition-transform duration-200 {expandedContainer ===
											container.container_name
												? 'rotate-90'
												: ''} {!container.has_scan
												? 'opacity-0'
												: ''}"
										/>
										<div>
											<div
												class="font-medium flex items-center gap-2"
											>
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
															This image includes VEX attestations from the supplier.
														</Tooltip.Content>
													</Tooltip.Root>
												{/if}
											</div>
											<div
												class="text-muted-foreground font-mono text-xs"
											>
												{container.image_name}
											</div>
										</div>
									</div>
								</Table.Cell>
								<Table.Cell>
									{#if container.has_scan}
										<div class="flex flex-wrap gap-1">
											{#each activeSeverities(container.vulns_by_severity) as sev (sev)}
												{#if expandedContainer === container.container_name}
													<button
														onclick={(e) =>
															toggleFilter(
																container.image_name,
																sev,
																e,
															)}
														class="inline-flex cursor-pointer items-center rounded-full border px-2 py-0.5 text-xs font-medium transition-all {SEVERITY_CLASSES[
															sev
														]} {isFilterActive(
															container.image_name,
															sev,
														)
															? 'ring-2 ring-offset-1 ring-current'
															: 'opacity-80 hover:opacity-100'}"
													>
														{container
															.vulns_by_severity[
															sev
														]}
														{sev}
													</button>
												{:else}
													<span
														class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {SEVERITY_CLASSES[
															sev
														]}"
													>
														{container
															.vulns_by_severity[
															sev
														]}
														{sev}
													</span>
												{/if}
											{/each}
											{#if activeSeverities(container.vulns_by_severity).length === 0}
												<span
													class="text-muted-foreground text-xs"
													>None found</span
												>
											{/if}
										</div>
									{:else}
										<span
											class="text-muted-foreground text-xs"
											>—</span
										>
									{/if}
								</Table.Cell>
								<Table.Cell class="text-center text-xs">
									{#if container.has_scan}
										<span class="text-muted-foreground"
											>{timeAgo(
												container.scanned_at,
											)}</span
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
							{#if expandedContainer === container.container_name}
								<Table.Row>
									<Table.Cell colspan={3} class="p-0">
										<div
											transition:slide={{ duration: 200 }}
											class="bg-muted/20 border-muted border-l-4 overflow-hidden"
										>
											{#if loadingContainers.has(container.image_name) && !getMeta(container.image_name).loadingMore}
												<div
													class="flex items-center gap-2 px-6 py-4 text-sm"
												>
													<Loader2
														class="text-muted-foreground h-4 w-4 animate-spin"
													/>
													<span
														class="text-muted-foreground"
														>Loading
														vulnerabilities…</span
													>
												</div>
											{:else}
												<svelte:boundary onerror={(e) => console.error("[DockGuard] sub-view render error:", e)}>
												{#if container.is_distro_eol}
													<div
														class="mx-6 mt-4 mb-2 rounded-md border border-orange-200 bg-orange-50 p-4 dark:border-orange-900/50 dark:bg-orange-900/10 text-orange-800 dark:text-orange-300 flex gap-3 text-sm"
													>
														<span
															class="font-medium"
															>End-of-Life OS{container.distro_display
																? ` (${container.distro_display})`
																: ""}:</span
														>
														<span
															>Vulnerability data
															may be incomplete or
															outdated.</span
														>
													</div>
												{/if}
												{@const vulns = visibleVulns(
													container.image_name,
												)}
												{@const meta = getMeta(
													container.image_name,
												)}
												{#if vulns.length === 0}
													<p
														class="text-muted-foreground px-6 py-4 text-sm"
													>
														{(activeFilters.get(
															container.image_name,
														)?.size ?? 0) > 0
															? "No vulnerabilities match the selected filters."
															: "No vulnerabilities found for this image."}
													</p>
												{:else}
													<div
														class="overflow-x-auto"
													>
														<Table.Root
															class="w-full min-w-[1000px] table-fixed text-xs"
														>
															<colgroup>
																<col
																	style="width:13%"
																/>
																<col
																	style="width:7%"
																/>
																<col
																	style="width:12%"
																/>
																<col
																	style="width:8%"
																/>
																<col
																	style="width:8%"
																/>
																<col
																	style="width:5%"
																/>
																<col
																	style="width:6%"
																/>
																<col
																	style="width:4%"
																/>
																{#if hasVexData(container.image_name)}
																	<col
																		style="width:4%"
																	/>
																{/if}
																<col
																	style="width:10%"
																/>
																<col
																	style="width:{hasVexData(container.image_name) ? '23' : '27'}%"
																/>
															</colgroup>
															<Table.Header>
																<Table.Row
																	class="bg-muted/30"
																>
																	<Table.Head
																		class="pl-2"
																	>
																		<SortButton
																			label="CVE ID"
																			size="sm"
																			sortDirection={vulnSortDir(
																				container.image_name,
																				"vuln_id",
																			)}
																			onclick={(
																				e,
																			) =>
																				toggleVulnSort(
																					container.image_name,
																					"vuln_id",
																					e,
																				)}
																		/>
																	</Table.Head>
																	<Table.Head
																		class="text-center"
																	>
																		<SortButton
																			label="Severity"
																			size="sm"
																			sortDirection={vulnSortDir(
																				container.image_name,
																				"severity",
																			)}
																			onclick={(
																				e,
																			) =>
																				toggleVulnSort(
																					container.image_name,
																					"severity",
																					e,
																				)}
																		/>
																	</Table.Head>
																	<Table.Head>
																		<SortButton
																			label="Package"
																			size="sm"
																			sortDirection={vulnSortDir(
																				container.image_name,
																				"package_name",
																			)}
																			onclick={(
																				e,
																			) =>
																				toggleVulnSort(
																					container.image_name,
																					"package_name",
																					e,
																				)}
																		/>
																	</Table.Head>
																	<Table.Head
																		class="text-center"
																		>Version</Table.Head
																	>
																	<Table.Head
																		class="text-center"
																		>Fixed
																		In</Table.Head
																	>
																	<Table.Head
																		class="text-center"
																	>
																		<Tooltip.Root
																		>
																			<Tooltip.Trigger
																			>
																				{#snippet child({
																					props,
																				})}
																					<SortButton
																						label="CVSS"
																						size="sm"
																						sortDirection={vulnSortDir(
																							container.image_name,
																							"cvss_base_score",
																						)}
																						{...props}
																						onclick={(
																							e,
																						) =>
																							toggleVulnSort(
																								container.image_name,
																								"cvss_base_score",
																								e,
																							)}
																					/>
																				{/snippet}
																			</Tooltip.Trigger>
																			<Tooltip.Content
																			>
																				Common
																				Vulnerability
																				Scoring
																				System.
																				A
																				0–10
																				numeric
																				score
																				measuring
																				severity:<br
																				/>
																				≥9.0
																				Critical
																				·
																				7.0–8.9
																				High
																				·
																				4.0–6.9
																				Medium
																				·
																				below
																				4.0
																				Low.
																			</Tooltip.Content>
																		</Tooltip.Root>
																	</Table.Head>
																	<Table.Head
																		class="text-center"
																	>
																		<Tooltip.Root
																		>
																			<Tooltip.Trigger
																			>
																				{#snippet child({
																					props,
																				})}
																					<SortButton
																						label="EPSS %"
																						size="sm"
																						sortDirection={vulnSortDir(
																							container.image_name,
																							"epss_score",
																						)}
																						{...props}
																						onclick={(
																							e,
																						) =>
																							toggleVulnSort(
																								container.image_name,
																								"epss_score",
																								e,
																							)}
																					/>
																				{/snippet}
																			</Tooltip.Trigger>
																			<Tooltip.Content
																			>
																				Exploit
																				Prediction
																				Scoring
																				System.
																				The
																				probability
																				this
																				vulnerability
																				will
																				be
																				exploited
																				in
																				the
																				wild
																				within
																				the
																				next
																				30
																				days.
																			</Tooltip.Content>
																		</Tooltip.Root>
																	</Table.Head>
																	<Table.Head
																		class="text-center"
																	>
																		<Tooltip.Root
																		>
																			<Tooltip.Trigger
																			>
																				{#snippet child({
																					props,
																				})}
																					<SortButton
																						label="KEV"
																						size="sm"
																						sortDirection={vulnSortDir(
																							container.image_name,
																							"is_kev",
																						)}
																						{...props}
																						onclick={(
																							e,
																						) =>
																							toggleVulnSort(
																								container.image_name,
																								"is_kev",
																								e,
																							)}
																					/>
																				{/snippet}
																			</Tooltip.Trigger>
																			<Tooltip.Content
																			>
																				Known
																				Exploited
																				Vulnerabilities.
																				A
																				✓
																				means
																				this
																				CVE
																				appears
																				in
																				the
																				CISA
																				KEV
																				catalog
																				—
																				confirmed
																				to
																				be
																				actively
																				exploited
																				in
																				the
																				wild.
																			</Tooltip.Content>
																		</Tooltip.Root>
																	</Table.Head>
																	{#if hasVexData(container.image_name)}
																		<Table.Head
																			class="text-center"
																		>
																			<Tooltip.Root>
																				<Tooltip.Trigger>
																					<span class="text-xs font-medium">VEX</span>
																				</Tooltip.Trigger>
																				<Tooltip.Content>
																					Vulnerability Exploitability eXchange — supplier assessment.
																				</Tooltip.Content>
																			</Tooltip.Root>
																		</Table.Head>
																	{/if}
																	<Table.Head
																		class="text-center"
																	>
																		<SortButton
																			label="First Seen"
																			size="sm"
																			sortDirection={vulnSortDir(
																				container.image_name,
																				"first_seen_at",
																			)}
																			onclick={(
																				e,
																			) =>
																				toggleVulnSort(
																					container.image_name,
																					"first_seen_at",
																					e,
																				)}
																		/>
																	</Table.Head>
																	<Table.Head
																		class="pr-6"
																		>Description</Table.Head
																	>
																</Table.Row>
															</Table.Header>
															<Table.Body>
																{#each vulns as vuln (vuln.id)}
																	<Table.Row
																		class="hover:bg-muted/30"
																	>
																		<Table.Cell
																			class="pl-2 font-mono"
																		>
																			<div
																				class="flex flex-wrap items-center gap-1"
																			>
																				{#if isNew(vuln, containerScanTimes.get(container.image_name))}
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
																					onclick={(
																						e,
																					) =>
																						e.stopPropagation()}
																					class="inline-flex items-center gap-1 text-blue-600 hover:underline dark:text-blue-400"
																					title={vuln.vuln_id}
																				>
																					{vuln.vuln_id}
																					<ExternalLink
																						class="h-3 w-3 shrink-0"
																					/>
																				</a>
																			</div>
																		</Table.Cell>
																		<SeverityCell
																			severity={vuln.severity}
																		/>
																		<Table.Cell
																			class="font-mono"
																		>
																			<Tooltip.Root
																			>
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
																				<Tooltip.Content
																					class="max-w-sm"
																				>
																					{@const paths =
																						vuln.locations
																							? vuln.locations.split(
																									"\n",
																								)
																							: []}
																					<p
																						class="mb-1 font-semibold"
																					>
																						{paths.length ===
																						1
																							? "Location:"
																							: "Locations:"}
																					</p>
																					{#if paths.length > 0}
																						<ul
																							class="space-y-0.5"
																						>
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
																							No
																							locations
																							noted.
																						</p>
																					{/if}
																				</Tooltip.Content>
																			</Tooltip.Root>
																		</Table.Cell>
																		<Table.Cell
																			class="text-center font-mono text-muted-foreground"
																			title={vuln.installed_version}
																			>{vuln.installed_version}</Table.Cell
																		>
																		<Table.Cell
																			class="text-center font-mono"
																			title={vuln.fixed_version ?? undefined}
																		>
																			{#if vuln.fixed_version}
																				{vuln.fixed_version}
																			{:else}
																				<span
																					class="text-muted-foreground"
																					>No
																					fix</span
																				>
																			{/if}
																		</Table.Cell>
																		<CvssCell
																			score={vuln.cvss_base_score}
																		/>
																		<EpssCell
																			score={vuln.epss_score}
																			percentile={vuln.epss_percentile}
																		/>
																		<KevCell
																			isKev={vuln.is_kev}
																		/>
																		{#if hasVexData(container.image_name)}
																			<VexStatusCell
																				vexStatus={vuln.vex_status}
																				vexJustification={vuln.vex_justification}
																				vexStatement={vuln.vex_statement}
																			/>
																		{/if}
																		<Table.Cell
																			class="text-center"
																		>
																			{#if vuln.first_seen_at}
																				<Tooltip.Root
																				>
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
																				<span
																					class="text-muted-foreground"
																					>—</span
																				>
																			{/if}
																		</Table.Cell>
																		<Table.Cell
																			class="text-muted-foreground pr-6 whitespace-normal"
																		>
																			<span
																				class="line-clamp-3"
																				title={vuln.description ??
																					undefined}
																			>
																				{vuln.description ?? ""}
																			</span>
																		</Table.Cell>
																	</Table.Row>
																{/each}
															</Table.Body>
														</Table.Root>
													</div>
												{/if}
												{#snippet failed(error, reset)}
													<div class="flex flex-col items-start gap-3 px-6 py-4">
														<p class="text-sm font-medium text-destructive">Error rendering vulnerabilities: {error.message}</p>
														<button class="text-xs underline text-muted-foreground" onclick={reset}>Try again</button>
													</div>
												{/snippet}
												</svelte:boundary>
											{/if}
											{#each [getMeta(container.image_name)] as capMeta}
												{#if capMeta.hasMore || capMeta.loadingMore}
													<!-- Infinite scroll sentinel: watched by MutationObserver + IntersectionObserver -->
													<div
														data-sentinel={container.image_name}
														class="flex items-center gap-2 border-t px-6 py-2 text-xs text-muted-foreground"
													>
														{#if capMeta.loadingMore}
															<Loader2
																class="h-3 w-3 animate-spin"
															/>
															<span
																>Loading more
																vulnerabilities…</span
															>
														{:else}
															<span
																class="text-muted-foreground/60"
																>Scroll for more</span
															>
														{/if}
													</div>
												{:else if capMeta.totalCount > SUBVIEW_MAX_ROWS && !capMeta.hasMore && capMeta.offset >= SUBVIEW_MAX_ROWS}
													<div
														class="border-t px-6 py-3 text-xs text-muted-foreground/80 bg-muted/20"
													>
														Showing {SUBVIEW_MAX_ROWS}
														of {capMeta.totalCount.toLocaleString()}
														vulnerabilities — use the
														severity filters above or
														sort by CVSS / EPSS to prioritize.
													</div>
												{:else if capMeta.totalCount > 0 && capMeta.totalCount > SUBVIEW_PAGE_SIZE}
													<div
														class="border-t px-6 py-2 text-[11px] text-muted-foreground/60"
													>
														Showing {capMeta.offset}
														of {capMeta.totalCount.toLocaleString()}
														vulnerabilities
													</div>
												{/if}
											{/each}
										</div>
									</Table.Cell>
								</Table.Row>
							{/if}
						{/each}
					</Table.Body>
				</Table.Root>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
