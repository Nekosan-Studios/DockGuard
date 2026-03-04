<script lang="ts">
	import type { PageData } from './$types';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import * as Table from '$lib/components/ui/table/index.js';
	import { SvelteSet, SvelteMap } from 'svelte/reactivity';
	import Container from '@lucide/svelte/icons/container';
	import ChevronRight from '@lucide/svelte/icons/chevron-right';
	import ExternalLink from '@lucide/svelte/icons/external-link';
	import CircleCheck from '@lucide/svelte/icons/circle-check';
	import Loader2 from '@lucide/svelte/icons/loader-2';
	import SortButton from './sort-button.svelte';
	import * as Tooltip from '$lib/components/ui/tooltip/index.js';
	import { formatDistanceToNow } from 'date-fns';
	import { slide } from 'svelte/transition';

	let { data }: { data: PageData } = $props();

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
	}

	const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];

	const SEVERITY_CLASSES: Record<string, string> = {
		Critical:
			'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-800',
		High: 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800',
		Medium:
			'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/40 dark:text-amber-300 dark:border-amber-800',
		Low: 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/40 dark:text-blue-300 dark:border-blue-800',
		Negligible:
			'bg-gray-100 text-gray-600 border-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:border-gray-600',
		Unknown:
			'bg-gray-100 text-gray-500 border-gray-300 dark:bg-gray-800 dark:text-gray-500 dark:border-gray-600'
	};

	// ── Parent table sort ──────────────────────────────────────────────────────
	type ParentSortCol = 'container_name' | 'vulns' | 'scanned_at';
	let parentSortCol = $state<ParentSortCol>('container_name');
	let parentSortDir = $state<'asc' | 'desc'>('asc');

	function toggleParentSort(col: ParentSortCol) {
		if (parentSortCol === col) {
			parentSortDir = parentSortDir === 'asc' ? 'desc' : 'asc';
		} else {
			parentSortCol = col;
			parentSortDir = 'asc';
		}
	}

	let sortedContainers = $derived.by(() => {
		const rows = [...data.containers];
		const dir = parentSortDir === 'asc' ? 1 : -1;
		return rows.sort((a, b) => {
			switch (parentSortCol) {
				case 'container_name':
					return dir * a.container_name.localeCompare(b.container_name);
				case 'vulns': {
					for (const sev of SEVERITY_ORDER) {
						const diff = (a.vulns_by_severity[sev] ?? 0) - (b.vulns_by_severity[sev] ?? 0);
						if (diff !== 0) return dir * diff;
					}
					return 0;
				}
				case 'scanned_at': {
					if (!a.scanned_at && !b.scanned_at) return 0;
					if (!a.scanned_at) return 1;
					if (!b.scanned_at) return -1;
					return dir * (a.scanned_at < b.scanned_at ? -1 : a.scanned_at > b.scanned_at ? 1 : 0);
				}
			}
		});
	});

	// ── Expandable row state ───────────────────────────────────────────────────
	let expandedContainers = new SvelteSet<string>();
	let containerVulns = new SvelteMap<string, Vulnerability[]>();
	let loadingContainers = new SvelteSet<string>();
	let activeFilters = new SvelteMap<string, SvelteSet<string>>();

	// ── Sub-table sort (per-container, three-way: none → asc → desc → none) ──
	type VulnSortCol =
		| 'vuln_id' | 'severity' | 'package_name'
		| 'cvss_base_score' | 'epss_score' | 'is_kev';
	interface VulnSort { col: VulnSortCol | null; dir: 'asc' | 'desc' }
	let vulnSortStates = new SvelteMap<string, VulnSort>();

	function getVulnSort(imageName: string): VulnSort {
		return vulnSortStates.get(imageName) ?? { col: null, dir: 'asc' };
	}

	function toggleVulnSort(imageName: string, col: VulnSortCol, e: MouseEvent) {
		e.stopPropagation();
		const current = getVulnSort(imageName);
		if (current.col !== col) {
			vulnSortStates.set(imageName, { col, dir: 'asc' });
		} else if (current.dir === 'asc') {
			vulnSortStates.set(imageName, { col, dir: 'desc' });
		} else {
			vulnSortStates.set(imageName, { col: null, dir: 'asc' }); // back to default
		}
	}

	function vulnSortDir(imageName: string, col: VulnSortCol): 'asc' | 'desc' | false {
		const s = getVulnSort(imageName);
		return s.col === col ? s.dir : false;
	}

	function sortedVulns(imageName: string, vulns: Vulnerability[]): Vulnerability[] {
		const { col, dir } = getVulnSort(imageName);
		if (!col) return vulns; // default: severity → CVSS desc from fetchVulns
		const m = dir === 'asc' ? 1 : -1;
		return [...vulns].sort((a, b) => {
			switch (col) {
				case 'vuln_id':
					return m * a.vuln_id.localeCompare(b.vuln_id);
				case 'severity':
					return m * (SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
				case 'package_name':
					return m * a.package_name.localeCompare(b.package_name);
				case 'cvss_base_score': {
					if (a.cvss_base_score === null && b.cvss_base_score === null) return 0;
					if (a.cvss_base_score === null) return 1;
					if (b.cvss_base_score === null) return -1;
					return m * (a.cvss_base_score - b.cvss_base_score);
				}
				case 'epss_score': {
					if (a.epss_score === null && b.epss_score === null) return 0;
					if (a.epss_score === null) return 1;
					if (b.epss_score === null) return -1;
					return m * (a.epss_score - b.epss_score);
				}
				case 'is_kev':
					return m * ((b.is_kev ? 1 : 0) - (a.is_kev ? 1 : 0));
			}
		});
	}

	function timeAgo(iso: string): string {
		return formatDistanceToNow(new Date(iso), { addSuffix: true });
	}

	function activeSeverities(vulnsBySeverity: Record<string, number>) {
		return SEVERITY_ORDER.filter((s) => (vulnsBySeverity[s] ?? 0) > 0);
	}

	async function fetchVulns(imageName: string) {
		loadingContainers.add(imageName);
		try {
			const res = await fetch(`/api/vulnerabilities?image_ref=${encodeURIComponent(imageName)}`);
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const payload = await res.json();
			const raw: Vulnerability[] = Array.isArray(payload)
				? payload
				: (payload.vulnerabilities ?? []);
			const sorted = raw.slice().sort((a, b) => {
				const si = SEVERITY_ORDER.indexOf(a.severity);
				const sj = SEVERITY_ORDER.indexOf(b.severity);
				if (si !== sj) return si - sj;
				return (b.cvss_base_score ?? 0) - (a.cvss_base_score ?? 0);
			});
			containerVulns.set(imageName, sorted);
		} catch (err) {
			console.error('Failed to fetch vulns for', imageName, err);
			containerVulns.set(imageName, []);
		} finally {
			loadingContainers.delete(imageName);
		}
	}

	const AUTO_FILTER_THRESHOLD = 15;

	function toggleExpanded(imageName: string, hasScan: boolean, vulnsBySeverity: Record<string, number> = {}, total = 0) {
		if (!hasScan) return;
		if (expandedContainers.has(imageName)) {
			expandedContainers.delete(imageName);
		} else {
			const isFirstOpen = !containerVulns.has(imageName);
			expandedContainers.add(imageName);
			if (isFirstOpen) {
				fetchVulns(imageName);
				// Auto-filter to highest severity on first open, but only if there are enough vulns
				if (total >= AUTO_FILTER_THRESHOLD) {
					const topSeverity = SEVERITY_ORDER.find((s) => (vulnsBySeverity[s] ?? 0) > 0);
					if (topSeverity) {
						activeFilters.set(imageName, new SvelteSet([topSeverity]));
					}
				}
			}
		}
	}

	function toggleFilter(imageName: string, severity: string, e: MouseEvent) {
		e.stopPropagation();
		if (!activeFilters.has(imageName)) activeFilters.set(imageName, new SvelteSet<string>());
		const filters = activeFilters.get(imageName)!;
		if (filters.has(severity)) filters.delete(severity);
		else filters.add(severity);
	}

	function isFilterActive(imageName: string, severity: string): boolean {
		return activeFilters.get(imageName)?.has(severity) ?? false;
	}

	function visibleVulns(imageName: string): Vulnerability[] {
		const vulns = containerVulns.get(imageName) ?? [];
		const filters = activeFilters.get(imageName);
		if (!filters || filters.size === 0) return vulns;
		return vulns.filter((v) => filters.has(v.severity));
	}

	function truncate(text: string | null, max = 120): string {
		if (!text) return '';
		return text.length > max ? text.slice(0, max) + '…' : text;
	}

	function cvssTooltip(score: number): string {
		if (score >= 9.0) return 'Critical severity';
		if (score >= 7.0) return 'High severity';
		if (score >= 4.0) return 'Medium severity';
		return 'Low severity';
	}

	function epssTooltip(score: number): string {
		if (score >= 0.5) return 'Very high exploitation risk';
		if (score >= 0.1) return 'Elevated exploitation risk';
		if (score >= 0.01) return 'Moderate exploitation risk';
		return 'Low exploitation risk';
	}

	function cvssClass(score: number | null): string {
		if (score === null) return 'text-muted-foreground';
		if (score >= 9.0) return 'font-bold text-red-700 dark:text-red-400';
		if (score >= 7.0) return 'font-semibold text-orange-600 dark:text-orange-400';
		if (score >= 4.0) return 'text-amber-600 dark:text-amber-400';
		return 'text-muted-foreground';
	}

	function epssClass(score: number | null): string {
		if (score === null) return 'text-muted-foreground';
		if (score >= 0.5) return 'font-bold text-red-700 dark:text-red-400';
		if (score >= 0.1) return 'font-semibold text-orange-600 dark:text-orange-400';
		if (score >= 0.01) return 'text-amber-600 dark:text-amber-400';
		return 'text-muted-foreground';
	}
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Containers</h1>
		<p class="text-muted-foreground">Running containers and their vulnerability status.</p>
	</div>

	<Card.Root>
		<Card.Header>
			<Card.Title>Running Containers</Card.Title>
			<Card.Description
				>Images currently running, cross-referenced with the latest scan results.</Card.Description
			>
		</Card.Header>
		<Card.Content>
			{#if data.containers.length === 0}
				<div class="flex flex-col items-center justify-center gap-2 py-8 text-center">
					<Container class="text-muted-foreground h-10 w-10" />
					<p class="text-muted-foreground text-sm">No running containers found.</p>
					<Badge variant="outline">Waiting for data</Badge>
				</div>
			{:else}
				<Table.Root>
					<Table.Header>
						<Table.Row>
							<Table.Head>
								<SortButton
									label="Container"
									sortDirection={parentSortCol === 'container_name' ? parentSortDir : false}
									onclick={() => toggleParentSort('container_name')}
								/>
							</Table.Head>
							<Table.Head>
								<SortButton
									label="Vulnerabilities"
									sortDirection={parentSortCol === 'vulns' ? parentSortDir : false}
									onclick={() => toggleParentSort('vulns')}
								/>
							</Table.Head>
							<Table.Head class="w-[180px] text-center">
								<SortButton
									label="Last Scanned"
									sortDirection={parentSortCol === 'scanned_at' ? parentSortDir : false}
									onclick={() => toggleParentSort('scanned_at')}
								/>
							</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each sortedContainers as container (container.image_name)}
							<!-- Parent row -->
							<Table.Row
								class={container.has_scan ? 'cursor-pointer hover:bg-muted/50' : ''}
								onclick={() => toggleExpanded(container.image_name, container.has_scan, container.vulns_by_severity, container.total ?? 0)}
							>
								<Table.Cell>
									<div class="flex items-center gap-2">
										<ChevronRight
											class="text-muted-foreground h-4 w-4 shrink-0 transition-transform duration-200 {expandedContainers.has(
												container.image_name
											)
												? 'rotate-90'
												: ''} {!container.has_scan ? 'opacity-0' : ''}"
										/>
										<div>
											<div class="font-medium">{container.container_name}</div>
											<div class="text-muted-foreground font-mono text-xs">
												{container.image_name}
											</div>
										</div>
									</div>
								</Table.Cell>
								<Table.Cell>
									{#if container.has_scan}
										<div class="flex flex-wrap gap-1">
											{#each activeSeverities(container.vulns_by_severity) as sev (sev)}
												{#if expandedContainers.has(container.image_name)}
													<button
														onclick={(e) => toggleFilter(container.image_name, sev, e)}
														class="inline-flex cursor-pointer items-center rounded-full border px-2 py-0.5 text-xs font-medium transition-all {SEVERITY_CLASSES[sev]} {isFilterActive(
															container.image_name,
															sev
														)
															? 'ring-2 ring-offset-1 ring-current'
															: 'opacity-80 hover:opacity-100'}"
													>
														{container.vulns_by_severity[sev]}
														{sev}
													</button>
												{:else}
													<span
														class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {SEVERITY_CLASSES[sev]}"
													>
														{container.vulns_by_severity[sev]}
														{sev}
													</span>
												{/if}
											{/each}
											{#if activeSeverities(container.vulns_by_severity).length === 0}
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
							{#if expandedContainers.has(container.image_name)}
								<Table.Row>
									<Table.Cell colspan={3} class="p-0">
										<div transition:slide={{ duration: 200 }} class="bg-muted/20 border-muted border-l-4 overflow-hidden">
											{#if loadingContainers.has(container.image_name)}
												<div class="flex items-center gap-2 px-6 py-4 text-sm">
													<Loader2 class="text-muted-foreground h-4 w-4 animate-spin" />
													<span class="text-muted-foreground">Loading vulnerabilities…</span>
												</div>
											{:else}
												{@const vulns = sortedVulns(container.image_name, visibleVulns(container.image_name))}
												{#if vulns.length === 0}
													<p class="text-muted-foreground px-6 py-4 text-sm">
														{(activeFilters.get(container.image_name)?.size ?? 0) > 0
															? 'No vulnerabilities match the selected filters.'
															: 'No vulnerabilities found for this image.'}
													</p>
												{:else}
													<div class="overflow-x-auto">
														<Table.Root class="w-full table-fixed text-xs">
															<colgroup>
																<col style="width:13%" />
																<col style="width:7%" />
																<col style="width:14%" />
																<col style="width:9%" />
																<col style="width:9%" />
																<col style="width:6%" />
																<col style="width:7%" />
																<col style="width:5%" />
																<col style="width:30%" />
															</colgroup>
															<Table.Header>
																<Table.Row class="bg-muted/30">
																	<Table.Head class="pl-2">
																		<SortButton
																			label="CVE ID"
																			size="sm"
																			sortDirection={vulnSortDir(container.image_name, 'vuln_id')}
																			onclick={(e) => toggleVulnSort(container.image_name, 'vuln_id', e)}
																		/>
																	</Table.Head>
																	<Table.Head class="text-center">
																		<SortButton
																			label="Severity"
																			size="sm"
																			sortDirection={vulnSortDir(container.image_name, 'severity')}
																			onclick={(e) => toggleVulnSort(container.image_name, 'severity', e)}
																		/>
																	</Table.Head>
																	<Table.Head>
																		<SortButton
																			label="Package"
																			size="sm"
																			sortDirection={vulnSortDir(container.image_name, 'package_name')}
																			onclick={(e) => toggleVulnSort(container.image_name, 'package_name', e)}
																		/>
																	</Table.Head>
																	<Table.Head class="text-center">Version</Table.Head>
																	<Table.Head class="text-center">Fixed In</Table.Head>
																	<Table.Head class="text-center">
																		<Tooltip.Root>
																			<Tooltip.Trigger>
																				{#snippet child({ props })}
																					<SortButton
																						label="CVSS"
																						size="sm"
																						sortDirection={vulnSortDir(container.image_name, 'cvss_base_score')}
																						{...props}
																						onclick={(e) => toggleVulnSort(container.image_name, 'cvss_base_score', e)}
																					/>
																				{/snippet}
																			</Tooltip.Trigger>
																			<Tooltip.Content>
																				Common Vulnerability Scoring System. A 0–10 numeric score measuring severity:<br />
																				≥9.0 Critical · 7.0–8.9 High · 4.0–6.9 Medium · below 4.0 Low.
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
																						sortDirection={vulnSortDir(container.image_name, 'epss_score')}
																						{...props}
																						onclick={(e) => toggleVulnSort(container.image_name, 'epss_score', e)}
																					/>
																				{/snippet}
																			</Tooltip.Trigger>
																			<Tooltip.Content>
																				Exploit Prediction Scoring System. The probability this vulnerability will be exploited in the wild within the next 30 days.
																			</Tooltip.Content>
																		</Tooltip.Root>
																	</Table.Head>
																	<Table.Head class="text-center">
																		<Tooltip.Root>
																			<Tooltip.Trigger>
																				{#snippet child({ props })}
																					<SortButton
																						label="KEV"
																						size="sm"
																						sortDirection={vulnSortDir(container.image_name, 'is_kev')}
																						{...props}
																						onclick={(e) => toggleVulnSort(container.image_name, 'is_kev', e)}
																					/>
																				{/snippet}
																			</Tooltip.Trigger>
																			<Tooltip.Content>
																				Known Exploited Vulnerabilities. A ✓ means this CVE appears in the CISA KEV catalog — confirmed to be actively exploited in the wild.
																			</Tooltip.Content>
																		</Tooltip.Root>
																	</Table.Head>
																	<Table.Head class="pr-6">Description</Table.Head>
																</Table.Row>
															</Table.Header>
															<Table.Body>
																{#each vulns as vuln (vuln.vuln_id + vuln.package_name + vuln.installed_version)}
																	<Table.Row class="hover:bg-muted/30">
																		<Table.Cell class="pl-2 font-mono">
																			<a
																				href={vuln.data_source ??
																					`https://nvd.nist.gov/vuln/detail/${vuln.vuln_id}`}
																				target="_blank"
																				rel="noopener noreferrer"
																				onclick={(e) => e.stopPropagation()}
																				class="inline-flex items-center gap-1 text-blue-600 hover:underline dark:text-blue-400"
																			>
																				{vuln.vuln_id}
																				<ExternalLink class="h-3 w-3 shrink-0" />
																			</a>
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
																				<Tooltip.Trigger class="cursor-default text-left">
																					<div class="flex flex-wrap items-baseline gap-x-1.5 gap-y-0.5">
																						<span>{vuln.package_name}</span>
																						{#if vuln.package_type}
																							<span class="inline-flex items-center rounded border border-slate-200 bg-slate-100 px-1 py-0 font-sans text-[10px] text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
																								{vuln.package_type}
																							</span>
																						{/if}
																					</div>
																				</Tooltip.Trigger>
																				<Tooltip.Content class="max-w-sm">
																					{@const paths = vuln.locations ? vuln.locations.split('\n') : []}
																					<p class="mb-1 font-semibold">{paths.length === 1 ? 'Location:' : 'Locations:'}</p>
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
																						<p class="text-xs text-muted-foreground">No locations noted.</p>
																					{/if}
																				</Tooltip.Content>
																			</Tooltip.Root>
																		</Table.Cell>
																		<Table.Cell class="text-center font-mono text-muted-foreground"
																			>{vuln.installed_version}</Table.Cell
																		>
																		<Table.Cell class="text-center font-mono">
																			{#if vuln.fixed_version}
																				{vuln.fixed_version}
																			{:else}
																				<span class="text-muted-foreground">No fix</span>
																			{/if}
																		</Table.Cell>
																		<Table.Cell class="text-center {cvssClass(vuln.cvss_base_score)}">
																			{#if vuln.cvss_base_score != null}
																				<Tooltip.Root>
																					<Tooltip.Trigger class="cursor-default">
																						{vuln.cvss_base_score.toFixed(1)}
																					</Tooltip.Trigger>
																					<Tooltip.Content>{cvssTooltip(vuln.cvss_base_score)}</Tooltip.Content>
																				</Tooltip.Root>
																			{:else}
																				—
																			{/if}
																		</Table.Cell>
																		<Table.Cell class="text-center {epssClass(vuln.epss_score)}">
																			{#if vuln.epss_score != null}
																				<Tooltip.Root>
																					<Tooltip.Trigger class="cursor-default">
																						{(vuln.epss_score * 100).toFixed(2)}%
																					</Tooltip.Trigger>
																					<Tooltip.Content>
																						<p>{epssTooltip(vuln.epss_score)}</p>
																						{#if vuln.epss_percentile != null}
																							{@const pct = Math.round(vuln.epss_percentile * 100)}
																							<p class="mt-1 {pct >= 90 ? 'font-semibold text-red-400' : pct >= 70 ? 'text-orange-400' : ''}">
																								{#if pct >= 50}
																									More likely to be exploited than {pct}% of all other vulnerabilities.
																								{:else}
																									{100 - pct}% of all other vulnerabilities are more likely to be exploited.
																								{/if}
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
																					<Tooltip.Trigger class="cursor-default">
																						<CircleCheck class="mx-auto h-4 w-4 text-red-600 dark:text-red-400" />
																					</Tooltip.Trigger>
																					<Tooltip.Content>Known Exploited Vulnerability — this CVE is confirmed to be actively exploited in the wild by CISA.</Tooltip.Content>
																				</Tooltip.Root>
																			{:else}
																				<Tooltip.Root>
																					<Tooltip.Trigger class="cursor-default">
																						<span class="text-muted-foreground">—</span>
																					</Tooltip.Trigger>
																					<Tooltip.Content>No confirmed exploit in the wild — not listed in the CISA KEV catalog.</Tooltip.Content>
																				</Tooltip.Root>
																			{/if}
																		</Table.Cell>
																		<Table.Cell class="text-muted-foreground pr-6">
																			<span title={vuln.description ?? undefined}>
																				{truncate(vuln.description)}
																			</span>
																		</Table.Cell>
																	</Table.Row>
																{/each}
															</Table.Body>
														</Table.Root>
													</div>
												{/if}
											{/if}
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
