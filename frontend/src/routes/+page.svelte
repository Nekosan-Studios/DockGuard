<script lang="ts">
	import type { PageData } from './$types';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import * as Table from '$lib/components/ui/table/index.js';
	import * as Chart from '$lib/components/ui/chart/index.js';
	import { LineChart } from 'layerchart';
	import Shield from '@lucide/svelte/icons/shield';
	import Container from '@lucide/svelte/icons/container';
	import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
	import Zap from '@lucide/svelte/icons/zap';
	import CircleCheck from '@lucide/svelte/icons/circle-check';
	import CircleX from '@lucide/svelte/icons/circle-x';

	import { formatDistanceToNow, format, parseISO } from 'date-fns';

	let { data }: { data: PageData } = $props();

	// Severity display order and color classes
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

	function timeAgo(iso: string): string {
		return formatDistanceToNow(new Date(iso), { addSuffix: true });
	}

	function activeSeverities(vulnsBySeverity: Record<string, number>) {
		return SEVERITY_ORDER.filter((s) => (vulnsBySeverity[s] ?? 0) > 0);
	}

	// Chart config
	const chartConfig = {
		critical: {
			label: 'Critical Vulnerabilities',
			color: 'var(--chart-1)'
		}
	} satisfies Chart.ChartConfig;

	// Parse trend dates for display
	const trendData = $derived(
		(data.summary.trend ?? []).map((d: { date: string; critical: number }) => ({
			...d,
			label: format(new Date(d.date + 'T12:00:00'), 'MMM d')
		}))
	);

	const hasTrend = $derived(trendData.length > 0);

	function formatDbBuilt(iso: string | null): string {
		if (!iso) return '—';
		return format(parseISO(iso), 'MMM d, yyyy');
	}
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Dashboard</h1>
		<p class="text-muted-foreground">Overview of your Docker security posture.</p>
	</div>

	<!-- Status bar -->
	<div class="bg-muted/50 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg border px-4 py-2.5 text-xs">
		<!-- Docker connectivity -->
		<span class="flex items-center gap-1.5">
			{#if data.summary.docker_connected}
				<CircleCheck class="h-3.5 w-3.5 text-green-500" />
				<span class="text-foreground font-medium">Docker</span>
				<span class="text-muted-foreground">Connected</span>
			{:else}
				<CircleX class="h-3.5 w-3.5 text-red-500" />
				<span class="text-foreground font-medium">Docker</span>
				<span class="text-red-500">Disconnected</span>
			{/if}
		</span>

		<span class="text-border select-none">|</span>

		<!-- Grype version -->
		<span class="flex items-center gap-1.5">
			<span class="text-muted-foreground">Grype</span>
			<span class="text-foreground font-medium">{data.summary.grype_version ?? '—'}</span>
		</span>

		<span class="text-border select-none">|</span>

		<!-- Vuln DB built -->
		<span class="flex items-center gap-1.5">
			<span class="text-muted-foreground">Vuln DB</span>
			<span class="text-foreground font-medium">{formatDbBuilt(data.summary.db_built)}</span>
		</span>

		<span class="text-border select-none">|</span>

		<!-- Last DB check -->
		<span class="flex items-center gap-1.5">
			<span class="text-muted-foreground">Last checked</span>
			<span class="text-foreground font-medium">
				{data.summary.last_db_checked_at ? timeAgo(data.summary.last_db_checked_at) : '—'}
			</span>
		</span>
	</div>

	<!-- Stat cards -->
	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<!-- Running containers + images scanned -->
		<Card.Root>
			<Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
				<Card.Title class="text-sm font-medium">Environment</Card.Title>
				<Container class="text-muted-foreground h-4 w-4" />
			</Card.Header>
			<Card.Content>
				{#if data.summary.running_containers === null}
					<div class="text-2xl font-bold">—</div>
					<p class="text-muted-foreground text-xs">No data yet</p>
				{:else}
					<div class="text-2xl font-bold">{data.summary.running_containers}</div>
					<p class="text-muted-foreground text-xs">
						running container{data.summary.running_containers === 1 ? '' : 's'} &middot;
						{data.summary.images_scanned} image{data.summary.images_scanned === 1 ? '' : 's'} scanned
					</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Critical vulnerabilities -->
		<Card.Root>
			<Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
				<Card.Title class="text-sm font-medium">Critical Vulnerabilities</Card.Title>
				<TriangleAlert class="text-muted-foreground h-4 w-4" />
			</Card.Header>
			<Card.Content>
				{#if data.summary.critical_count === null}
					<div class="text-2xl font-bold">—</div>
					<p class="text-muted-foreground text-xs">No data yet</p>
				{:else}
					<div class="text-2xl font-bold">{data.summary.critical_count}</div>
					<p class="text-muted-foreground text-xs">across running containers</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Actively exploited (KEV) -->
		<Card.Root>
			<Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
				<Card.Title class="text-sm font-medium">Actively Exploited</Card.Title>
				<Zap class="text-muted-foreground h-4 w-4" />
			</Card.Header>
			<Card.Content>
				{#if data.summary.kev_count === null}
					<div class="text-2xl font-bold">—</div>
					<p class="text-muted-foreground text-xs">No data yet</p>
				{:else}
					<div class="text-2xl font-bold {data.summary.kev_count > 0 ? 'text-red-600 dark:text-red-400' : ''}">
						{data.summary.kev_count}
					</div>
					<p class="text-muted-foreground text-xs">known exploited vulnerabilities (KEV)</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- New vulnerabilities (24h) -->
		<Card.Root>
			<Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
				<Card.Title class="text-sm font-medium">New (Last 24h)</Card.Title>
				<Shield class="text-muted-foreground h-4 w-4" />
			</Card.Header>
			<Card.Content>
				{#if data.summary.new_vulns_24h === null}
					<div class="text-2xl font-bold">—</div>
					<p class="text-muted-foreground text-xs">No data yet</p>
				{:else}
					<div class="text-2xl font-bold {(data.summary.new_vulns_24h ?? 0) > 0 ? 'text-amber-600 dark:text-amber-400' : ''}">
						{data.summary.new_vulns_24h ?? 0}
					</div>
					<p class="text-muted-foreground text-xs">newly discovered vulnerabilities</p>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>

	<!-- Critical vuln trend chart -->
	<Card.Root>
		<Card.Header>
			<Card.Title>Critical Vulnerabilities — 30-Day Trend</Card.Title>
			<Card.Description>
				Total critical vulnerabilities across all scanned images per day.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			{#if !hasTrend}
				<div class="flex flex-col items-center justify-center gap-2 py-8 text-center">
					<Shield class="text-muted-foreground h-10 w-10" />
					<p class="text-muted-foreground text-sm">No scan data yet — trend will appear here.</p>
				</div>
			{:else}
				<Chart.Container config={chartConfig} class="h-[200px] w-full">
					<LineChart
						data={trendData}
						x="label"
						series={[
							{
								key: 'critical',
								label: chartConfig.critical.label,
								color: chartConfig.critical.color
							}
						]}
						axis={true}
						props={{
							xAxis: {
								format: (d: string) => d
							},
							yAxis: {
								format: (d: number) => Number.isInteger(d) ? String(d) : '',
								ticks: 4
							}
						}}
					>
						{#snippet tooltip()}
							<Chart.Tooltip indicator="line" />
						{/snippet}
					</LineChart>
				</Chart.Container>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Recent activity -->
	<Card.Root>
		<Card.Header>
			<Card.Title>Recent Activity</Card.Title>
			<Card.Description>Latest scan results and detected changes.</Card.Description>
		</Card.Header>
		<Card.Content>
			{#if data.activities.length === 0}
				<div class="flex flex-col items-center justify-center gap-2 py-8 text-center">
					<Shield class="text-muted-foreground h-10 w-10" />
					<p class="text-muted-foreground text-sm">No scans have run yet.</p>
					<Badge variant="outline">Waiting for data</Badge>
				</div>
			{:else}
				<Table.Root>
					<Table.Header>
						<Table.Row>
							<Table.Head class="w-[80px]">Type</Table.Head>
							<Table.Head class="w-[130px]">Scanned</Table.Head>
							<Table.Head>Container</Table.Head>
							<Table.Head>Image</Table.Head>
							<Table.Head>Vulnerabilities</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each data.activities as activity (activity.scan_id)}
							<Table.Row>
								<Table.Cell>
									<span
										class="inline-flex items-center rounded-full border border-indigo-200 bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-700 dark:border-indigo-800 dark:bg-indigo-900/40 dark:text-indigo-300"
									>
										Scan
									</span>
								</Table.Cell>
								<Table.Cell class="text-muted-foreground text-xs">
									{timeAgo(activity.scanned_at)}
								</Table.Cell>
								<Table.Cell class="text-sm">
									{#if activity.container_name}
										{activity.container_name}
									{:else}
										<span class="text-muted-foreground">—</span>
									{/if}
								</Table.Cell>
								<Table.Cell class="font-mono text-sm">
									{activity.image_name}
								</Table.Cell>
								<Table.Cell>
									<div class="flex flex-wrap gap-1">
										{#each activeSeverities(activity.vulns_by_severity) as sev (sev)}
											<span
												class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {SEVERITY_CLASSES[sev]}"
											>
												{activity.vulns_by_severity[sev]}
												{sev}
											</span>
										{/each}
									</div>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
