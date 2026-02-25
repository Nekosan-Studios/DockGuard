<script lang="ts">
	import type { PageData } from './$types';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import * as Table from '$lib/components/ui/table/index.js';
	import Shield from '@lucide/svelte/icons/shield';
	import Container from '@lucide/svelte/icons/container';
	import Image from '@lucide/svelte/icons/image';
	import TriangleAlert from '@lucide/svelte/icons/triangle-alert';

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

	function formatDate(iso: string): string {
		const d = new Date(iso);
		return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
	}

	function formatTime(iso: string): string {
		const d = new Date(iso);
		return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
	}

	function activeSeverities(vulnsBySeverity: Record<string, number>) {
		return SEVERITY_ORDER.filter((s) => (vulnsBySeverity[s] ?? 0) > 0);
	}
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Dashboard</h1>
		<p class="text-muted-foreground">Overview of your Docker security posture.</p>
	</div>

	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<Card.Root>
			<Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
				<Card.Title class="text-sm font-medium">Running Containers</Card.Title>
				<Container class="text-muted-foreground h-4 w-4" />
			</Card.Header>
			<Card.Content>
				<div class="text-2xl font-bold">—</div>
				<p class="text-muted-foreground text-xs">No data yet</p>
			</Card.Content>
		</Card.Root>

		<Card.Root>
			<Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
				<Card.Title class="text-sm font-medium">Images Scanned</Card.Title>
				<Image class="text-muted-foreground h-4 w-4" />
			</Card.Header>
			<Card.Content>
				<div class="text-2xl font-bold">—</div>
				<p class="text-muted-foreground text-xs">No data yet</p>
			</Card.Content>
		</Card.Root>

		<Card.Root>
			<Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
				<Card.Title class="text-sm font-medium">Critical Vulnerabilities</Card.Title>
				<TriangleAlert class="text-muted-foreground h-4 w-4" />
			</Card.Header>
			<Card.Content>
				<div class="text-2xl font-bold">—</div>
				<p class="text-muted-foreground text-xs">No data yet</p>
			</Card.Content>
		</Card.Root>

		<Card.Root>
			<Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
				<Card.Title class="text-sm font-medium">Security Score</Card.Title>
				<Shield class="text-muted-foreground h-4 w-4" />
			</Card.Header>
			<Card.Content>
				<div class="text-2xl font-bold">—</div>
				<p class="text-muted-foreground text-xs">No data yet</p>
			</Card.Content>
		</Card.Root>
	</div>

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
							<Table.Head>Image</Table.Head>
							<Table.Head>Vulnerabilities</Table.Head>
							<Table.Head class="w-[70px] text-right">Total</Table.Head>
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
									<div>{formatDate(activity.scanned_at)}</div>
									<div>{formatTime(activity.scanned_at)}</div>
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
								<Table.Cell class="text-muted-foreground text-right text-sm">
									{activity.total}
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
