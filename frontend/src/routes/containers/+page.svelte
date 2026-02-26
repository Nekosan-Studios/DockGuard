<script lang="ts">
	import type { PageData } from './$types';
	import * as Card from '$lib/components/ui/card/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import * as Table from '$lib/components/ui/table/index.js';
	import Container from '@lucide/svelte/icons/container';
	import { formatDistanceToNow } from 'date-fns';

	let { data }: { data: PageData } = $props();

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
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Containers</h1>
		<p class="text-muted-foreground">Running containers and their vulnerability status.</p>
	</div>

	<Card.Root>
		<Card.Header>
			<Card.Title>Running Containers</Card.Title>
			<Card.Description>Images currently running, cross-referenced with the latest scan results.</Card.Description>
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
							<Table.Head>Container</Table.Head>
							<Table.Head>Vulnerabilities</Table.Head>
							<Table.Head class="w-[70px] text-right">Total</Table.Head>
							<Table.Head class="w-[150px]">Last Scanned</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each data.containers as container (container.image_name)}
							<Table.Row>
								<Table.Cell>
									<div class="font-medium">{container.container_name}</div>
									<div class="text-muted-foreground font-mono text-xs">{container.image_name}</div>
								</Table.Cell>
								<Table.Cell>
									{#if container.has_scan}
										<div class="flex flex-wrap gap-1">
											{#each activeSeverities(container.vulns_by_severity) as sev (sev)}
												<span
													class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {SEVERITY_CLASSES[sev]}"
												>
													{container.vulns_by_severity[sev]}
													{sev}
												</span>
											{/each}
											{#if activeSeverities(container.vulns_by_severity).length === 0}
												<span class="text-muted-foreground text-xs">None found</span>
											{/if}
										</div>
									{:else}
										<span class="text-muted-foreground text-xs">—</span>
									{/if}
								</Table.Cell>
								<Table.Cell class="text-muted-foreground text-right text-sm">
									{#if container.has_scan}
										{container.total}
									{:else}
										—
									{/if}
								</Table.Cell>
								<Table.Cell class="text-xs">
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
						{/each}
					</Table.Body>
				</Table.Root>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
