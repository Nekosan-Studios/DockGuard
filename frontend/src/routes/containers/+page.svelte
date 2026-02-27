<script lang="ts">
	import type { PageData } from "./$types";
	import * as Card from "$lib/components/ui/card/index.js";
	import { Badge } from "$lib/components/ui/badge/index.js";
	import Container from "@lucide/svelte/icons/container";
	import { formatDistanceToNow } from "date-fns";
	import DataTable from "./data-table.svelte";
	import {
		createColumns,
		activeSeverities,
		SEVERITY_CLASSES,
		type ContainerRow,
	} from "./columns.js";

	let { data }: { data: PageData } = $props();

	const columns = createColumns(containerCell, vulnsCell, scannedCell);

	function timeAgo(iso: string): string {
		return formatDistanceToNow(new Date(iso), { addSuffix: true });
	}
</script>

{#snippet containerCell({ row }: { row: ContainerRow })}
	<div class="font-medium">{row.container_name}</div>
	<div class="text-muted-foreground font-mono text-xs">{row.image_name}</div>
{/snippet}

{#snippet vulnsCell({ row }: { row: ContainerRow })}
	{#if row.has_scan}
		<div class="flex flex-wrap gap-1">
			{#each activeSeverities(row.vulns_by_severity) as sev (sev)}
				<span
					class="inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium {SEVERITY_CLASSES[
						sev
					]}"
				>
					{row.vulns_by_severity[sev]}
					{sev}
				</span>
			{/each}
			{#if activeSeverities(row.vulns_by_severity).length === 0}
				<span class="text-muted-foreground text-xs">None found</span>
			{/if}
		</div>
	{:else}
		<span class="text-muted-foreground text-xs">—</span>
	{/if}
{/snippet}

{#snippet scannedCell({ row }: { row: ContainerRow })}
	{#if row.has_scan}
		<span class="text-muted-foreground">{timeAgo(row.scanned_at!)}</span>
	{:else}
		<span
			class="inline-flex items-center rounded-full border border-amber-200 bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 dark:border-amber-800 dark:bg-amber-900/40 dark:text-amber-300"
		>
			Not yet scanned
		</span>
	{/if}
{/snippet}

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Containers</h1>
		<p class="text-muted-foreground">
			Running containers and their vulnerability status.
		</p>
	</div>

	<Card.Root>
		<Card.Header>
			<Card.Title>Running Containers</Card.Title>
			<Card.Description
				>Images currently running, cross-referenced with the latest scan
				results.</Card.Description
			>
		</Card.Header>
		<Card.Content>
			{#if data.containers.length === 0}
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
				<DataTable {columns} data={data.containers} />
			{/if}
		</Card.Content>
	</Card.Root>
</div>
