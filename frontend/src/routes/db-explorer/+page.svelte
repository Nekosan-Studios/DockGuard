<script lang="ts">
	import Database from '@lucide/svelte/icons/database';
	import * as Card from '$lib/components/ui/card/index.js';
	import * as Table from '$lib/components/ui/table/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';

	let { data } = $props();

	type TableData = {
		table: string;
		columns: string[];
		rows: Record<string, unknown>[];
		count: number;
	};

	let selectedTable = $state<string>(data.tables[0] ?? '');
	let tableData = $state<TableData | null>(null);
	let loading = $state(false);
	let error = $state<string | null>(null);

	async function loadTable(tableName: string) {
		if (!tableName) return;
		loading = true;
		error = null;
		tableData = null;
		try {
			const res = await fetch(`/api/db/${encodeURIComponent(tableName)}`);
			if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
			tableData = await res.json();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Unknown error';
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		loadTable(selectedTable);
	});

	function formatValue(val: unknown): string {
		if (val === null || val === undefined) return '';
		const s = String(val);
		return s.length > 80 ? s.slice(0, 80) + '…' : s;
	}

	function isNull(val: unknown): boolean {
		return val === null || val === undefined;
	}
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">DB Explorer</h1>
		<p class="text-muted-foreground">Read-only view of the application database.</p>
	</div>

	<Card.Root>
		<Card.Header>
			<div class="flex flex-wrap items-center gap-3">
				{#if data.tables.length === 0}
					<span class="text-muted-foreground text-sm">No tables available.</span>
				{:else}
					<select
						bind:value={selectedTable}
						class="border-input bg-background ring-offset-background focus:ring-ring flex h-9 rounded-md border px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-1"
					>
						{#each data.tables as table}
							<option value={table}>{table}</option>
						{/each}
					</select>
					{#if tableData}
						<Badge variant="secondary">{tableData.count} row{tableData.count !== 1 ? 's' : ''}</Badge>
						<Badge variant="outline">{tableData.columns.length} column{tableData.columns.length !== 1 ? 's' : ''}</Badge>
						{#if tableData.count === 100}
							<span class="text-muted-foreground text-xs">Showing first 100 rows</span>
						{/if}
					{/if}
				{/if}
			</div>
		</Card.Header>

		<Card.Content>
			{#if loading}
				<div class="text-muted-foreground flex items-center justify-center py-16 text-sm">
					Loading…
				</div>
			{:else if error}
				<div class="flex items-center justify-center py-16 text-center">
					<div>
						<p class="text-destructive font-medium">Failed to load table</p>
						<p class="text-muted-foreground mt-1 text-sm">{error}</p>
					</div>
				</div>
			{:else if !tableData || tableData.rows.length === 0}
				<div class="flex flex-col items-center justify-center gap-3 py-16 text-center">
					<Database class="text-muted-foreground h-10 w-10" />
					<p class="text-muted-foreground text-sm">
						{tableData ? 'No rows in this table.' : 'Select a table to browse its rows.'}
					</p>
				</div>
			{:else}
				<div class="overflow-auto rounded-md border">
					<Table.Root>
						<Table.Header>
							<Table.Row>
								{#each tableData.columns as col}
									<Table.Head class="whitespace-nowrap font-mono text-xs">{col}</Table.Head>
								{/each}
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{#each tableData.rows as row}
								<Table.Row>
									{#each tableData.columns as col}
										<Table.Cell
											class="max-w-xs font-mono text-xs {isNull(row[col])
												? 'text-muted-foreground italic'
												: ''}"
										>
											{isNull(row[col]) ? 'null' : formatValue(row[col])}
										</Table.Cell>
									{/each}
								</Table.Row>
							{/each}
						</Table.Body>
					</Table.Root>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
