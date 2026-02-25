<script lang="ts">
	import * as Card from '$lib/components/ui/card/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import Shield from '@lucide/svelte/icons/shield';
	import Container from '@lucide/svelte/icons/container';
	import Image from '@lucide/svelte/icons/image';
	import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
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
			<div class="flex flex-col items-center justify-center gap-2 py-8 text-center">
				<Shield class="text-muted-foreground h-10 w-10" />
				<p class="text-muted-foreground text-sm">No scans have run yet.</p>
				<Badge variant="outline">Waiting for data</Badge>
			</div>
		</Card.Content>
	</Card.Root>
</div>
