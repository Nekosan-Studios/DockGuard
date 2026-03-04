<script lang="ts">
	import * as Card from '$lib/components/ui/card/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import Cylinder from '@lucide/svelte/icons/cylinder';
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Images</h1>
		<p class="text-muted-foreground">Scan history and vulnerability trends for your images.</p>
	</div>

	<Card.Root>
		<Card.Content>
			<div class="flex flex-col items-center justify-center gap-3 py-16 text-center">
				<Cylinder class="text-muted-foreground h-12 w-12" />
				<div>
					<p class="font-semibold">Images</p>
					<p class="text-muted-foreground mt-1 text-sm">
						Browse all scanned images, view vulnerability history over time, and compare digests.
					</p>
				</div>
				<Badge variant="outline">Coming Soon</Badge>
			</div>
		</Card.Content>
	</Card.Root>
</div>
