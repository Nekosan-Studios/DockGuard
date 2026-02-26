<script lang="ts">
	import * as Card from '$lib/components/ui/card/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import Settings from '@lucide/svelte/icons/settings';
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Settings</h1>
		<p class="text-muted-foreground">Configure scan intervals, notifications, and integrations.</p>
	</div>

	<Card.Root>
		<Card.Content>
			<div class="flex flex-col items-center justify-center gap-3 py-16 text-center">
				<Settings class="text-muted-foreground h-12 w-12" />
				<div>
					<p class="font-semibold">Settings</p>
					<p class="text-muted-foreground mt-1 text-sm">
						Adjust scan frequency, set alert thresholds, and manage notification channels.
					</p>
				</div>
				<Badge variant="outline">Coming Soon</Badge>
			</div>
		</Card.Content>
	</Card.Root>
</div>
