<script lang="ts">
	import * as Card from '$lib/components/ui/card/index.js';
	import { Badge } from '$lib/components/ui/badge/index.js';
	import ListTodo from '@lucide/svelte/icons/list-todo';
</script>

<div class="flex flex-col gap-6">
	<div>
		<h1 class="text-2xl font-bold tracking-tight">Tasks</h1>
		<p class="text-muted-foreground">Background scan jobs and scheduler status.</p>
	</div>

	<Card.Root>
		<Card.Content>
			<div class="flex flex-col items-center justify-center gap-3 py-16 text-center">
				<ListTodo class="text-muted-foreground h-12 w-12" />
				<div>
					<p class="font-semibold">Tasks</p>
					<p class="text-muted-foreground mt-1 text-sm">
						Monitor scheduled scan jobs, view run history, and manage scan intervals.
					</p>
				</div>
				<Badge variant="outline">Coming Soon</Badge>
			</div>
		</Card.Content>
	</Card.Root>
</div>
