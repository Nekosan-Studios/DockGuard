<script lang="ts">
	import LayoutDashboard from '@lucide/svelte/icons/layout-dashboard';
	import Container from '@lucide/svelte/icons/container';
	import Image from '@lucide/svelte/icons/image';
	import ListTodo from '@lucide/svelte/icons/list-todo';
	import Settings from '@lucide/svelte/icons/settings';
	import Shield from '@lucide/svelte/icons/shield';
	import * as Sidebar from '$lib/components/ui/sidebar/index.js';

	const items = [
		{ title: 'Dashboard', url: '/', icon: LayoutDashboard },
		{ title: 'Containers', url: '/containers', icon: Container },
		{ title: 'Images', url: '/images', icon: Image },
		{ title: 'Tasks', url: '/tasks', icon: ListTodo },
		{ title: 'Settings', url: '/settings', icon: Settings }
	];
</script>

<Sidebar.Root collapsible="icon">
	<Sidebar.Header>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<Sidebar.MenuButton size="lg" class="pointer-events-none">
					<div
						class="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground"
					>
						<Shield class="size-4" />
					</div>
					<div class="flex flex-col gap-0.5 leading-none">
						<span class="font-semibold">DockerWatch</span>
						<span class="text-xs text-muted-foreground">Security Monitor</span>
					</div>
				</Sidebar.MenuButton>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Header>

	<Sidebar.Content>
		<Sidebar.Group>
			<Sidebar.GroupLabel>Navigation</Sidebar.GroupLabel>
			<Sidebar.GroupContent>
				<Sidebar.Menu>
					{#each items as item (item.title)}
						<Sidebar.MenuItem>
							<Sidebar.MenuButton>
								{#snippet child({ props })}
									<a href={item.url} {...props}>
										<item.icon />
										<span>{item.title}</span>
									</a>
								{/snippet}
							</Sidebar.MenuButton>
						</Sidebar.MenuItem>
					{/each}
				</Sidebar.Menu>
			</Sidebar.GroupContent>
		</Sidebar.Group>
	</Sidebar.Content>

	<Sidebar.Rail />
</Sidebar.Root>
