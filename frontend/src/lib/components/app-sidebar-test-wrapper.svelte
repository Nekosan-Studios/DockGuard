<script lang="ts">
    import * as Sidebar from "$lib/components/ui/sidebar/index.js";
    import AppSidebar from "./app-sidebar.svelte";
</script>

<Sidebar.Provider>
    <AppSidebar />
</Sidebar.Provider>
