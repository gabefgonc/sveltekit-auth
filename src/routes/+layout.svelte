<script lang="ts">
	import '../app.css';
	import { page } from '$app/stores';
	import NavLink from '$lib/components/NavLink.svelte';
	import Button from '$lib/components/Button.svelte';
</script>

<svelte:head>
	<title>SvelteKit Auth</title>
</svelte:head>

<nav class="h-24 w-full flex justify-between items-center">
	{#if !$page.data.user}
		<div class="flex gap-4 m-2">
			<NavLink href="/login">Login</NavLink>
			<NavLink href="/register">Register</NavLink>
		</div>
	{/if}

	{#if $page.data.user}
		<div class="flex gap-4 m-2">
			<NavLink href="/admin">Admin</NavLink>

			<form action="/logout" method="POST">
				<Button type="submit">Log out</Button>
			</form>
		</div>
	{/if}
</nav>

<main class="page">
	<slot />
</main>
