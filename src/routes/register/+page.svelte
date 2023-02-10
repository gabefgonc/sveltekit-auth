<script lang="ts">
	import TextField from '$lib/components/TextField.svelte';
	import Button from '$lib/components/Button.svelte';
	import type { ActionData } from './$types';

	export let form: ActionData;
</script>

<div class="flex flex-col w-full h-full justify-center items-center">
	<h1 class="text-3xl font-bold">Register</h1>

	<form class="flex flex-col items-center" action="?/register" method="POST">
		{#if form?.userAlreadyExists}
			<p class="text-red-500">User already exists</p>
		{/if}

		{#if form?.message}
			<p class="text-red-500">{form.message}</p>
		{/if}
		<TextField name="Username" />
		<TextField name="Password" inputType="password" />
		<Button type="submit" class="mt-4">Register</Button>
	</form>
</div>
