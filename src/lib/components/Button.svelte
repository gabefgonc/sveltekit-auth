<script lang="ts">
	export let type: string | undefined = undefined;
	let clazz: string = '';
	export { clazz as class };
</script>

<button
	{type}
	{...$$restProps}
	class={`${clazz || ''} bg-primary rounded-xl text-white text-2xl p-4`}
>
	<slot />
</button>
