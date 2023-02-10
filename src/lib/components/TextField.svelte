<script lang="ts">
  export let inputType: string = 'text'
  export let name: string
</script>

<div class="flex flex-col">
  <label class="text-xl font-bold text-slate-800" for={name.toLowerCase()}>{name}</label>
  <input class="h-10 w-80 bg-gray-300 rounded-lg" type={inputType} name={name.toLowerCase()}>
</div>
