<x-app-layout>
<x-slot name="header"><h2 class="font-semibold text-xl">{{ $scan->name }}</h2></x-slot>
<div class="py-6 max-w-7xl mx-auto sm:px-6 lg:px-8">
  <div class="bg-white dark:bg-gray-800 p-6 rounded-lg space-y-4">
    <div>
      <strong>Status:</strong> {{ $scan->status }} — {{ $scan->completed_targets }} / {{ $scan->total_targets }}
    </div>
    <div>
      <h3 class="font-semibold">Targets</h3>
      <table class="w-full">
        <thead><tr><th>Target</th><th>Status</th><th>Error</th></tr></thead>
        <tbody>
          @foreach($targets as $t)
            <tr class="border-t">
              <td class="py-1">{{ $t->target }}</td>
              <td class="py-1">{{ $t->status }}</td>
              <td class="py-1 text-red-600">{{ $t->last_error }}</td>
            </tr>
          @endforeach
        </tbody>
      </table>
      {{ $targets->links() }}
    </div>

    <div>
      <h3 class="font-semibold">Results (sample)</h3>
      <table class="w-full">
        <thead><tr><th>IP</th><th>Data</th></tr></thead>
        <tbody>
          @foreach($results as $r)
            <tr class="border-t">
              <td class="py-1">{{ $r->ip }}</td>
              <td class="py-1"><pre class="text-xs">{{ json_encode($r->data) }}</pre></td>
            </tr>
          @endforeach
        </tbody>
      </table>
      {{ $results->links() }}
    </div>
  </div>
</div>
</x-app-layout>
