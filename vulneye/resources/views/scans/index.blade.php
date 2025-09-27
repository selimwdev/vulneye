<x-app-layout>
<x-slot name="header"><h2 class="font-semibold text-xl">Scans</h2></x-slot>
<div class="py-6 max-w-7xl mx-auto sm:px-6 lg:px-8">
  <div class="bg-white dark:bg-gray-800 p-6 rounded-lg">
    <table class="w-full">
      <thead><tr><th>Name</th><th>Status</th><th>Total</th><th>Completed</th><th>Started</th><th></th></tr></thead>
      <tbody>
        @foreach($scans as $s)
          <tr class="border-t">
            <td class="py-2">{{ $s->name }}</td>
            <td class="py-2">{{ $s->status }}</td>
            <td class="py-2">{{ $s->total_targets }}</td>
            <td class="py-2">{{ $s->completed_targets }}</td>
            <td class="py-2">{{ $s->created_at }}</td>
            <td class="py-2"><a href="{{ route('scans.show',$s) }}" class="text-blue-600">View</a></td>
          </tr>
        @endforeach
      </tbody>
    </table>

    {{ $scans->links() }}
  </div>
</div>
</x-app-layout>
