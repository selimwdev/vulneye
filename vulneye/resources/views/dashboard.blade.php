<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">
            {{ __('Dashboard') }}
        </h2>
    </x-slot>

    <meta name="csrf-token" content="{{ csrf_token() }}">

    <div class="py-12">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8 space-y-6">

            @forelse($scans as $scan)
            @php
                // اسم الملف ثابت حسب scan_id
                $pdfName = "scan_{$scan->id}_report.pdf";
                $pdfUrl = url("/storage/reports/scan_{$scan->id}/{$pdfName}");
            @endphp
            <div class="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-4">
                <div class="flex justify-between items-center">
                    <div>
                        <h3 class="font-semibold text-lg text-gray-700 dark:text-gray-200">{{ $scan->name }}</h3>
                        <p class="text-sm text-gray-500 dark:text-gray-400">
                            {{ $scan->targets_count }} IPs — Status: {{ $scan->status }}
                        </p>
                    </div>

                    <!-- Show IPs Button -->
                    <button onclick="document.getElementById('ips-{{ $scan->id }}').classList.toggle('hidden')"
                            class="px-2 py-1 border border-blue-500 text-blue-700 rounded-md hover:bg-blue-100 dark:hover:bg-blue-700 dark:text-blue-300">
                        Show IPs
                    </button>

                    <!-- Generate Report Button -->
                    <button
                        onclick="generateReport({{ $scan->id }}, this)"
                        class="px-2 py-1 border border-green-500 text-green-700 rounded-md hover:bg-green-100 dark:hover:bg-green-700 dark:text-green-300"
                    >
                        Generate Report
                    </button>

                    <!-- Report Status -->
                    <span id="report-status-{{ $scan->id }}" class="text-sm text-gray-500 ms-2">
                        <a href="{{ $pdfUrl }}" class="text-green-600 underline" target="_blank">Download PDF</a>
                    </span>
                </div>

                <div class="mt-2 hidden" id="ips-{{ $scan->id }}">
                    <textarea class="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-md bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-gray-200" rows="6" readonly>
@foreach($scan->targets as $target){{ $target->ip }}
@endforeach
                    </textarea>
                </div>
            </div>
            @empty
            <div class="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 text-gray-500 dark:text-gray-400">
                No scans found.
            </div>
            @endforelse

        </div>
    </div>

    <script>
        function generateReport(scanId, btn) {
            const statusEl = document.getElementById('report-status-' + scanId);
            btn.disabled = true;
            statusEl.textContent = 'Queued...';

            fetch("{{ url('/scans') }}/" + scanId + "/generate-report", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                },
                credentials: 'same-origin',
                body: JSON.stringify({ logo: 'logo4.svg' })
            })
            .then(response => response.json())
            .then(data => {
                if(data.status === 'queued'){
                    statusEl.textContent = 'Report queued...';
                    pollReport(scanId, statusEl, btn);
                } else {
                    statusEl.textContent = data.message || data.status;
                    btn.disabled = false;
                }
            })
            .catch(err => {
                statusEl.textContent = 'Error: ' + err.message;
                btn.disabled = false;
            });
        }

        function pollReport(scanId, statusEl, btn) {
            const pdfUrl = `/storage/reports/scan_${scanId}/scan_${scanId}_report.pdf`;
            const interval = setInterval(() => {
                fetch("{{ url('/scans') }}/" + scanId + "/report-status", {
                    credentials: 'same-origin'
                })
                .then(r => r.json())
                .then(j => {
                    if(j.status === 'ready'){
                        clearInterval(interval);
                        statusEl.innerHTML = `<a href="${pdfUrl}" class="text-green-600 underline" target="_blank">Download PDF</a>`;
                        btn.disabled = false;
                    } else if(j.status === 'failed'){
                        clearInterval(interval);
                        statusEl.textContent = 'Report generation failed';
                        btn.disabled = false;
                    } else {
                        // الرابط دايمًا ظاهر بدون timestamp
                        statusEl.innerHTML = `<a href="${pdfUrl}" class="text-green-600 underline" target="_blank">Download PDF</a> <span class="text-gray-500">Processing...</span>`;
                    }
                })
                .catch(err => {
                    clearInterval(interval);
                    statusEl.textContent = 'Error checking status';
                    btn.disabled = false;
                });
            }, 3000);
        }
    </script>
</x-app-layout>
