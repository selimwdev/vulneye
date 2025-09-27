<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">
            Network Security Scanner
        </h2>
    </x-slot>

    <div class="py-6 max-w-7xl mx-auto sm:px-6 lg:px-8">
        <div class="bg-white dark:bg-gray-800 shadow-sm sm:rounded-lg p-6">
            <form id="scanForm" class="space-y-4">
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-200">Scan Name (optional)</label>
                <input type="text" id="scanName" class="w-full p-2 border rounded-md bg-white dark:bg-gray-700" placeholder="network-scan-test-1">

                <label for="ips" class="block text-gray-700 dark:text-gray-200">Enter IPs (one per line):</label>
                <textarea id="ips" rows="10" class="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200"></textarea>

                <div class="flex items-center gap-3">
                    <button type="submit" class="px-2 py-1 border border-blue-500 text-blue-700 rounded-md hover:bg-blue-100 dark:hover:bg-blue-700 dark:text-blue-300">Start Scan</button>
                    <span id="status" class="text-gray-600 dark:text-gray-300"></span>
                </div>
            </form>

            <div class="mt-6">
                <h3 class="font-semibold text-gray-700 dark:text-gray-200">Scan Info</h3>
                <pre id="scanInfo" class="bg-gray-100 dark:bg-gray-700 p-3 rounded-md"></pre>
            </div>
        </div>
    </div>

    <script>
        const scanForm = document.getElementById('scanForm');
        const statusEl = document.getElementById('status');
        const scanInfo = document.getElementById('scanInfo');

        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            statusEl.textContent = 'Submitting...';
            scanInfo.textContent = '';

            const ips = document.getElementById('ips').value.split(/\r?\n/).map(i => i.trim()).filter(Boolean);
            const name = document.getElementById('scanName').value.trim();

            const resp = await fetch("{{ route('network-security-scanner.submit') }}", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': document.querySelector('meta[name=\"csrf-token\"]').getAttribute('content')
                },
                body: JSON.stringify({ ips, name })
            });

            const data = await resp.json();
            if (resp.ok) {
                statusEl.textContent = 'Jobs submitted. Scan ID: ' + data.scan_id;
                scanInfo.textContent = JSON.stringify(data, null, 2);
            } else {
                statusEl.textContent = 'Error: ' + (data.message || 'server error');
            }
        });
    </script>
</x-app-layout>
