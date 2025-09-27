<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-2xl text-gray-800 dark:text-gray-200 leading-tight">
            Network Discovery
        </h2>
    </x-slot>

    <div class="py-6 max-w-7xl mx-auto sm:px-6 lg:px-8">
        <div class="bg-white dark:bg-gray-800 shadow-sm sm:rounded-lg p-6 space-y-6">

            <!-- Form -->
            <form id="scanForm" class="space-y-4">
                <div>
                    <label for="targets" class="block mb-2 text-gray-700 dark:text-gray-200">Enter IP ranges (one per line)</label>
                    <textarea id="targets" name="targets" rows="6" placeholder="Example:
192.168.1.0/24
10.0.0.1-10.0.0.20"
                        class="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200"></textarea>
                    <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Supports address lists — will be sent as an array to the server</p>
                </div>

                <!-- Controls -->
                <div class="flex flex-wrap items-center gap-3">
                    <button type="submit" class="px-2 py-1 border border-blue-500 text-blue-700 rounded-md hover:bg-blue-100 dark:hover:bg-blue-700 dark:text-blue-300">Start Scan</button>
                    <span id="status" class="text-gray-500 dark:text-gray-400"></span>

                    <div class="ml-auto flex items-center gap-2 flex-wrap">
                        <label class="flex items-center gap-1">
                            Delimiter:
                            <select id="delimiter" class="p-1 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-200">
                                <option value=",">Comma (CSV)</option>
                                <option value="\n">New Line</option>
                                <option value=" ">Space</option>
                            </select>
                        </label>

                        <label class="flex items-center gap-1">
                            <input type="checkbox" id="includeNotes" class="h-4 w-4 text-blue-600 rounded border-gray-300 dark:border-gray-600">
                            Include Notes
                        </label>

                        <button id="copyBtn" type="button" class="px-2 py-1 border border-gray-400 rounded-md text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700" disabled>Copy</button>
                        <button id="downloadBtn" type="button" class="px-2 py-1 border border-green-500 text-green-700 rounded-md hover:bg-green-100 dark:hover:bg-green-700 dark:text-green-300" disabled>Download</button>
                        <button id="previewBtn" type="button" class="px-2 py-1 border border-blue-500 text-blue-700 rounded-md hover:bg-blue-100 dark:hover:bg-blue-700 dark:text-blue-300" disabled>Preview</button>
                    </div>
                </div>
            </form>

            <hr class="border-gray-300 dark:border-gray-600">

            <!-- Results -->
            <h5 class="text-lg font-semibold text-gray-700 dark:text-gray-200">Results — Live IPs Only</h5>
            <div id="results" class="mt-2 overflow-auto"></div>

            <!-- Preview -->
            <div id="previewContainer" class="mt-3 hidden">
                <h6 class="font-medium text-gray-700 dark:text-gray-200">Preview:</h6>
                <pre id="preview" class="bg-gray-100 dark:bg-gray-700 p-2 rounded-md text-gray-900 dark:text-gray-200 overflow-auto"></pre>
            </div>
        </div>
    </div>

    <script>
        const statusEl = document.getElementById('status');
        const resultsEl = document.getElementById('results');
        const copyBtn = document.getElementById('copyBtn');
        const downloadBtn = document.getElementById('downloadBtn');
        const previewBtn = document.getElementById('previewBtn');
        const delimiterEl = document.getElementById('delimiter');
        const includeNotesEl = document.getElementById('includeNotes');
        const previewContainer = document.getElementById('previewContainer');
        const previewEl = document.getElementById('preview');

        // Correct Laravel route
        const scanUrl = "{{ route('network-scan.scan') }}";

        let currentLive = [];

        document.getElementById('scanForm').addEventListener('submit', async function (e) {
            e.preventDefault();
            resultsEl.innerHTML = '';
            previewContainer.style.display = 'none';
            statusEl.textContent = 'Sending...';
            toggleExportButtons(false);

            const lines = document.getElementById('targets').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
            if (lines.length === 0) {
                statusEl.textContent = 'Please enter at least one range.';
                return;
            }

            try {
                const resp = await fetch(scanUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                    },
                    body: JSON.stringify({ targets: lines })
                });

                if (!resp.ok) {
                    let bodyText = await resp.text();
                    statusEl.textContent = 'Server error: ' + resp.status + ' - ' + bodyText;
                    toggleExportButtons(false);
                    return;
                }

                const json = await resp.json();
                const live = json.live || [];
                currentLive = live.slice();

                renderResults(live);
                if (live.length === 0) {
                    statusEl.textContent = 'No live IPs found.';
                    toggleExportButtons(false);
                } else {
                    statusEl.textContent = 'Done. ' + live.length + ' live IPs.';
                    toggleExportButtons(true);
                }
            } catch (err) {
                statusEl.textContent = 'Error: ' + err.message;
                toggleExportButtons(false);
            }
        });

        function renderResults(live) {
            resultsEl.innerHTML = '';
            if (!live || live.length === 0) {
                resultsEl.innerHTML = '<div class="text-gray-500 dark:text-gray-400">No live IPs found.</div>';
                return;
            }

            const table = document.createElement('table');
            table.className = 'w-full table-auto border-collapse';
            table.innerHTML = '<thead><tr class="bg-gray-200 dark:bg-gray-700"><th class="border px-2 py-1">IP</th><th class="border px-2 py-1">Source</th></tr></thead>';
            const tbody = document.createElement('tbody');
            live.forEach(r => {
                const ip = r.ip || '';
                const sources = r.target_sources ? r.target_sources.join(', ') : '';
                const tr = document.createElement('tr');
                tr.innerHTML = `<td class="border px-2 py-1">${escapeHtml(ip)}</td><td class="border px-2 py-1">${escapeHtml(sources)}</td>`;
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            resultsEl.appendChild(table);
        }

        function escapeHtml(str) {
            return String(str || '').replace(/[&<>"'`]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;'}[s]));
        }

        function toggleExportButtons(enabled) {
            copyBtn.disabled = !enabled;
            downloadBtn.disabled = !enabled;
            previewBtn.disabled = !enabled;
        }

        function buildExportString() {
            const delimRaw = delimiterEl.value;
            const delim = delimRaw === '\\n' ? '\n' : delimRaw;
            const includeNotes = includeNotesEl.checked;

            const parts = currentLive.map(r => {
                const ip = r.ip || '';
                const sources = r.target_sources ? r.target_sources.join(', ') : '';
                if (includeNotes && sources) return `${ip} - ${sources}`;
                return ip;
            }).filter(Boolean);

            if (delim === ',' && includeNotesEl.checked) {
                const escaped = parts.map(p => p.includes(',') || p.includes('"') ? `"${p.replace(/"/g,'""')}"` : p);
                return escaped.join(delim);
            }

            return parts.join(delim);
        }

        copyBtn.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(buildExportString());
                statusEl.textContent = 'Copied to clipboard.';
            } catch (err) {
                statusEl.textContent = 'Copy failed: ' + err.message;
            }
        });

        downloadBtn.addEventListener('click', () => {
            const txt = buildExportString();
            const ext = delimiterEl.value === ',' ? 'csv' : 'txt';
            const blob = new Blob([txt], { type: 'text/plain;charset=utf-8' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `live_ips.${ext}`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(a.href);
            statusEl.textContent = `Downloaded live_ips.${ext}`;
        });

        previewBtn.addEventListener('click', () => {
            previewEl.textContent = buildExportString() || '(Nothing to display)';
            previewContainer.style.display = 'block';
        });

        delimiterEl.addEventListener('change', () => { if (previewContainer.style.display !== 'none') previewEl.textContent = buildExportString(); });
        includeNotesEl.addEventListener('change', () => { if (previewContainer.style.display !== 'none') previewEl.textContent = buildExportString(); });
    </script>
</x-app-layout>
