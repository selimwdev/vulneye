<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Scan;
use App\Models\ScanTarget;
use App\Jobs\ScanIpBatchJob;

class NetworkSecurityScannerController extends Controller
{
    public function index()
    {
        return view('network-security-scanner');
    }

    public function submit(Request $request)
    {
        $request->validate([
            'ips' => 'required|array|min:1',
            'ips.*' => 'required|string'
        ]);

        $ips = $request->input('ips');
        $name = $request->input('name') ?: 'network-scan-'.date('Ymd-His');

        // create scan record
        $scan = Scan::create([
            'name' => $name,
            'status' => 'pending',
            'total_targets' => count($ips),
            'completed_targets' => 0,
        ]);

        // create scan targets and collect ids
        $targetRecords = [];
        foreach ($ips as $ip) {
            $t = ScanTarget::create([
                'scan_id' => $scan->id,
                'target' => $ip,
                'status' => 'pending'
            ]);
            $targetRecords[] = ['id' => $t->id, 'target' => $t->target];
        }

        // dispatch batches of size 5 (you can tune this)
        $batchSize = 5;
        $chunks = array_chunk($targetRecords, $batchSize);

        foreach ($chunks as $chunk) {
            ScanIpBatchJob::dispatch($scan->id, $chunk);
        }

        // mark scan running (optionally)
        $scan->update(['status' => 'running']);

        return response()->json([
            'message' => count($chunks) . ' jobs submitted',
            'scan_id' => $scan->id,
        ]);
    }
}
