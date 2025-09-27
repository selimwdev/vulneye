<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use App\Models\Scan;
use App\Models\ScanTarget;
use App\Models\ScanResult;
use Illuminate\Support\Facades\Log;

class ScanIpBatchJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $scanId;
    protected $targets; // array of scan_target ids OR target strings
    protected $batchSize;

    public $tries = 3;
    public $timeout = 0;

    public function __construct(int $scanId, array $targets, int $batchSize = 20)
    {
        $this->scanId = $scanId;
        $this->targets = $targets;
        $this->batchSize = $batchSize;
    }

    public function handle()
    {
        $scan = Scan::find($this->scanId);
        if (!$scan) {
            Log::error("Scan not found: ID {$this->scanId}");
            return;
        }

        if ($scan->status !== 'running') {
            $scan->update(['status' => 'running']);
        }

        $batches = array_chunk($this->targets, $this->batchSize);

        foreach ($batches as $batchIndex => $batch) {
            Log::info("Processing batch ".($batchIndex+1)." of ".count($batches));

            foreach ($batch as $targetItem) {
                if (is_array($targetItem)) {
                    $targetId = $targetItem['id'];
                    $targetStr = $targetItem['target'];
                } else {
                    $targetId = $targetItem;
                    $targetModel = ScanTarget::find($targetId);
                    if (!$targetModel) {
                        Log::warning("Target not found: ID {$targetId}");
                        continue;
                    }
                    $targetStr = $targetModel->target;
                }

                $targetModel = ScanTarget::find($targetId);
                if ($targetModel) {
                    $targetModel->update(['status' => 'in_progress', 'last_error' => null]);
                }

                try {
                    Log::info("Sending target to pipeline: {$targetStr}");
                    $resp = Http::timeout(0)->post('http://127.0.0.1:5112/pipeline', [
                        'target' => $targetStr
                    ]);

                    if (!$resp->successful()) {
                        $errBody = $resp->body();
                        Log::error("HTTP error {$resp->status()} for target {$targetStr}: {$errBody}");
                        if ($targetModel) {
                            $targetModel->update(['status' => 'error', 'last_error' => 'HTTP '.$resp->status().' '.$errBody]);
                        }
                        continue;
                    }

                    $json = $resp->json();
                    Log::info("Pipeline response for {$targetStr}: ".json_encode($json));

                    $uniqueIps = [];

                    // جمع الـ IPs من alive_hosts
                    if (isset($json['alive_hosts']) && is_array($json['alive_hosts'])) {
                        foreach ($json['alive_hosts'] as $host) {
                            $ip = is_array($host) && isset($host['ip']) ? $host['ip'] : (string)$host;
                            if ($ip && !in_array($ip, $uniqueIps)) {
                                $uniqueIps[] = $ip;
                            }
                        }
                    }

                    // fallback لأي array من strings/numbers
                    if (empty($uniqueIps)) {
                        foreach ($json as $value) {
                            if (is_array($value)) {
                                foreach ($value as $v) {
                                    if ((is_string($v) || is_numeric($v)) && !in_array((string)$v, $uniqueIps)) {
                                        $uniqueIps[] = (string)$v;
                                    }
                                }
                            }
                        }
                    }

                    if (empty($uniqueIps)) {
                        Log::warning("No IPs found for target {$targetStr}");
                    }

                    // حفظ IP فريد لكل scan_id + scan_target_id
                    foreach ($uniqueIps as $ip) {
                        $exists = ScanResult::where('scan_id', $scan->id)
                            ->where('scan_target_id', $targetId)
                            ->where('ip', $ip)
                            ->exists();

                        if (!$exists) {
                            ScanResult::create([
                                'scan_id' => $scan->id,
                                'scan_target_id' => $targetId,
                                'ip' => $ip,
                                'data' => json_encode($json),
                            ]);
                        }
                    }

                    if ($targetModel) {
                        $targetModel->update(['status' => 'done']);
                    }

                } catch (\Exception $e) {
                    Log::error("Exception for target {$targetStr}: ".$e->getMessage());
                    if ($targetModel) {
                        $targetModel->update(['status' => 'error', 'last_error' => $e->getMessage()]);
                    }
                }
            }

            $completed = ScanTarget::where('scan_id', $scan->id)->where('status', 'done')->count();
            $scan->update(['completed_targets' => $completed]);
        }

        $remaining = ScanTarget::where('scan_id', $scan->id)->whereIn('status', ['pending','in_progress'])->count();
        if ($remaining === 0) {
            $scan->update(['status' => 'completed']);
            Log::info("Scan {$scan->id} completed successfully.");
        }
    }
}
