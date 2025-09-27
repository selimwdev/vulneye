<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Log;
use App\Models\Scan;
use App\Models\ScanResult;
use Symfony\Component\Process\Process;

class GenerateScanReportJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public $scanId;
    public $logo;
    public $tries = 3;
    public $timeout = 0;

    public function __construct(int $scanId, string $logo = 'logo4.svg')
    {
        $this->scanId = $scanId;
        $this->logo = $logo;
    }

    public function handle()
    {
        $scan = Scan::find($this->scanId);
        if (! $scan) {
            Log::error("GenerateScanReportJob: Scan not found id={$this->scanId}");
            return;
        }

        // مجلد مؤقت
        $tmpDir = storage_path("app/reports/scan_{$scan->id}");
        if (! is_dir($tmpDir)) mkdir($tmpDir, 0755, true);

        // جلب نتائج الـ scan
        $results = ScanResult::where('scan_id', $scan->id)->get();
        if ($results->isEmpty()) {
            Log::warning("GenerateScanReportJob: no results for scan {$scan->id}");
            $scan->update(['report_status' => 'no_results']);
            return;
        }

        // حفظ كل result.data في json
        $jsonPaths = [];
        foreach ($results as $index => $res) {
            $data = $res->data;
            $content = is_null($data) ? json_encode(['note' => 'no data', 'id' => $res->id])
                                      : (is_string($data) ? $data : json_encode($data));
            $filePath = $tmpDir . DIRECTORY_SEPARATOR . "result_{$index}.json";
            file_put_contents($filePath, $content);
            $jsonPaths[] = $filePath;
        }

        // PDF الناتج بدون timestamp، مميز حسب scan_id
        $outputPdfName = "scan_{$scan->id}_report.pdf";
        $outputPdfTmpPath = $tmpDir . DIRECTORY_SEPARATOR . $outputPdfName;

        // سكربت بايثون واللوجو
        $pythonScript = base_path('../report_new.py');
        $logoPath = base_path("../{$this->logo}");

        // أمر التشغيل
        $cmd = array_merge(['python', $pythonScript], $jsonPaths, [$outputPdfTmpPath], ["--logo={$logoPath}"]);
        Log::info('GenerateScanReportJob running command: ' . implode(' ', array_map(fn($p) => escapeshellarg($p), $cmd)));

        try {
            $process = new Process($cmd);
            $process->setTimeout(null);
            $process->setIdleTimeout(null);
            $process->run(function ($type, $buffer) {
                if (Process::ERR === $type) Log::error('Python stderr: ' . $buffer);
                else Log::info('Python stdout: ' . $buffer);
            });

            if (! $process->isSuccessful()) {
                Log::error('Python process failed: ' . $process->getErrorOutput());
                $scan->update(['report_status' => 'failed', 'report_error' => $process->getErrorOutput()]);
                return;
            }

            if (! file_exists($outputPdfTmpPath)) {
                Log::error('Expected PDF not found at ' . $outputPdfTmpPath);
                $scan->update(['report_status' => 'failed', 'report_error' => 'pdf_not_generated']);
                return;
            }

            // حفظ في storage/public/reports/... لظهور الرابط على الويب
            $storageDir = "public/reports/scan_{$scan->id}";
            Storage::putFileAs($storageDir, $outputPdfTmpPath, $outputPdfName);

            $publicUrl = Storage::url("reports/scan_{$scan->id}/{$outputPdfName}");

            // تحديث الـ Scan
            $scan->update([
                'report_status' => 'ready',
                'report_path' => $storageDir . '/' . $outputPdfName,
                'report_url' => $publicUrl,
            ]);

            Log::info("Report generated for scan {$scan->id} -> {$publicUrl}");

        } catch (\Throwable $e) {
            Log::error("GenerateScanReportJob exception: " . $e->getMessage());
            $scan->update(['report_status' => 'failed', 'report_error' => $e->getMessage()]);
        }
    }
}
