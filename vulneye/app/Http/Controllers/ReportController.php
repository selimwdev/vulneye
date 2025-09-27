<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Scan;
use App\Jobs\GenerateScanReportJob;
use Illuminate\Support\Facades\Response;

class ReportController extends Controller
{
    public function generate(Scan $scan)
    {
        // فقط مالك الـ scan يمكنه تشغيله
        //$this->authorize('view', $scan);

        // dispatch job مع اسم لوجو ثابت
        $logo = 'logo4.svg';
        GenerateScanReportJob::dispatch($scan->id, $logo);

        return response()->json([
            'status' => 'queued',
            'message' => 'Report generation started. You will find the PDF in the scan record when ready.'
        ]);
    }

    public function status(Scan $scan)
    {
        // فقط مالك الـ scan
       // $this->authorize('view', $scan);

        if($scan->report_status === 'ready' && $scan->report_url){
            return response()->json(['status' => 'ready', 'url' => $scan->report_url]);
        }

        return response()->json([
            'status' => $scan->report_status ?? 'processing'
        ]);
    }
}
