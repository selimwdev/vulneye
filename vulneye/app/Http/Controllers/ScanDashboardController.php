<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Scan;

class ScanDashboardController extends Controller
{
    public function index()
    {
        $scans = Scan::orderBy('created_at','desc')->paginate(20);
        return view('scans.index', compact('scans'));
    }

    public function show(Scan $scan)
    {
        $targets = $scan->targets()->paginate(50);
        $results = $scan->results()->paginate(200);
        return view('scans.show', compact('scan','targets','results'));
    }
}
