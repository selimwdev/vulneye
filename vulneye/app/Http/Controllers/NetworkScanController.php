<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class NetworkScanController extends Controller
{
    public function index()
    {
        return view('network_scan');
    }

    /**
     * Scan endpoint:
     * - expects request JSON: { "targets": ["192.168.1.1-192.168.1.10", "10.0.0.0/30", ...] }
     * - sends for each target POST {"target": "<string>"} to Flask
     * - expects Flask response like: {"alive_hosts":["192.168.1.1","192.168.1.2"], "count": 2}
     * - returns JSON with unique live IPs and which targets produced them
     */
    public function scan(Request $request)
    {
        $data = $request->validate([
            'targets' => 'required|array|min:1',
            'targets.*' => 'required|string'
        ]);

        // رابط الـ Flask ثابت هنا (بدون استخدام env)
        $flaskUrl = 'http://127.0.0.1:5006/scan';

        $allResults = collect(); // per-target raw responses
        $ipIndex = collect();    // dedup index: ip => ['ip'=>..., 'target_sources'=>[...]]

        try {
            foreach ($data['targets'] as $target) {
                $payload = ['target' => $target];

                // نرسل الطلب للـ Flask
                $resp = Http::timeout(120)->post($flaskUrl, $payload);

                if (! $resp->successful()) {
                    // خزن خطأ الاستجابة واستمر
                    $allResults->push([
                        'target' => $target,
                        'error' => true,
                        'status' => $resp->status(),
                        'body' => $resp->body()
                    ]);
                    continue;
                }

                $json = $resp->json();

                // حط الرد الخام للـ target في allResults
                $allResults->push([
                    'target' => $target,
                    'response' => $json
                ]);

                // الشكل المتوقع: {"alive_hosts": [...], "count": N}
                if (is_array($json) && array_key_exists('alive_hosts', $json) && is_array($json['alive_hosts'])) {
                    foreach ($json['alive_hosts'] as $ip) {
                        $ipStr = (string) $ip;
                        if (! $ipIndex->has($ipStr)) {
                            $ipIndex->put($ipStr, [
                                'ip' => $ipStr,
                                'target_sources' => [$target],
                            ]);
                        } else {
                            $entry = $ipIndex->get($ipStr);
                            if (! in_array($target, $entry['target_sources'])) {
                                $entry['target_sources'][] = $target;
                                $ipIndex->put($ipStr, $entry);
                            }
                        }
                    }
                } else {
                    // لو الشكل مختلف، نحاول نبحث عن أول مصفوفة قيم نصية في الـ response
                    if (is_array($json)) {
                        foreach ($json as $k => $v) {
                            if (is_array($v)) {
                                $allStrings = true;
                                foreach ($v as $elem) {
                                    if (!is_string($elem) && !is_numeric($elem)) {
                                        $allStrings = false;
                                        break;
                                    }
                                }
                                if ($allStrings) {
                                    foreach ($v as $ip) {
                                        $ipStr = (string) $ip;
                                        if (! $ipIndex->has($ipStr)) {
                                            $ipIndex->put($ipStr, [
                                                'ip' => $ipStr,
                                                'target_sources' => [$target],
                                            ]);
                                        } else {
                                            $entry = $ipIndex->get($ipStr);
                                            if (! in_array($target, $entry['target_sources'])) {
                                                $entry['target_sources'][] = $target;
                                                $ipIndex->put($ipStr, $entry);
                                            }
                                        }
                                    }
                                    break; // وقف بعد ما نلاقي أول مصفوفة نصية
                                }
                            }
                        }
                    }
                    // لو مفيش، نخلي الـ raw response محفوظ في allResults (فوق) ونمشّي
                }

                // لو محتاج تأخير بسيط عشان ما تضغطش على Flask، فكّر تفعل السطر ده:
                // usleep(50000); // 50ms
            }

            // بناء قائمة الـ live من ipIndex
            $liveList = $ipIndex->values()->map(function ($e) {
                return [
                    'ip' => $e['ip'],
                    'target_sources' => $e['target_sources'],
                ];
            })->values();

            return response()->json([
                'live' => $liveList,
                'count' => $liveList->count(),
                'all' => $allResults->values()
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Exception calling Flask API',
                'message' => $e->getMessage()
            ], 500);
        }
    }
}
