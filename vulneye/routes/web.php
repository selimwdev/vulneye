<?php

use App\Http\Controllers\ProfileController;
use App\Http\Controllers\NetworkScanController;
use App\Http\Controllers\ScanDashboardController;
use App\Http\Controllers\NetworkSecurityScannerController;
use App\Http\Controllers\ReportController;
use App\Models\Scan;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});


Route::get('/dashboard', function () {
    // نجيب كل الـ scans مع عدد الـ IPs وكل الـ targets
    $scans = Scan::withCount('targets')->with('targets')->orderBy('created_at','desc')->get();

    return view('dashboard', compact('scans'));
})->middleware(['auth', 'verified'])->name('dashboard');

Route::post('/scans/{scan}/generate-report', [ReportController::class, 'generate'])->name('scans.generate-report');

Route::get('/scans/{scan}/report-status', [ReportController::class, 'status'])->name('scans.report-status');
    
   
Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');
    Route::get('/network-scan', [NetworkScanController::class, 'index'])->name('network-scan.index');
    Route::post('/network-scan/scan', [NetworkScanController::class, 'scan'])->name('network-scan.scan');
Route::get('/network-security-scanner', [NetworkSecurityScannerController::class, 'index'])->name('network-security-scanner.index');
Route::post('/network-security-scanner', [NetworkSecurityScannerController::class, 'submit'])->name('network-security-scanner.submit');
Route::get('/scans', [ScanDashboardController::class, 'index'])->name('scans.index');
Route::get('/scans/{scan}', [ScanDashboardController::class, 'show'])->name('scans.show');

Route::get('/scans/{scan}/details', [ScanDashboardController::class, 'details'])->name('scans.details'); // API JSON for ajax


});

require __DIR__.'/auth.php';
