<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateScanResultsTable extends Migration
{
    public function up()
    {
        Schema::create('scan_results', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained('scans')->onDelete('cascade');
            $table->foreignId('scan_target_id')->nullable()->constrained('scan_targets')->onDelete('set null');
            $table->string('ip')->index();
            $table->json('data')->nullable(); // raw JSON result from flask or parsed
            $table->timestamps();

            // unique constraint على combination من scan_id و scan_target_id فقط
            $table->unique(['scan_id', 'scan_target_id'], 'unique_scan_target');
        });
    }

    public function down()
    {
        Schema::dropIfExists('scan_results');
    }
}
