<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateScanTargetsTable extends Migration
{
    public function up()
    {
        Schema::create('scan_targets', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained('scans')->onDelete('cascade');
            $table->string('target')->index(); // the IP or CIDR line user provided
            $table->enum('status', ['pending','in_progress','done','error'])->default('pending')->index();
            $table->text('last_error')->nullable();
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('scan_targets');
    }
}
