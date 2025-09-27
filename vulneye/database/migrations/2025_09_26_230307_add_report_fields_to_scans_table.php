<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up()
{
    Schema::table('scans', function (Blueprint $table) {
        $table->string('report_status')->nullable()->default(null); // queued, ready, failed, no_results
        $table->string('report_path')->nullable();
        $table->string('report_url')->nullable();
        $table->text('report_error')->nullable();
    });
}


    /**
     * Reverse the migrations.
     */
    public function down()
{
    Schema::table('scans', function (Blueprint $table) {
        $table->dropColumn(['report_status', 'report_path', 'report_url', 'report_error']);
    });
}

};
