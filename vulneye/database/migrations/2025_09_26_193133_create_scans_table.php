<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateScansTable extends Migration
{
    public function up()
    {
        Schema::create('scans', function (Blueprint $table) {
            $table->id();
            $table->string('name')->index();
            $table->enum('status', ['pending','running','completed','failed'])->default('pending')->index();
            $table->integer('total_targets')->unsigned()->default(0);
            $table->integer('completed_targets')->unsigned()->default(0);
            $table->json('meta')->nullable(); // أي بيانات إضافية
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('scans');
    }
}
