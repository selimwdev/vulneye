<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ScanTarget extends Model
{
    protected $fillable = ['scan_id','target','status','last_error'];

    public function scan()
    {
        return $this->belongsTo(Scan::class);
    }

    public function results()
    {
        return $this->hasMany(ScanResult::class);
    }
}
