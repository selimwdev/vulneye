<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ScanResult extends Model
{
    protected $fillable = ['scan_id','scan_target_id','ip','data'];

    protected $casts = [
        'data' => 'array',
    ];

    public function scan()
    {
        return $this->belongsTo(Scan::class);
    }

    public function target()
    {
        return $this->belongsTo(ScanTarget::class, 'scan_target_id');
    }
}
