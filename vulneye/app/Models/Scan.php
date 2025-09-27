<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Scan extends Model
{
    protected $fillable = ['name','status','total_targets','completed_targets','meta'];

    protected $casts = [
        'meta' => 'array',
    ];

    public function targets(): HasMany
    {
        return $this->hasMany(ScanTarget::class);
    }

    public function results(): HasMany
    {
        return $this->hasMany(ScanResult::class);
    }
}
