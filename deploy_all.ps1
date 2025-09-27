<#
    deploy_all.ps1
    تشغيل وتهيئة المشاريع داخل المجلد الحالي وفولدراته الفرعية على Windows.
    شغله كـ Administrator.
#>

# ---------- تعديل: ضع هنا أين تريد أن يبدأ السكربت (أو شغله في جذر المشروع) ----------
$root = Get-Location

# Helper: تحقق من وجود أمر
function Command-Exists($cmd) {
    $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

Write-Host "Starting deployment from $root" -ForegroundColor Cyan

# 1) تأكد من وجود nmap — إن لم يكن، نحاول اقتراح تثبيت عبر Chocolatey (إن متوفر)
if (-not (Command-Exists "nmap")) {
    Write-Host "nmap غير موجود." -ForegroundColor Yellow
    if (Command-Exists "choco") {
        Write-Host "Installing nmap via Chocolatey..." -ForegroundColor Green
        choco install nmap -y
    } else {
        Write-Host "لم يتم العثور على Chocolatey. الرجاء تثبيت nmap يدوياً أو تثبيت Chocolatey أولاً." -ForegroundColor Red
    }
} else {
    Write-Host "nmap موجود." -ForegroundColor Green
}

# دالة للتعامل مع فولدر مشروع واحد
function Process-Folder($folder) {
    Push-Location $folder
    Write-Host "`n=== Processing: $folder ===" -ForegroundColor Cyan

    # 2) إذا موجود requirements.txt => تثبيت بايثون ريكويرمنتس
    if (Test-Path "./requirements.txt") {
        if (Command-Exists "python" -or Command-Exists "python3") {
            $py = if (Command-Exists "python") { "python" } else { "python3" }
            Write-Host "Installing Python requirements with $py -m pip install -r requirements.txt"
            & $py -m pip install -r requirements.txt
        } else {
            Write-Host "Python غير مثبت أو ليس في PATH. رجاء تثبيت Python." -ForegroundColor Red
        }
    }

    # 3) إذا موجود app.py => نفتح الملف (يفتح بـ notepad أو VSCode لو موجود)
    if (Test-Path "./app.py") {
        Write-Host "Found app.py"
        if (Command-Exists "code") {
            Write-Host "Opening app.py in VS Code..."
            Start-Process code -ArgumentList "app.py"
        } else {
            Write-Host "Opening app.py in Notepad..."
            Start-Process notepad -ArgumentList "app.py"
        }
    }

    # 4) إذا موجود pipeline.py => نشغّله في نافذة جديدة (حتى يستمر)
    if (Test-Path "./pipeline.py") {
        Write-Host "Running pipeline.py in new PowerShell window..."
        $psCommand = "python -u `"$((Resolve-Path pipeline.py).Path)`""
        Start-Process powershell -ArgumentList "-NoExit","-Command",$psCommand
    }

    # 5) إذا هذا فولدر لارفيل (contains artisan) => نفّذ أوامر لارافيل
    if (Test-Path "./artisan") {
        Write-Host "Laravel project detected."

        # composer install
        if (Command-Exists "composer") {
            Write-Host "Running composer install..."
            composer install --no-interaction
        } else {
            Write-Host "Composer غير مثبت أو ليس في PATH. قم بتنزيله من https://getcomposer.org" -ForegroundColor Red
        }

        # storage:link
        Write-Host "Running php artisan storage:link (if not exists)..."
        & php artisan storage:link --force

        # تشغيل queues في نافذة جديدة
        Write-Host "Starting queue worker in new PowerShell window..."
        $queueCmd = "php `"$((Resolve-Path ./artisan).Path)`" queue:work --tries=3 --timeout=0"
        Start-Process powershell -ArgumentList "-NoExit","-Command",$queueCmd

        # تشغيل خادم التطوير على 127.0.0.1:8000 (نافذة جديدة)
        Write-Host "Starting php artisan serve on 127.0.0.1:8000..."
        $serveCmd = "php `"$((Resolve-Path ./artisan).Path)`" serve --host=127.0.0.1 --port=8000"
        Start-Process powershell -ArgumentList "-NoExit","-Command",$serveCmd

        # انتظر قليلًا للتأكد أن الخادم شغّال
        Start-Sleep -Seconds 3
        Write-Host "Attempting to open http://127.0.0.1:8000 in default browser..."
        Start-Process "http://127.0.0.1:8000"
    }

    Pop-Location
}

# Process root and all subfolders (top-level)
$folders = Get-ChildItem -Directory -Force
# أولاً معالجة الجذر نفسه
Process-Folder $root

foreach ($f in $folders) {
    Process-Folder $f.FullName
}

Write-Host "`nAll done. راجع النوافذ المفتوحة لتأكد من أن الخدمات تعمل." -ForegroundColor Green
