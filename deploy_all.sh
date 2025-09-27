#!/usr/bin/env bash
# deploy_all.sh
# تشغيل وتهيئة المشاريع داخل المجلد الحالي وفولدراته الفرعية على Linux/Mac.
# شغله ب sudo أو كـ root.

set -euo pipefail

ROOT="$(pwd)"
echo "Starting deployment from $ROOT"

# 1) nmap check & install (Debian/Ubuntu example)
if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap غير موجود."
  if command -v apt-get >/dev/null 2>&1; then
    echo "Attempting to install nmap via apt-get..."
    apt-get update && apt-get install -y nmap
  elif command -v yum >/dev/null 2>&1; then
    echo "Attempting to install nmap via yum..."
    yum install -y nmap
  else
    echo "لا يوجد مثبت للحزم معروف تلقائياً. الرجاء تثبيت nmap يدوياً."
  fi
else
  echo "nmap موجود."
fi

process_folder() {
  local folder="$1"
  echo -e "\n=== Processing: $folder ==="
  cd "$folder"

  # Install Python requirements
  if [ -f "requirements.txt" ]; then
    if command -v python3 >/dev/null 2>&1; then
      echo "Installing Python requirements..."
      python3 -m pip install -r requirements.txt
    elif command -v python >/dev/null 2>&1; then
      echo "Installing Python requirements with python..."
      python -m pip install -r requirements.txt
    else
      echo "Python غير مثبت. تخطي تثبيت requirements."
    fi
  fi

  # Open app.py (attempt VS Code, else cat)
  if [ -f "app.py" ]; then
    echo "Found app.py"
    if command -v code >/dev/null 2>&1; then
      code "app.py" &
    else
      echo "No VS Code found — printing header of app.py:"
      echo "----- app.py (top 100 lines) -----"
      head -n 100 app.py || true
    fi
  fi

  # Run pipeline.py in background
  if [ -f "pipeline.py" ]; then
    echo "Running pipeline.py in background..."
    if command -v python3 >/dev/null 2>&1; then
      nohup python3 pipeline.py > pipeline.log 2>&1 &
    else
      nohup python pipeline.py > pipeline.log 2>&1 &
    fi
  fi

  # If Laravel project (artisan exists)
  if [ -f "artisan" ]; then
    echo "Laravel project detected."

    # composer install
    if command -v composer >/dev/null 2>&1; then
      composer install --no-interaction --no-progress || true
    else
      echo "Composer غير مثبت. الرجاء تثبيته (https://getcomposer.org)."
    fi

    # storage link
    php artisan storage:link --force || true

    # start queue worker (nohup so it keeps running)
    echo "Starting queue worker (nohup) ..."
    nohup php artisan queue:work --tries=3 --timeout=0 > laravel-queue.log 2>&1 &

    # start php artisan serve on 127.0.0.1:8000 (if port free)
    # check if port 8000 is used
    if ! ss -ltn | grep -q ":8000"; then
      echo "Starting php artisan serve on 127.0.0.1:8000..."
      nohup php artisan serve --host=127.0.0.1 --port=8000 > laravel-serve.log 2>&1 &
      sleep 2
      # try to open browser if available
      if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "http://127.0.0.1:8000" || true
      elif command -v open >/dev/null 2>&1; then
        open "http://127.0.0.1:8000" || true
      fi
    else
      echo "Port 8000 already in use; skipping php artisan serve."
    fi
  fi

  cd "$ROOT"
}

# Process root itself
process_folder "$ROOT"

# Process subfolders (only top-level directories)
for d in */ ; do
  if [ -d "$d" ]; then
    process_folder "$d"
  fi
done

echo "Done. راجع ملفات السجل pipeline.log و laravel-serve.log و laravel-queue.log لمعرفة المخرجات."
