<p align="center">
  <img src="https://github.com/user-attachments/assets/ed6abf32-7e21-4bdd-862c-cc757ad3a7b8" alt="logo4"/>
</p>

# Vulneye framework V1.0 — Automated Network Security Scanner 

# Manual Installation and Run Guide

This guide explains how to manually set up and run the full environment step by step.

---

## 1 — Pre-requisites

* **PHP** (≥ 8.x) with extensions: `mbstring`, `xml`, `pdo`, `openssl`
* **Composer**
* **Python 3** (≥ 3.8)
* **pip**
* **nmap**
* **Git** (optional, for version control)

Ensure that all these tools are in your PATH.

---

## 2 — Install Laravel dependencies

From the Laravel project folder (e.g. `vulneye`):

```bash
composer install --no-interaction --prefer-dist
cp .env.example .env   # (Windows: Copy-Item .env.example .env)
php artisan key:generate
php artisan storage:link --force
```

---

## 3 — Install nmap

Check if `nmap` exists:

```bash
nmap --version
```

If not installed:

* **Linux (Debian/Ubuntu):**

  ```bash
  sudo apt update && sudo apt install -y nmap
  ```
* **macOS (Homebrew):**

  ```bash
  brew install nmap
  ```
* **Windows (Chocolatey):**

  ```powershell
  choco install nmap -y
  ```

---

## 4 — Install all Python requirements

Install every `requirements.txt` found in the project folders:

**Linux / macOS / WSL:**

```bash
find . -name "requirements.txt" -exec pip install -r {} \;
```

**Windows PowerShell:**

```powershell
Get-ChildItem -Recurse -Filter requirements.txt | ForEach-Object {
    pip install -r $_.FullName
}
```

> **Recommended:** create and activate a virtual environment before running pip installs:
>
> ```bash
> python3 -m venv .venv
> source .venv/bin/activate   # Linux/macOS
> .venv\Scripts\Activate.ps1  # Windows PowerShell
> pip install -r requirements.txt
> ```

---

## 5 — Run Python apps

### 5.1 Run `app.py`

From the folder containing `app.py`:

```bash
python app.py
```

(or `python3 app.py` depending on your environment)

### 5.2 Run `pipeline.py`

From the correct folder:

```bash
python pipeline.py
```

* On Linux/macOS you can run in background:

  ```bash
  nohup python3 pipeline.py > pipeline.log 2>&1 &
  ```
* On Windows (PowerShell):

  ```powershell
  Start-Process powershell -ArgumentList '-NoExit','-Command','python "C:\path\to\pipeline.py"'
  ```

---

## 6 — Run Laravel app (vulneye)

From inside `vulneye` folder:

### 6.1 Start queues

```bash
php artisan queue:work --tries=3 --timeout=0
```

(For background: use `nohup` on Linux or open a new PowerShell window on Windows)

### 6.2 Start Laravel dev server

```bash
php artisan serve --host=127.0.0.1 --port=8000
```

Access the app in your browser:

```
http://127.0.0.1:8000
```

---

## 7 — Common issues

* **Composer install fails** → Check PHP version and required extensions.
* **Queue not processing** → Verify `.env` `QUEUE_CONNECTION` and that Redis/DB is running.
* **Port already in use** → Change Laravel serve port (`--port=8080`).
* **Permission errors (Linux)** → Run: `sudo chown -R $USER:www-data storage bootstrap/cache`.

---

## 8 — How to use the framework (Web UI)

After you start the Laravel app and open `http://127.0.0.1:8000`, follow these steps to use the framework's main scanning and reporting features.

1. **Create an account**

   * Open `http://127.0.0.1:8000` in your browser.
   * Click the register/sign-up link and create a new account using a valid email and password.
   * Verify your account if the app requires email verification.

2. **Open Network Security Scanner**

   * Log in with your account.
   * In the site header, find and click **"Network Security Scanner"** (or similar menu item).

3. **Add target IPs**

   * In the Network Security Scanner page, there is an input area for target IPs.
   * Enter each IP address you want to scan on a separate line (one IP per line).
   * Example:

     ```text
     192.168.1.10
     192.168.1.15
     10.0.0.5
     ```
   * Double-check the IPs before starting the scan.

4. **Start the scan**

   * Click the **"Scan"** button to begin scanning the listed IPs.
   * The scan will run in the background (pipeline / worker processes handle scanning).
   * You can monitor progress in the UI if there is a progress indicator, or check server logs (`pipeline.log`, `laravel-queue.log`).

5. **Generate report**

   * After the scan completes, go back to the application main (home) page.
   * Click **"Generate Report"** (or similar) to compile the scan results into a downloadable report.
   * **Important:** Wait until the scan has fully finished — if the scan is still running, the report will not include complete results and may be empty.

6. **Download the report**

   * When the report is ready the UI will provide a download link.
   * Click the link to download the PDF (or other supported format).

7. **Verify results**

   * Before sharing the report, open it and verify that expected findings are present.
   * If results are missing, confirm that the scan completed successfully and re-run if needed.

---

## 9 — Final checks & verification

* Open `http://127.0.0.1:8000` to see Laravel app.
* Monitor logs:

  * Laravel: `storage/logs/laravel.log`
  * pipeline: `pipeline.log`
  * queue: `laravel-queue.log`
* Verify `php artisan` commands work and `composer` dependencies installed.

---

✅ The environment should now be fully set up: Laravel app running, Python apps running, and queues active. Follow the Web UI steps above to perform network scans and generate reports.
