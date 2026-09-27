# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

CLYLAR Network Scanner is a Flask web app, branded for NT (National Telecom), that:
- wraps `nmap` to discover hosts and services
- looks up CVEs through the NVD API
- runs recurring scans on a schedule
- includes a Gemini-powered chatbot that can read scan data and start scans

UI text is mostly Thai. Code comments are a mix of Thai and English.

## Commands

```bash
pip install -r requirements.txt
python app.py          # dev server at http://127.0.0.1:5000 (debug=True, auto-reload)
```

- The `nmap` binary must be installed and on PATH, because `python-nmap` shells out to it. The fast, intense and vuln scans use OS detection (`-O` / `-A`), which usually needs admin/root.
- Config comes from `.env` (see `.env.example`): `GOOGLE_API_KEY` and `GEMINI_MODEL`. `SECRET_KEY` is read from the environment and falls back to a hardcoded default.
- The first run creates `instance/scanner.db` (SQLite). If no superadmin exists, it also creates one with the login `admin` / `admin123`.
- There is no test suite, linter or build step. To check a change, run the app and use the page in a browser.

## Architecture

The app is three flat Python modules with no packages:
- `app.py`: all the web-facing code. Routes, permission decorators, APScheduler setup, startup migrations, CSV/PDF export, nmap XML import and the chatbot API.
- `scanner.py`: the nmap wrappers (`run_network_scan`, `run_vuln_scan`), the NVD CVE lookup, target and argument validation, and default-gateway detection.
- `models.py`: the SQLAlchemy models `User`, `ScanJob`, `ScheduledScan` and `SavedTarget`.

### Scan lifecycle
Scans run synchronously:
- **In the HTTP request** for manual scans, rescans, drill-downs, "run now", `/api/chat/scan` and chatbot-triggered scans.
- **In the APScheduler thread** for scheduled scans.

Every entry point follows the same steps:
1. Create `ScanJob(status='Running')` and commit.
2. Call the scanner.
3. Set the status to `Completed` or `Failed`, store `result_data`, and commit.

"Cancel" only changes the status in the database. It does not stop nmap.

`scan_type` is one of `discovery`, `fast_scan`, `intense`, `custom`, `vuln_scan` or `xml_upload`:
- `vuln_scan` goes to `run_vuln_scan`. Every other type goes to `run_network_scan`.
- `custom` arguments are checked against the `ALLOWED_FLAGS` whitelist in `scanner.py`.
- `xml_upload` jobs come from imported nmap `-oX` files and can't be rescanned.

Display names are in `SCAN_TYPE_LABELS`, which templates reach through the `scan_label` Jinja filter.

### Result data
Scan output is stored as a JSON string in `ScanJob.result_data`. It is a list of host dicts shaped like `{ip, mac, mac_vendor, os, ports: [{port, protocol, state, name, version_info, cves?}]}`. Discovery hosts have `status` instead of `os` and `ports`.

When a scan fails, the scanner returns `[{"error": "..."}]`. Callers detect this with `results_data[0].get('error')`.

There are no separate host or port tables. The dashboard, topology, devices, vulnerabilities, exports and chatbot context all re-parse this JSON and aggregate it in Python.

CVEs are stored at `ports[].cves[]`, with the keys `cve_id`, `severity`, `cvss_score`, `cwe_name` and `description`.

### Roles and visibility
The roles are `superadmin`, `admin` and `user`. `visible_scans_query()` and `visible_schedules_query()` enforce access control, so every read of `ScanJob` or `ScheduledScan` must go through them:
- Admins and superadmins see only the scans they own (`owner_id == current_user.id`). A superadmin does **not** see other admins' scans.
- A `user` sees the scans of the admin who created their account (`User.created_by`).

`SavedTarget` has no owner and is shared by every user.

Routes are protected with `@admin_required` or `@superadmin_required`. `user_management_required` does exactly the same thing as `admin_required`.

### Scheduling
The `BackgroundScheduler` starts when `app.py` is imported. At startup, `register_apscheduler_job` registers every active `ScheduledScan` as a cron job, and `execute_scheduled_scan` runs inside its own `app.app_context()`.

With `debug=True`, the reloader runs the module in two processes. That starts two schedulers, so a scheduled scan can run twice in development.

### Database migrations
There is no Alembic. `db.create_all()` doesn't change tables that already exist, so each new column also needs a matching `ALTER TABLE ... ADD COLUMN` in the `PRAGMA table_info` block under `with app.app_context():` in `app.py`.

Timestamps are naive datetimes in Asia/Bangkok time, created by `now_th()`.

### Chatbot
`/api/chat` is admin-only. It builds a system prompt from live data (`_build_app_context`) and calls the Gemini REST API (`_call_gemini`), which reloads `.env` on every call. If the model's reply contains `##SCAN_CMD##` followed by a JSON line, the server runs that scan for real.

## Templates / frontend

Pages are server-rendered Jinja using Bootstrap 5.3, Tabler icons and Chart.js, all loaded from CDNs. There is no bundler and there are no static JS or CSS files. Each template has its own inline `<style>` and `<script>`.

- `base.html` contains the NT-branded sidebar and topbar **and** the whole chatbot widget. The chatbot keeps its history in `localStorage`, keyed by user.
- Theme colors are CSS variables on `:root` (`--nt-gold`, `--nt-text`, and so on). The NT logo mark is in `templates/partials/_nt_mark.html`.
- Pages set the topbar title with `{% block page_title %}` and `{% block page_subtitle %}`; older pages still render their own `<h2>`. `{% block page_context %}` tells the chatbot what page the user is on.
- `inject_layout_context` gives every template `thai_date_today` (a Buddhist-calendar date), `now_year` and `notification_count` (the number of running scans).
- The PDF export builds an HTML string in Python for `xhtml2pdf`, which doesn't support `rowspan`.

## Known issues

- `instance/scanner.db` is tracked in git even though `.gitignore` excludes it. It changes every time the app runs, so keep it out of feature commits.
- The NVD API key is hardcoded in `scanner.py`. `lookup_cves_nvd` catches every error and returns `[]`, so an API failure looks the same as "0 CVEs".
- No CSRF protection is set up, so forms post without tokens.
- Scan data is not always escaped in the browser. `dashboard.html` and `network_topology.html` put `json.dumps(...)` output into `<script>` with `| safe`, and many templates write scan data (service names, version strings) into `innerHTML`. Service names and versions can come from a scanned host's banners or an uploaded XML file. In new code, use the `| tojson` filter and `textContent` instead.
