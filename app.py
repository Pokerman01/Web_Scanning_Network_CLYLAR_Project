from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from models import db, User, ScanJob, ScheduledScan, SavedTarget
from scanner import run_network_scan, run_vuln_scan
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
import json
import atexit

TZ = ZoneInfo("Asia/Bangkok")

def now_th():
    return datetime.now(TZ).replace(tzinfo=None)


import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Custom Jinja filter ---
SCAN_TYPE_LABELS = {
    'fast_scan': 'Fast Scan',
    'discovery': 'Discovery',
    'intense': 'Intense Scan',
    'custom': 'Custom Scan',
    'xml_upload': 'XML Upload',
    'vuln_scan': 'Vulnerability Scan (CVE)',
}

@app.template_filter('scan_label')
def scan_label_filter(value):
    return SCAN_TYPE_LABELS.get(value, value)

@app.template_filter('from_json')
def from_json_filter(value):
    if not value:
        return []
    try:
        import json as _json
        return _json.loads(value)
    except Exception:
        return []

# --- APScheduler ---
scheduler = BackgroundScheduler(timezone="Asia/Bangkok")
scheduler.start()
atexit.register(lambda: scheduler.shutdown())


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ─────────────────────────────────────────
#  Permission decorators
# ─────────────────────────────────────────

def superadmin_required(f):
    """เฉพาะ superadmin เท่านั้น"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'superadmin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """admin หรือ superadmin (สแกนได้ / จัดการ schedule ได้)"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_any_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def user_management_required(f):
    """admin, superadmin สร้าง user ได้"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_any_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────
#  Helper: กรอง ScanJob ตาม role
# ─────────────────────────────────────────

def visible_scans_query():
    """
    superadmin → เห็นเฉพาะ scan ของตัวเอง
    admin      → เห็น scan ของตัวเอง
    user       → เห็น scan ของ admin ที่สร้างตัวเอง
    """
    if current_user.role == 'superadmin':
        return ScanJob.query.filter_by(owner_id=current_user.id)
    elif current_user.role in ('admin', 'superadmin'):
        return ScanJob.query.filter_by(owner_id=current_user.id)
    else:
        # user → เห็น scan ของ admin ที่สร้างตัวเอง
        admin_id = current_user.created_by
        if admin_id:
            return ScanJob.query.filter_by(owner_id=admin_id)
        return ScanJob.query.filter(ScanJob.id == None)  # ไม่เห็นอะไรเลย


def visible_schedules_query():
    """schedule filter เช่นเดียวกับ scan"""
    if current_user.is_any_admin:
        return ScheduledScan.query.filter_by(owner_id=current_user.id)
    else:
        admin_id = current_user.created_by
        if admin_id:
            return ScheduledScan.query.filter_by(owner_id=admin_id)
        return ScheduledScan.query.filter(ScheduledScan.id == None)


# ─────────────────────────────────────────
#  Helpers: Schedule calculation
# ─────────────────────────────────────────

def calc_next_run(schedule):
    now = now_th()
    base = now.replace(hour=schedule.cron_hour, minute=schedule.cron_minute, second=0, microsecond=0)

    if schedule.repeat == 'daily':
        if base <= now:
            base += timedelta(days=1)
        return base
    elif schedule.repeat == 'weekly':
        dow = schedule.day_of_week or 0
        days_ahead = (dow - now.weekday()) % 7
        candidate = base + timedelta(days=days_ahead)
        if candidate <= now:
            candidate += timedelta(weeks=1)
        return candidate
    elif schedule.repeat == 'monthly':
        dom = schedule.day_of_month or 1
        try:
            candidate = base.replace(day=dom)
        except ValueError:
            import calendar
            last_day = calendar.monthrange(base.year, base.month)[1]
            candidate = base.replace(day=last_day)
        if candidate <= now:
            if candidate.month == 12:
                candidate = candidate.replace(year=candidate.year + 1, month=1)
            else:
                candidate = candidate.replace(month=candidate.month + 1)
        return candidate
    return base


def execute_scheduled_scan(schedule_id):
    with app.app_context():
        schedule = ScheduledScan.query.get(schedule_id)
        if not schedule or not schedule.is_active:
            return

        new_job = ScanJob(
            target=schedule.target,
            scan_type=schedule.scan_type,
            status='Running',
            triggered_by='schedule',
            owner_id=schedule.owner_id
        )
        db.session.add(new_job)
        db.session.commit()

        results = run_vuln_scan(schedule.target) if schedule.scan_type == 'vuln_scan' else run_network_scan(schedule.target, schedule.scan_type,
                                   custom_args=schedule.custom_args)

        results_data = json.loads(results)
        has_error = results_data and results_data[0].get('error')
        new_job.status = 'Failed' if has_error else 'Completed'
        new_job.result_data = results
        schedule.last_run = now_th()
        schedule.next_run = calc_next_run(schedule)
        db.session.commit()


def register_apscheduler_job(schedule):
    job_id = f'schedule_{schedule.id}'
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if not schedule.is_active:
        return

    if schedule.repeat == 'daily':
        trigger = CronTrigger(hour=schedule.cron_hour, minute=schedule.cron_minute)
    elif schedule.repeat == 'weekly':
        trigger = CronTrigger(day_of_week=schedule.day_of_week,
                              hour=schedule.cron_hour, minute=schedule.cron_minute)
    elif schedule.repeat == 'monthly':
        trigger = CronTrigger(day=schedule.day_of_month,
                              hour=schedule.cron_hour, minute=schedule.cron_minute)
    else:
        return

    scheduler.add_job(func=execute_scheduled_scan, trigger=trigger,
                      args=[schedule.id], id=job_id, replace_existing=True)


# ─────────────────────────────────────────
#  Init DB
# ─────────────────────────────────────────

with app.app_context():
    db.create_all()

    import sqlite3, os
    db_path = os.path.join(app.instance_path, 'scanner.db')
    if os.path.exists(db_path):
        con = sqlite3.connect(db_path)
        cur = con.cursor()

        # Migration: scan_job
        cols = [r[1] for r in cur.execute("PRAGMA table_info(scan_job)")]
        if 'scan_name' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN scan_name VARCHAR(150)")
        if 'owner_id' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN owner_id INTEGER REFERENCES user(id)")

        # Migration: scheduled_scan
        cols2 = [r[1] for r in cur.execute("PRAGMA table_info(scheduled_scan)")]
        if 'owner_id' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN owner_id INTEGER REFERENCES user(id)")
        if 'custom_args' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN custom_args VARCHAR(500)")

        # Migration: user
        cols3 = [r[1] for r in cur.execute("PRAGMA table_info(user)")]
        if 'created_by' not in cols3:
            cur.execute("ALTER TABLE user ADD COLUMN created_by INTEGER REFERENCES user(id)")
        if 'created_at' not in cols3:
            cur.execute("ALTER TABLE user ADD COLUMN created_at DATETIME")

        con.commit()
        con.close()

    # สร้าง superadmin ถ้ายังไม่มี
    if not User.query.filter_by(role='superadmin').first():
        hashed_pw = generate_password_hash('admin123')
        superadmin = User(username='admin', password_hash=hashed_pw, role='superadmin')
        db.session.add(superadmin)
        db.session.commit()

    # migrate: user เดิมที่เป็น role='admin' และไม่มี owner_id ใน scan → set owner_id
    # (กรณี upgrade จาก version เก่า ให้ผูก scan เก่ากับ superadmin)
    superadmin_user = User.query.filter_by(role='superadmin').first()
    if superadmin_user:
        ScanJob.query.filter_by(owner_id=None).update({'owner_id': superadmin_user.id})
        ScheduledScan.query.filter_by(owner_id=None).update({'owner_id': superadmin_user.id})
        db.session.commit()

    for s in ScheduledScan.query.filter_by(is_active=True).all():
        register_apscheduler_job(s)


# ─────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ─────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        if not current_user.is_any_admin:
            abort(403)
        target = request.form.get('target')
        scan_type = request.form.get('scan_type')
        scan_name = request.form.get('scan_name', '').strip() or None
        custom_args = request.form.get('custom_args', '').strip() or None
        new_job = ScanJob(
            target=target, scan_type=scan_type, scan_name=scan_name,
            status='Running', triggered_by='manual',
            owner_id=current_user.id
        )
        db.session.add(new_job)
        if target and not SavedTarget.query.filter_by(target=target).first():
            db.session.add(SavedTarget(target=target))
        db.session.commit()
        results = run_vuln_scan(target) if scan_type == 'vuln_scan' else run_network_scan(target, scan_type, custom_args=custom_args)
        results_data = json.loads(results)
        has_error = results_data and results_data[0].get('error')
        new_job.status = 'Failed' if has_error else 'Completed'
        new_job.result_data = results
        db.session.commit()
        if has_error:
            flash(f'Scan failed: {results_data[0]["error"]}', 'danger')
        else:
            flash('Scan completed successfully!', 'success')
        return redirect(url_for('dashboard'))

    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()
    latest_scan = history[0] if history else None
    scan_data = json.loads(latest_scan.result_data) if latest_scan and latest_scan.result_data else []

    from collections import Counter
    all_device_map = {}
    for job in history:
        if not job.result_data:
            continue
        try:
            job_data = json.loads(job.result_data)
        except Exception:
            continue
        for d in job_data:
            ip = d.get('ip', '')
            if not ip:
                continue
            if ip not in all_device_map:
                all_device_map[ip] = set()
            for p in d.get('ports', []):
                label = f"{p.get('port')}/{p.get('name','?')}"
                all_device_map[ip].add(label)

    total_devices = len(all_device_map)
    online_devices = sum(1 for d in scan_data if d.get('status', '').lower() in ('up', 'online', 'open') or d.get('ports'))
    offline_devices = len(scan_data) - online_devices

    port_device_counter = Counter()
    for ip, ports in all_device_map.items():
        for p in ports:
            port_device_counter[p] += 1
    top_ports = port_device_counter.most_common(6)

    device_port_data = []
    for ip, ports in sorted(all_device_map.items()):
        count = len(ports)
        color = '#198754' if count < 3 else ('#ffc107' if count <= 6 else '#dc3545')
        device_port_data.append({'ip': ip, 'count': count, 'color': color})

    from collections import Counter as _Counter
    target_scan_counts = _Counter(j.target for j in history if j.status == 'Completed')

    all_jobs = visible_scans_query().all()
    schedules_all = visible_schedules_query().all()
    task_completed = sum(1 for j in all_jobs if j.status == 'Completed')
    task_running   = sum(1 for j in all_jobs if j.status == 'Running')
    task_wait      = sum(1 for s in schedules_all if s.is_active)
    total_tasks    = len(all_jobs) + task_wait

    all_ports_global = set()
    total_cves_found = 0
    seen_cves = set()
    all_cves_list = []  # for the CVE detail modal
    for job in history:
        if not job.result_data:
            continue
        try:
            job_data = json.loads(job.result_data)
        except Exception:
            continue
        for d in job_data:
            for p in d.get('ports', []):
                port_label = str(p.get('port', ''))
                if port_label:
                    all_ports_global.add(port_label)
                for cve in p.get('cves', []):
                    cve_id = cve if isinstance(cve, str) else cve.get('id', str(cve))
                    if cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        total_cves_found += 1
                        severity = cve.get('severity', 'unknown') if isinstance(cve, dict) else 'unknown'
                        all_cves_list.append({
                            'id': cve_id,
                            'severity': severity,
                            'port': p.get('port', ''),
                            'service': p.get('name', ''),
                            'ip': d.get('ip', ''),
                        })
    total_open_ports = len(all_ports_global)

    # คำนวณ owner_seq ของ latest_scan เพื่อโชว์ #N ที่ถูกต้องใน dashboard
    latest_owner_seq = None
    if latest_scan and latest_scan.owner_id is not None:
        owner_jobs_sorted = ScanJob.query.filter_by(owner_id=latest_scan.owner_id).order_by(ScanJob.timestamp).all()
        latest_owner_seq = next((i+1 for i, j in enumerate(owner_jobs_sorted) if j.id == latest_scan.id), latest_scan.id)

    return render_template(
        'dashboard.html',
        history=history,
        scan_data=scan_data,
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        total_open_ports=total_open_ports,
        top_ports=top_ports,
        device_port_data=device_port_data,
        target_scan_counts=target_scan_counts,
        total_tasks=total_tasks,
        task_completed=task_completed,
        task_running=task_running,
        task_wait=task_wait,
        latest_owner_seq=latest_owner_seq,
        total_cves_found=total_cves_found,
        all_cves_json=json.dumps(all_cves_list),
    )


# ─────────────────────────────────────────
#  HISTORY
# ─────────────────────────────────────────
#  NETWORK TOPOLOGY PAGE
# ─────────────────────────────────────────

@app.route('/topology')
@login_required
def topology_page():
    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()

    scans_data = []
    for job in history:
        if job.status != 'Completed' or not job.result_data:
            continue
        try:
            raw = json.loads(job.result_data)
        except Exception:
            continue

        hosts_list = []
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get('hosts', raw.get('results', []))
        else:
            items = []

        for h in items:
            ports = []
            for p in (h.get('ports') or []):
                ports.append({
                    'port': p.get('port', ''),
                    'protocol': p.get('protocol', 'tcp'),
                    'name': p.get('name', ''),
                    'version_info': p.get('version_info', '')
                })
            hosts_list.append({
                'ip':    h.get('ip', ''),
                'mac':   h.get('mac', ''),
                'os':    h.get('os', h.get('status', '')),
                'ports': ports
            })

        date_str = job.timestamp.strftime('%Y-%m-%d') if job.timestamp else '1970-01-01'
        scans_data.append({
            'job_id':    job.id,
            'job_name':  job.scan_name or f'Job #{job.id}',
            'scan_type': job.scan_type or '',
            'date':      date_str,
            'target':    job.target,
            'hosts':     hosts_list
        })

    import json as _json
    scans_json = _json.dumps(scans_data)
    return render_template('network_topology.html', scans_json=scans_json)


# ─────────────────────────────────────────

@app.route('/history')
@login_required
def history_page():
    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()
    from collections import defaultdict

    # คำนวณลำดับ scan ของ target เดียวกัน (count badge)
    target_jobs = defaultdict(list)
    for j in history:
        target_jobs[j.target].append(j)
    scan_seq_map = {}
    for target, tlist in target_jobs.items():
        sorted_list = sorted(tlist, key=lambda x: x.timestamp or 0)
        for idx, tj in enumerate(sorted_list, 1):
            scan_seq_map[tj.id] = (idx, len(sorted_list))

    # คำนวณลำดับ scan ของแต่ละ owner แยกกัน (#1, #2, #3 ...)
    # ดึงจาก DB โดยตรงตาม owner_id จริงๆ ไม่ผ่าน visible_scans_query
    # เพื่อให้นับถูก: admin สแกนครั้งแรก = #1 เสมอ ไม่สนว่า global id เป็นเท่าไหร่
    owner_seq_map = {}
    unique_owner_ids = {j.owner_id for j in history if j.owner_id is not None}
    for oid in unique_owner_ids:
        owner_all = ScanJob.query.filter_by(owner_id=oid).order_by(ScanJob.timestamp).all()
        for idx, tj in enumerate(owner_all, 1):
            owner_seq_map[tj.id] = idx

    return render_template('history.html', history=history,
                           scan_seq_map=scan_seq_map,
                           owner_seq_map=owner_seq_map)


# ─────────────────────────────────────────
#  DELETE SCAN HISTORY
# ─────────────────────────────────────────

@app.route('/history/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    # เฉพาะ admin และ superadmin เท่านั้นที่ลบได้
    if not current_user.is_any_admin:
        abort(403)
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    db.session.delete(job)
    db.session.commit()
    flash(f'ลบ Scan #{scan_id} เรียบร้อยแล้ว', 'success')
    return redirect(url_for('history_page'))


@app.route('/history/delete-by-target', methods=['POST'])
@login_required
def delete_scans_by_target():
    # เฉพาะ admin และ superadmin เท่านั้นที่ลบได้
    if not current_user.is_any_admin:
        abort(403)
    target = request.form.get('target', '').strip()
    if not target:
        flash('ไม่พบ Target ที่ระบุ', 'danger')
        return redirect(url_for('history_page'))
    jobs = visible_scans_query().filter_by(target=target).all()
    count = len(jobs)
    for job in jobs:
        db.session.delete(job)
    db.session.commit()
    flash(f'ลบ Scan ของ {target} ทั้งหมด {count} รายการเรียบร้อยแล้ว', 'success')
    return redirect(url_for('history_page'))


# ─────────────────────────────────────────
#  TASKS
# ─────────────────────────────────────────

@app.route("/tasks")
@login_required
def tasks_page():
    schedules = visible_schedules_query().order_by(ScheduledScan.created_at.desc()).all()
    from collections import Counter
    all_jobs = visible_scans_query().all()
    target_scan_counts = Counter(j.target for j in all_jobs if j.status == 'Completed')
    return render_template("tasks.html", schedules=schedules, target_scan_counts=target_scan_counts)


# ─────────────────────────────────────────
#  API
# ─────────────────────────────────────────

@app.route('/api/scanned-ips')
@login_required
def scanned_ips():
    saved = SavedTarget.query.order_by(SavedTarget.target).all()
    return jsonify([{'id': s.id, 'target': s.target, 'label': s.label or ''} for s in saved])


@app.route('/api/scanned-ips', methods=['POST'])
@login_required
@admin_required
def save_ip():
    data = request.get_json()
    target = (data.get('target') or '').strip()
    label = (data.get('label') or '').strip() or None
    if not target:
        return jsonify({'error': 'target required'}), 400
    if SavedTarget.query.filter_by(target=target).first():
        return jsonify({'error': 'already exists'}), 409
    s = SavedTarget(target=target, label=label)
    db.session.add(s)
    db.session.commit()
    return jsonify({'id': s.id, 'target': s.target, 'label': s.label or ''}), 201


@app.route('/api/scanned-ips/<int:ip_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_saved_ip(ip_id):
    s = SavedTarget.query.get_or_404(ip_id)
    db.session.delete(s)
    db.session.commit()
    return jsonify({'deleted': ip_id})


@app.route('/api/jobs')
@login_required
def api_jobs():
    jobs = visible_scans_query().order_by(ScanJob.timestamp.desc()).limit(100).all()
    from collections import defaultdict
    target_jobs = defaultdict(list)
    for j in jobs:
        target_jobs[j.target].append(j)
    target_seq = {}
    for target, tlist in target_jobs.items():
        sorted_list = sorted(tlist, key=lambda x: x.timestamp or 0)
        for idx, tj in enumerate(sorted_list, 1):
            target_seq[tj.id] = (idx, len(sorted_list))

    # คำนวณลำดับ scan ของแต่ละ owner แยกกัน (#1, #2, #3 ...)
    # เหมือนกับที่ history และ dashboard ใช้
    owner_seq_map = {}
    unique_owner_ids = {j.owner_id for j in jobs if j.owner_id is not None}
    for oid in unique_owner_ids:
        owner_all = ScanJob.query.filter_by(owner_id=oid).order_by(ScanJob.timestamp).all()
        for idx, tj in enumerate(owner_all, 1):
            owner_seq_map[tj.id] = idx

    result = []
    for j in jobs:
        seq, total = target_seq.get(j.id, (1, 1))
        result.append({
            'id': j.id,
            'owner_seq': owner_seq_map.get(j.id, j.id),
            'scan_name': j.scan_name or '',
            'target': j.target,
            'scan_type': j.scan_type,
            'status': j.status,
            'triggered_by': j.triggered_by or 'manual',
            'timestamp': j.timestamp.strftime('%Y-%m-%d %H:%M:%S') if j.timestamp else '',
            'scan_seq': seq,
            'scan_total': total,
        })
    return jsonify(result)


# ─────────────────────────────────────────
#  SCAN DETAIL
# ─────────────────────────────────────────

@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    scan_data = json.loads(job.result_data) if job.result_data else []
    same_target_jobs = visible_scans_query().filter_by(target=job.target).order_by(ScanJob.timestamp).all()
    target_scan_count = len(same_target_jobs)
    scan_seq = next((i+1 for i, j in enumerate(same_target_jobs) if j.id == job.id), 1)

    # คำนวณลำดับของ job นี้ในบรรดา scan ทั้งหมดของ owner จริงๆ (ดึงตรงจาก DB)
    all_owner_jobs = ScanJob.query.filter_by(owner_id=job.owner_id).order_by(ScanJob.timestamp).all()
    owner_seq = next((i+1 for i, j in enumerate(all_owner_jobs) if j.id == job.id), job.id)

    template = 'vuln_scan_detail.html' if job.scan_type == 'vuln_scan' else 'scan_detail.html'
    return render_template(template, job=job, scan_data=scan_data,
                           target_scan_count=target_scan_count, scan_seq=scan_seq,
                           owner_seq=owner_seq)


# ─────────────────────────────────────────
#  SCHEDULED SCANS
# ─────────────────────────────────────────

@app.route('/schedules/create', methods=['POST'])
@login_required
@admin_required
def create_schedule():
    name = request.form.get('name')
    target = request.form.get('target')
    scan_type = request.form.get('scan_type')
    repeat = request.form.get('repeat', 'daily')
    time_str = request.form.get('time', '00:00')
    custom_args = request.form.get('custom_args', '').strip() or None

    try:
        hour, minute = map(int, time_str.split(':'))
    except ValueError:
        flash('Invalid time format', 'danger')
        return redirect(url_for('tasks_page'))

    day_of_week = int(request.form.get('day_of_week', 0)) if repeat == 'weekly' else None
    day_of_month = int(request.form.get('day_of_month', 1)) if repeat == 'monthly' else None

    schedule = ScheduledScan(
        name=name, target=target, scan_type=scan_type,
        cron_hour=hour, cron_minute=minute,
        repeat=repeat, day_of_week=day_of_week, day_of_month=day_of_month,
        is_active=True, created_by=current_user.id,
        owner_id=current_user.id,
        custom_args=custom_args if scan_type == 'custom' else None
    )
    schedule.next_run = calc_next_run(schedule)
    db.session.add(schedule)
    db.session.commit()
    register_apscheduler_job(schedule)

    flash(f'Schedule "{name}" created! Next run: {schedule.next_run.strftime("%Y-%m-%d %H:%M")}', 'success')
    return redirect(url_for('tasks_page'))


@app.route('/schedules/<int:schedule_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_schedule(schedule_id):
    schedule = visible_schedules_query().filter_by(id=schedule_id).first_or_404()
    schedule.is_active = not schedule.is_active
    if schedule.is_active:
        schedule.next_run = calc_next_run(schedule)
    db.session.commit()
    register_apscheduler_job(schedule)
    return jsonify({'is_active': schedule.is_active,
                    'next_run': schedule.next_run.strftime('%Y-%m-%d %H:%M') if schedule.next_run else None})


@app.route('/schedules/<int:schedule_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_schedule(schedule_id):
    schedule = visible_schedules_query().filter_by(id=schedule_id).first_or_404()
    job_id = f'schedule_{schedule.id}'
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    db.session.delete(schedule)
    db.session.commit()
    flash(f'Schedule "{schedule.name}" deleted.', 'success')
    return redirect(url_for('tasks_page'))


@app.route('/tasks/<int:job_id>/cancel', methods=['POST'])
@login_required
@admin_required
def cancel_job(job_id):
    """หยุด job ที่กำลัง Running และเปลี่ยน status เป็น Cancelled"""
    job = visible_scans_query().filter_by(id=job_id).first_or_404()
    if job.status != 'Running':
        return jsonify({'error': 'Job is not running'}), 400
    job.status = 'Cancelled'
    db.session.commit()
    return jsonify({'success': True, 'status': 'Cancelled'})


@app.route('/tasks/<int:job_id>/rescan', methods=['POST'])
@login_required
@admin_required
def rescan_job(job_id):
    """สร้าง job ใหม่ด้วย target เดิม + scan_type ที่เลือกใหม่ (เก็บ job เดิมไว้เป็นประวัติ)"""
    original = visible_scans_query().filter_by(id=job_id).first_or_404()

    # ห้าม rescan ถ้า scan มาจาก XML Upload
    if original.scan_type == 'xml_upload':
        flash('❌ ไม่สามารถ Rescan ได้ เนื่องจาก scan นี้มาจาก XML Upload', 'danger')
        return redirect(url_for('tasks_page'))

    # ห้าม rescan ถ้า target นี้กำลัง Running อยู่
    running = visible_scans_query().filter_by(target=original.target, status='Running').first()
    if running:
        flash(f'❌ Target "{original.target}" กำลังสแกนอยู่ กรุณารอให้เสร็จก่อน', 'danger')
        return redirect(url_for('tasks_page'))

    scan_type   = request.form.get('scan_type', original.scan_type)
    scan_name   = original.scan_name
    target      = original.target
    custom_args = request.form.get('custom_args', '').strip() or None

    # เก็บ job เดิมไว้เป็นประวัติ — ไม่ลบ
    # สร้าง job ใหม่เพิ่มเข้าไป
    new_job = ScanJob(
        target=target,
        scan_type=scan_type,
        scan_name=scan_name,
        status='Running',
        triggered_by='rescan',
        owner_id=current_user.id,
    )
    db.session.add(new_job)
    db.session.commit()

    results = run_vuln_scan(target) if scan_type == 'vuln_scan' else run_network_scan(target, scan_type, custom_args=custom_args)
    results_data = json.loads(results)
    has_error = results_data and results_data[0].get('error')
    new_job.status = 'Failed' if has_error else 'Completed'
    new_job.result_data = results
    db.session.commit()

    if has_error:
        flash(f'Rescan failed: {results_data[0]["error"]}', 'danger')
    else:
        flash(f'🔁 Rescan "{target}" เสร็จสิ้น! (ประวัติเดิมถูกเก็บไว้)', 'success')

    return redirect(url_for('tasks_page'))



@app.route('/scan/<int:scan_id>/drilldown', methods=['POST'])
@login_required
@admin_required
def drilldown_scan(scan_id):
    """Progressive Drill-down: สแกน host เฉพาะตัวจากผลสแกนครั้งก่อน"""
    parent_job = visible_scans_query().filter_by(id=scan_id).first_or_404()

    host_ip   = request.form.get('host_ip', '').strip()
    scan_type = request.form.get('scan_type', 'fast_scan')
    custom_args = request.form.get('custom_args', '').strip() or None

    if not host_ip:
        flash('กรุณาระบุ IP ที่ต้องการสแกน', 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    # ตรวจว่า IP นี้กำลังสแกนอยู่หรือไม่
    running = visible_scans_query().filter_by(target=host_ip, status='Running').first()
    if running:
        flash(f'❌ Target "{host_ip}" กำลังสแกนอยู่ กรุณารอให้เสร็จก่อน', 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    # สร้าง scan name ที่อ้างอิง parent scan
    parent_label = parent_job.scan_name or f'Scan #{parent_job.id}'
    scan_name = f'Drill-down: {host_ip} (from {parent_label})'

    new_job = ScanJob(
        target=host_ip,
        scan_type=scan_type,
        scan_name=scan_name,
        status='Running',
        triggered_by='drilldown',
        owner_id=current_user.id,
    )
    db.session.add(new_job)
    # บันทึก IP ไว้ในรายชื่อ saved targets ถ้ายังไม่มี
    if not SavedTarget.query.filter_by(target=host_ip).first():
        db.session.add(SavedTarget(target=host_ip))
    db.session.commit()

    results = run_vuln_scan(host_ip) if scan_type == 'vuln_scan' else run_network_scan(host_ip, scan_type, custom_args=custom_args)
    results_data = json.loads(results)
    has_error = results_data and results_data[0].get('error')
    new_job.status = 'Failed' if has_error else 'Completed'
    new_job.result_data = results
    db.session.commit()

    if has_error:
        flash(f'Drill-down scan failed: {results_data[0]["error"]}', 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    flash(f'🔍 Drill-down scan on {host_ip} completed!', 'success')
    return redirect(url_for('scan_detail', scan_id=new_job.id))


@app.route('/schedules/<int:schedule_id>/run_now', methods=['POST'])
@login_required
@admin_required
def run_schedule_now(schedule_id):
    schedule = visible_schedules_query().filter_by(id=schedule_id).first_or_404()
    execute_scheduled_scan(schedule.id)
    flash(f'Schedule "{schedule.name}" triggered manually!', 'success')
    return redirect(url_for('tasks_page'))


# ─────────────────────────────────────────
#  USER MANAGEMENT
# ─────────────────────────────────────────

@app.route('/users')
@login_required
@user_management_required
def user_management():
    if current_user.role == 'superadmin':
        # superadmin เห็น: admin ทุกคน + user ทุกคน (ยกเว้นตัวเอง)
        admins = User.query.filter_by(role='admin').order_by(User.id).all()
        users  = User.query.filter_by(role='user').order_by(User.id).all()
    else:
        # admin เห็น: เฉพาะ user ใต้สังกัดตัวเอง
        admins = []
        users  = User.query.filter_by(role='user', created_by=current_user.id).order_by(User.id).all()

    return render_template('user_management.html', admins=admins, users=users)


@app.route('/users/create', methods=['POST'])
@login_required
@user_management_required
def create_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role     = request.form.get('role', 'user')

    # admin ธรรมดาสร้างได้แค่ user เท่านั้น
    if current_user.role == 'admin' and role != 'user':
        flash('Admin สามารถสร้างได้เฉพาะ User เท่านั้น', 'danger')
        return redirect(url_for('user_management'))

    if not username or not password:
        flash('กรุณากรอก username และ password', 'danger')
        return redirect(url_for('user_management'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" มีอยู่แล้ว', 'danger')
        return redirect(url_for('user_management'))

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        created_by=current_user.id
    )
    db.session.add(new_user)
    db.session.commit()
    flash(f'สร้าง {role} "{username}" สำเร็จ', 'success')
    return redirect(url_for('user_management'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@user_management_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('ไม่สามารถลบตัวเองได้', 'danger')
        return redirect(url_for('user_management'))

    # superadmin ลบได้ทุกคน ยกเว้น superadmin ด้วยกัน
    if user.role == 'superadmin':
        flash('ไม่สามารถลบ Superadmin ได้', 'danger')
        return redirect(url_for('user_management'))

    # admin ลบได้เฉพาะ user ใต้สังกัดตัวเอง
    if current_user.role == 'admin' and user.created_by != current_user.id:
        abort(403)

    deleted_username = user.username
    deleted_role = user.role

    # ถ้าลบ admin ให้ลบ ScanJob + ScheduledScan + user ใต้สังกัดทั้งหมดก่อน
    if user.role == 'admin':
        sub_users = User.query.filter_by(created_by=user.id).all()
        for sub_user in sub_users:
            # ลบ ScanJob และ ScheduledScan ของ sub_user ด้วย
            ScanJob.query.filter_by(owner_id=sub_user.id).delete()
            ScheduledScan.query.filter_by(owner_id=sub_user.id).delete()
            db.session.delete(sub_user)
        # ลบ ScanJob และ ScheduledScan ของ admin เอง
        ScanJob.query.filter_by(owner_id=user.id).delete()
        ScheduledScan.query.filter_by(owner_id=user.id).delete()
    else:
        # ลบ ScanJob และ ScheduledScan ของ user ธรรมดา
        ScanJob.query.filter_by(owner_id=user.id).delete()
        ScheduledScan.query.filter_by(owner_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()

    if deleted_role == 'admin':
        flash(f'ลบ Admin "{deleted_username}" และ User ใต้สังกัดทั้งหมดแล้ว', 'success')
    else:
        flash(f'ลบ "{deleted_username}" แล้ว', 'success')
    return redirect(url_for('user_management'))


@app.route('/users/<int:user_id>/reset_password', methods=['POST'])
@login_required
@user_management_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)

    # ป้องกัน admin reset password ของ user ที่ไม่ใช่ของตัวเอง
    if current_user.role == 'admin' and user.created_by != current_user.id and user.id != current_user.id:
        abort(403)

    # ป้องกัน reset password ของ superadmin
    if user.role == 'superadmin' and current_user.role != 'superadmin':
        abort(403)

    new_pw = request.form.get('new_password', '').strip()
    if not new_pw:
        flash('กรุณากรอก password ใหม่', 'danger')
        return redirect(url_for('user_management'))

    user.password_hash = generate_password_hash(new_pw)
    db.session.commit()
    flash(f'Reset password ของ "{user.username}" สำเร็จ', 'success')
    return redirect(url_for('user_management'))


# ─────────────────────────────────────────
#  UPLOAD XML
# ─────────────────────────────────────────

@app.route('/upload-xml', methods=['POST'])
@login_required
@admin_required
def upload_xml():
    import xml.etree.ElementTree as ET
    import os

    file = request.files.get('nmap_xml')
    if not file or file.filename == '':
        flash('กรุณาเลือกไฟล์ XML', 'danger')
        return redirect(url_for('tasks_page'))

    if not file.filename.lower().endswith('.xml'):
        flash('ไฟล์ต้องเป็น .xml เท่านั้น', 'danger')
        return redirect(url_for('tasks_page'))

    scan_name = request.form.get('xml_scan_name', '').strip() or os.path.splitext(file.filename)[0]

    try:
        xml_content = file.read()
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        flash('ไฟล์ XML ไม่ถูกต้อง', 'danger')
        return redirect(url_for('tasks_page'))

    scan_results = []
    hosts_el = root.findall('host')
    if not hosts_el:
        flash('ไม่พบข้อมูล host ในไฟล์ XML', 'danger')
        return redirect(url_for('tasks_page'))

    targets_found = []
    for host in hosts_el:
        status_el = host.find('status')
        if status_el is None or status_el.get('state') != 'up':
            continue
        addr_el = host.find("address[@addrtype='ipv4']") or host.find('address')
        ip = addr_el.get('addr', 'Unknown') if addr_el is not None else 'Unknown'
        targets_found.append(ip)
        mac_el = host.find("address[@addrtype='mac']")
        mac = mac_el.get('addr', 'Unknown') if mac_el is not None else 'Unknown'
        mac_vendor = mac_el.get('vendor', '') if mac_el is not None else ''
        osmatch = host.find('.//osmatch')
        os_info = osmatch.get('name', 'Unknown') if osmatch is not None else 'Unknown'
        ports = []
        for port_el in host.findall('.//port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            service_el = port_el.find('service')
            name = service_el.get('name', '') if service_el is not None else ''
            product = service_el.get('product', '') if service_el is not None else ''
            version = service_el.get('version', '') if service_el is not None else ''
            extrainfo = service_el.get('extrainfo', '') if service_el is not None else ''
            full_version = f"{product} {version} {extrainfo}".strip() or 'Unknown Version'
            ports.append({
                'port': int(port_el.get('portid', 0)),
                'protocol': port_el.get('protocol', 'tcp'),
                'state': 'open',
                'name': name,
                'version_info': full_version,
            })
        scan_results.append({'ip': ip, 'os': os_info, 'mac': mac, 'mac_vendor': mac_vendor, 'ports': ports})

    if not scan_results:
        flash('ไม่พบ host ที่ online ในไฟล์ XML', 'danger')
        return redirect(url_for('tasks_page'))

    target_display = targets_found[0] if len(targets_found) == 1 else f"{targets_found[0]} (+{len(targets_found)-1} more)"

    new_job = ScanJob(
        scan_name=scan_name, target=target_display,
        scan_type='xml_upload', status='Completed',
        triggered_by='manual', result_data=json.dumps(scan_results),
        owner_id=current_user.id
    )
    db.session.add(new_job)
    for ip in set(targets_found):
        if not SavedTarget.query.filter_by(target=ip).first():
            db.session.add(SavedTarget(target=ip))
    db.session.commit()
    flash(f'นำเข้าไฟล์ XML สำเร็จ! พบ {len(scan_results)} host', 'success')
    return redirect(url_for('scan_detail', scan_id=new_job.id))


# ─────────────────────────────────────────
#  EXPORT CSV / PDF
# ─────────────────────────────────────────

@app.route('/scan/<int:scan_id>/export/csv')
@login_required
def export_csv(scan_id):
    import csv, io
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    scan_data = json.loads(job.result_data) if job.result_data else []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Scan Job ID', 'Target', 'Scan Type', 'Timestamp'])
    writer.writerow([job.id, job.target, SCAN_TYPE_LABELS.get(job.scan_type, job.scan_type),
                     job.timestamp.strftime('%Y-%m-%d %H:%M:%S') if job.timestamp else ''])
    writer.writerow([])
    writer.writerow(['IP Address', 'MAC Address', 'OS / Status', 'Port', 'Protocol', 'State', 'Service', 'Version'])

    for device in scan_data:
        ip = device.get('ip', '')
        mac = device.get('mac', '')
        mac_vendor = device.get('mac_vendor', '')
        mac_display = mac if mac not in ('Unknown', '') else ''
        if mac_display and mac_vendor:
            mac_display = f'{mac_display} ({mac_vendor})'
        os_info = device.get('os') or device.get('status', '')
        ports = device.get('ports', [])
        if ports:
            for port in ports:
                ver = port.get('version_info', '')
                if ver == 'Unknown Version': ver = ''
                writer.writerow([ip, mac_display, os_info,
                                  port.get('port', ''), (port.get('protocol', 'tcp') or '').lower(),
                                  'open', port.get('name', '') or '—', ver])
        else:
            writer.writerow([ip, mac_display, os_info, '—', '—', '—', 'No ports', '—'])

    output.seek(0)
    from flask import Response
    import re as _re
    custom_name = request.args.get('filename', '').strip()
    if custom_name:
        custom_name = _re.sub(r'[\\/:*?"<>|]', '_', custom_name)
        filename = custom_name + '.csv'
    else:
        filename = f"scan_{job.id}_{job.target.replace('/', '_').replace(' ', '_')}_{job.timestamp.strftime('%Y%m%d_%H%M%S') if job.timestamp else 'export'}.csv"
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename="{filename}"'})


@app.route('/scan/<int:scan_id>/export/pdf')
@login_required
def export_pdf(scan_id):
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    scan_data = json.loads(job.result_data) if job.result_data else []

    timestamp_str = job.timestamp.strftime('%Y-%m-%d %H:%M:%S') if job.timestamp else 'N/A'
    total_hosts = len(scan_data)
    total_ports = sum(len(d.get('ports', [])) for d in scan_data)
    scan_name_display = job.scan_name if job.scan_name else f'Scan #{job.id}'

    is_vuln_scan = job.scan_type in ('vuln', 'vulnerability', 'cve') if hasattr(job, 'scan_type') else False

    rows_html = ''
    for idx, device in enumerate(scan_data):
        ip      = device.get('ip', '') or '—'
        mac     = device.get('mac', '') or ''
        if mac in ('Unknown', ''): mac = '—'
        mac_vendor = device.get('mac_vendor', '') or ''
        mac_display = mac
        if mac != '—' and mac_vendor:
            mac_display = f'{mac} ({mac_vendor[:18]})'
        os_info = (device.get('os') or device.get('status') or '—')
        if len(os_info) > 35: os_info = os_info[:33] + '..'
        ports   = device.get('ports', [])
        bg      = '#f4f7ff' if idx % 2 == 1 else '#ffffff'
        border_top = 'border-top:2px solid #d0d8f0;'

        # xhtml2pdf does NOT support rowspan — repeat IP/MAC/OS on every row
        if not ports:
            rows_html += (
                f'<tr style="background-color:{bg};{border_top}">'
                f'<td class="c-ip">{ip}</td>'
                f'<td class="c-mac">{mac_display}</td>'
                f'<td class="c-os">{os_info}</td>'
                f'<td class="c-port" style="color:#aaa;font-style:italic;">—</td>'
                f'<td class="c-proto" style="color:#aaa;font-style:italic;">—</td>'
                f'<td class="c-state" style="color:#aaa;font-style:italic;">—</td>'
                f'<td class="c-svc" style="color:#aaa;font-style:italic;">No ports</td>'
                f'<td class="c-ver" style="color:#aaa;font-style:italic;">—</td>'
                f'</tr>'
            )
        else:
            for pi, p in enumerate(ports):
                proto  = (p.get('protocol') or 'tcp').lower()
                state  = 'open'
                svc    = p.get('name') or '—'
                ver    = p.get('version_info') or ''
                if ver == 'Unknown Version': ver = ''
                if len(ver) > 45: ver = ver[:43] + '..'

                # Build CVE badges — one per line using nested table (xhtml2pdf-safe)
                cves = p.get('cves') or []
                cve_rows = ''
                for cve in cves[:5]:  # max 5 CVEs to keep row height manageable
                    cve_id   = cve.get('cve_id', '')
                    score    = cve.get('cvss_score', '')
                    sev      = (cve.get('severity') or '').upper()
                    sev_color = {'CRITICAL':'#dc2626','HIGH':'#ea580c','MEDIUM':'#ca8a04','LOW':'#16a34a'}.get(sev,'#64748b')
                    sev_bg    = {'CRITICAL':'#fee2e2','HIGH':'#ffedd5','MEDIUM':'#fef9c3','LOW':'#dcfce7'}.get(sev,'#f1f5f9')
                    score_txt = f'({score})' if score else ''
                    cwe_name  = cve.get('cwe_name', '')
                    cwe_html  = (
                        f' <span style="font-size:6px;color:#475569;background:#f1f5f9;'
                        f'border:1px solid #cbd5e1;border-radius:2px;padding:0px 3px;">'
                        f'{cwe_name}</span>'
                    ) if cwe_name else ''
                    if cve_id:
                        cve_rows += (
                            f'<tr><td style="padding:1px 0;">'
                            f'<span style="background:{sev_bg};color:{sev_color};'
                            f'border:1px solid {sev_color};border-radius:2px;'
                            f'padding:0px 3px;font-size:6.5px;font-weight:bold;">'
                            f'{cve_id}{score_txt}</span>{cwe_html}'
                            f'</td></tr>'
                        )
                extra_cves = len(cves) - 5
                if extra_cves > 0:
                    cve_rows += f'<tr><td style="font-size:6.5px;color:#64748b;padding:1px 0;">+{extra_cves} more</td></tr>'

                if ver and cve_rows:
                    ver_cell = (
                        f'<table style="border-collapse:collapse;width:100%;">'
                        f'<tr><td style="font-size:7.5px;color:#555;padding:0 0 2px 0;">{ver}</td></tr>'
                        f'{cve_rows}'
                        f'</table>'
                    )
                elif cve_rows:
                    ver_cell = (
                        f'<table style="border-collapse:collapse;width:100%;">'
                        f'{cve_rows}'
                        f'</table>'
                    )
                else:
                    ver_cell = ver if ver else '<i style="color:#aaa;">—</i>'

                # Repeat IP/MAC/OS on every row (no rowspan)
                ip_cell  = ip  if pi == 0 else f'<span style="color:#bbb;">{ip}</span>'
                mac_cell = mac_display if pi == 0 else ''
                os_cell  = os_info     if pi == 0 else ''
                bt       = border_top  if pi == 0 else ''

                rows_html += (
                    f'<tr style="background-color:{bg};{bt}">'
                    f'<td class="c-ip">{ip_cell}</td>'
                    f'<td class="c-mac">{mac_cell}</td>'
                    f'<td class="c-os">{os_cell}</td>'
                    f'<td class="c-port">{p.get("port","")}</td>'
                    f'<td class="c-proto">{proto}</td>'
                    f'<td class="c-state">{state}</td>'
                    f'<td class="c-svc">{svc}</td>'
                    f'<td class="c-ver">{ver_cell}</td>'
                    f'</tr>'
                )

    html_content = f'''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Scan Report</title>
<style>
@page {{ size: A4 landscape; margin: 12mm 10mm; }}
body {{ font-family: Arial, sans-serif; font-size: 9px; color: #1a1a2e; margin: 0; padding: 0; }}
.hdr {{ background-color: #0f3460; padding: 10px 14px 8px; margin-bottom: 10px; }}
.hdr-title {{ font-size: 15px; font-weight: bold; color: #ffffff; margin: 0 0 3px 0; }}
.hdr-sub {{ font-size: 8px; color: #a8c7fa; }}
.info-table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; }}
.info-table td {{ width: 25%; padding: 6px 10px; border: 1px solid #dde4f5; background-color: #f8f9ff; vertical-align: top; }}
.lbl {{ font-size: 7px; color: #999; text-transform: uppercase; }}
.val {{ font-size: 11px; font-weight: bold; color: #0f3460; margin-top: 2px; }}
.sec {{ font-size: 10px; font-weight: bold; color: #0f3460; padding-left: 7px; border-left: 4px solid #0f3460; margin: 8px 0 5px; text-transform: uppercase; }}
table.rt {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
table.rt thead tr {{ background-color: #0f3460; }}
table.rt thead th {{ padding: 5px; font-size: 8px; font-weight: bold; color: #ffffff; text-align: left; overflow: hidden; }}
table.rt tbody td {{ padding: 3px 4px; vertical-align: top; border-bottom: 1px solid #e8ecf5; overflow: hidden; word-wrap: break-word; font-family: Arial, sans-serif; font-size: 7.5px; color: #555; }}
.c-ip    {{ width: 11%; font-size: 7.5px; color: #333; }}
.c-mac   {{ width: 13%; font-size: 7.5px; color: #555; }}
.c-os    {{ width: 15%; font-size: 7.5px; color: #555; }}
.c-port  {{ width: 7%;  font-size: 7.5px; color: #333; }}
.c-proto {{ width: 6%;  font-size: 7.5px; color: #555; }}
.c-state {{ width: 6%;  font-size: 7.5px; color: #888; }}
.c-svc   {{ width: 10%; font-size: 7.5px; color: #333; }}
.c-ver   {{ width: 32%; font-size: 7.5px; color: #555; }}
.ftr {{ margin-top: 10px; padding-top: 5px; border-top: 1px solid #dde4f5; font-size: 7.5px; color: #aaa; }}
</style></head><body>
<div class="hdr"><p class="hdr-title">Network Scan Report</p><p class="hdr-sub">{scan_name_display} | Generated {datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")} (Bangkok)</p></div>
<table class="info-table"><tr>
  <td><div class="lbl">Target</div><div class="val" style="font-size:9px;">{job.target}</div></td>
  <td><div class="lbl">Scan Profile</div><div class="val" style="font-size:9px;">{SCAN_TYPE_LABELS.get(job.scan_type, job.scan_type)}</div></td>
  <td><div class="lbl">Timestamp</div><div class="val" style="font-size:9px;">{timestamp_str}</div></td>
  <td><div class="lbl">Hosts / Open Ports</div><div class="val">{total_hosts} hosts &nbsp; {total_ports} ports</div></td>
</tr></table>
<div class="sec">Scan Results</div>
<table class="rt"><thead><tr>
  <th class="c-ip">IP Address</th>
  <th class="c-mac">MAC Address</th>
  <th class="c-os">OS / Status</th>
  <th class="c-port">Port</th>
  <th class="c-proto">Protocol</th>
  <th class="c-state">State</th>
  <th class="c-svc">Service</th>
  <th class="c-ver">Version</th>
</tr></thead><tbody>{rows_html}</tbody></table>
<div class="ftr">ScanPhotodash &nbsp;|&nbsp; Scan Job #{job.id} &nbsp;|&nbsp; Total: {total_hosts} hosts, {total_ports} open ports</div>
</body></html>'''

    from flask import Response
    import io
    try:
        from xhtml2pdf import pisa
        pdf_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(html_content.encode('utf-8'), dest=pdf_buffer, encoding='utf-8')
        if pisa_status.err:
            return Response("PDF generation failed", status=500)
        pdf_buffer.seek(0)
        import re as _re2
        custom_name = request.args.get('filename', '').strip()
        if custom_name:
            custom_name = _re2.sub(r'[\\/:*?"<>|]', '_', custom_name)
            filename = custom_name + '.pdf'
        else:
            safe_target = job.target.replace('/', '_').replace(' ', '_').replace('\\', '_')
            ts_str = job.timestamp.strftime('%Y%m%d_%H%M%S') if job.timestamp else 'export'
            filename = f"scan_{job.id}_{safe_target}_{ts_str}.pdf"
        return Response(pdf_buffer.read(), mimetype='application/pdf',
                        headers={'Content-Disposition': f'attachment; filename="{filename}"'})
    except ImportError:
        filename = f"scan_{job.id}_report.html"
        return Response(html_content, mimetype='text/html',
                        headers={'Content-Disposition': f'attachment; filename="{filename}"'})


# ─────────────────────────────────────────
#  ERROR HANDLERS
# ─────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


if __name__ == '__main__':
    app.run(debug=True)
