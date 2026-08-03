from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Bangkok")

def now_th():
    return datetime.now(TZ).replace(tzinfo=None)

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # role: 'superadmin' | 'admin' | 'user'
    role = db.Column(db.String(20), default='user')
    # admin ที่สร้าง user/admin คนนี้
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=now_th)

    subordinates = db.relationship('User', backref=db.backref('creator', remote_side=[id]),
                                   foreign_keys=[created_by])

    @property
    def is_superadmin(self):
        return self.role == 'superadmin'

    @property
    def is_any_admin(self):
        return self.role in ('admin', 'superadmin')


class ScanJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_name = db.Column(db.String(150), nullable=True)
    target = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(50))
    status = db.Column(db.String(20), default='Running')
    timestamp = db.Column(db.DateTime, default=now_th)
    result_data = db.Column(db.Text)
    triggered_by = db.Column(db.String(20), default='manual')
    # admin/superadmin ที่เป็นเจ้าของ scan นี้
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    owner = db.relationship('User', foreign_keys=[owner_id])


class SavedTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(100), unique=True, nullable=False)
    label = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, default=now_th)


class ScheduledScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    cron_hour = db.Column(db.Integer, nullable=False)
    cron_minute = db.Column(db.Integer, default=0)
    repeat = db.Column(db.String(20), default='daily')
    day_of_week = db.Column(db.Integer, nullable=True)
    day_of_month = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now_th)
    last_run = db.Column(db.DateTime, nullable=True)
    next_run = db.Column(db.DateTime, nullable=True)
    # custom nmap args สำหรับ scan_type == 'custom'
    custom_args = db.Column(db.String(500), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    # owner ของ schedule (admin/superadmin)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
