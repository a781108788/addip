#!/bin/bash
# 3proxy Web Management System - One-Click Deployment Script
# Author: 3proxy-web-manager
# Version: 2.0
# Description: Optimized 3proxy web management with monitoring, backup, and performance features

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置变量
WORKDIR=/opt/3proxy-web
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_PATH=/usr/local/etc/3proxy/3proxy.cfg
LOGDIR=/var/log/3proxy
BACKUP_DIR=/opt/3proxy-web/backups

# 获取本地IP
function get_local_ip() {
    local pubip lanip
    pubip=$(curl -s ifconfig.me || curl -s ip.sb || curl -s icanhazip.com)
    lanip=$(hostname -I | awk '{print $1}')
    if [[ -n "$pubip" && "$pubip" != "$lanip" ]]; then
        echo "$pubip"
    else
        echo "$lanip"
    fi
}

# 卸载函数
function uninstall_3proxy_web() {
    echo -e "${YELLOW}正在卸载3proxy Web管理系统...${NC}"
    
    systemctl stop 3proxy-web 2>/dev/null || true
    systemctl stop 3proxy 2>/dev/null || true
    systemctl disable 3proxy-web 2>/dev/null || true
    systemctl disable 3proxy 2>/dev/null || true
    
    rm -rf $WORKDIR
    rm -f /etc/systemd/system/3proxy-web.service
    rm -f /etc/systemd/system/3proxy.service
    rm -f /usr/local/bin/3proxy
    rm -rf /usr/local/etc/3proxy
    rm -rf $LOGDIR
    rm -f /etc/logrotate.d/3proxy
    rm -f /etc/sysctl.d/99-proxy-optimize.conf
    rm -f /etc/sysctl.d/99-bbr.conf
    
    systemctl daemon-reload
    
    echo -e "${RED}3proxy Web管理系统已完全卸载${NC}"
}

# 处理命令行参数
if [[ "$1" == "uninstall" ]]; then
    uninstall_3proxy_web
    exit 0
fi

if [[ "$1" == "reinstall" ]]; then
    uninstall_3proxy_web
    echo -e "${GREEN}正在重新安装...${NC}"
fi

# 生成随机端口和密码
PORT=$((RANDOM%55534+10000))
ADMINUSER="admin"
ADMINPASS=$(tr -dc 'A-Za-z0-9!@#$%^&*' </dev/urandom | head -c 16)
SECRET_KEY=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)

echo -e "\n${BLUE}========= 1. 安装系统依赖 =========${NC}\n"
apt update
apt install -y gcc make git wget curl python3 python3-pip python3-venv sqlite3 \
    cron logrotate redis-server nginx certbot python3-certbot-nginx \
    htop iotop nethogs

# 启动Redis
systemctl enable redis-server
systemctl start redis-server

echo -e "\n${BLUE}========= 2. 编译安装 3proxy =========${NC}\n"
if [ ! -f "$THREEPROXY_PATH" ]; then
    cd /tmp
    rm -rf 3proxy
    git clone --depth=1 https://github.com/3proxy/3proxy.git
    cd 3proxy
    make -f Makefile.Linux
    mkdir -p /usr/local/bin /usr/local/etc/3proxy $LOGDIR
    cp bin/3proxy /usr/local/bin/
    chmod +x /usr/local/bin/3proxy
fi

echo -e "\n${BLUE}========= 3. 系统性能优化 =========${NC}\n"

# 启用BBR
cat > /etc/sysctl.d/99-bbr.conf <<EOF
# Enable BBR
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

# 系统优化参数
cat > /etc/sysctl.d/99-proxy-optimize.conf <<EOF
# Network optimizations for proxy server
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.ipv4.netfilter.ip_conntrack_max = 1000000

# TCP optimizations
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 50000

# Buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# File descriptors
fs.file-max = 2000000
EOF

sysctl -p /etc/sysctl.d/99-bbr.conf
sysctl -p /etc/sysctl.d/99-proxy-optimize.conf

# 系统限制优化
cat > /etc/security/limits.d/99-proxy.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 65535
* hard nproc 65535
EOF

echo -e "\n${BLUE}========= 4. 部署Web管理系统 =========${NC}\n"

# 创建工作目录
mkdir -p $WORKDIR/{app/{routes,static/{css,js,lib},templates},services,logs} $BACKUP_DIR
cd $WORKDIR

# 创建Python虚拟环境
python3 -m venv venv
source venv/bin/activate

# 创建requirements.txt
cat > requirements.txt <<EOF
Flask==2.3.2
Flask-SQLAlchemy==3.0.5
Flask-SocketIO==5.3.4
Flask-Login==0.6.2
Flask-Compress==1.13
Flask-Caching==2.0.2
Flask-WTF==1.1.1
Werkzeug==2.3.6
psutil==5.9.5
APScheduler==3.10.1
redis==4.5.5
python-socketio==5.9.0
gunicorn==20.1.0
eventlet==0.33.3
python-dotenv==1.0.0
EOF

pip install -r requirements.txt

# ==================== 创建配置文件 ====================
cat > config.py <<EOF
import os
from datetime import timedelta

class Config:
    # Flask配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or '${SECRET_KEY}'
    
    # 数据库配置
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'proxy_manager.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 3proxy配置
    PROXY_CONFIG_FILE = '${PROXYCFG_PATH}'
    PROXY_LOG_DIR = '${LOGDIR}'
    
    # 监控配置
    MONITORING_INTERVAL = 5  # 秒
    MONITORING_CACHE_TTL = 3  # 秒
    
    # 备份配置
    BACKUP_DIR = '${BACKUP_DIR}'
    BACKUP_RETENTION_DAYS = 7
    
    # 分页配置
    PROXIES_PER_PAGE = 50
    
    # Redis配置
    REDIS_URL = 'redis://localhost:6379/0'
    
    # 日志配置
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Session配置
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
EOF

# ==================== app/__init__.py ====================
cat > app/__init__.py <<'EOF'
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_compress import Compress
from flask_caching import Cache
import logging

db = SQLAlchemy()
socketio = SocketIO()
login_manager = LoginManager()
compress = Compress()
cache = Cache()

def create_app(config_name='config.Config'):
    app = Flask(__name__)
    app.config.from_object(config_name)
    
    # 初始化扩展
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet')
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    compress.init_app(app)
    cache.init_app(app, config={'CACHE_TYPE': 'redis', 'CACHE_REDIS_URL': app.config['REDIS_URL']})
    
    # 设置日志
    if not app.debug:
        logging.basicConfig(level=logging.INFO)
    
    # 初始化服务
    from services.system_monitor import SystemMonitor
    from services.backup_service import BackupService
    from services.proxy_manager import ProxyManager
    from services.log_manager import LogManager
    
    app.system_monitor = SystemMonitor()
    app.backup_service = BackupService()
    app.proxy_manager = ProxyManager()
    app.log_manager = LogManager()
    
    app.system_monitor.init_app(app, socketio)
    app.backup_service.init_app(app)
    app.proxy_manager.init_app(app)
    app.log_manager.init_app(app)
    
    # 启动监控
    app.system_monitor.start_monitoring()
    
    # 注册蓝图
    from app.routes import main, proxy, monitor, backup, auth
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(proxy.bp, url_prefix='/proxy')
    app.register_blueprint(monitor.bp, url_prefix='/monitor')
    app.register_blueprint(backup.bp, url_prefix='/backup')
    
    # 创建数据库表
    with app.app_context():
        db.create_all()
        # 创建默认管理员
        from app.models import User
        if not User.query.filter_by(username='${ADMINUSER}').first():
            admin = User(username='${ADMINUSER}')
            admin.set_password('${ADMINPASS}')
            admin.is_admin = True
            db.session.add(admin)
            db.session.commit()
    
    return app
EOF

# ==================== app/models.py ====================
cat > app/models.py <<'EOF'
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ProxyGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_range = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), default='server')
    color = db.Column(db.String(20), default='primary')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    proxies = db.relationship('Proxy', backref='group', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def proxy_count(self):
        return self.proxies.count()
    
    @property
    def active_proxy_count(self):
        return self.proxies.filter_by(status='active').count()

class Proxy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('proxy_group.id'))
    type = db.Column(db.String(20), default='http')
    external_ip = db.Column(db.String(45), nullable=False)
    internal_ip = db.Column(db.String(45))
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(50))
    password = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')
    max_connections = db.Column(db.Integer, default=1000)
    current_connections = db.Column(db.Integer, default=0)
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_received = db.Column(db.BigInteger, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'external_ip': self.external_ip,
            'port': self.port,
            'status': self.status,
            'username': self.username,
            'connections': f"{self.current_connections}/{self.max_connections}",
            'traffic': {
                'sent': self.bytes_sent,
                'received': self.bytes_received
            }
        }

class SystemMetrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cpu_percent = db.Column(db.Float)
    memory_percent = db.Column(db.Float)
    disk_percent = db.Column(db.Float)
    network_sent = db.Column(db.BigInteger)
    network_recv = db.Column(db.BigInteger)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
EOF

# ==================== 创建路由文件 ====================
mkdir -p app/routes

# auth.py - 认证路由
cat > app/routes/auth.py <<'EOF'
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from app.models import User

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash('用户名或密码错误', 'danger')
    
    return render_template('auth/login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
EOF

# main.py - 主页路由
cat > app/routes/main.py <<'EOF'
from flask import Blueprint, render_template
from flask_login import login_required
from app.models import db, ProxyGroup, Proxy, SystemMetrics
from sqlalchemy import func

bp = Blueprint('main', __name__)

@bp.route('/')
@bp.route('/dashboard')
@login_required
def dashboard():
    # 统计数据
    total_groups = ProxyGroup.query.count()
    total_proxies = Proxy.query.count()
    active_proxies = Proxy.query.filter_by(status='active').count()
    total_connections = db.session.query(func.sum(Proxy.current_connections)).scalar() or 0
    
    # 最新系统指标
    latest_metrics = SystemMetrics.query.order_by(SystemMetrics.timestamp.desc()).first()
    
    return render_template('dashboard.html',
                         total_groups=total_groups,
                         total_proxies=total_proxies,
                         active_proxies=active_proxies,
                         total_connections=total_connections,
                         metrics=latest_metrics)
EOF

# proxy.py - 代理管理路由
cat > app/routes/proxy.py <<'EOF'
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, current_app
from flask_login import login_required
from app.models import db, ProxyGroup, Proxy
from app import cache
import ipaddress
import random
import string

bp = Blueprint('proxy', __name__)

@bp.route('/groups')
@login_required
def groups():
    groups = ProxyGroup.query.all()
    return render_template('proxy/groups.html', groups=groups)

@bp.route('/group/<int:group_id>')
@login_required
def group_details(group_id):
    group = ProxyGroup.query.get_or_404(group_id)
    page = request.args.get('page', 1, type=int)
    
    proxies = Proxy.query.filter_by(group_id=group_id).paginate(
        page=page, 
        per_page=current_app.config['PROXIES_PER_PAGE'],
        error_out=False
    )
    
    # 统计信息
    active_count = Proxy.query.filter_by(group_id=group_id, status='active').count()
    total_connections = db.session.query(db.func.sum(Proxy.current_connections)).filter_by(group_id=group_id).scalar() or 0
    total_sent = db.session.query(db.func.sum(Proxy.bytes_sent)).filter_by(group_id=group_id).scalar() or 0
    total_received = db.session.query(db.func.sum(Proxy.bytes_received)).filter_by(group_id=group_id).scalar() or 0
    
    return render_template('proxy/details.html', 
                         group=group,
                         proxies=proxies,
                         active_count=active_count,
                         total_connections=total_connections,
                         total_sent=total_sent,
                         total_received=total_received)

@bp.route('/add_group', methods=['POST'])
@login_required
def add_group():
    name = request.form.get('name')
    ip_range = request.form.get('ip_range')
    description = request.form.get('description')
    icon = request.form.get('icon', 'server')
    color = request.form.get('color', 'primary')
    
    try:
        # 验证IP范围
        ipaddress.ip_network(ip_range)
        
        group = ProxyGroup(
            name=name,
            ip_range=ip_range,
            description=description,
            icon=icon,
            color=color
        )
        db.session.add(group)
        db.session.commit()
        
        flash('代理组添加成功', 'success')
    except ValueError:
        flash('无效的IP范围格式', 'danger')
    
    return redirect(url_for('proxy.groups'))

@bp.route('/add_proxy/<int:group_id>', methods=['POST'])
@login_required
def add_proxy(group_id):
    group = ProxyGroup.query.get_or_404(group_id)
    
    # 批量添加
    if request.form.get('batch_add'):
        ip_start = request.form.get('ip_start')
        ip_end = request.form.get('ip_end')
        port_start = int(request.form.get('port_start', 3128))
        port_count = int(request.form.get('port_count', 1))
        
        try:
            start_ip = ipaddress.ip_address(ip_start)
            end_ip = ipaddress.ip_address(ip_end)
            
            count = 0
            current_port = port_start
            
            for ip_int in range(int(start_ip), int(end_ip) + 1):
                ip = str(ipaddress.ip_address(ip_int))
                for i in range(port_count):
                    username = f"user_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"
                    password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                    
                    proxy = Proxy(
                        group_id=group_id,
                        external_ip=ip,
                        port=current_port + i,
                        username=username,
                        password=password,
                        type=request.form.get('type', 'http')
                    )
                    db.session.add(proxy)
                    count += 1
            
            db.session.commit()
            flash(f'成功添加 {count} 个代理', 'success')
            
        except Exception as e:
            flash(f'添加失败: {str(e)}', 'danger')
    
    # 单个添加
    else:
        external_ip = request.form.get('external_ip')
        port = int(request.form.get('port'))
        username = request.form.get('username')
        password = request.form.get('password')
        
        proxy = Proxy(
            group_id=group_id,
            external_ip=external_ip,
            port=port,
            username=username,
            password=password,
            type=request.form.get('type', 'http')
        )
        db.session.add(proxy)
        db.session.commit()
        
        flash('代理添加成功', 'success')
    
    # 重新生成3proxy配置
    current_app.proxy_manager.update_proxy_config()
    
    return redirect(url_for('proxy.group_details', group_id=group_id))

@bp.route('/api/proxy/<int:proxy_id>', methods=['DELETE'])
@login_required
def delete_proxy(proxy_id):
    proxy = Proxy.query.get_or_404(proxy_id)
    db.session.delete(proxy)
    db.session.commit()
    
    # 重新生成配置
    current_app.proxy_manager.update_proxy_config()
    
    return jsonify({'success': True})

@bp.route('/api/optimize', methods=['POST'])
@login_required
def optimize_performance():
    try:
        results = current_app.proxy_manager.optimize_proxy_performance()
        return jsonify({'success': True, 'optimizations': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
EOF

# monitor.py - 监控路由
cat > app/routes/monitor.py <<'EOF'
from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from app import socketio
import json

bp = Blueprint('monitor', __name__)

@bp.route('/system')
@login_required
def system():
    return render_template('monitor/system.html')

@bp.route('/api/metrics/current')
@login_required
def current_metrics():
    from flask import current_app
    metrics = current_app.system_monitor.get_current_metrics()
    return jsonify(metrics)

@bp.route('/api/metrics/history')
@login_required
def metrics_history():
    from flask import current_app
    minutes = request.args.get('minutes', 60, type=int)
    history = current_app.system_monitor.get_metrics_history(minutes)
    return jsonify(history)

@socketio.on('connect', namespace='/monitoring')
def handle_connect():
    print('Client connected to monitoring')

@socketio.on('disconnect', namespace='/monitoring')
def handle_disconnect():
    print('Client disconnected from monitoring')
EOF

# backup.py - 备份路由
cat > app/routes/backup.py <<'EOF'
from flask import Blueprint, render_template, jsonify, send_file
from flask_login import login_required
from pathlib import Path
import os

bp = Blueprint('backup', __name__)

@bp.route('/management')
@login_required
def management():
    from flask import current_app
    backup_dir = Path(current_app.config['BACKUP_DIR'])
    backups = []
    
    if backup_dir.exists():
        for backup_file in backup_dir.glob('*.tar.gz'):
            stat = backup_file.stat()
            backups.append({
                'name': backup_file.name,
                'size': stat.st_size,
                'created': stat.st_mtime
            })
    
    backups.sort(key=lambda x: x['created'], reverse=True)
    return render_template('backup/management.html', backups=backups)

@bp.route('/api/backup/create', methods=['POST'])
@login_required
def create_backup():
    from flask import current_app
    try:
        success = current_app.backup_service.perform_weekly_backup()
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@bp.route('/download/<filename>')
@login_required
def download_backup(filename):
    from flask import current_app
    backup_path = Path(current_app.config['BACKUP_DIR']) / filename
    if backup_path.exists() and backup_path.suffix == '.gz':
        return send_file(backup_path, as_attachment=True)
    return "File not found", 404
EOF

# __init__.py for routes
cat > app/routes/__init__.py <<'EOF'
# Routes package
EOF

# ==================== 创建服务模块 ====================

# system_monitor.py
cat > services/system_monitor.py <<'EOF'
import psutil
import time
from threading import Thread, Lock
from collections import deque
from datetime import datetime, timedelta

class SystemMonitor:
    def __init__(self, app=None, socketio=None):
        self.app = app
        self.socketio = socketio
        self.monitoring = False
        self.metrics_cache = {}
        self.metrics_history = deque(maxlen=720)  # 1小时数据，5秒间隔
        self.cache_lock = Lock()
        
    def init_app(self, app, socketio):
        self.app = app
        self.socketio = socketio
        
    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            thread = Thread(target=self._monitor_loop, daemon=True)
            thread.start()
    
    def stop_monitoring(self):
        self.monitoring = False
    
    def _monitor_loop(self):
        while self.monitoring:
            try:
                metrics = self._collect_metrics()
                
                with self.cache_lock:
                    self.metrics_cache = metrics
                    self.metrics_history.append(metrics)
                
                if self.socketio:
                    self.socketio.emit('system_metrics', metrics, namespace='/monitoring')
                
                self._save_metrics_to_db(metrics)
                
                time.sleep(self.app.config.get('MONITORING_INTERVAL', 5))
                
            except Exception as e:
                if self.app:
                    self.app.logger.error(f"监控错误: {e}")
                time.sleep(10)
    
    def _collect_metrics(self):
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        
        try:
            load_avg = psutil.getloadavg()
        except AttributeError:
            load_avg = [0, 0, 0]
        
        process_count = len(psutil.pids())
        
        metrics = {
            'timestamp': datetime.utcnow().isoformat(),
            'cpu': {
                'percent': cpu_percent,
                'per_core': cpu_per_core,
                'count': psutil.cpu_count(),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
            },
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used,
                'free': memory.free
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            },
            'system': {
                'load_avg': load_avg,
                'process_count': process_count,
                'boot_time': psutil.boot_time()
            }
        }
        
        return metrics
    
    def get_current_metrics(self):
        with self.cache_lock:
            return self.metrics_cache.copy()
    
    def get_metrics_history(self, minutes=60):
        with self.cache_lock:
            cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
            return [
                m for m in self.metrics_history 
                if datetime.fromisoformat(m['timestamp']) > cutoff_time
            ]
    
    def _save_metrics_to_db(self, metrics):
        if self.app:
            with self.app.app_context():
                from app.models import SystemMetrics, db
                
                metric = SystemMetrics(
                    cpu_percent=metrics['cpu']['percent'],
                    memory_percent=metrics['memory']['percent'],
                    disk_percent=metrics['disk']['percent'],
                    network_sent=metrics['network']['bytes_sent'],
                    network_recv=metrics['network']['bytes_recv']
                )
                
                db.session.add(metric)
                db.session.commit()
                
                # 清理旧数据
                cutoff_date = datetime.utcnow() - timedelta(days=7)
                SystemMetrics.query.filter(
                    SystemMetrics.timestamp < cutoff_date
                ).delete()
                db.session.commit()
EOF

# backup_service.py
cat > services/backup_service.py <<'EOF'
import os
import tarfile
import gzip
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import logging

class BackupService:
    def __init__(self, app=None):
        self.app = app
        self.scheduler = BackgroundScheduler(daemon=True)
        self.logger = logging.getLogger('backup_service')
        
    def init_app(self, app):
        self.app = app
        self.backup_dir = Path(app.config['BACKUP_DIR'])
        self.backup_dir.mkdir(exist_ok=True)
        
        # 每周日凌晨2点备份
        self.scheduler.add_job(
            func=self.perform_weekly_backup,
            trigger=CronTrigger(day_of_week='sun', hour=2, minute=0),
            id='weekly_backup',
            name='Weekly Backup',
            replace_existing=True
        )
        
        self.scheduler.start()
    
    def perform_weekly_backup(self):
        try:
            self.logger.info("开始执行每周备份...")
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            temp_backup_dir = self.backup_dir / f"temp_backup_{timestamp}"
            temp_backup_dir.mkdir(exist_ok=True)
            
            self._backup_proxy_config(temp_backup_dir)
            self._backup_database(temp_backup_dir)
            self._backup_app_config(temp_backup_dir)
            
            archive_path = self._create_compressed_archive(temp_backup_dir, timestamp)
            
            shutil.rmtree(temp_backup_dir)
            
            self._rotate_backups()
            
            self.logger.info(f"备份完成: {archive_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"备份失败: {e}")
            return False
    
    def _backup_proxy_config(self, backup_dir):
        proxy_config = self.app.config['PROXY_CONFIG_FILE']
        if os.path.exists(proxy_config):
            dest = backup_dir / '3proxy.cfg'
            shutil.copy2(proxy_config, dest)
            self.logger.info("3proxy配置备份完成")
    
    def _backup_database(self, backup_dir):
        db_uri = self.app.config['SQLALCHEMY_DATABASE_URI']
        
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri.replace('sqlite:///', '')
            if os.path.exists(db_path):
                dest = backup_dir / 'database.db'
                shutil.copy2(db_path, dest)
        
        self.logger.info("数据库备份完成")
    
    def _backup_app_config(self, backup_dir):
        config_files = ['config.py', 'requirements.txt']
        for config_file in config_files:
            if os.path.exists(config_file):
                shutil.copy2(config_file, backup_dir / config_file)
    
    def _create_compressed_archive(self, source_dir, timestamp):
        archive_name = f"3proxy_backup_{timestamp}.tar.gz"
        archive_path = self.backup_dir / archive_name
        
        with tarfile.open(archive_path, "w:gz", compresslevel=6) as tar:
            tar.add(source_dir, arcname=f"backup_{timestamp}")
        
        return archive_path
    
    def _rotate_backups(self):
        backup_files = list(self.backup_dir.glob("3proxy_backup_*.tar.gz"))
        backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        # 只保留最新的备份
        for old_backup in backup_files[1:]:
            old_backup.unlink()
            self.logger.info(f"删除旧备份: {old_backup}")
EOF

# proxy_manager.py
cat > services/proxy_manager.py <<'EOF'
import os
import subprocess
import shutil
from pathlib import Path

class ProxyManager:
    def __init__(self, app=None):
        self.app = app
        self.config_file = None
        
    def init_app(self, app):
        self.app = app
        self.config_file = app.config['PROXY_CONFIG_FILE']
    
    def update_proxy_config(self):
        """更新3proxy配置文件"""
        from app.models import Proxy, ProxyGroup
        
        config_lines = [
            "daemon",
            "pidfile /var/run/3proxy.pid",
            "log /var/log/3proxy/3proxy.log D",
            "rotate 2",
            "nscache 65536",
            "nscache6 65536",
            "maxconn 10000",
            "timeouts 1 5 30 60 180 1800 15 60",
            "",
            "auth strong",
            ""
        ]
        
        # 获取所有代理
        proxies = Proxy.query.filter_by(status='active').all()
        
        # 生成用户列表
        users = []
        for proxy in proxies:
            if proxy.username and proxy.password:
                users.append(f"{proxy.username}:CL:{proxy.password}")
        
        if users:
            config_lines.append(f"users {' '.join(users)}")
            config_lines.append("")
        
        # 生成代理配置
        for proxy in proxies:
            if proxy.type == 'http':
                config_lines.append(f"auth strong")
                if proxy.username:
                    config_lines.append(f"allow {proxy.username}")
                config_lines.append(f"proxy -n -a -p{proxy.port} -i{proxy.external_ip} -e{proxy.external_ip}")
                config_lines.append("")
            elif proxy.type == 'socks5':
                config_lines.append(f"auth strong")
                if proxy.username:
                    config_lines.append(f"allow {proxy.username}")
                config_lines.append(f"socks -n -a -p{proxy.port} -i{proxy.external_ip} -e{proxy.external_ip}")
                config_lines.append("")
        
        # 写入配置文件
        config_dir = os.path.dirname(self.config_file)
        os.makedirs(config_dir, exist_ok=True)
        
        with open(self.config_file, 'w') as f:
            f.write('\n'.join(config_lines))
        
        # 重启3proxy
        self._restart_proxy_service()
    
    def optimize_proxy_performance(self):
        """优化代理性能"""
        optimizations = []
        
        # BBR已在系统初始化时启用
        optimizations.append("BBR拥塞控制已启用")
        
        # 系统参数已优化
        optimizations.append("系统参数已优化")
        
        # 更新配置
        self.update_proxy_config()
        optimizations.append("3proxy配置已更新")
        
        return optimizations
    
    def _restart_proxy_service(self):
        """重启3proxy服务"""
        try:
            subprocess.run(['systemctl', 'restart', '3proxy'], check=True)
        except:
            subprocess.run(['killall', '3proxy'], stderr=subprocess.DEVNULL)
            subprocess.run(['/usr/local/bin/3proxy', self.config_file])
EOF

# log_manager.py
cat > services/log_manager.py <<'EOF'
import logging
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
import os
from pathlib import Path

class LogManager:
    def __init__(self, app=None):
        self.app = app
        self.handlers = {}
        
    def init_app(self, app):
        self.app = app
        self.setup_logging()
        self._setup_proxy_log_rotation()
    
    def setup_logging(self):
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # 应用主日志
        app_handler = TimedRotatingFileHandler(
            filename=log_dir / 'app.log',
            when='midnight',
            interval=1,
            backupCount=3,
            encoding='utf-8'
        )
        app_handler.setFormatter(self._get_formatter())
        app_handler.setLevel(logging.INFO)
        
        # 错误日志
        error_handler = RotatingFileHandler(
            filename=log_dir / 'error.log',
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        )
        error_handler.setFormatter(self._get_detailed_formatter())
        error_handler.setLevel(logging.ERROR)
        
        self.app.logger.addHandler(app_handler)
        self.app.logger.addHandler(error_handler)
        self.app.logger.setLevel(logging.INFO)
    
    def _get_formatter(self):
        return logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def _get_detailed_formatter(self):
        return logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(funcName)s() - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def _setup_proxy_log_rotation(self):
        """设置3proxy日志轮换"""
        logrotate_config = """${LOGDIR}/*.log {
    daily
    rotate 2
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        /bin/kill -USR1 `cat /var/run/3proxy.pid 2>/dev/null` 2>/dev/null || true
    endscript
}
"""
        
        with open('/etc/logrotate.d/3proxy', 'w') as f:
            f.write(logrotate_config)
EOF

# __init__.py for services
cat > services/__init__.py <<'EOF'
# Services package
EOF

# ==================== 创建模板文件 ====================

# base.html
cat > app/templates/base.html <<'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}3proxy 管理系统{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --dark-bg: #1a1a1a;
            --light-bg: #ecf0f1;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--light-bg);
        }
        
        .navbar {
            background-color: var(--primary-color) !important;
            box-shadow: 0 2px 4px rgba(0,0,0,.1);
        }
        
        .card {
            border: none;
            box-shadow: 0 2px 8px rgba(0,0,0,.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,.15);
        }
        
        .proxy-group-card {
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }
        
        .proxy-group-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background-color: var(--secondary-color);
            transform: translateX(-100%);
            transition: transform 0.3s;
        }
        
        .proxy-group-card:hover::before {
            transform: translateX(0);
        }
        
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        
        .metric-card .metric-icon {
            position: absolute;
            right: -10px;
            bottom: -10px;
            font-size: 60px;
            opacity: 0.3;
        }
        
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }
        
        .status-active { background-color: var(--success-color); }
        .status-inactive { background-color: var(--warning-color); }
        .status-error { background-color: var(--danger-color); }
        
        @media (max-width: 768px) {
            .metric-card {
                margin-bottom: 15px;
            }
        }
    </style>
    {% block styles %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock"></i> 3proxy Manager
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('main.dashboard') }}">
                            <i class="bi bi-speedometer2"></i> 仪表板
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('proxy.groups') }}">
                            <i class="bi bi-collection"></i> 代理管理
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('monitor.system') }}">
                            <i class="bi bi-activity"></i> 系统监控
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('backup.management') }}">
                            <i class="bi bi-archive"></i> 备份管理
                        </a>
                    </li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('auth.logout') }}">
                            <i class="bi bi-box-arrow-right"></i> 退出
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <main class="container-fluid mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </main>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const socket = io('/monitoring', {
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 5
        });
    </script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

# 创建其他模板目录
mkdir -p app/templates/{auth,proxy,monitor,backup}

# login.html
cat > app/templates/auth/login.html <<'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - 3proxy 管理系统</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            width: 100%;
            max-width: 400px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
    </style>
</head>
<body>
    <div class="login-card card">
        <div class="card-body p-5">
            <h3 class="text-center mb-4">3proxy 管理系统</h3>
            <form method="POST">
                <div class="mb-3">
                    <label class="form-label">用户名</label>
                    <input type="text" class="form-control" name="username" required autofocus>
                </div>
                <div class="mb-3">
                    <label class="form-label">密码</label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">登录</button>
            </form>
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }} mt-3">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
        </div>
    </div>
</body>
</html>
EOF

# dashboard.html
cat > app/templates/dashboard.html <<'EOF'
{% extends "base.html" %}

{% block title %}仪表板 - 3proxy Manager{% endblock %}

{% block content %}
<h2 class="mb-4">系统概览</h2>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card metric-card">
            <div class="card-body">
                <h5 class="card-title">代理组</h5>
                <h2>{{ total_groups }}</h2>
                <i class="bi bi-collection metric-icon"></i>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
            <div class="card-body">
                <h5 class="card-title">总代理数</h5>
                <h2>{{ total_proxies }}</h2>
                <i class="bi bi-hdd-network metric-icon"></i>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
            <div class="card-body">
                <h5 class="card-title">活跃代理</h5>
                <h2>{{ active_proxies }}</h2>
                <i class="bi bi-activity metric-icon"></i>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
            <div class="card-body">
                <h5 class="card-title">总连接数</h5>
                <h2>{{ total_connections }}</h2>
                <i class="bi bi-diagram-3 metric-icon"></i>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">系统资源监控</h5>
            </div>
            <div class="card-body">
                <canvas id="resourceChart" height="100"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">快速操作</h5>
            </div>
            <div class="card-body">
                <div class="d-grid gap-2">
                    <a href="{{ url_for('proxy.groups') }}" class="btn btn-primary">
                        <i class="bi bi-plus-circle"></i> 添加代理
                    </a>
                    <button class="btn btn-success" onclick="optimizePerformance()">
                        <i class="bi bi-speedometer"></i> 性能优化
                    </button>
                    <button class="btn btn-info" onclick="createBackup()">
                        <i class="bi bi-archive"></i> 立即备份
                    </button>
                    <a href="{{ url_for('monitor.system') }}" class="btn btn-warning">
                        <i class="bi bi-activity"></i> 查看监控
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
const ctx = document.getElementById('resourceChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'CPU使用率',
            data: [],
            borderColor: 'rgb(255, 99, 132)',
            tension: 0.1
        }, {
            label: '内存使用率',
            data: [],
            borderColor: 'rgb(54, 162, 235)',
            tension: 0.1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                max: 100
            }
        }
    }
});

socket.on('system_metrics', function(data) {
    const time = new Date(data.timestamp).toLocaleTimeString();
    
    if (chart.data.labels.length > 30) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
        chart.data.datasets[1].data.shift();
    }
    
    chart.data.labels.push(time);
    chart.data.datasets[0].data.push(data.cpu.percent);
    chart.data.datasets[1].data.push(data.memory.percent);
    chart.update();
});

function optimizePerformance() {
    if (confirm('确定要执行性能优化吗？')) {
        fetch('/proxy/api/optimize', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('优化完成:\n' + data.optimizations.join('\n'));
                } else {
                    alert('优化失败: ' + data.error);
                }
            });
    }
}

function createBackup() {
    if (confirm('确定要立即创建备份吗？')) {
        fetch('/backup/api/backup/create', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('备份创建成功！');
                } else {
                    alert('备份失败: ' + data.error);
                }
            });
    }
}
</script>
{% endblock %}
EOF

# groups.html
cat > app/templates/proxy/groups.html <<'EOF'
{% extends "base.html" %}

{% block title %}代理组管理 - 3proxy Manager{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h2><i class="bi bi-collection"></i> 代理组管理</h2>
        <p class="text-muted">点击代理组卡片查看详细代理列表</p>
    </div>
    <div class="col-auto">
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addGroupModal">
            <i class="bi bi-plus-circle"></i> 添加代理组
        </button>
    </div>
</div>

<div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 row-cols-xl-4 g-4">
    {% for group in groups %}
    <div class="col">
        <div class="card proxy-group-card h-100" onclick="window.location.href='{{ url_for('proxy.group_details', group_id=group.id) }}'">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-start mb-3">
                    <div>
                        <h5 class="card-title mb-1">
                            <i class="bi bi-{{ group.icon }}"></i> {{ group.name }}
                        </h5>
                        <small class="text-muted">{{ group.ip_range }}</small>
                    </div>
                    <span class="badge bg-{{ group.color }} rounded-pill">
                        {{ group.active_proxy_count }}/{{ group.proxy_count }}
                    </span>
                </div>
                
                <p class="card-text text-muted small">{{ group.description or '暂无描述' }}</p>
                
                <div class="d-flex justify-content-between align-items-center mt-3">
                    <div class="small">
                        <span class="status-indicator status-active"></span>
                        活跃: {{ group.active_proxy_count }}
                    </div>
                    <div class="small text-muted">
                        创建于: {{ group.created_at.strftime('%Y-%m-%d') }}
                    </div>
                </div>
            </div>
            <div class="card-footer bg-transparent">
                <div class="progress" style="height: 4px;">
                    <div class="progress-bar bg-success" 
                         style="width: {{ (group.active_proxy_count / group.proxy_count * 100) if group.proxy_count > 0 else 0 }}%">
                    </div>
                </div>
            </div>
        </div>
    </div>
    {% endfor %}
</div>

<!-- 添加代理组模态框 -->
<div class="modal fade" id="addGroupModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">添加代理组</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="{{ url_for('proxy.add_group') }}">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">组名称</label>
                        <input type="text" class="form-control" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">IP段</label>
                        <input type="text" class="form-control" name="ip_range" 
                               placeholder="例如: 192.168.1.0/24" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">描述</label>
                        <textarea class="form-control" name="description" rows="3"></textarea>
                    </div>
                    <div class="row">
                        <div class="col">
                            <label class="form-label">图标</label>
                            <select class="form-select" name="icon">
                                <option value="server">服务器</option>
                                <option value="hdd-network">网络</option>
                                <option value="shield">安全</option>
                                <option value="globe">全球</option>
                            </select>
                        </div>
                        <div class="col">
                            <label class="form-label">颜色</label>
                            <select class="form-select" name="color">
                                <option value="primary">蓝色</option>
                                <option value="success">绿色</option>
                                <option value="warning">黄色</option>
                                <option value="info">青色</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="submit" class="btn btn-primary">添加</button>
                </div>
            </form>
        </div>
    </div>
</div>
{% endblock %}
EOF

# details.html
cat > app/templates/proxy/details.html <<'EOF'
{% extends "base.html" %}

{% block title %}{{ group.name }} - 代理列表{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="{{ url_for('proxy.groups') }}">代理组</a></li>
                <li class="breadcrumb-item active">{{ group.name }}</li>
            </ol>
        </nav>
        <h2><i class="bi bi-{{ group.icon }}"></i> {{ group.name }}</h2>
        <p class="text-muted">{{ group.description }} - {{ group.ip_range }}</p>
    </div>
    <div class="col-auto">
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addProxyModal">
            <i class="bi bi-plus-circle"></i> 添加代理
        </button>
        <button class="btn btn-secondary" onclick="location.reload()">
            <i class="bi bi-arrow-clockwise"></i> 刷新
        </button>
    </div>
</div>

<!-- 统计信息 -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card text-white bg-success">
            <div class="card-body">
                <h5 class="card-title">活跃代理</h5>
                <h2 class="mb-0">{{ active_count }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-warning">
            <div class="card-body">
                <h5 class="card-title">总连接数</h5>
                <h2 class="mb-0">{{ total_connections }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-info">
            <div class="card-body">
                <h5 class="card-title">上行流量</h5>
                <h2 class="mb-0">{{ (total_sent / 1024 / 1024 / 1024) | round(2) }} GB</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-primary">
            <div class="card-body">
                <h5 class="card-title">下行流量</h5>
                <h2 class="mb-0">{{ (total_received / 1024 / 1024 / 1024) | round(2) }} GB</h2>
            </div>
        </div>
    </div>
</div>

<!-- 代理列表 -->
<div class="card">
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>状态</th>
                        <th>类型</th>
                        <th>外部IP</th>
                        <th>端口</th>
                        <th>用户名</th>
                        <th>连接数</th>
                        <th>上行流量</th>
                        <th>下行流量</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {% for proxy in proxies.items %}
                    <tr>
                        <td>
                            <span class="status-indicator status-{{ proxy.status }}"></span>
                            {{ proxy.status }}
                        </td>
                        <td><span class="badge bg-secondary">{{ proxy.type }}</span></td>
                        <td>{{ proxy.external_ip }}</td>
                        <td>{{ proxy.port }}</td>
                        <td>{{ proxy.username or '-' }}</td>
                        <td>
                            <div class="progress" style="width: 100px;">
                                <div class="progress-bar" style="width: {{ (proxy.current_connections / proxy.max_connections * 100) }}%">
                                    {{ proxy.current_connections }}/{{ proxy.max_connections }}
                                </div>
                            </div>
                        </td>
                        <td>{{ (proxy.bytes_sent / 1024 / 1024) | round(2) }} MB</td>
                        <td>{{ (proxy.bytes_received / 1024 / 1024) | round(2) }} MB</td>
                        <td>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteProxy({{ proxy.id }})">
                                <i class="bi bi-trash"></i>
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <!-- 分页 -->
        {% if proxies.pages > 1 %}
        <nav>
            <ul class="pagination justify-content-center">
                <li class="page-item {% if not proxies.has_prev %}disabled{% endif %}">
                    <a class="page-link" href="?page={{ proxies.prev_num }}">上一页</a>
                </li>
                {% for page in proxies.iter_pages(left_edge=2, right_edge=2, left_current=2, right_current=2) %}
                    {% if page %}
                        <li class="page-item {% if page == proxies.page %}active{% endif %}">
                            <a class="page-link" href="?page={{ page }}">{{ page }}</a>
                        </li>
                    {% else %}
                        <li class="page-item disabled"><span class="page-link">...</span></li>
                    {% endif %}
                {% endfor %}
                <li class="page-item {% if not proxies.has_next %}disabled{% endif %}">
                    <a class="page-link" href="?page={{ proxies.next_num }}">下一页</a>
                </li>
            </ul>
        </nav>
        {% endif %}
    </div>
</div>

<!-- 添加代理模态框 -->
<div class="modal fade" id="addProxyModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">添加代理</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="{{ url_for('proxy.add_proxy', group_id=group.id) }}">
                <div class="modal-body">
                    <ul class="nav nav-tabs mb-3">
                        <li class="nav-item">
                            <a class="nav-link active" data-bs-toggle="tab" href="#single">单个添加</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" data-bs-toggle="tab" href="#batch">批量添加</a>
                        </li>
                    </ul>
                    
                    <div class="tab-content">
                        <div class="tab-pane fade show active" id="single">
                            <div class="row">
                                <div class="col-md-6">
                                    <label class="form-label">类型</label>
                                    <select class="form-select" name="type">
                                        <option value="http">HTTP</option>
                                        <option value="socks5">SOCKS5</option>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">外部IP</label>
                                    <input type="text" class="form-control" name="external_ip" required>
                                </div>
                            </div>
                            <div class="row mt-3">
                                <div class="col-md-4">
                                    <label class="form-label">端口</label>
                                    <input type="number" class="form-control" name="port" required>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label">用户名</label>
                                    <input type="text" class="form-control" name="username">
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label">密码</label>
                                    <input type="text" class="form-control" name="password">
                                </div>
                            </div>
                        </div>
                        
                        <div class="tab-pane fade" id="batch">
                            <input type="hidden" name="batch_add" value="1">
                            <div class="row">
                                <div class="col-md-6">
                                    <label class="form-label">起始IP</label>
                                    <input type="text" class="form-control" name="ip_start" placeholder="192.168.1.100">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">结束IP</label>
                                    <input type="text" class="form-control" name="ip_end" placeholder="192.168.1.200">
                                </div>
                            </div>
                            <div class="row mt-3">
                                <div class="col-md-6">
                                    <label class="form-label">起始端口</label>
                                    <input type="number" class="form-control" name="port_start" value="3128">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label">每个IP的端口数</label>
                                    <input type="number" class="form-control" name="port_count" value="1">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="submit" class="btn btn-primary">添加</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
function deleteProxy(proxyId) {
    if (confirm('确定要删除这个代理吗？')) {
        fetch(`/proxy/api/proxy/${proxyId}`, { method: 'DELETE' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                }
            });
    }
}
</script>
{% endblock %}
EOF

# system.html
cat > app/templates/monitor/system.html <<'EOF'
{% extends "base.html" %}

{% block title %}系统监控 - 3proxy Manager{% endblock %}

{% block content %}
<h2 class="mb-4"><i class="bi bi-activity"></i> 系统监控</h2>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card">
            <div class="card-body">
                <h6 class="card-subtitle mb-2 text-muted">CPU 使用率</h6>
                <h2 class="card-title mb-0"><span id="cpu-percent">0</span>%</h2>
                <div class="progress mt-2">
                    <div id="cpu-progress" class="progress-bar" style="width: 0%"></div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body">
                <h6 class="card-subtitle mb-2 text-muted">内存使用率</h6>
                <h2 class="card-title mb-0"><span id="memory-percent">0</span>%</h2>
                <div class="progress mt-2">
                    <div id="memory-progress" class="progress-bar bg-info" style="width: 0%"></div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body">
                <h6 class="card-subtitle mb-2 text-muted">磁盘使用率</h6>
                <h2 class="card-title mb-0"><span id="disk-percent">0</span>%</h2>
                <div class="progress mt-2">
                    <div id="disk-progress" class="progress-bar bg-warning" style="width: 0%"></div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card">
            <div class="card-body">
                <h6 class="card-subtitle mb-2 text-muted">系统负载</h6>
                <h2 class="card-title mb-0"><span id="load-avg">0.00</span></h2>
                <small class="text-muted">1分钟平均</small>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">CPU 历史</h5>
            </div>
            <div class="card-body">
                <canvas id="cpuChart" height="200"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">内存历史</h5>
            </div>
            <div class="card-body">
                <canvas id="memoryChart" height="200"></canvas>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">网络流量</h5>
            </div>
            <div class="card-body">
                <canvas id="networkChart" height="200"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">系统信息</h5>
            </div>
            <div class="card-body">
                <table class="table table-sm">
                    <tr>
                        <td>CPU核心数</td>
                        <td><span id="cpu-count">-</span></td>
                    </tr>
                    <tr>
                        <td>总内存</td>
                        <td><span id="memory-total">-</span></td>
                    </tr>
                    <tr>
                        <td>进程数</td>
                        <td><span id="process-count">-</span></td>
                    </tr>
                    <tr>
                        <td>运行时间</td>
                        <td><span id="uptime">-</span></td>
                    </tr>
                </table>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
// 图表配置
const chartConfig = {
    type: 'line',
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            duration: 0
        },
        scales: {
            y: {
                beginAtZero: true,
                max: 100
            }
        }
    }
};

// CPU图表
const cpuChart = new Chart(document.getElementById('cpuChart').getContext('2d'), {
    ...chartConfig,
    data: {
        labels: [],
        datasets: [{
            label: 'CPU %',
            data: [],
            borderColor: 'rgb(255, 99, 132)',
            backgroundColor: 'rgba(255, 99, 132, 0.1)',
            tension: 0.1
        }]
    }
});

// 内存图表
const memoryChart = new Chart(document.getElementById('memoryChart').getContext('2d'), {
    ...chartConfig,
    data: {
        labels: [],
        datasets: [{
            label: '内存 %',
            data: [],
            borderColor: 'rgb(54, 162, 235)',
            backgroundColor: 'rgba(54, 162, 235, 0.1)',
            tension: 0.1
        }]
    }
});

// 网络图表
const networkChart = new Chart(document.getElementById('networkChart').getContext('2d'), {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: '下载 MB/s',
            data: [],
            borderColor: 'rgb(75, 192, 192)',
            backgroundColor: 'rgba(75, 192, 192, 0.1)',
            tension: 0.1
        }, {
            label: '上传 MB/s',
            data: [],
            borderColor: 'rgb(255, 206, 86)',
            backgroundColor: 'rgba(255, 206, 86, 0.1)',
            tension: 0.1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
            duration: 0
        },
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});

let lastNetworkBytes = null;

// 更新数据
socket.on('system_metrics', function(data) {
    const time = new Date(data.timestamp).toLocaleTimeString();
    
    // 更新实时数据
    document.getElementById('cpu-percent').textContent = data.cpu.percent.toFixed(1);
    document.getElementById('cpu-progress').style.width = data.cpu.percent + '%';
    
    document.getElementById('memory-percent').textContent = data.memory.percent.toFixed(1);
    document.getElementById('memory-progress').style.width = data.memory.percent + '%';
    
    document.getElementById('disk-percent').textContent = data.disk.percent.toFixed(1);
    document.getElementById('disk-progress').style.width = data.disk.percent + '%';
    
    if (data.system.load_avg) {
        document.getElementById('load-avg').textContent = data.system.load_avg[0].toFixed(2);
    }
    
    // 系统信息
    document.getElementById('cpu-count').textContent = data.cpu.count;
    document.getElementById('memory-total').textContent = (data.memory.total / 1024 / 1024 / 1024).toFixed(2) + ' GB';
    document.getElementById('process-count').textContent = data.system.process_count;
    
    // 计算运行时间
    const uptime = Date.now() / 1000 - data.system.boot_time;
    const days = Math.floor(uptime / 86400);
    const hours = Math.floor((uptime % 86400) / 3600);
    document.getElementById('uptime').textContent = `${days}天 ${hours}小时`;
    
    // 更新图表
    if (cpuChart.data.labels.length > 60) {
        cpuChart.data.labels.shift();
        cpuChart.data.datasets[0].data.shift();
        memoryChart.data.labels.shift();
        memoryChart.data.datasets[0].data.shift();
        networkChart.data.labels.shift();
        networkChart.data.datasets[0].data.shift();
        networkChart.data.datasets[1].data.shift();
    }
    
    cpuChart.data.labels.push(time);
    cpuChart.data.datasets[0].data.push(data.cpu.percent);
    cpuChart.update();
    
    memoryChart.data.labels.push(time);
    memoryChart.data.datasets[0].data.push(data.memory.percent);
    memoryChart.update();
    
    // 计算网络速率
    if (lastNetworkBytes) {
        const downloadRate = (data.network.bytes_recv - lastNetworkBytes.recv) / 1024 / 1024;
        const uploadRate = (data.network.bytes_sent - lastNetworkBytes.sent) / 1024 / 1024;
        
        networkChart.data.labels.push(time);
        networkChart.data.datasets[0].data.push(Math.max(0, downloadRate));
        networkChart.data.datasets[1].data.push(Math.max(0, uploadRate));
        networkChart.update();
    }
    
    lastNetworkBytes = {
        recv: data.network.bytes_recv,
        sent: data.network.bytes_sent
    };
});
</script>
{% endblock %}
EOF

# management.html
cat > app/templates/backup/management.html <<'EOF'
{% extends "base.html" %}

{% block title %}备份管理 - 3proxy Manager{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h2><i class="bi bi-archive"></i> 备份管理</h2>
        <p class="text-muted">系统每周日凌晨2点自动备份，只保留最新备份</p>
    </div>
    <div class="col-auto">
        <button class="btn btn-primary" onclick="createBackup()">
            <i class="bi bi-plus-circle"></i> 立即备份
        </button>
    </div>
</div>

<div class="card">
    <div class="card-body">
        <table class="table">
            <thead>
                <tr>
                    <th>备份文件</th>
                    <th>大小</th>
                    <th>创建时间</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>
                {% for backup in backups %}
                <tr>
                    <td>{{ backup.name }}</td>
                    <td>{{ (backup.size / 1024 / 1024) | round(2) }} MB</td>
                    <td>{{ backup.created | date }}</td>
                    <td>
                        <a href="{{ url_for('backup.download_backup', filename=backup.name) }}" class="btn btn-sm btn-primary">
                            <i class="bi bi-download"></i> 下载
                        </a>
                    </td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="4" class="text-center text-muted">暂无备份</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<script>
function createBackup() {
    if (confirm('确定要立即创建备份吗？')) {
        const btn = event.target;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 备份中...';
        
        fetch('/backup/api/backup/create', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('备份创建成功！');
                    location.reload();
                } else {
                    alert('备份失败: ' + data.error);
                }
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-plus-circle"></i> 立即备份';
            });
    }
}
</script>
{% endblock %}
EOF

# ==================== 创建主运行文件 ====================
cat > run.py <<'EOF'
from app import create_app, socketio

app = create_app()

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=${PORT}, debug=False)
EOF

# ==================== 创建初始3proxy配置 ====================
cat > $PROXYCFG_PATH <<EOF
daemon
pidfile /var/run/3proxy.pid
log $LOGDIR/3proxy.log D
rotate 2

nscache 65536
nscache6 65536
maxconn 10000

timeouts 1 5 30 60 180 1800 15 60

auth none
proxy -p3128
EOF

# ==================== 创建系统服务 ====================

# 3proxy服务
cat > /etc/systemd/system/3proxy.service <<EOF
[Unit]
Description=3proxy Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=$THREEPROXY_PATH $PROXYCFG_PATH
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# Web管理服务
cat > /etc/systemd/system/3proxy-web.service <<EOF
[Unit]
Description=3proxy Web Management System
After=network.target redis.service

[Service]
Type=simple
User=root
WorkingDirectory=$WORKDIR
Environment="PATH=$WORKDIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$WORKDIR/venv/bin/gunicorn --worker-class eventlet -w 2 --bind 0.0.0.0:${PORT} --timeout 120 run:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# ==================== 配置日志轮换 ====================
cat > /etc/logrotate.d/3proxy <<EOF
$LOGDIR/*.log {
    daily
    rotate 2
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        /bin/kill -USR1 \`cat /var/run/3proxy.pid 2>/dev/null\` 2>/dev/null || true
    endscript
}
EOF

# ==================== 启动服务 ====================
systemctl daemon-reload
systemctl enable 3proxy
systemctl enable 3proxy-web
systemctl start 3proxy
systemctl start 3proxy-web

# ==================== 完成安装 ====================
MYIP=$(get_local_ip)

echo -e "\n${GREEN}========= 安装完成！=========${NC}"
echo -e "${BLUE}访问地址：${NC} http://$MYIP:${PORT}"
echo -e "${BLUE}管理员账号：${NC} ${ADMINUSER}"
echo -e "${BLUE}管理员密码：${NC} ${ADMINPASS}"
echo -e "\n${YELLOW}功能特性：${NC}"
echo -e "- 美化的Web UI，响应式设计"
echo -e "- 代理组卡片视图，二级页面防止卡顿"
echo -e "- 实时系统监控（CPU、内存、磁盘）"
echo -e "- 每周自动备份，支持手动备份"
echo -e "- BBR优化，高并发性能优化"
echo -e "- 日志自动轮换（2-3天）"
echo -e "\n${YELLOW}管理命令：${NC}"
echo -e "- 查看服务状态: systemctl status 3proxy-web"
echo -e "- 重启服务: systemctl restart 3proxy-web"
echo -e "- 查看日志: journalctl -u 3proxy-web -f"
echo -e "- 卸载系统: bash $0 uninstall"
echo -e "- 重新安装: bash $0 reinstall"
echo -e "\n${GREEN}请保存好管理员密码！${NC}\n"
