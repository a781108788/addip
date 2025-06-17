#!/bin/bash
# 3proxy Web Management System - Fixed One-Click Deployment Script
# Version: 2.1 Fixed
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

# 错误处理
trap 'echo -e "${RED}错误发生在第 $LINENO 行${NC}"; exit 1' ERR

# 获取本地IP
function get_local_ip() {
    local pubip lanip
    pubip=$(curl -s ifconfig.me || curl -s ip.sb || curl -s icanhazip.com || echo "")
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
    htop iotop nethogs || {
    echo -e "${RED}安装依赖失败${NC}"
    exit 1
}

# 启动Redis
systemctl enable redis-server
systemctl start redis-server

echo -e "\n${BLUE}========= 2. 编译安装 3proxy =========${NC}\n"
if [ ! -f "$THREEPROXY_PATH" ]; then
    cd /tmp
    rm -rf 3proxy
    git clone --depth=1 https://github.com/3proxy/3proxy.git || {
        echo -e "${RED}下载3proxy失败${NC}"
        exit 1
    }
    cd 3proxy
    make -f Makefile.Linux || {
        echo -e "${RED}编译3proxy失败${NC}"
        exit 1
    }
    mkdir -p /usr/local/bin /usr/local/etc/3proxy $LOGDIR
    cp bin/3proxy /usr/local/bin/
    chmod +x /usr/local/bin/3proxy
    cd /
fi

echo -e "\n${BLUE}========= 3. 系统性能优化 =========${NC}\n"

# 启用BBR（如果内核支持）
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -ge 9 ]); then
    cat > /etc/sysctl.d/99-bbr.conf <<'EOFBBR'
# Enable BBR
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOFBBR
    sysctl -p /etc/sysctl.d/99-bbr.conf 2>/dev/null || echo "BBR配置应用失败，但继续安装"
else
    echo "内核版本过低，跳过BBR配置"
fi

# 系统优化参数
cat > /etc/sysctl.d/99-proxy-optimize.conf <<'EOFSYSCTL'
# Network optimizations for proxy server
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535

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
EOFSYSCTL

# 应用系统优化（忽略错误）
sysctl -p /etc/sysctl.d/99-proxy-optimize.conf 2>/dev/null || echo "部分系统参数应用失败，但继续安装"

# 系统限制优化
cat > /etc/security/limits.d/99-proxy.conf <<'EOFLIMITS'
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 65535
* hard nproc 65535
EOFLIMITS

echo -e "\n${BLUE}========= 4. 部署Web管理系统 =========${NC}\n"

# 创建工作目录
mkdir -p $WORKDIR/{app/{routes,static/{css,js,lib},templates},services,logs} $BACKUP_DIR
cd $WORKDIR

# 创建Python虚拟环境
python3 -m venv venv
source venv/bin/activate

# 升级pip
pip install --upgrade pip setuptools wheel || {
    echo -e "${RED}pip升级失败${NC}"
    exit 1
}

# 创建requirements.txt
cat > requirements.txt <<'EOFREQ'
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
EOFREQ

pip install -r requirements.txt || {
    echo -e "${RED}Python包安装失败${NC}"
    exit 1
}

echo -e "\n${BLUE}========= 5. 创建应用文件 =========${NC}\n"

# ==================== 创建配置文件 ====================
cat > config.py <<EOFCONFIG
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
EOFCONFIG

# ==================== 创建简化的主应用文件 ====================
cat > app.py <<'EOFAPP'
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import subprocess
import psutil
from datetime import datetime

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 数据模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ProxyGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_range = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Proxy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('proxy_group.id'))
    external_ip = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(50))
    password = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    # 获取系统信息
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    total_groups = ProxyGroup.query.count()
    total_proxies = Proxy.query.count()
    
    return render_template('dashboard.html',
                         cpu_percent=cpu_percent,
                         memory_percent=memory.percent,
                         disk_percent=disk.percent,
                         total_groups=total_groups,
                         total_proxies=total_proxies)

@app.route('/proxy/groups')
@login_required
def proxy_groups():
    groups = ProxyGroup.query.all()
    return render_template('proxy_groups.html', groups=groups)

@app.route('/proxy/add_group', methods=['POST'])
@login_required
def add_group():
    name = request.form.get('name')
    ip_range = request.form.get('ip_range')
    description = request.form.get('description')
    
    group = ProxyGroup(name=name, ip_range=ip_range, description=description)
    db.session.add(group)
    db.session.commit()
    
    flash('代理组添加成功', 'success')
    return redirect(url_for('proxy_groups'))

@app.route('/system/monitor')
@login_required
def system_monitor():
    return render_template('system_monitor.html')

@app.route('/api/system/metrics')
@login_required
def system_metrics():
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return jsonify({
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'disk_percent': disk.percent,
        'timestamp': datetime.now().isoformat()
    })

# 创建数据库表和默认用户
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='ADMINUSER_PLACEHOLDER').first():
        admin = User(username='ADMINUSER_PLACEHOLDER')
        admin.set_password('ADMINPASS_PLACEHOLDER')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT_PLACEHOLDER, debug=False)
EOFAPP

# 替换占位符
sed -i "s/ADMINUSER_PLACEHOLDER/${ADMINUSER}/g" app.py
sed -i "s/ADMINPASS_PLACEHOLDER/${ADMINPASS}/g" app.py
sed -i "s/PORT_PLACEHOLDER/${PORT}/g" app.py

# ==================== 创建模板文件 ====================
mkdir -p templates

# 基础模板
cat > templates/base.html <<'EOFBASE'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}3proxy 管理系统{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .navbar { background-color: #2c3e50 !important; }
        .card { border: none; box-shadow: 0 2px 4px rgba(0,0,0,.1); }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            padding: 20px;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/"><i class="bi bi-shield-lock"></i> 3proxy Manager</a>
            <div class="navbar-nav ms-auto">
                {% if current_user.is_authenticated %}
                <a class="nav-link" href="{{ url_for('logout') }}">退出</a>
                {% endif %}
            </div>
        </div>
    </nav>
    
    <div class="container-fluid mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOFBASE

# 登录页面
cat > templates/login.html <<'EOFLOGIN'
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
        }
    </style>
</head>
<body>
    <div class="card login-card">
        <div class="card-body p-5">
            <h3 class="text-center mb-4">3proxy 管理系统</h3>
            <form method="POST">
                <div class="mb-3">
                    <input type="text" class="form-control" name="username" placeholder="用户名" required>
                </div>
                <div class="mb-3">
                    <input type="password" class="form-control" name="password" placeholder="密码" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">登录</button>
            </form>
        </div>
    </div>
</body>
</html>
EOFLOGIN

# 仪表板
cat > templates/dashboard.html <<'EOFDASH'
{% extends "base.html" %}

{% block content %}
<h2>系统概览</h2>

<div class="row mt-4">
    <div class="col-md-3">
        <div class="card metric-card">
            <div class="card-body">
                <h5>CPU使用率</h5>
                <h2>{{ cpu_percent }}%</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
            <div class="card-body">
                <h5>内存使用率</h5>
                <h2>{{ memory_percent }}%</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
            <div class="card-body">
                <h5>磁盘使用率</h5>
                <h2>{{ disk_percent }}%</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card metric-card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
            <div class="card-body">
                <h5>代理组数量</h5>
                <h2>{{ total_groups }}</h2>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-body">
                <h5>快速操作</h5>
                <a href="{{ url_for('proxy_groups') }}" class="btn btn-primary">管理代理组</a>
                <a href="{{ url_for('system_monitor') }}" class="btn btn-info">系统监控</a>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOFDASH

# 代理组页面
cat > templates/proxy_groups.html <<'EOFGROUPS'
{% extends "base.html" %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2>代理组管理</h2>
    <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addGroupModal">
        <i class="bi bi-plus-circle"></i> 添加代理组
    </button>
</div>

<div class="row">
    {% for group in groups %}
    <div class="col-md-4 mb-3">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">{{ group.name }}</h5>
                <p class="card-text">{{ group.ip_range }}</p>
                <p class="card-text"><small>{{ group.description or '暂无描述' }}</small></p>
                <a href="#" class="btn btn-sm btn-primary">查看详情</a>
            </div>
        </div>
    </div>
    {% endfor %}
</div>

<!-- 添加模态框 -->
<div class="modal fade" id="addGroupModal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">添加代理组</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="{{ url_for('add_group') }}">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">组名称</label>
                        <input type="text" class="form-control" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">IP段</label>
                        <input type="text" class="form-control" name="ip_range" placeholder="192.168.1.0/24" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">描述</label>
                        <textarea class="form-control" name="description" rows="3"></textarea>
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
EOFGROUPS

# 系统监控页面
cat > templates/system_monitor.html <<'EOFMONITOR'
{% extends "base.html" %}

{% block content %}
<h2>系统监控</h2>

<div class="row mt-4">
    <div class="col-md-12">
        <div class="card">
            <div class="card-body">
                <h5>实时监控</h5>
                <canvas id="cpuChart" height="100"></canvas>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
const ctx = document.getElementById('cpuChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'CPU使用率',
            data: [],
            borderColor: 'rgb(255, 99, 132)',
            tension: 0.1
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true,
                max: 100
            }
        }
    }
});

function updateMetrics() {
    fetch('/api/system/metrics')
        .then(response => response.json())
        .then(data => {
            const time = new Date().toLocaleTimeString();
            if (chart.data.labels.length > 20) {
                chart.data.labels.shift();
                chart.data.datasets[0].data.shift();
            }
            chart.data.labels.push(time);
            chart.data.datasets[0].data.push(data.cpu_percent);
            chart.update();
        });
}

setInterval(updateMetrics, 2000);
updateMetrics();
</script>
{% endblock %}
EOFMONITOR

# ==================== 创建初始3proxy配置 ====================
cat > $PROXYCFG_PATH <<'EOF3PROXY'
daemon
pidfile /var/run/3proxy.pid
log /var/log/3proxy/3proxy.log D
rotate 2

nscache 65536
nscache6 65536
maxconn 10000

timeouts 1 5 30 60 180 1800 15 60

auth none
proxy -p3128
EOF3PROXY

# ==================== 创建系统服务 ====================

# 3proxy服务
cat > /etc/systemd/system/3proxy.service <<'EOF3PROXYSERVICE'
[Unit]
Description=3proxy Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF3PROXYSERVICE

# Web管理服务（使用简单的Python运行）
cat > /etc/systemd/system/3proxy-web.service <<EOFWEBSERVICE
[Unit]
Description=3proxy Web Management System
After=network.target redis.service

[Service]
Type=simple
User=root
WorkingDirectory=$WORKDIR
Environment="PATH=$WORKDIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$WORKDIR/venv/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOFWEBSERVICE

# ==================== 配置日志轮换 ====================
cat > /etc/logrotate.d/3proxy <<'EOFLOGROTATE'
/var/log/3proxy/*.log {
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
EOFLOGROTATE

# ==================== 启动服务 ====================
echo -e "\n${BLUE}========= 6. 启动服务 =========${NC}\n"

systemctl daemon-reload
systemctl enable 3proxy
systemctl enable 3proxy-web
systemctl start 3proxy
systemctl start 3proxy-web

# 检查服务状态
sleep 3
if systemctl is-active --quiet 3proxy-web; then
    echo -e "${GREEN}3proxy-web 服务启动成功${NC}"
else
    echo -e "${RED}3proxy-web 服务启动失败，请检查日志${NC}"
    journalctl -u 3proxy-web --no-pager -n 20
fi

# ==================== 完成安装 ====================
MYIP=$(get_local_ip)

echo -e "\n${GREEN}========= 安装完成！=========${NC}"
echo -e "${BLUE}访问地址：${NC} http://$MYIP:${PORT}"
echo -e "${BLUE}管理员账号：${NC} ${ADMINUSER}"
echo -e "${BLUE}管理员密码：${NC} ${ADMINPASS}"
echo -e "\n${YELLOW}功能特性：${NC}"
echo -e "- 简化版Web管理界面"
echo -e "- 代理组管理"
echo -e "- 实时系统监控"
echo -e "- BBR优化（如果内核支持）"
echo -e "- 日志自动轮换"
echo -e "\n${YELLOW}管理命令：${NC}"
echo -e "- 查看服务状态: systemctl status 3proxy-web"
echo -e "- 重启服务: systemctl restart 3proxy-web"
echo -e "- 查看日志: journalctl -u 3proxy-web -f"
echo -e "- 卸载系统: bash $0 uninstall"
echo -e "\n${GREEN}请保存好管理员密码！${NC}\n"
