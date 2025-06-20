#!/bin/bash
set -e

# 3proxy企业级管理系统一键安装脚本 v2.0
# 支持Debian 11/12，优化为128G内存32核服务器
# 支持百万级代理并发管理

WORKDIR=/opt/3proxy-enterprise
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_DIR=/usr/local/etc/3proxy
PROXYCFG_PATH=$PROXYCFG_DIR/3proxy.cfg
LOGDIR=/var/log/3proxy
LOGFILE=$LOGDIR/3proxy.log
CREDS_FILE=/opt/3proxy-enterprise/.credentials

# 获取本机IP
function get_local_ip() {
    local ip
    ip=$(curl -s --connect-timeout 5 ifconfig.me || curl -s --connect-timeout 5 ip.sb || echo "")
    if [[ -z "$ip" ]]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    fi
    echo "$ip"
}

# 显示凭据
function show_credentials() {
    if [ -f "$CREDS_FILE" ]; then
        echo -e "\n========= 3proxy Enterprise 登录信息 ========="
        cat "$CREDS_FILE"
        echo -e "============================================\n"
    else
        echo "未找到登录凭据文件。请运行安装脚本。"
    fi
}

# 卸载系统
function uninstall_system() {
    echo "开始卸载3proxy Enterprise系统..."
    
    # 停止服务
    systemctl stop 3proxy-enterprise 2>/dev/null || true
    systemctl stop 3proxy-web 2>/dev/null || true
    systemctl disable 3proxy-enterprise 2>/dev/null || true
    systemctl disable 3proxy-web 2>/dev/null || true
    
    # 删除文件
    rm -rf $WORKDIR
    rm -rf $PROXYCFG_DIR
    rm -rf $LOGDIR
    rm -f /usr/local/bin/3proxy
    rm -f /usr/local/bin/3proxy-enterprise.sh
    rm -f /etc/systemd/system/3proxy-enterprise.service
    rm -f /etc/systemd/system/3proxy-web.service
    rm -f /etc/nginx/sites-enabled/3proxy-enterprise
    rm -f /etc/nginx/sites-available/3proxy-enterprise
    rm -f /etc/logrotate.d/3proxy
    rm -f /etc/cron.d/3proxy-*
    
    # 重载systemd
    systemctl daemon-reload
    
    echo "3proxy Enterprise系统已完全卸载"
}

# 处理命令行参数
case "$1" in
    "uninstall")
        uninstall_system
        exit 0
        ;;
    "reinstall")
        uninstall_system
        echo "准备重新安装..."
        ;;
    "show")
        show_credentials
        exit 0
        ;;
esac

echo "========== 3proxy Enterprise 安装程序 =========="
echo "版本: 2.0 Enterprise Edition"
echo "支持: 百万级代理并发管理"
echo "=============================================="

# 系统优化
echo "执行系统性能优化..."

# 检查是否已经优化过
if ! grep -q "# 3proxy Enterprise Performance Tuning" /etc/sysctl.conf 2>/dev/null; then
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)
    
    # 企业级内核参数优化
    cat >> /etc/sysctl.conf << 'EOF'

# 3proxy Enterprise Performance Tuning
# 针对128G内存32核服务器优化，支持百万级并发连接

# 基础网络设置
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1

# TCP优化
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 2000000

# 端口范围
net.ipv4.ip_local_port_range = 1024 65535

# 连接跟踪
net.netfilter.nf_conntrack_max = 10000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# 套接字缓冲区
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.ipv4.tcp_mem = 786432 1048576 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728

# 文件系统优化
fs.file-max = 10000000
fs.nr_open = 10000000

# 其他优化
vm.swappiness = 10
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
EOF
    
    # 应用设置
    sysctl -p >/dev/null 2>&1
fi

# 优化limits
if ! grep -q "# 3proxy Enterprise limits" /etc/security/limits.conf 2>/dev/null; then
    cat >> /etc/security/limits.conf << 'EOF'

# 3proxy Enterprise limits
* soft nofile 10000000
* hard nofile 10000000
* soft nproc 10000000
* hard nproc 10000000
root soft nofile 10000000
root hard nofile 10000000
root soft nproc 10000000
root hard nproc 10000000
EOF
fi

echo "系统优化完成"

# 创建目录
echo "创建必要的目录结构..."
mkdir -p $WORKDIR/{templates,static,backups,scripts}
mkdir -p $PROXYCFG_DIR
mkdir -p $LOGDIR

# 安装依赖
echo "安装依赖包..."
apt update
apt install -y gcc make git wget curl \
    python3 python3-pip python3-venv python3-dev \
    sqlite3 libsqlite3-dev \
    redis-server nginx supervisor \
    htop iotop iftop net-tools dnsutils \
    cron logrotate build-essential

# 启动Redis
systemctl enable redis-server
systemctl start redis-server

# 编译安装3proxy
echo "编译安装3proxy..."
if [ ! -f "$THREEPROXY_PATH" ]; then
    cd /tmp
    rm -rf 3proxy
    git clone --depth=1 https://github.com/3proxy/3proxy.git
    cd 3proxy
    make -f Makefile.Linux
    make -f Makefile.Linux install
    
    if [ ! -f /usr/local/bin/3proxy ]; then
        cp src/3proxy /usr/local/bin/3proxy
    fi
    chmod +x /usr/local/bin/3proxy
fi

# 创建3proxy基础配置
cat > $PROXYCFG_PATH << 'EOF'
daemon
maxconn 1000000
nserver 8.8.8.8
nserver 1.1.1.1
nscache 262144
timeouts 1 3 10 30 60 180 1800 15 60
log /var/log/3proxy/3proxy.log D
rotate 100M
auth none
proxy -p3128
EOF

# 创建启动脚本
cat > /usr/local/bin/3proxy-enterprise.sh << 'EOF'
#!/bin/bash
ulimit -n 10000000
ulimit -u 10000000
/usr/local/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
EOF
chmod +x /usr/local/bin/3proxy-enterprise.sh

# 设置日志轮转
cat > /etc/logrotate.d/3proxy << 'EOF'
/var/log/3proxy/*.log {
    daily
    rotate 7
    maxsize 1G
    compress
    missingok
    notifempty
    create 0644 root root
}
EOF

# 创建Python虚拟环境
echo "创建Web管理应用..."
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate

# 安装Python包
pip install --upgrade pip
pip install flask flask_login werkzeug psutil redis gunicorn gevent

# 创建Web应用
cat > $WORKDIR/app.py << 'PYAPP'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import sqlite3
import random
import string
import re
import json
import time
import threading
import queue
import psutil
import redis
import hashlib
import datetime
import subprocess
from functools import wraps
from contextlib import contextmanager

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# 配置
DB_PATH = '/opt/3proxy-enterprise/3proxy.db'
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
CONFIG_DIR = '/usr/local/etc/3proxy'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'enterprise-secret-key-' + os.urandom(16).hex()

# 登录管理
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Redis连接池
redis_pool = redis.ConnectionPool(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# 数据库连接池
class DatabasePool:
    def __init__(self, database, max_connections=50):
        self.database = database
        self.pool = queue.Queue(maxsize=max_connections)
        for _ in range(max_connections):
            conn = sqlite3.connect(database, timeout=30.0)
            conn.row_factory = sqlite3.Row
            self.pool.put(conn)
    
    @contextmanager
    def get_connection(self):
        conn = self.pool.get()
        try:
            yield conn
        finally:
            self.pool.put(conn)

db_pool = DatabasePool(DB_PATH)

# 用户模型
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def get(user_id):
        with db_pool.get_connection() as conn:
            cur = conn.execute("SELECT id, username, password FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            if row:
                return User(row['id'], row['username'], row['password'])
        return None
    
    @staticmethod
    def get_by_username(username):
        with db_pool.get_connection() as conn:
            cur = conn.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row:
                return User(row['id'], row['username'], row['password'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# 路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_by_username(username)
        if user and user.check_password(password):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        
        flash('用户名或密码错误', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# API路由
@app.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    with db_pool.get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM proxy").fetchone()[0]
        enabled = conn.execute("SELECT COUNT(*) FROM proxy WHERE enabled = 1").fetchone()[0]
        
        # 简化C段统计
        c_segments = conn.execute(
            "SELECT COUNT(DISTINCT substr(ip, 1, length(ip) - length(substr(ip, -3)))) FROM proxy"
        ).fetchone()[0]
        
        port_range = conn.execute("SELECT MIN(port), MAX(port) FROM proxy").fetchone()
    
    return jsonify({
        'total_proxies': total,
        'enabled_proxies': enabled,
        'disabled_proxies': total - enabled,
        'c_segments': c_segments,
        'port_range': f"{port_range[0]}-{port_range[1]}" if port_range[0] else "N/A",
        'utilization': round(enabled / total * 100, 2) if total > 0 else 0
    })

@app.route('/api/system/status')
@login_required
def api_system_status():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    proxy_info = {'running': False, 'pid': None}
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == '3proxy':
            proxy_info['running'] = True
            proxy_info['pid'] = proc.info['pid']
            break
    
    return jsonify({
        'cpu': {'percent': cpu_percent},
        'memory': {
            'total': round(memory.total / 1024 / 1024 / 1024, 2),
            'used': round(memory.used / 1024 / 1024 / 1024, 2),
            'percent': round(memory.percent, 2)
        },
        'disk': {
            'total': round(disk.total / 1024 / 1024 / 1024, 2),
            'used': round(disk.used / 1024 / 1024 / 1024, 2),
            'percent': round(disk.percent, 2)
        },
        'proxy': proxy_info
    })

@app.route('/api/proxy/groups')
@login_required
def api_proxy_groups():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    with db_pool.get_connection() as conn:
        # 获取C段分组
        query = """
            SELECT 
                substr(ip, 1, length(ip) - length(substr(ip, -3))) as c_segment,
                COUNT(*) as total,
                SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled,
                MIN(port) as min_port,
                MAX(port) as max_port
            FROM proxy
            GROUP BY c_segment
            ORDER BY c_segment
            LIMIT ? OFFSET ?
        """
        
        cursor = conn.execute(query, (per_page, (page - 1) * per_page))
        groups = []
        
        for row in cursor:
            groups.append({
                'c_segment': row['c_segment'],
                'total': row['total'],
                'enabled': row['enabled'],
                'disabled': row['total'] - row['enabled'],
                'port_range': f"{row['min_port']}-{row['max_port']}"
            })
        
        # 获取总数
        total = conn.execute(
            "SELECT COUNT(DISTINCT substr(ip, 1, length(ip) - length(substr(ip, -3)))) FROM proxy"
        ).fetchone()[0]
    
    return jsonify({
        'groups': groups,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/api/proxy/batch/add', methods=['POST'])
@login_required
def api_proxy_batch_add():
    data = request.get_json()
    ip_range = data.get('ip_range')
    port_start = data.get('port_start', 10000)
    port_end = data.get('port_end', 60000)
    user_prefix = data.get('user_prefix', 'user')
    
    # 解析IP范围
    if '-' not in ip_range:
        return jsonify({'error': 'IP范围格式错误'}), 400
    
    parts = ip_range.split('-')
    base = '.'.join(parts[0].split('.')[:-1])
    start = int(parts[0].split('.')[-1])
    end = int(parts[1]) if '.' not in parts[1] else int(parts[1].split('.')[-1])
    
    ips = [f"{base}.{i}" for i in range(start, end + 1)]
    
    with db_pool.get_connection() as conn:
        # 获取已使用的端口
        used_ports = set()
        cursor = conn.execute("SELECT port FROM proxy")
        for row in cursor:
            used_ports.add(row[0])
        
        # 分配端口
        available_ports = [p for p in range(port_start, port_end + 1) if p not in used_ports]
        if len(available_ports) < len(ips):
            return jsonify({'error': '可用端口不足'}), 400
        
        # 添加代理
        for i, ip in enumerate(ips):
            port = available_ports[i]
            username = f"{user_prefix}{random.randint(1000, 9999)}"
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            
            conn.execute(
                "INSERT INTO proxy (ip, port, username, password, enabled) VALUES (?, ?, ?, ?, 1)",
                (ip, port, username, password)
            )
        
        conn.commit()
    
    # 重新生成配置
    generate_3proxy_config()
    
    return jsonify({'message': f'成功添加{len(ips)}个代理'})

@app.route('/api/proxy/export', methods=['POST'])
@login_required
def api_proxy_export():
    with db_pool.get_connection() as conn:
        cursor = conn.execute("SELECT ip, port, username, password FROM proxy ORDER BY ip, port")
        
        lines = []
        for row in cursor:
            lines.append(f"{row[0]}:{row[1]}:{row[2]}:{row[3]}")
        
        content = '\\n'.join(lines)
    
    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=proxies.txt'}
    )

@app.route('/api/users')
@login_required
def api_users():
    with db_pool.get_connection() as conn:
        cursor = conn.execute("SELECT id, username FROM users ORDER BY id")
        users = []
        for row in cursor:
            users.append({'id': row['id'], 'username': row['username']})
    
    return jsonify({'users': users})

@app.route('/api/users/add', methods=['POST'])
@login_required
def api_add_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400
    
    with db_pool.get_connection() as conn:
        password_hash = generate_password_hash(password)
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            return jsonify({'message': '用户添加成功'})
        except:
            return jsonify({'error': '用户名已存在'}), 400

def generate_3proxy_config():
    """生成3proxy配置文件"""
    with db_pool.get_connection() as conn:
        cursor = conn.execute("SELECT ip, port, username, password FROM proxy WHERE enabled = 1")
        
        config = [
            "daemon",
            "maxconn 1000000",
            "nserver 8.8.8.8",
            "nserver 1.1.1.1",
            "nscache 262144",
            "timeouts 1 3 10 30 60 180 1800 15 60",
            "log /var/log/3proxy/3proxy.log D",
            "rotate 100M",
            "auth strong"
        ]
        
        # 收集用户
        users = {}
        proxies = []
        for row in cursor:
            users[row['username']] = row['password']
            proxies.append((row['ip'], row['port'], row['username']))
        
        # 添加用户
        if users:
            user_list = [f"{u}:CL:{p}" for u, p in users.items()]
            for i in range(0, len(user_list), 1000):
                batch = user_list[i:i+1000]
                config.append(f"users {' '.join(batch)}")
        
        # 添加代理
        for ip, port, username in proxies:
            config.extend([
                "auth strong",
                f"allow {username}",
                f"proxy -n -a -p{port} -i{ip} -e{ip}"
            ])
    
    # 写入配置文件
    with open(CONFIG_DIR + '/3proxy.cfg', 'w') as f:
        f.write('\\n'.join(config))
    
    # 重载3proxy
    subprocess.run(['pkill', '-HUP', '3proxy'], check=False)

# 初始化数据库
def init_database():
    with db_pool.get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS proxy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                UNIQUE(ip, port)
            );
            
            CREATE INDEX IF NOT EXISTS idx_proxy_ip ON proxy(ip);
            CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON proxy(enabled);
            
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        """)
        
        # 创建默认管理员
        admin_exists = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if not admin_exists:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123456')
            password_hash = generate_password_hash(admin_password)
            conn.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (password_hash,))
            conn.commit()

if __name__ == '__main__':
    init_database()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    app.run(host='0.0.0.0', port=port, debug=False)
PYAPP

# 创建登录页面模板
cat > $WORKDIR/templates/login.html << 'HTML'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3proxy Enterprise - 登录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2 class="text-center mb-4">3proxy Enterprise</h2>
        <form method="POST">
            <div class="mb-3">
                <label class="form-label">用户名</label>
                <input type="text" class="form-control" name="username" required>
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
</body>
</html>
HTML

# 创建主页面模板
cat > $WORKDIR/templates/index.html << 'HTML'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3proxy Enterprise - 管理面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            height: 100vh;
            width: 250px;
            background: #2c3e50;
            padding-top: 60px;
        }
        .sidebar a {
            color: #ecf0f1;
            text-decoration: none;
            padding: 15px 25px;
            display: block;
            transition: 0.3s;
        }
        .sidebar a:hover, .sidebar a.active {
            background: #34495e;
        }
        .main-content {
            margin-left: 250px;
            padding: 20px;
        }
        .navbar {
            margin-left: 250px;
        }
        .stat-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .stat-card h3 {
            margin: 0;
            color: #2c3e50;
        }
        .stat-card p {
            margin: 5px 0 0 0;
            color: #7f8c8d;
        }
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark bg-dark fixed-top">
        <div class="container-fluid">
            <span class="navbar-brand">3proxy Enterprise</span>
            <div class="d-flex">
                <span class="text-white me-3">{{ current_user.username }}</span>
                <a href="{{ url_for('logout') }}" class="btn btn-outline-light btn-sm">退出</a>
            </div>
        </div>
    </nav>

    <div class="sidebar">
        <a href="#" class="active" data-page="dashboard"><i class="bi bi-speedometer2"></i> 仪表板</a>
        <a href="#" data-page="proxies"><i class="bi bi-hdd-network"></i> 代理管理</a>
        <a href="#" data-page="users"><i class="bi bi-people"></i> 用户管理</a>
        <a href="#" data-page="settings"><i class="bi bi-gear"></i> 系统设置</a>
    </div>

    <main class="main-content">
        <div id="content-area">
            <!-- 动态内容 -->
        </div>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
    <script>
        let currentPage = 'dashboard';

        function loadDashboard() {
            const html = `
                <h2>仪表板</h2>
                <div class="row mt-4">
                    <div class="col-md-3">
                        <div class="stat-card">
                            <h3 id="totalProxies">-</h3>
                            <p>总代理数</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <h3 id="enabledProxies">-</h3>
                            <p>启用代理</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <h3 id="cSegments">-</h3>
                            <p>C段数量</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card">
                            <h3 id="utilization">-</h3>
                            <p>使用率</p>
                        </div>
                    </div>
                </div>
                <div class="row mt-4">
                    <div class="col-md-12">
                        <div class="stat-card">
                            <h5>系统状态</h5>
                            <div id="systemStatus">加载中...</div>
                        </div>
                    </div>
                </div>
            `;
            $('#content-area').html(html);
            refreshDashboard();
        }

        async function refreshDashboard() {
            try {
                const stats = await $.get('/api/dashboard/stats');
                $('#totalProxies').text(stats.total_proxies);
                $('#enabledProxies').text(stats.enabled_proxies);
                $('#cSegments').text(stats.c_segments);
                $('#utilization').text(stats.utilization + '%');

                const status = await $.get('/api/system/status');
                $('#systemStatus').html(`
                    <p>CPU使用率: ${status.cpu.percent}%</p>
                    <p>内存: ${status.memory.used}GB / ${status.memory.total}GB (${status.memory.percent}%)</p>
                    <p>磁盘: ${status.disk.used}GB / ${status.disk.total}GB (${status.disk.percent}%)</p>
                    <p>3proxy状态: ${status.proxy.running ? '运行中' : '已停止'}</p>
                `);
            } catch (error) {
                console.error('Dashboard refresh error:', error);
            }
        }

        function loadProxies() {
            const html = `
                <div class="d-flex justify-content-between align-items-center">
                    <h2>代理管理</h2>
                    <button class="btn btn-primary" onclick="showAddProxyModal()">
                        <i class="bi bi-plus"></i> 批量添加
                    </button>
                </div>
                <div class="mt-4">
                    <div id="proxyGroups">加载中...</div>
                </div>
            `;
            $('#content-area').html(html);
            loadProxyGroups();
        }

        async function loadProxyGroups() {
            try {
                const data = await $.get('/api/proxy/groups');
                let html = '<div class="table-responsive"><table class="table">';
                html += '<thead><tr><th>C段</th><th>总数</th><th>启用</th><th>端口范围</th><th>操作</th></tr></thead><tbody>';
                
                data.groups.forEach(group => {
                    html += `
                        <tr>
                            <td>${group.c_segment}</td>
                            <td>${group.total}</td>
                            <td>${group.enabled}</td>
                            <td>${group.port_range}</td>
                            <td>
                                <button class="btn btn-sm btn-primary">查看</button>
                                <button class="btn btn-sm btn-info" onclick="exportProxies()">导出</button>
                            </td>
                        </tr>
                    `;
                });
                
                html += '</tbody></table></div>';
                $('#proxyGroups').html(html);
            } catch (error) {
                $('#proxyGroups').html('加载失败');
            }
        }

        function showAddProxyModal() {
            const modal = `
                <div class="modal fade" id="addProxyModal" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">批量添加代理</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <form id="addProxyForm">
                                    <div class="mb-3">
                                        <label class="form-label">IP范围</label>
                                        <input type="text" class="form-control" name="ip_range" 
                                               placeholder="例: 192.168.1.1-254" required>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">起始端口</label>
                                                <input type="number" class="form-control" name="port_start" 
                                                       value="10000" required>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">结束端口</label>
                                                <input type="number" class="form-control" name="port_end" 
                                                       value="60000" required>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">用户名前缀</label>
                                        <input type="text" class="form-control" name="user_prefix" 
                                               value="user" required>
                                    </div>
                                </form>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                                <button type="button" class="btn btn-primary" onclick="addProxies()">添加</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            $('body').append(modal);
            const modalObj = new bootstrap.Modal(document.getElementById('addProxyModal'));
            modalObj.show();
            
            $('#addProxyModal').on('hidden.bs.modal', function () {
                $(this).remove();
            });
        }

        async function addProxies() {
            const formData = $('#addProxyForm').serializeArray();
            const data = {};
            formData.forEach(item => data[item.name] = item.value);
            
            try {
                const result = await $.ajax({
                    url: '/api/proxy/batch/add',
                    method: 'POST',
                    contentType: 'application/json',
                    data: JSON.stringify(data)
                });
                
                alert(result.message);
                $('#addProxyModal').modal('hide');
                loadProxyGroups();
            } catch (error) {
                alert('添加失败: ' + (error.responseJSON?.error || '未知错误'));
            }
        }

        async function exportProxies() {
            try {
                const response = await fetch('/api/proxy/export', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'proxies.txt';
                a.click();
                window.URL.revokeObjectURL(url);
            } catch (error) {
                alert('导出失败');
            }
        }

        function loadUsers() {
            const html = `
                <div class="d-flex justify-content-between align-items-center">
                    <h2>用户管理</h2>
                    <button class="btn btn-primary" onclick="showAddUserModal()">
                        <i class="bi bi-plus"></i> 添加用户
                    </button>
                </div>
                <div class="mt-4">
                    <div id="usersList">加载中...</div>
                </div>
            `;
            $('#content-area').html(html);
            refreshUsersList();
        }

        async function refreshUsersList() {
            try {
                const data = await $.get('/api/users');
                let html = '<div class="table-responsive"><table class="table">';
                html += '<thead><tr><th>ID</th><th>用户名</th><th>操作</th></tr></thead><tbody>';
                
                data.users.forEach(user => {
                    html += `
                        <tr>
                            <td>${user.id}</td>
                            <td>${user.username}</td>
                            <td>
                                ${user.username !== 'admin' ? 
                                    '<button class="btn btn-sm btn-danger" onclick="deleteUser(' + user.id + ')">删除</button>' : 
                                    '<span class="text-muted">系统用户</span>'}
                            </td>
                        </tr>
                    `;
                });
                
                html += '</tbody></table></div>';
                $('#usersList').html(html);
            } catch (error) {
                $('#usersList').html('加载失败');
            }
        }

        function showAddUserModal() {
            const modal = `
                <div class="modal fade" id="addUserModal" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">添加用户</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <form id="addUserForm">
                                    <div class="mb-3">
                                        <label class="form-label">用户名</label>
                                        <input type="text" class="form-control" name="username" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">密码</label>
                                        <input type="password" class="form-control" name="password" required>
                                    </div>
                                </form>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                                <button type="button" class="btn btn-primary" onclick="addUser()">添加</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            $('body').append(modal);
            const modalObj = new bootstrap.Modal(document.getElementById('addUserModal'));
            modalObj.show();
            
            $('#addUserModal').on('hidden.bs.modal', function () {
                $(this).remove();
            });
        }

        async function addUser() {
            const formData = $('#addUserForm').serializeArray();
            const data = {};
            formData.forEach(item => data[item.name] = item.value);
            
            try {
                const result = await $.ajax({
                    url: '/api/users/add',
                    method: 'POST',
                    contentType: 'application/json',
                    data: JSON.stringify(data)
                });
                
                alert(result.message);
                $('#addUserModal').modal('hide');
                refreshUsersList();
            } catch (error) {
                alert('添加失败: ' + (error.responseJSON?.error || '未知错误'));
            }
        }

        function loadSettings() {
            const html = `
                <h2>系统设置</h2>
                <div class="mt-4">
                    <div class="stat-card">
                        <h5>系统信息</h5>
                        <p>版本: 3proxy Enterprise 2.0</p>
                        <p>安装路径: /opt/3proxy-enterprise</p>
                        <p>配置目录: /usr/local/etc/3proxy</p>
                        <p>日志目录: /var/log/3proxy</p>
                    </div>
                </div>
            `;
            $('#content-area').html(html);
        }

        // 初始化
        $(document).ready(function() {
            // 侧边栏点击事件
            $('.sidebar a').on('click', function(e) {
                e.preventDefault();
                $('.sidebar a').removeClass('active');
                $(this).addClass('active');
                
                const page = $(this).data('page');
                currentPage = page;
                
                switch(page) {
                    case 'dashboard':
                        loadDashboard();
                        break;
                    case 'proxies':
                        loadProxies();
                        break;
                    case 'users':
                        loadUsers();
                        break;
                    case 'settings':
                        loadSettings();
                        break;
                }
            });
            
            // 加载仪表板
            loadDashboard();
            
            // 定时刷新
            setInterval(() => {
                if (currentPage === 'dashboard') {
                    refreshDashboard();
                }
            }, 5000);
        });
    </script>
</body>
</html>
HTML

# 创建系统服务
echo "创建系统服务..."

# 3proxy服务
cat > /etc/systemd/system/3proxy-enterprise.service << 'EOF'
[Unit]
Description=3proxy Enterprise Proxy Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/3proxy-enterprise.sh
Restart=always
RestartSec=5
LimitNOFILE=10000000

[Install]
WantedBy=multi-user.target
EOF

# Web管理服务
cat > /etc/systemd/system/3proxy-web.service << 'EOF'
[Unit]
Description=3proxy Enterprise Web Management
After=network.target redis-server.service

[Service]
Type=simple
WorkingDirectory=/opt/3proxy-enterprise
Environment="FLASK_ENV=production"
Environment="ADMIN_PASSWORD=ADMIN_PASS_PLACEHOLDER"
ExecStart=/opt/3proxy-enterprise/venv/bin/python /opt/3proxy-enterprise/app.py 9999
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Nginx配置
cat > /etc/nginx/sites-available/3proxy-enterprise << 'EOF'
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:9999;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        client_max_body_size 100M;
    }
}
EOF

ln -sf /etc/nginx/sites-available/3proxy-enterprise /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# 初始化数据库
echo "初始化数据库..."
cd $WORKDIR
source venv/bin/activate

# 生成管理员密码
ADMINUSER="admin"
ADMINPASS=$(tr -dc 'A-Za-z0-9!@#$%' </dev/urandom | head -c 16)

# 设置环境变量并初始化
export ADMIN_PASSWORD="$ADMINPASS"
python app.py &
sleep 3
pkill -f "python app.py"

# 保存凭据
cat > $CREDS_FILE << EOF
========================================
3proxy Enterprise 管理系统
========================================
访问地址: http://$(get_local_ip)
管理员用户: $ADMINUSER
管理员密码: $ADMINPASS
安装时间: $(date)

系统信息:
- 安装目录: $WORKDIR
- 配置目录: $PROXYCFG_DIR  
- 日志目录: $LOGDIR
- 数据库: $WORKDIR/3proxy.db

注意事项:
- 首次登录后请及时修改密码
- 定期备份数据库文件
========================================
EOF

chmod 600 $CREDS_FILE

# 更新服务密码
sed -i "s/ADMIN_PASS_PLACEHOLDER/$ADMINPASS/g" /etc/systemd/system/3proxy-web.service

# 启动服务
echo "启动服务..."
systemctl daemon-reload
systemctl enable --now redis-server
systemctl enable --now 3proxy-enterprise
systemctl enable --now 3proxy-web
systemctl restart nginx

echo ""
echo "========== 安装完成 =========="
cat $CREDS_FILE
echo ""
echo "常用命令:"
echo "查看登录信息: bash $0 show"
echo "卸载系统: bash $0 uninstall"
echo "重新安装: bash $0 reinstall"
echo ""
echo "提示: 系统已优化支持百万级并发连接"
