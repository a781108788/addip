#!/bin/bash
set -e

# 3proxy企业级管理系统 - 专为大规模代理设计
# 支持: Debian 12, 128G内存, 32核CPU
# 特性: 多进程架构, 负载均衡, 故障恢复

WORKDIR=/opt/3proxy-enterprise
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_DIR=/usr/local/etc/3proxy
LOGDIR=/var/log/3proxy
CREDS_FILE=/opt/3proxy-enterprise/.credentials
BACKUP_DIR=/opt/3proxy-enterprise/backups
INSTANCES=8  # 3proxy实例数量，可根据CPU核心数调整

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

function print_banner() {
    echo -e "${GREEN}"
    echo "================================================"
    echo "   3proxy 企业级管理系统 v2.0"
    echo "   专为大规模代理部署优化"
    echo "================================================"
    echo -e "${NC}"
}

function get_local_ip() {
    local pubip lanip
    pubip=$(curl -s --connect-timeout 3 ifconfig.me || curl -s --connect-timeout 3 ip.sb || echo "")
    lanip=$(hostname -I | awk '{print $1}')
    if [[ -n "$pubip" && "$pubip" != "$lanip" ]]; then
        echo "$pubip"
    else
        echo "$lanip"
    fi
}

function check_system() {
    echo -e "\n${YELLOW}=== 系统检查 ===${NC}\n"
    
    # 检查系统版本
    if ! grep -q "Debian GNU/Linux 12" /etc/os-release 2>/dev/null; then
        echo -e "${YELLOW}警告: 系统不是 Debian 12，可能存在兼容性问题${NC}"
    fi
    
    # 检查内存
    total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 16 ]; then
        echo -e "${RED}错误: 内存不足，建议至少16GB${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ 内存检查通过: ${total_mem}GB${NC}"
    
    # 检查CPU
    cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 8 ]; then
        echo -e "${YELLOW}警告: CPU核心数较少(${cpu_cores}核)，建议至少8核${NC}"
    else
        echo -e "${GREEN}✓ CPU检查通过: ${cpu_cores}核${NC}"
    fi
    
    # 自动调整实例数
    INSTANCES=$((cpu_cores / 4))
    [ "$INSTANCES" -lt 2 ] && INSTANCES=2
    [ "$INSTANCES" -gt 16 ] && INSTANCES=16
    echo -e "${GREEN}✓ 将启动 ${INSTANCES} 个3proxy实例${NC}"
}

function optimize_system() {
    echo -e "\n${YELLOW}=== 系统优化 ===${NC}\n"
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d) 2>/dev/null || true
    
    # 创建优化配置文件
    cat > /etc/sysctl.d/99-3proxy-enterprise.conf <<'EOF'
# 3proxy Enterprise Optimization for Debian 12
# Optimized for 128G RAM, 32 cores, 10k+ proxies

# Basic Network
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1

# Disable rp_filter for multi-IP support
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# ARP optimization for multiple subnets
net.ipv4.neigh.default.gc_thresh1 = 8192
net.ipv4.neigh.default.gc_thresh2 = 32768
net.ipv4.neigh.default.gc_thresh3 = 65536
net.ipv4.neigh.default.gc_stale_time = 120
net.ipv4.neigh.default.gc_interval = 30
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.default.arp_announce = 2

# Routing table optimization
net.ipv4.route.max_size = 8388608
net.ipv4.route.gc_thresh = 1048576
net.ipv4.route.gc_timeout = 300
net.ipv4.route.gc_min_interval_ms = 500
net.ipv4.route.gc_elasticity = 8

# Connection tracking for high concurrency
net.netfilter.nf_conntrack_max = 4194304
net.netfilter.nf_conntrack_buckets = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_generic_timeout = 120

# TCP optimization for proxy workload
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 2097152
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1

# Port range
net.ipv4.ip_local_port_range = 1024 65530

# Socket and memory optimization
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.core.optmem_max = 67108864
net.ipv4.tcp_mem = 2097152 8388608 16777216
net.ipv4.udp_mem = 1048576 4194304 8388608
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 524288
net.core.wmem_default = 524288

# TCP congestion control
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

# File handles
fs.file-max = 10000000
fs.nr_open = 10000000
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 8192

# Process limits
kernel.pid_max = 4194304
kernel.threads-max = 4194304

# Security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# VM optimization
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.max_map_count = 262144
EOF

    # 应用配置
    sysctl -p /etc/sysctl.d/99-3proxy-enterprise.conf >/dev/null 2>&1
    
    # 禁用所有接口的rp_filter
    for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 0 > "$i" 2>/dev/null || true
    done
    
    # 设置ARP参数
    for i in /proc/sys/net/ipv4/conf/*/arp_ignore; do
        echo 1 > "$i" 2>/dev/null || true
    done
    for i in /proc/sys/net/ipv4/conf/*/arp_announce; do
        echo 2 > "$i" 2>/dev/null || true
    done
    
    # 加载必要模块
    modprobe nf_conntrack >/dev/null 2>&1 || true
    modprobe tcp_bbr >/dev/null 2>&1 || true
    
    # 设置连接跟踪哈希表大小
    echo 1048576 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    
    # 优化limits
    cat > /etc/security/limits.d/99-3proxy.conf <<EOF
* soft nofile 5000000
* hard nofile 5000000
* soft nproc 2000000
* hard nproc 2000000
root soft nofile 5000000
root hard nofile 5000000
root soft nproc 2000000
root hard nproc 2000000
EOF

    # 优化systemd
    mkdir -p /etc/systemd/system.conf.d/
    cat > /etc/systemd/system.conf.d/99-3proxy.conf <<EOF
[Manager]
DefaultLimitNOFILE=5000000
DefaultLimitNPROC=2000000
DefaultTasksMax=infinity
EOF

    systemctl daemon-reload
    
    echo -e "${GREEN}✓ 系统优化完成${NC}"
}

function install_dependencies() {
    echo -e "\n${YELLOW}=== 安装依赖 ===${NC}\n"
    
    apt update
    apt install -y \
        build-essential \
        git \
        wget \
        curl \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        sqlite3 \
        nginx \
        redis-server \
        supervisor \
        htop \
        iftop \
        vnstat \
        cron \
        gzip \
        libssl-dev \
        libpcre3-dev \
        zlib1g-dev
    
    # 启动Redis
    systemctl enable redis-server
    systemctl start redis-server
    
    echo -e "${GREEN}✓ 依赖安装完成${NC}"
}

function install_3proxy() {
    echo -e "\n${YELLOW}=== 安装3proxy ===${NC}\n"
    
    if [ ! -f "$THREEPROXY_PATH" ]; then
        cd /tmp
        rm -rf 3proxy
        git clone --depth=1 https://github.com/z3APA3A/3proxy.git
        cd 3proxy
        
        # 优化编译选项
        sed -i 's/CFLAGS = -g/CFLAGS = -O3 -march=native -mtune=native/' Makefile.Linux
        make -f Makefile.Linux -j$(nproc)
        
        mkdir -p /usr/local/bin /usr/local/etc/3proxy /var/log/3proxy
        cp bin/3proxy /usr/local/bin/3proxy
        chmod +x /usr/local/bin/3proxy
        
        echo -e "${GREEN}✓ 3proxy安装完成${NC}"
    else
        echo -e "${GREEN}✓ 3proxy已安装${NC}"
    fi
}

function setup_load_balancer() {
    echo -e "\n${YELLOW}=== 配置负载均衡 ===${NC}\n"
    
    # 创建Nginx负载均衡配置
    cat > /etc/nginx/sites-available/3proxy-lb <<'EOF'
upstream 3proxy_backends {
    least_conn;
    # 后端服务器将在脚本中动态生成
    include /etc/nginx/3proxy-backends.conf;
}

server {
    listen 8888;
    server_name _;
    
    access_log /var/log/nginx/3proxy-access.log;
    error_log /var/log/nginx/3proxy-error.log;
    
    location / {
        proxy_pass http://3proxy_backends;
        proxy_connect_timeout 10s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        proxy_buffering off;
        tcp_nodelay on;
    }
}
EOF

    # 生成后端服务器列表
    echo "# 3proxy backend servers" > /etc/nginx/3proxy-backends.conf
    for i in $(seq 1 $INSTANCES); do
        port=$((30000 + i))
        echo "server 127.0.0.1:$port max_fails=3 fail_timeout=30s;" >> /etc/nginx/3proxy-backends.conf
    done
    
    ln -sf /etc/nginx/sites-available/3proxy-lb /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # 优化Nginx
    cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
worker_cpu_affinity auto;
worker_rlimit_nofile 5000000;
pid /run/nginx.pid;

events {
    worker_connections 65536;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 300;
    keepalive_requests 10000;
    types_hash_max_size 2048;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip off;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    systemctl restart nginx
    echo -e "${GREEN}✓ 负载均衡配置完成${NC}"
}

function setup_web_management() {
    echo -e "\n${YELLOW}=== 部署Web管理系统 ===${NC}\n"
    
    mkdir -p $WORKDIR/templates $WORKDIR/static $BACKUP_DIR
    cd $WORKDIR
    
    # 创建Python虚拟环境
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install flask flask_login flask_wtf wtforms Werkzeug psutil redis hiredis gunicorn gevent
    
    # 生成管理员账号
    ADMINUSER="admin$(shuf -i 1000-9999 -n 1)"
    ADMINPASS=$(tr -dc 'A-Za-z0-9!@#$%^&*' </dev/urandom | head -c 20)
    
    # 保存凭据
    cat > $CREDS_FILE <<EOF
3proxy企业级管理系统
====================
Web管理地址: http://$(get_local_ip):9999
管理员用户名: $ADMINUSER
管理员密码: $ADMINPASS
安装时间: $(date)
代理端口: 8888 (Nginx负载均衡)
3proxy实例数: $INSTANCES
====================
EOF
    chmod 600 $CREDS_FILE
    
    # 创建主应用文件
    cat > $WORKDIR/app.py << 'EOF'
import os
import sqlite3
import random
import string
import re
import json
import time
import threading
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.serving import WSGIRequestHandler
import psutil
import redis
from collections import defaultdict
from io import BytesIO

# 配置
DB_PATH = '3proxy.db'
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-in-production')
INSTANCES = int(os.environ.get('INSTANCES', '8'))
PROXYCFG_DIR = '/usr/local/etc/3proxy'
LOGDIR = '/var/log/3proxy'

# 初始化
app = Flask(__name__)
app.secret_key = SECRET_KEY
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Redis连接
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

# 禁用Werkzeug日志
WSGIRequestHandler.log_request = lambda self, code='-', size='-': None

def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """初始化数据库"""
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS proxy (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            instance INTEGER DEFAULT 1,
            ip_range TEXT,
            port_range TEXT,
            user_prefix TEXT,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip, port)
        );
        
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS ip_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_str TEXT NOT NULL,
            type TEXT DEFAULT 'range',
            iface TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS system_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            cpu_percent REAL,
            memory_percent REAL,
            connections INTEGER,
            traffic_in BIGINT,
            traffic_out BIGINT
        );
        
        CREATE INDEX IF NOT EXISTS idx_proxy_ip ON proxy(ip);
        CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON proxy(enabled);
        CREATE INDEX IF NOT EXISTS idx_proxy_instance ON proxy(instance);
    ''')
    
    # 创建默认管理员
    admin_user = os.environ.get('ADMINUSER', 'admin')
    admin_pass = os.environ.get('ADMINPASS', 'admin123')
    
    cursor = db.execute('SELECT id FROM users WHERE username = ?', (admin_user,))
    if not cursor.fetchone():
        db.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)',
                   (admin_user, generate_password_hash(admin_pass)))
    
    db.commit()
    db.close()

class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    db.close()
    if row:
        return User(row['id'], row['username'], row['is_admin'])
    return None

def detect_nic():
    """检测主网卡"""
    for nic in sorted(os.listdir('/sys/class/net')):
        if nic.startswith(('e', 'en', 'eth')):
            return nic
    return 'eth0'

def get_used_ports():
    """获取已使用的端口"""
    db = get_db()
    cursor = db.execute('SELECT port FROM proxy')
    ports = set(row['port'] for row in cursor.fetchall())
    db.close()
    return ports

def distribute_proxies_to_instances(proxies):
    """将代理分配到不同的3proxy实例"""
    if not proxies:
        return {}
    
    # 按实例分组
    instances = defaultdict(list)
    
    # 平均分配
    for i, proxy in enumerate(proxies):
        instance = (i % INSTANCES) + 1
        proxy['instance'] = instance
        instances[instance].append(proxy)
    
    return instances

def generate_3proxy_config(instance_id):
    """生成单个3proxy实例的配置"""
    db = get_db()
    cursor = db.execute('''
        SELECT ip, port, username, password 
        FROM proxy 
        WHERE enabled = 1 AND instance = ?
        ORDER BY ip, port
    ''', (instance_id,))
    
    proxies = cursor.fetchall()
    db.close()
    
    # 基础配置
    base_port = 30000 + instance_id
    config = [
        f"# 3proxy instance {instance_id}",
        "daemon",
        f"pidfile /var/run/3proxy-{instance_id}.pid",
        f"log {LOGDIR}/3proxy-{instance_id}.log D",
        "rotate 7",
        "archiver gz /usr/bin/gzip %F",
        "maxconn 50000",
        "nserver 8.8.8.8",
        "nserver 1.1.1.1",
        "nserver 8.8.4.4",
        "nscache 65536",
        "nscache6 65536",
        "stacksize 6291456",
        "timeouts 1 5 30 60 180 1800 15 60",
        "",
        "# HTTP proxy for load balancer",
        f"proxy -p{base_port}",
        "",
        "# User authentication",
        "auth strong",
        ""
    ]
    
    # 收集用户
    users = {}
    for proxy in proxies:
        users[proxy['username']] = proxy['password']
    
    # 添加用户（分批避免行过长）
    user_list = [f"{user}:CL:{pw}" for user, pw in users.items()]
    batch_size = 50
    for i in range(0, len(user_list), batch_size):
        batch = user_list[i:i+batch_size]
        config.append(f"users {' '.join(batch)}")
    
    config.append("")
    
    # 添加代理配置
    for proxy in proxies:
        config.extend([
            f"# Proxy {proxy['ip']}:{proxy['port']}",
            "auth strong",
            f"allow {proxy['username']}",
            f"proxy -n -a -p{proxy['port']} -i{proxy['ip']} -e{proxy['ip']}",
            ""
        ])
    
    # 写入配置文件
    config_path = f"{PROXYCFG_DIR}/3proxy-{instance_id}.cfg"
    with open(config_path, 'w') as f:
        f.write('\n'.join(config))
    
    return len(proxies)

def reload_all_instances():
    """重载所有3proxy实例"""
    success = True
    for i in range(1, INSTANCES + 1):
        count = generate_3proxy_config(i)
        
        # 使用supervisor重启实例
        try:
            subprocess.run(['supervisorctl', 'restart', f'3proxy-{i}'], 
                         check=True, capture_output=True)
            redis_client.hset('proxy_stats', f'instance_{i}_count', count)
            redis_client.hset('proxy_stats', f'instance_{i}_status', 'running')
        except:
            success = False
            redis_client.hset('proxy_stats', f'instance_{i}_status', 'error')
    
    # 更新总数
    db = get_db()
    total = db.execute('SELECT COUNT(*) as cnt FROM proxy WHERE enabled = 1').fetchone()['cnt']
    redis_client.set('proxy_total_count', total)
    db.close()
    
    return success

def get_system_stats():
    """获取系统统计信息"""
    stats = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory': psutil.virtual_memory()._asdict(),
        'disk': psutil.disk_usage('/')._asdict(),
        'network': psutil.net_io_counters()._asdict(),
        'connections': len(psutil.net_connections()),
        'load_average': os.getloadavg(),
        'instances': {}
    }
    
    # 获取每个实例的状态
    for i in range(1, INSTANCES + 1):
        pid_file = f"/var/run/3proxy-{i}.pid"
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                proc = psutil.Process(pid)
                stats['instances'][i] = {
                    'status': 'running',
                    'cpu': proc.cpu_percent(),
                    'memory': proc.memory_info().rss / 1024 / 1024,  # MB
                    'connections': len(proc.connections()),
                    'proxy_count': redis_client.hget('proxy_stats', f'instance_{i}_count') or 0
                }
            except:
                stats['instances'][i] = {'status': 'stopped'}
        else:
            stats['instances'][i] = {'status': 'stopped'}
    
    return stats

# 路由定义
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        cursor = db.execute('SELECT id, username, password, is_admin FROM users WHERE username = ?', 
                           (username,))
        user = cursor.fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username'], user['is_admin']))
            return redirect(url_for('index'))
        
        flash('用户名或密码错误', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', instances=INSTANCES)

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_system_stats())

@app.route('/api/proxy_groups')
@login_required
def api_proxy_groups():
    db = get_db()
    cursor = db.execute('''
        SELECT 
            SUBSTR(ip, 1, LENGTH(ip) - LENGTH(SUBSTR(ip, -3))) as c_segment,
            COUNT(*) as total,
            SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled,
            MIN(port) as min_port,
            MAX(port) as max_port,
            user_prefix
        FROM proxy
        GROUP BY c_segment, user_prefix
        ORDER BY c_segment
    ''')
    
    groups = []
    for row in cursor.fetchall():
        c_seg = row['c_segment'].rstrip('.')
        groups.append({
            'c_segment': c_seg,
            'total': row['total'],
            'enabled': row['enabled'],
            'port_range': f"{row['min_port']}-{row['max_port']}",
            'user_prefix': row['user_prefix'] or '',
            'traffic': redis_client.hget('traffic_stats', c_seg) or 0
        })
    
    db.close()
    return jsonify(groups)

@app.route('/api/proxy_group/<c_segment>')
@login_required
def api_proxy_group_detail(c_segment):
    db = get_db()
    cursor = db.execute('''
        SELECT * FROM proxy 
        WHERE ip LIKE ? 
        ORDER BY ip, port
    ''', (c_segment + '.%',))
    
    proxies = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify(proxies)

@app.route('/api/batch_add_proxy', methods=['POST'])
@login_required
def api_batch_add_proxy():
    try:
        data = request.get_json()
        ip_range = data.get('ip_range', '').strip()
        port_range = data.get('port_range', '').strip()
        user_prefix = data.get('user_prefix', '').strip()
        
        if not ip_range or not user_prefix:
            return jsonify({'status': 'error', 'message': '请填写必要参数'})
        
        # 解析IP范围
        match = re.match(r'(\d+\.\d+\.\d+\.)(\d+)-(\d+)', ip_range)
        if not match:
            return jsonify({'status': 'error', 'message': 'IP范围格式错误'})
        
        ip_base = match.group(1)
        ip_start = int(match.group(2))
        ip_end = int(match.group(3))
        
        if ip_start < 1 or ip_end > 254 or ip_start > ip_end:
            return jsonify({'status': 'error', 'message': 'IP范围无效'})
        
        ips = [f"{ip_base}{i}" for i in range(ip_start, ip_end + 1)]
        
        # 获取已使用的端口
        used_ports = get_used_ports()
        
        # 解析或生成端口范围
        if port_range:
            match = re.match(r'(\d+)-(\d+)', port_range)
            if not match:
                return jsonify({'status': 'error', 'message': '端口范围格式错误'})
            port_start = int(match.group(1))
            port_end = int(match.group(2))
        else:
            # 自动分配端口
            port_start = 10000
            port_end = 65530
        
        # 生成可用端口
        available_ports = [p for p in range(port_start, port_end + 1) 
                          if p not in used_ports and p not in range(30000, 30020)]
        
        if len(available_ports) < len(ips):
            return jsonify({
                'status': 'error', 
                'message': f'可用端口不足，需要{len(ips)}个，但只有{len(available_ports)}个可用'
            })
        
        # 随机选择端口
        selected_ports = random.sample(available_ports, len(ips))
        
        # 分配到实例
        proxies = []
        for i, (ip, port) in enumerate(zip(ips, selected_ports)):
            instance = (i % INSTANCES) + 1
            username = f"{user_prefix}{random.choice(string.ascii_lowercase)}{random.randint(100, 999)}"
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            
            proxies.append({
                'ip': ip,
                'port': port,
                'username': username,
                'password': password,
                'instance': instance,
                'ip_range': ip_range,
                'port_range': f"{min(selected_ports)}-{max(selected_ports)}",
                'user_prefix': user_prefix
            })
        
        # 批量插入数据库
        db = get_db()
        db.executemany('''
            INSERT INTO proxy (ip, port, username, password, instance, ip_range, port_range, user_prefix)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', [(p['ip'], p['port'], p['username'], p['password'], p['instance'], 
               p['ip_range'], p['port_range'], p['user_prefix']) for p in proxies])
        db.commit()
        db.close()
        
        # 添加IP到系统
        nic = detect_nic()
        for ip in ips:
            os.system(f"ip addr add {ip}/32 dev {nic} 2>/dev/null || true")
        
        # 重载配置
        reload_all_instances()
        
        return jsonify({
            'status': 'success',
            'message': f'成功添加 {len(proxies)} 个代理',
            'details': {
                'count': len(proxies),
                'port_range': f"{min(selected_ports)}-{max(selected_ports)}",
                'instances': INSTANCES
            }
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/delete_group/<c_segment>', methods=['POST'])
@login_required
def api_delete_group(c_segment):
    try:
        db = get_db()
        
        # 获取要删除的IP列表
        cursor = db.execute('SELECT DISTINCT ip FROM proxy WHERE ip LIKE ?', (c_segment + '.%',))
        ips = [row['ip'] for row in cursor.fetchall()]
        
        # 删除代理
        db.execute('DELETE FROM proxy WHERE ip LIKE ?', (c_segment + '.%',))
        db.commit()
        db.close()
        
        # 从系统中删除IP
        nic = detect_nic()
        for ip in ips:
            os.system(f"ip addr del {ip}/32 dev {nic} 2>/dev/null || true")
        
        # 重载配置
        reload_all_instances()
        
        return jsonify({'status': 'success', 'message': f'已删除 {c_segment}.x 段所有代理'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/toggle_proxy/<int:proxy_id>/<action>', methods=['POST'])
@login_required
def api_toggle_proxy(proxy_id, action):
    try:
        enabled = 1 if action == 'enable' else 0
        
        db = get_db()
        db.execute('UPDATE proxy SET enabled = ? WHERE id = ?', (enabled, proxy_id))
        db.commit()
        db.close()
        
        # 重载配置
        reload_all_instances()
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/export_proxies', methods=['POST'])
@login_required
def api_export_proxies():
    try:
        data = request.get_json()
        c_segments = data.get('c_segments', [])
        
        if not c_segments:
            return jsonify({'status': 'error', 'message': '请选择要导出的代理组'})
        
        db = get_db()
        
        output = []
        for c_seg in c_segments:
            cursor = db.execute('''
                SELECT ip, port, username, password 
                FROM proxy 
                WHERE ip LIKE ? AND enabled = 1
                ORDER BY ip, port
            ''', (c_seg + '.%',))
            
            for row in cursor.fetchall():
                output.append(f"{row['ip']}:{row['port']}:{row['username']}:{row['password']}")
        
        db.close()
        
        # 生成文件
        content = '\n'.join(output)
        filename = f"proxy_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        return Response(
            content,
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# 后台任务
def collect_stats():
    """收集系统统计信息"""
    while True:
        try:
            stats = get_system_stats()
            
            # 保存到Redis
            redis_client.hset('system_stats', 'cpu', stats['cpu_percent'])
            redis_client.hset('system_stats', 'memory', stats['memory']['percent'])
            redis_client.hset('system_stats', 'connections', stats['connections'])
            
            # 保存到数据库（每5分钟）
            if int(time.time()) % 300 == 0:
                db = get_db()
                db.execute('''
                    INSERT INTO system_stats (cpu_percent, memory_percent, connections)
                    VALUES (?, ?, ?)
                ''', (stats['cpu_percent'], stats['memory']['percent'], stats['connections']))
                db.commit()
                db.close()
            
        except Exception as e:
            print(f"Stats collection error: {e}")
        
        time.sleep(5)

# 启动后台线程
stats_thread = threading.Thread(target=collect_stats, daemon=True)
stats_thread.start()

# 初始化数据库
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999, debug=False)
EOF

    # 创建模板文件
    mkdir -p $WORKDIR/templates
    
    # login.html
    cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3proxy企业级管理系统 - 登录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
            padding: 40px;
            width: 100%;
            max-width: 400px;
            animation: fadeIn 0.5s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header h1 {
            color: #1e3c72;
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .login-header p {
            color: #666;
            font-size: 14px;
        }
        .form-control:focus {
            border-color: #2a5298;
            box-shadow: 0 0 0 0.2rem rgba(42, 82, 152, 0.25);
        }
        .btn-login {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            border: none;
            color: white;
            padding: 12px;
            font-weight: 500;
            border-radius: 10px;
            transition: all 0.3s ease;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(42, 82, 152, 0.4);
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <h1>3proxy 企业级管理系统</h1>
            <p>高性能分布式代理管理平台</p>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <div class="mb-3">
                <label for="username" class="form-label">用户名</label>
                <input type="text" class="form-control" id="username" name="username" required autofocus>
            </div>
            <div class="mb-4">
                <label for="password" class="form-label">密码</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-login w-100">登录系统</button>
        </form>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

    # index.html (主界面)
    cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3proxy企业级管理系统</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #1e3c72;
            --secondary-color: #2a5298;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
        }
        
        body {
            background: #f0f2f5;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 1rem 0;
        }
        
        .navbar-brand {
            font-weight: bold;
            font-size: 1.5rem;
        }
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
            height: 100%;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .instance-card {
            background: white;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: all 0.2s ease;
        }
        
        .instance-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .instance-status {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
        }
        
        .status-running { background-color: #28a745; }
        .status-stopped { background-color: #dc3545; }
        .status-warning { background-color: #ffc107; }
        
        .proxy-group-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.06);
            cursor: pointer;
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        
        .proxy-group-card:hover {
            border-color: var(--primary-color);
            transform: translateX(5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .proxy-group-card.selected {
            background: #f0f7ff;
            border-color: var(--primary-color);
        }
        
        .btn-gradient {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .btn-gradient:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(42, 82, 152, 0.4);
            color: white;
        }
        
        .modal-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            border-radius: 15px 15px 0 0;
        }
        
        .table-container {
            max-height: 500px;
            overflow-y: auto;
        }
        
        .progress {
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .badge-status {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .loading {
            animation: pulse 1.5s infinite;
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand">
                <i class="bi bi-shield-check me-2"></i>3proxy 企业级管理系统
            </span>
            <div class="d-flex align-items-center">
                <span class="text-white me-3">
                    <i class="bi bi-person-circle me-1"></i>{{ current_user.username }}
                </span>
                <a href="/logout" class="btn btn-outline-light btn-sm">
                    <i class="bi bi-box-arrow-right"></i> 退出
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <!-- 系统状态 -->
        <div class="row mb-4">
            <div class="col-xl-3 col-lg-6 mb-3">
                <div class="stat-card text-center">
                    <i class="bi bi-cpu text-primary" style="font-size: 2rem;"></i>
                    <div class="stat-number text-primary" id="cpu-usage">0%</div>
                    <div class="stat-label">CPU 使用率</div>
                    <div class="progress mt-3">
                        <div class="progress-bar bg-primary" id="cpu-progress" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            
            <div class="col-xl-3 col-lg-6 mb-3">
                <div class="stat-card text-center">
                    <i class="bi bi-memory text-success" style="font-size: 2rem;"></i>
                    <div class="stat-number text-success" id="memory-usage">0%</div>
                    <div class="stat-label">内存使用率</div>
                    <div class="progress mt-3">
                        <div class="progress-bar bg-success" id="memory-progress" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            
            <div class="col-xl-3 col-lg-6 mb-3">
                <div class="stat-card text-center">
                    <i class="bi bi-hdd-network text-info" style="font-size: 2rem;"></i>
                    <div class="stat-number text-info" id="proxy-count">0</div>
                    <div class="stat-label">活跃代理数</div>
                </div>
            </div>
            
            <div class="col-xl-3 col-lg-6 mb-3">
                <div class="stat-card text-center">
                    <i class="bi bi-diagram-3 text-warning" style="font-size: 2rem;"></i>
                    <div class="stat-number text-warning" id="connection-count">0</div>
                    <div class="stat-label">当前连接数</div>
                </div>
            </div>
        </div>

        <!-- 实例状态 -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-light">
                        <h5 class="mb-0"><i class="bi bi-server me-2"></i>3proxy 实例状态</h5>
                    </div>
                    <div class="card-body">
                        <div class="row" id="instances-container">
                            <!-- 动态生成 -->
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 代理管理 -->
        <div class="row">
            <div class="col-lg-4 mb-4">
                <div class="card">
                    <div class="card-header bg-light">
                        <h5 class="mb-0"><i class="bi bi-plus-circle me-2"></i>批量添加代理</h5>
                    </div>
                    <div class="card-body">
                        <form id="add-proxy-form">
                            <div class="mb-3">
                                <label class="form-label">IP范围</label>
                                <input type="text" class="form-control" id="ip-range" 
                                       placeholder="192.168.1.2-254" required>
                                <small class="text-muted">格式: x.x.x.start-end</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">端口范围 <small class="text-muted">(可选)</small></label>
                                <input type="text" class="form-control" id="port-range" 
                                       placeholder="10000-20000">
                                <small class="text-muted">留空自动分配(10000-65530)</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">用户名前缀</label>
                                <input type="text" class="form-control" id="user-prefix" 
                                       placeholder="user" required>
                            </div>
                            <button type="submit" class="btn btn-gradient w-100">
                                <i class="bi bi-plus-lg me-2"></i>批量添加
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-lg-8 mb-4">
                <div class="card">
                    <div class="card-header bg-light d-flex justify-content-between align-items-center">
                        <h5 class="mb-0"><i class="bi bi-list-ul me-2"></i>代理组管理</h5>
                        <div>
                            <button class="btn btn-sm btn-outline-primary" onclick="refreshGroups()">
                                <i class="bi bi-arrow-clockwise"></i> 刷新
                            </button>
                            <button class="btn btn-sm btn-outline-success" onclick="exportSelected()">
                                <i class="bi bi-download"></i> 导出选中
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div id="proxy-groups-container" style="max-height: 600px; overflow-y: auto;">
                            <!-- 动态生成 -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 代理详情模态框 -->
    <div class="modal fade" id="proxyDetailModal" tabindex="-1" data-bs-backdrop="static">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">代理详情</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="proxy-detail-content">
                        <!-- 动态生成 -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <script>
        let selectedGroups = new Set();
        let refreshInterval;

        // 工具函数
        function showToast(message, type = 'success') {
            // 简单的提示实现
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
            alertDiv.style.zIndex = '9999';
            alertDiv.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(alertDiv);
            
            setTimeout(() => {
                alertDiv.remove();
            }, 3000);
        }

        // 更新系统状态
        async function updateStats() {
            try {
                const response = await axios.get('/api/stats');
                const stats = response.data;
                
                // 更新CPU
                document.getElementById('cpu-usage').textContent = stats.cpu_percent.toFixed(1) + '%';
                document.getElementById('cpu-progress').style.width = stats.cpu_percent + '%';
                
                // 更新内存
                document.getElementById('memory-usage').textContent = stats.memory.percent.toFixed(1) + '%';
                document.getElementById('memory-progress').style.width = stats.memory.percent + '%';
                
                // 更新连接数
                document.getElementById('connection-count').textContent = stats.connections.toLocaleString();
                
                // 更新实例状态
                updateInstances(stats.instances);
                
            } catch (error) {
                console.error('Failed to update stats:', error);
            }
        }

        // 更新实例状态
        function updateInstances(instances) {
            const container = document.getElementById('instances-container');
            container.innerHTML = '';
            
            let totalProxies = 0;
            
            Object.entries(instances).forEach(([id, instance]) => {
                const statusClass = instance.status === 'running' ? 'status-running' : 'status-stopped';
                const statusText = instance.status === 'running' ? '运行中' : '已停止';
                
                if (instance.proxy_count) {
                    totalProxies += parseInt(instance.proxy_count);
                }
                
                const html = `
                    <div class="col-xl-3 col-lg-4 col-md-6 mb-2">
                        <div class="instance-card">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <span class="instance-status ${statusClass}"></span>
                                    <strong>实例 ${id}</strong>
                                </div>
                                <small class="text-muted">${statusText}</small>
                            </div>
                            ${instance.status === 'running' ? `
                                <div class="mt-2 small text-muted">
                                    <div>代理数: ${instance.proxy_count || 0}</div>
                                    <div>CPU: ${instance.cpu?.toFixed(1) || 0}%</div>
                                    <div>内存: ${instance.memory?.toFixed(1) || 0} MB</div>
                                    <div>连接: ${instance.connections || 0}</div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
                container.innerHTML += html;
            });
            
            // 更新总代理数
            document.getElementById('proxy-count').textContent = totalProxies.toLocaleString();
        }

        // 加载代理组
        async function loadProxyGroups() {
            try {
                const response = await axios.get('/api/proxy_groups');
                const groups = response.data;
                
                const container = document.getElementById('proxy-groups-container');
                container.innerHTML = '';
                
                groups.forEach(group => {
                    const isSelected = selectedGroups.has(group.c_segment);
                    const html = `
                        <div class="proxy-group-card ${isSelected ? 'selected' : ''}" 
                             data-segment="${group.c_segment}"
                             onclick="toggleGroupSelection('${group.c_segment}')">
                            <div class="row align-items-center">
                                <div class="col-auto">
                                    <input type="checkbox" class="form-check-input" 
                                           ${isSelected ? 'checked' : ''}
                                           onclick="event.stopPropagation();">
                                </div>
                                <div class="col">
                                    <h6 class="mb-1">
                                        <i class="bi bi-diagram-3 text-primary me-2"></i>
                                        ${group.c_segment}.x
                                    </h6>
                                    <div class="small text-muted">
                                        <span class="me-3">
