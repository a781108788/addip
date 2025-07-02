#!/bin/bash
set -e

# 系统配置
WORKDIR=/opt/xray-manager
XRAY_PATH=/usr/local/bin/xray
XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json
XRAY_LOG_PATH=/var/log/xray
CREDS_FILE=/opt/xray-manager/.credentials

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

function print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function get_local_ip() {
    local pubip lanip
    pubip=$(curl -s --connect-timeout 3 ifconfig.me || curl -s --connect-timeout 3 ip.sb || curl -s --connect-timeout 3 icanhazip.com || echo "")
    lanip=$(hostname -I | awk '{print $1}')
    if [[ -n "$pubip" && "$pubip" != "$lanip" ]]; then
        echo "$pubip"
    else
        echo "$lanip"
    fi
}

function show_credentials() {
    if [ -f "$CREDS_FILE" ]; then
        echo -e "\n========= Xray 代理管理系统登录信息 ========="
        cat "$CREDS_FILE"
        echo -e "============================================\n"
    else
        print_error "未找到登录凭据文件。请运行安装脚本。"
    fi
}

function check_system() {
    print_info "检查系统环境..."
    
    # 检查操作系统
    if [ -f /etc/debian_version ]; then
        DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1)
        print_info "检测到 Debian $DEBIAN_VERSION"
    else
        print_error "此脚本仅支持 Debian 系统"
        exit 1
    fi
    
    # 检查架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            XRAY_ARCH="64"
            ;;
        aarch64)
            XRAY_ARCH="arm64-v8a"
            ;;
        *)
            print_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    # 检查内存
    MEM_TOTAL=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$MEM_TOTAL" -lt 4 ]; then
        print_warning "系统内存小于4GB，可能影响性能"
    fi
}

function optimize_system() {
    print_info "优化系统参数..."
    
    # 检查是否已经优化过
    if grep -q "# Xray 性能优化" /etc/sysctl.conf 2>/dev/null; then
        print_warning "系统已经优化过，跳过..."
        return
    fi
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    
    # 优化内核参数
    cat >> /etc/sysctl.conf <<'EOF'

# Xray 性能优化 - 支持百万级并发
# 基础网络优化
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1

# TCP 优化
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 65536
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

# 端口范围
net.ipv4.ip_local_port_range = 1024 65535

# 连接跟踪
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120

# 网络缓冲
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.core.netdev_budget = 600
net.core.optmem_max = 25165824
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# BBR 拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 文件句柄
fs.file-max = 6000000
fs.nr_open = 6000000
fs.inotify.max_user_instances = 65536

# 内存优化
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.overcommit_memory = 1

# 安全优化
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
EOF
    
    # 立即应用
    sysctl -p >/dev/null 2>&1
    
    # 加载必要模块
    modprobe tcp_bbr 2>/dev/null || true
    modprobe nf_conntrack 2>/dev/null || true
    
    # 优化文件描述符限制
    if ! grep -q "# Xray limits" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf <<'EOF'

# Xray limits
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
root soft nofile 1000000
root hard nofile 1000000
root soft nproc 1000000
root hard nproc 1000000
EOF
    fi
    
    # 优化 systemd 限制
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/99-xray-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1000000
DefaultLimitNPROC=1000000
DefaultTasksMax=infinity
EOF
    
    systemctl daemon-reload
    
    print_success "系统优化完成"
}

function install_xray() {
    print_info "安装 Xray..."
    
    # 检查是否已安装
    if [ -f "$XRAY_PATH" ]; then
        CURRENT_VERSION=$($XRAY_PATH version | grep Xray | cut -d' ' -f2)
        print_info "Xray 已安装，版本: $CURRENT_VERSION"
        return
    fi
    
    # 下载最新版 Xray
    cd /tmp
    LATEST_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d'"' -f4)
    print_info "下载 Xray $LATEST_VERSION..."
    
    wget -q --show-progress "https://github.com/XTLS/Xray-core/releases/download/${LATEST_VERSION}/Xray-linux-${XRAY_ARCH}.zip"
    
    # 解压安装
    unzip -q Xray-linux-${XRAY_ARCH}.zip
    mkdir -p /usr/local/bin /usr/local/etc/xray /usr/local/share/xray
    cp xray /usr/local/bin/
    cp *.dat /usr/local/share/xray/
    chmod +x /usr/local/bin/xray
    
    # 清理
    rm -f Xray-linux-${XRAY_ARCH}.zip xray *.dat
    
    print_success "Xray 安装完成"
}

function setup_directories() {
    print_info "创建目录结构..."
    
    mkdir -p $WORKDIR/{templates,static,backups,logs}
    mkdir -p $XRAY_LOG_PATH
    mkdir -p /usr/local/etc/xray
    
    # 创建日志文件
    touch $XRAY_LOG_PATH/access.log
    touch $XRAY_LOG_PATH/error.log
    chmod 666 $XRAY_LOG_PATH/*.log
}

function install_dependencies() {
    print_info "安装系统依赖..."
    
    apt update
    apt install -y \
        python3 python3-pip python3-venv python3-dev \
        gcc make git wget curl unzip \
        sqlite3 redis-server \
        nginx certbot python3-certbot-nginx \
        supervisor cron \
        net-tools iftop htop
    
    # 启动 Redis
    systemctl enable redis-server
    systemctl start redis-server
    
    print_success "依赖安装完成"
}

function setup_python_env() {
    print_info "配置 Python 环境..."
    
    cd $WORKDIR
    python3 -m venv venv
    source venv/bin/activate
    
    # 升级 pip
    pip install --upgrade pip
    
    # 安装 Python 依赖
    pip install \
        flask==2.3.3 \
        flask-login==0.6.2 \
        flask-wtf==1.1.1 \
        flask-cors==4.0.0 \
        werkzeug==2.3.7 \
        psutil==5.9.5 \
        redis==5.0.0 \
        celery==5.3.1 \
        gevent==23.9.1 \
        gunicorn==21.2.0 \
        requests==2.31.0 \
        python-dateutil==2.8.2 \
        apscheduler==3.10.4
    
    deactivate
    
    print_success "Python 环境配置完成"
}

function create_webapp() {
    print_info "创建 Web 应用..."
    
    # ========== app.py - 主应用 ==========
    cat > $WORKDIR/app.py << 'PYEOF'
import os
import sys
import json
import time
import sqlite3
import random
import string
import hashlib
import subprocess
import threading
import queue
from datetime import datetime, timedelta
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import psutil
import redis
import requests
from apscheduler.schedulers.background import BackgroundScheduler

# 配置
DB_PATH = 'xray.db'
XRAY_CONFIG_PATH = '/usr/local/etc/xray/config.json'
XRAY_LOG_PATH = '/var/log/xray'
SECRET_KEY = os.environ.get('SECRET_KEY', 'xray-manager-secret-key-change-me')
REDIS_HOST = 'localhost'
REDIS_PORT = 6379

# Flask 应用
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# CORS
CORS(app)

# 登录管理
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录'

# Redis 连接
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    redis_client.ping()
except:
    print("Warning: Redis connection failed, using memory cache")
    redis_client = None

# 任务队列
task_queue = queue.Queue(maxsize=1000)

# 数据库连接池
class DatabasePool:
    def __init__(self, db_path, pool_size=20):
        self.db_path = db_path
        self.pool = queue.Queue(maxsize=pool_size)
        self._initialize_pool()
    
    def _initialize_pool(self):
        for _ in range(self.pool.qsize(), self.pool.maxsize):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            conn.execute('PRAGMA foreign_keys=ON')
            self.pool.put(conn)
    
    @contextmanager
    def get_connection(self):
        conn = self.pool.get()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.pool.put(conn)

# 初始化数据库池
db_pool = DatabasePool(DB_PATH)

# 用户模型
class User(UserMixin):
    def __init__(self, id, username, email, role='user'):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    with db_pool.get_connection() as conn:
        user = conn.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?", 
            (user_id,)
        ).fetchone()
        if user:
            return User(user['id'], user['username'], user['email'], user['role'])
    return None

# Xray 配置管理
class XrayManager:
    def __init__(self):
        self.config_lock = threading.Lock()
        
    def generate_config(self):
        """生成 Xray 配置"""
        with db_pool.get_connection() as conn:
            # 获取所有启用的代理
            proxies = conn.execute("""
                SELECT p.*, g.name as group_name 
                FROM proxies p
                LEFT JOIN proxy_groups g ON p.group_id = g.id
                WHERE p.enabled = 1
                ORDER BY p.port
            """).fetchall()
            
            # 基础配置
            config = {
                "log": {
                    "access": f"{XRAY_LOG_PATH}/access.log",
                    "error": f"{XRAY_LOG_PATH}/error.log",
                    "loglevel": "warning"
                },
                "api": {
                    "services": ["HandlerService", "LoggerService", "StatsService"],
                    "tag": "api"
                },
                "inbounds": [],
                "outbounds": [
                    {
                        "protocol": "freedom",
                        "settings": {},
                        "tag": "direct"
                    },
                    {
                        "protocol": "blackhole",
                        "settings": {},
                        "tag": "blocked"
                    }
                ],
                "routing": {
                    "domainStrategy": "IPIfNonMatch",
                    "rules": [
                        {
                            "inboundTag": ["api"],
                            "outboundTag": "api",
                            "type": "field"
                        }
                    ]
                },
                "stats": {},
                "policy": {
                    "levels": {
                        "0": {
                            "handshake": 4,
                            "connIdle": 300,
                            "uplinkOnly": 2,
                            "downlinkOnly": 5,
                            "statsUserUplink": true,
                            "statsUserDownlink": true,
                            "bufferSize": 512
                        }
                    },
                    "system": {
                        "statsInboundUplink": true,
                        "statsInboundDownlink": true,
                        "statsOutboundUplink": true,
                        "statsOutboundDownlink": true
                    }
                }
            }
            
            # API 入站
            config["inbounds"].append({
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                },
                "tag": "api"
            })
            
            # 添加代理入站
            for proxy in proxies:
                inbound = {
                    "listen": proxy['bind_ip'],
                    "port": proxy['port'],
                    "protocol": proxy['protocol'],
                    "tag": f"proxy-{proxy['id']}",
                    "settings": {}
                }
                
                if proxy['protocol'] == 'http':
                    inbound["settings"] = {
                        "auth": "password",
                        "accounts": [
                            {
                                "user": proxy['username'],
                                "pass": proxy['password']
                            }
                        ],
                        "allowTransparent": False,
                        "userLevel": 0
                    }
                elif proxy['protocol'] == 'socks':
                    inbound["settings"] = {
                        "auth": "password",
                        "accounts": [
                            {
                                "user": proxy['username'],
                                "pass": proxy['password']
                            }
                        ],
                        "udp": True,
                        "userLevel": 0
                    }
                
                # 流量限制
                if proxy['traffic_limit'] > 0:
                    inbound["sniffing"] = {
                        "enabled": True,
                        "destOverride": ["http", "tls"]
                    }
                
                config["inbounds"].append(inbound)
            
        return config
    
    def reload_config(self):
        """重载 Xray 配置"""
        with self.config_lock:
            try:
                # 生成配置
                config = self.generate_config()
                
                # 写入配置文件
                with open(XRAY_CONFIG_PATH, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                
                # 验证配置
                result = subprocess.run(
                    ['/usr/local/bin/xray', 'test', '-c', XRAY_CONFIG_PATH],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    raise Exception(f"配置验证失败: {result.stderr}")
                
                # 重载服务
                subprocess.run(['systemctl', 'reload', 'xray'], check=True)
                
                # 清除缓存
                if redis_client:
                    redis_client.delete('proxy_stats')
                
                return True, "配置重载成功"
                
            except Exception as e:
                return False, str(e)
    
    def get_stats(self):
        """获取统计信息"""
        try:
            # 使用 Xray API 获取统计
            response = requests.get('http://127.0.0.1:10085/stats/query', timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {}

# 初始化 Xray 管理器
xray_manager = XrayManager()

# 工具函数
def generate_password(length=16):
    """生成随机密码"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

def format_bytes(bytes_value):
    """格式化字节数"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def get_system_info():
    """获取系统信息"""
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory': {
            'percent': psutil.virtual_memory().percent,
            'used': psutil.virtual_memory().used,
            'total': psutil.virtual_memory().total
        },
        'disk': {
            'percent': psutil.disk_usage('/').percent,
            'used': psutil.disk_usage('/').used,
            'total': psutil.disk_usage('/').total
        },
        'network': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
        'xray': check_xray_status()
    }

def check_xray_status():
    """检查 Xray 状态"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'xray'],
            capture_output=True,
            text=True
        )
        is_running = result.stdout.strip() == 'active'
        
        # 获取进程信息
        if is_running:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                if proc.info['name'] == 'xray':
                    return {
                        'running': True,
                        'pid': proc.info['pid'],
                        'memory': proc.info['memory_info'].rss,
                        'connections': len(proc.connections())
                    }
        
        return {'running': False}
    except:
        return {'running': False}

# 后台任务
def background_tasks():
    """后台任务处理"""
    while True:
        try:
            task = task_queue.get(timeout=1)
            if task['type'] == 'reload_config':
                xray_manager.reload_config()
            elif task['type'] == 'check_expired':
                check_expired_proxies()
            elif task['type'] == 'update_traffic':
                update_traffic_stats()
            task_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Background task error: {e}")

def check_expired_proxies():
    """检查过期代理"""
    with db_pool.get_connection() as conn:
        # 禁用过期代理
        conn.execute("""
            UPDATE proxies 
            SET enabled = 0 
            WHERE enabled = 1 
            AND expire_time IS NOT NULL 
            AND expire_time < datetime('now')
        """)
        
        if conn.total_changes > 0:
            task_queue.put({'type': 'reload_config'})

def update_traffic_stats():
    """更新流量统计"""
    # 从 Xray 日志或 API 获取流量信息
    stats = xray_manager.get_stats()
    
    with db_pool.get_connection() as conn:
        for stat in stats.get('stats', []):
            if 'user' in stat['name'] and 'traffic' in stat['name']:
                # 解析用户和流量信息
                parts = stat['name'].split('>>>')
                if len(parts) >= 2:
                    user = parts[0].replace('user>>>', '')
                    direction = 'uplink' if 'uplink' in parts[1] else 'downlink'
                    bytes_value = stat['value']
                    
                    # 更新数据库
                    conn.execute("""
                        UPDATE proxies 
                        SET traffic_used = traffic_used + ?,
                            last_used = datetime('now')
                        WHERE username = ?
                    """, (bytes_value, user))

# 定时任务
scheduler = BackgroundScheduler()
scheduler.add_job(check_expired_proxies, 'interval', minutes=5)
scheduler.add_job(update_traffic_stats, 'interval', minutes=1)
scheduler.start()

# 启动后台任务线程
task_thread = threading.Thread(target=background_tasks, daemon=True)
task_thread.start()

# 路由
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with db_pool.get_connection() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            
            if user and check_password_hash(user['password'], password):
                user_obj = User(user['id'], user['username'], user['email'], user['role'])
                login_user(user_obj, remember=True)
                return redirect(url_for('index'))
            
            flash('用户名或密码错误', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# API 路由
@app.route('/api/stats')
@login_required
def api_stats():
    """获取统计信息"""
    # 缓存统计信息
    if redis_client:
        cached = redis_client.get('system_stats')
        if cached:
            return json.loads(cached)
    
    stats = {
        'system': get_system_info(),
        'proxies': {
            'total': 0,
            'active': 0,
            'online': 0,
            'traffic_today': 0
        }
    }
    
    with db_pool.get_connection() as conn:
        # 代理统计
        stats['proxies']['total'] = conn.execute("SELECT COUNT(*) FROM proxies").fetchone()[0]
        stats['proxies']['active'] = conn.execute("SELECT COUNT(*) FROM proxies WHERE enabled = 1").fetchone()[0]
        
        # 今日流量
        today_traffic = conn.execute("""
            SELECT SUM(traffic_used) 
            FROM proxies 
            WHERE date(last_used) = date('now')
        """).fetchone()[0]
        stats['proxies']['traffic_today'] = today_traffic or 0
    
    # 缓存5秒
    if redis_client:
        redis_client.setex('system_stats', 5, json.dumps(stats))
    
    return jsonify(stats)

@app.route('/api/proxy/groups')
@login_required
def api_proxy_groups():
    """获取代理组列表"""
    with db_pool.get_connection() as conn:
        groups = conn.execute("""
            SELECT g.*, 
                COUNT(p.id) as proxy_count,
                COUNT(CASE WHEN p.enabled = 1 THEN 1 END) as active_count,
                SUM(p.traffic_used) as total_traffic
            FROM proxy_groups g
            LEFT JOIN proxies p ON g.id = p.group_id
            GROUP BY g.id
            ORDER BY g.created_at DESC
        """).fetchall()
    
    return jsonify([dict(g) for g in groups])

@app.route('/api/proxy/group/<int:group_id>')
@login_required
def api_proxy_group_detail(group_id):
    """获取代理组详情"""
    with db_pool.get_connection() as conn:
        proxies = conn.execute("""
            SELECT * FROM proxies 
            WHERE group_id = ?
            ORDER BY port
        """, (group_id,)).fetchall()
    
    return jsonify([dict(p) for p in proxies])

@app.route('/api/proxy/add', methods=['POST'])
@login_required
def api_proxy_add():
    """添加代理"""
    data = request.get_json()
    
    # 验证数据
    required_fields = ['bind_ip', 'port', 'protocol']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400
    
    # 生成账号密码
    if 'username' not in data:
        data['username'] = f"user_{random.randint(1000, 9999)}"
    if 'password' not in data:
        data['password'] = generate_password()
    
    try:
        with db_pool.get_connection() as conn:
            # 检查端口是否已使用
            existing = conn.execute(
                "SELECT id FROM proxies WHERE bind_ip = ? AND port = ?",
                (data['bind_ip'], data['port'])
            ).fetchone()
            
            if existing:
                return jsonify({'error': '端口已被使用'}), 400
            
            # 插入数据
            conn.execute("""
                INSERT INTO proxies (
                    bind_ip, port, protocol, username, password,
                    group_id, remark, traffic_limit, expire_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data['bind_ip'], data['port'], data['protocol'],
                data['username'], data['password'],
                data.get('group_id'), data.get('remark', ''),
                data.get('traffic_limit', 0), data.get('expire_time')
            ))
        
        # 重载配置
        task_queue.put({'type': 'reload_config'})
        
        return jsonify({'success': True, 'message': '代理添加成功'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/batch_add', methods=['POST'])
@login_required
def api_proxy_batch_add():
    """批量添加代理"""
    data = request.get_json()
    
    # 解析IP范围
    ip_range = data.get('ip_range', '')
    port_start = data.get('port_start', 10000)
    port_end = data.get('port_end', 10100)
    protocol = data.get('protocol', 'http')
    username_prefix = data.get('username_prefix', 'user')
    group_id = data.get('group_id')
    
    # 解析IP
    ips = []
    if '-' in ip_range:
        # 格式: 192.168.1.1-192.168.1.10
        start_ip, end_ip = ip_range.split('-')
        start_parts = start_ip.strip().split('.')
        end_parts = end_ip.strip().split('.')
        
        if len(start_parts) == 4 and len(end_parts) == 4:
            base = '.'.join(start_parts[:3])
            for i in range(int(start_parts[3]), int(end_parts[3]) + 1):
                ips.append(f"{base}.{i}")
    else:
        # 单个IP
        ips = [ip_range.strip()]
    
    # 生成端口列表
    ports = list(range(port_start, port_end + 1))
    
    # 检查数量是否匹配
    if len(ips) * len(ports) > 10000:
        return jsonify({'error': '批量添加数量不能超过10000'}), 400
    
    added_count = 0
    
    try:
        with db_pool.get_connection() as conn:
            # 获取已使用的端口
            used_ports = set()
            for ip in ips:
                existing = conn.execute(
                    "SELECT port FROM proxies WHERE bind_ip = ?",
                    (ip,)
                ).fetchall()
                used_ports.update(p[0] for p in existing)
            
            # 批量插入
            for ip in ips:
                for port in ports:
                    if port in used_ports:
                        continue
                    
                    username = f"{username_prefix}_{port}"
                    password = generate_password()
                    
                    conn.execute("""
                        INSERT INTO proxies (
                            bind_ip, port, protocol, username, password,
                            group_id, remark
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ip, port, protocol, username, password,
                        group_id, f"批量添加 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    ))
                    
                    added_count += 1
        
        # 重载配置
        if added_count > 0:
            task_queue.put({'type': 'reload_config'})
        
        return jsonify({
            'success': True,
            'message': f'成功添加 {added_count} 个代理',
            'count': added_count
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/update/<int:proxy_id>', methods=['POST'])
@login_required
def api_proxy_update(proxy_id):
    """更新代理"""
    data = request.get_json()
    
    try:
        with db_pool.get_connection() as conn:
            # 构建更新语句
            update_fields = []
            update_values = []
            
            for field in ['username', 'password', 'enabled', 'remark', 'traffic_limit', 'expire_time']:
                if field in data:
                    update_fields.append(f"{field} = ?")
                    update_values.append(data[field])
            
            if update_fields:
                update_values.append(proxy_id)
                conn.execute(
                    f"UPDATE proxies SET {', '.join(update_fields)} WHERE id = ?",
                    update_values
                )
        
        # 重载配置
        task_queue.put({'type': 'reload_config'})
        
        return jsonify({'success': True, 'message': '更新成功'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/delete/<int:proxy_id>', methods=['POST'])
@login_required
def api_proxy_delete(proxy_id):
    """删除代理"""
    try:
        with db_pool.get_connection() as conn:
            conn.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
        
        # 重载配置
        task_queue.put({'type': 'reload_config'})
        
        return jsonify({'success': True, 'message': '删除成功'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/batch_action', methods=['POST'])
@login_required
def api_proxy_batch_action():
    """批量操作"""
    data = request.get_json()
    action = data.get('action')
    ids = data.get('ids', [])
    
    if not ids:
        return jsonify({'error': '请选择代理'}), 400
    
    try:
        with db_pool.get_connection() as conn:
            if action == 'enable':
                conn.execute(f"UPDATE proxies SET enabled = 1 WHERE id IN ({','.join('?' * len(ids))})", ids)
            elif action == 'disable':
                conn.execute(f"UPDATE proxies SET enabled = 0 WHERE id IN ({','.join('?' * len(ids))})", ids)
            elif action == 'delete':
                conn.execute(f"DELETE FROM proxies WHERE id IN ({','.join('?' * len(ids))})", ids)
            else:
                return jsonify({'error': '无效的操作'}), 400
        
        # 重载配置
        task_queue.put({'type': 'reload_config'})
        
        return jsonify({'success': True, 'message': f'批量{action}成功'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/export', methods=['POST'])
@login_required
def api_proxy_export():
    """导出代理"""
    data = request.get_json()
    format_type = data.get('format', 'txt')
    ids = data.get('ids', [])
    
    with db_pool.get_connection() as conn:
        if ids:
            proxies = conn.execute(
                f"SELECT * FROM proxies WHERE id IN ({','.join('?' * len(ids))})",
                ids
            ).fetchall()
        else:
            proxies = conn.execute("SELECT * FROM proxies").fetchall()
    
    # 生成导出内容
    if format_type == 'txt':
        lines = []
        for p in proxies:
            if p['protocol'] == 'http':
                lines.append(f"http://{p['username']}:{p['password']}@{p['bind_ip']}:{p['port']}")
            elif p['protocol'] == 'socks':
                lines.append(f"socks5://{p['username']}:{p['password']}@{p['bind_ip']}:{p['port']}")
        
        content = '\n'.join(lines)
        mimetype = 'text/plain'
        filename = f"proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
    elif format_type == 'json':
        data = []
        for p in proxies:
            data.append({
                'protocol': p['protocol'],
                'host': p['bind_ip'],
                'port': p['port'],
                'username': p['username'],
                'password': p['password']
            })
        
        content = json.dumps(data, indent=2)
        mimetype = 'application/json'
        filename = f"proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    else:
        return jsonify({'error': '不支持的格式'}), 400
    
    return Response(
        content,
        mimetype=mimetype,
        headers={
            'Content-Disposition': f'attachment; filename={filename}'
        }
    )

@app.route('/api/config/reload', methods=['POST'])
@login_required
def api_config_reload():
    """重载配置"""
    success, message = xray_manager.reload_config()
    return jsonify({'success': success, 'message': message})

@app.route('/api/users')
@login_required
def api_users():
    """获取用户列表"""
    if current_user.role != 'admin':
        return jsonify({'error': '权限不足'}), 403
    
    with db_pool.get_connection() as conn:
        users = conn.execute("SELECT id, username, email, role, created_at FROM users").fetchall()
    
    return jsonify([dict(u) for u in users])

@app.route('/api/user/add', methods=['POST'])
@login_required
def api_user_add():
    """添加用户"""
    if current_user.role != 'admin':
        return jsonify({'error': '权限不足'}), 403
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email', '')
    role = data.get('role', 'user')
    
    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400
    
    try:
        with db_pool.get_connection() as conn:
            # 检查用户名是否存在
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            
            if existing:
                return jsonify({'error': '用户名已存在'}), 400
            
            # 插入用户
            conn.execute(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), email, role)
            )
        
        return jsonify({'success': True, 'message': '用户添加成功'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 错误处理
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    app.run(host='0.0.0.0', port=port, debug=False)
PYEOF

    # ========== init_db.py - 数据库初始化 ==========
    cat > $WORKDIR/init_db.py << 'PYEOF'
import sqlite3
import os
from werkzeug.security import generate_password_hash

# 数据库路径
DB_PATH = 'xray.db'

# 管理员账号
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin123')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@xray.local')

# 创建数据库连接
conn = sqlite3.connect(DB_PATH)
conn.execute('PRAGMA foreign_keys = ON')

# 创建表
conn.executescript('''
-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

-- 代理组表
CREATE TABLE IF NOT EXISTS proxy_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 代理表
CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bind_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'http',  -- http, socks
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    group_id INTEGER,
    remark TEXT,
    traffic_limit INTEGER DEFAULT 0,  -- 流量限制（字节）0=无限
    traffic_used INTEGER DEFAULT 0,   -- 已用流量（字节）
    expire_time DATETIME,             -- 过期时间
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME,
    FOREIGN KEY (group_id) REFERENCES proxy_groups(id) ON DELETE SET NULL,
    UNIQUE(bind_ip, port)
);

-- 流量日志表
CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id INTEGER NOT NULL,
    upload_bytes INTEGER DEFAULT 0,
    download_bytes INTEGER DEFAULT 0,
    connections INTEGER DEFAULT 0,
    log_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
);

-- API密钥表
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    name TEXT,
    user_id INTEGER NOT NULL,
    permissions TEXT,  -- JSON格式的权限列表
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 操作日志表
CREATE TABLE IF NOT EXISTS operation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_proxies_group ON proxies(group_id);
CREATE INDEX IF NOT EXISTS idx_proxies_enabled ON proxies(enabled);
CREATE INDEX IF NOT EXISTS idx_proxies_port ON proxies(port);
CREATE INDEX IF NOT EXISTS idx_proxies_expire ON proxies(expire_time);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_proxy ON traffic_logs(proxy_id);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_time ON traffic_logs(log_time);
CREATE INDEX IF NOT EXISTS idx_operation_logs_user ON operation_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_operation_logs_time ON operation_logs(created_at);
''')

# 插入默认管理员
try:
    conn.execute(
        "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
        (ADMIN_USER, generate_password_hash(ADMIN_PASS), ADMIN_EMAIL, 'admin')
    )
    print(f"管理员账号创建成功:")
    print(f"  用户名: {ADMIN_USER}")
    print(f"  密码: {ADMIN_PASS}")
except sqlite3.IntegrityError:
    print("管理员账号已存在")

# 插入默认代理组
try:
    conn.execute(
        "INSERT INTO proxy_groups (name, description) VALUES (?, ?)",
        ('默认组', '系统默认代理组')
    )
except:
    pass

conn.commit()
conn.close()

print("数据库初始化完成")
PYEOF

    # ========== templates/base.html - 基础模板 ==========
    cat > $WORKDIR/templates/base.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Xray 代理管理系统{% endblock %}</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <!-- DataTables CSS -->
    <link href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    
    <style>
        :root {
            --primary-color: #4a90e2;
            --secondary-color: #5cb85c;
            --danger-color: #d9534f;
            --warning-color: #f0ad4e;
            --info-color: #5bc0de;
            --dark-color: #2c3e50;
            --light-color: #ecf0f1;
        }
        
        body {
            background-color: #f5f7fa;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color), #357abd);
            box-shadow: 0 2px 4px rgba(0,0,0,.1);
        }
        
        .sidebar {
            background-color: white;
            box-shadow: 2px 0 4px rgba(0,0,0,.05);
            min-height: calc(100vh - 56px);
            padding-top: 1rem;
        }
        
        .sidebar .nav-link {
            color: var(--dark-color);
            padding: 0.75rem 1rem;
            margin: 0.25rem 0;
            border-radius: 0.375rem;
            transition: all 0.3s;
        }
        
        .sidebar .nav-link:hover {
            background-color: var(--light-color);
            color: var(--primary-color);
            transform: translateX(5px);
        }
        
        .sidebar .nav-link.active {
            background-color: var(--primary-color);
            color: white;
        }
        
        .card {
            border: none;
            border-radius: 0.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,.08);
            transition: all 0.3s;
        }
        
        .card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,.12);
            transform: translateY(-2px);
        }
        
        .stat-card {
            padding: 1.5rem;
            text-align: center;
            background: white;
            border-radius: 0.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,.08);
        }
        
        .stat-card .stat-icon {
            font-size: 3rem;
            margin-bottom: 0.5rem;
            opacity: 0.8;
        }
        
        .stat-card .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 0.25rem;
        }
        
        .stat-card .stat-label {
            color: #6c757d;
            font-size: 0.875rem;
        }
        
        .btn-gradient {
            background: linear-gradient(135deg, var(--primary-color), #357abd);
            color: white;
            border: none;
            transition: all 0.3s;
        }
        
        .btn-gradient:hover {
            background: linear-gradient(135deg, #357abd, var(--primary-color));
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,.2);
        }
        
        .table-hover tbody tr:hover {
            background-color: rgba(74, 144, 226, 0.05);
        }
        
        .badge-status {
            padding: 0.375rem 0.75rem;
            font-weight: normal;
        }
        
        .loading {
            display: inline-block;
            width: 1rem;
            height: 1rem;
            border: 2px solid #f3f3f3;
            border-top: 2px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .toast-container {
            position: fixed;
            top: 80px;
            right: 20px;
            z-index: 1050;
        }
        
        .progress-bar-animated {
            animation: progress-bar-stripes 1s linear infinite;
        }
        
        /* 响应式调整 */
        @media (max-width: 768px) {
            .sidebar {
                position: fixed;
                top: 56px;
                left: -250px;
                width: 250px;
                z-index: 1040;
                transition: left 0.3s;
            }
            
            .sidebar.show {
                left: 0;
            }
        }
    </style>
    
    {% block styles %}{% endblock %}
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-check"></i> Xray Manager
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle"></i> {{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="/profile"><i class="bi bi-person"></i> 个人资料</a></li>
                            <li><a class="dropdown-item" href="/settings"><i class="bi bi-gear"></i> 系统设置</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="/logout"><i class="bi bi-box-arrow-right"></i> 退出登录</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <div class="container-fluid">
        <div class="row">
            <!-- 侧边栏 -->
            <nav class="col-md-3 col-lg-2 d-md-block sidebar">
                <div class="position-sticky">
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link {% if request.endpoint == 'index' %}active{% endif %}" href="/">
                                <i class="bi bi-speedometer2"></i> 仪表盘
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link {% if 'proxy' in request.endpoint %}active{% endif %}" href="/proxies">
                                <i class="bi bi-hdd-network"></i> 代理管理
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link {% if 'group' in request.endpoint %}active{% endif %}" href="/groups">
                                <i class="bi bi-collection"></i> 代理组
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link {% if 'traffic' in request.endpoint %}active{% endif %}" href="/traffic">
                                <i class="bi bi-graph-up"></i> 流量统计
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link {% if 'log' in request.endpoint %}active{% endif %}" href="/logs">
                                <i class="bi bi-journal-text"></i> 操作日志
                            </a>
                        </li>
                        {% if current_user.role == 'admin' %}
                        <li class="nav-item">
                            <a class="nav-link {% if 'user' in request.endpoint %}active{% endif %}" href="/users">
                                <i class="bi bi-people"></i> 用户管理
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link {% if 'api' in request.endpoint %}active{% endif %}" href="/api-keys">
                                <i class="bi bi-key"></i> API密钥
                            </a>
                        </li>
                        {% endif %}
                    </ul>
                </div>
            </nav>
            
            <!-- 主内容区 -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4 py-3">
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
                
                {% block content %}{% endblock %}
            </main>
        </div>
    </div>
    
    <!-- Toast 容器 -->
    <div class="toast-container"></div>
    
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- DataTables JS -->
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    
    <script>
        // 全局函数
        function showToast(message, type = 'success') {
            const toast = $(`
                <div class="toast" role="alert">
                    <div class="toast-header">
                        <i class="bi bi-${type === 'success' ? 'check-circle' : 'exclamation-circle'} me-2"></i>
                        <strong class="me-auto">${type === 'success' ? '成功' : '错误'}</strong>
                        <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                    </div>
                    <div class="toast-body">${message}</div>
                </div>
            `);
            
            $('.toast-container').append(toast);
            const bsToast = new bootstrap.Toast(toast[0]);
            bsToast.show();
            
            toast.on('hidden.bs.toast', function () {
                $(this).remove();
            });
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('已复制到剪贴板');
            }).catch(err => {
                showToast('复制失败', 'error');
            });
        }
        
        // 初始化 DataTables 中文
        $.extend(true, $.fn.dataTable.defaults, {
            language: {
                url: 'https://cdn.datatables.net/plug-ins/1.13.6/i18n/zh.json'
            }
        });
    </script>
    
    {% block scripts %}{% endblock %}
</body>
</html>
HTMLEOF

    # ========== templates/login.html - 登录页面 ==========
    cat > $WORKDIR/templates/login.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - Xray 代理管理系统</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            padding: 2rem;
            border-radius: 1rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            width: 100%;
            max-width: 400px;
            animation: fadeIn 0.5s ease-out;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .login-header h1 {
            color: #333;
            font-size: 1.75rem;
            margin-bottom: 0.5rem;
        }
        
        .login-header p {
            color: #666;
            margin: 0;
        }
        
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 0.75rem;
            font-weight: 500;
            transition: all 0.3s;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
        
        .icon-box {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem;
            font-size: 2rem;
            color: white;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <div class="icon-box">
                <i class="bi bi-shield-lock"></i>
            </div>
            <h1>Xray Manager</h1>
            <p>企业级代理管理系统</p>
        </div>
        
        <form method="post" action="/login">
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
            
            <div class="mb-3">
                <label for="username" class="form-label">用户名</label>
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="bi bi-person"></i>
                    </span>
                    <input type="text" class="form-control" id="username" name="username" required autofocus>
                </div>
            </div>
            
            <div class="mb-4">
                <label for="password" class="form-label">密码</label>
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="bi bi-lock"></i>
                    </span>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
            </div>
            
            <button type="submit" class="btn btn-primary btn-login w-100">
                <i class="bi bi-box-arrow-in-right"></i> 登录
            </button>
        </form>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
HTMLEOF

    # ========== templates/index.html - 仪表盘页面 ==========
    cat > $WORKDIR/templates/index.html << 'HTMLEOF'
{% extends "base.html" %}

{% block title %}仪表盘 - Xray 代理管理系统{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2>系统仪表盘</h2>
    <button class="btn btn-gradient btn-sm" onclick="refreshStats()">
        <i class="bi bi-arrow-clockwise"></i> 刷新
    </button>
</div>

<!-- 统计卡片 -->
<div class="row mb-4">
    <div class="col-md-3 mb-3">
        <div class="stat-card text-primary">
            <div class="stat-icon">
                <i class="bi bi-hdd-network"></i>
            </div>
            <div class="stat-value" id="total-proxies">0</div>
            <div class="stat-label">代理总数</div>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card text-success">
            <div class="stat-icon">
                <i class="bi bi-check-circle"></i>
            </div>
            <div class="stat-value" id="active-proxies">0</div>
            <div class="stat-label">活跃代理</div>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card text-info">
            <div class="stat-icon">
                <i class="bi bi-arrow-up-down"></i>
            </div>
            <div class="stat-value" id="traffic-today">0</div>
            <div class="stat-label">今日流量</div>
        </div>
    </div>
    
    <div class="col-md-3 mb-3">
        <div class="stat-card text-warning">
            <div class="stat-icon">
                <i class="bi bi-plug"></i>
            </div>
            <div class="stat-value" id="online-connections">0</div>
            <div class="stat-label">在线连接</div>
        </div>
    </div>
</div>

<!-- 系统状态 -->
<div class="row mb-4">
    <div class="col-md-6 mb-3">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">系统资源</h5>
            </div>
            <div class="card-body">
                <div class="mb-3">
                    <div class="d-flex justify-content-between mb-1">
                        <span>CPU 使用率</span>
                        <span id="cpu-percent">0%</span>
                    </div>
                    <div class="progress" style="height: 20px;">
                        <div class="progress-bar bg-primary progress-bar-animated" id="cpu-progress" style="width: 0%"></div>
                    </div>
                </div>
                
                <div class="mb-3">
                    <div class="d-flex justify-content-between mb-1">
                        <span>内存使用率</span>
                        <span id="memory-percent">0%</span>
                    </div>
                    <div class="progress" style="height: 20px;">
                        <div class="progress-bar bg-success progress-bar-animated" id="memory-progress" style="width: 0%"></div>
                    </div>
                </div>
                
                <div>
                    <div class="d-flex justify-content-between mb-1">
                        <span>磁盘使用率</span>
                        <span id="disk-percent">0%</span>
                    </div>
                    <div class="progress" style="height: 20px;">
                        <div class="progress-bar bg-warning progress-bar-animated" id="disk-progress" style="width: 0%"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-6 mb-3">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Xray 状态</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-6 mb-3">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-circle-fill me-2" id="xray-status-icon" style="color: #dc3545;"></i>
                            <span>运行状态: <strong id="xray-status">未运行</strong></span>
                        </div>
                    </div>
                    <div class="col-6 mb-3">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-cpu me-2"></i>
                            <span>进程 PID: <strong id="xray-pid">-</strong></span>
                        </div>
                    </div>
                    <div class="col-6 mb-3">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-memory me-2"></i>
                            <span>内存占用: <strong id="xray-memory">-</strong></span>
                        </div>
                    </div>
                    <div class="col-6 mb-3">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-diagram-3 me-2"></i>
                            <span>连接数: <strong id="xray-connections">-</strong></span>
                        </div>
                    </div>
                </div>
                
                <div class="mt-3">
                    <button class="btn btn-primary btn-sm me-2" onclick="reloadXray()">
                        <i class="bi bi-arrow-clockwise"></i> 重载配置
                    </button>
                    <button class="btn btn-success btn-sm me-2" onclick="startXray()">
                        <i class="bi bi-play-circle"></i> 启动
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="stopXray()">
                        <i class="bi bi-stop-circle"></i> 停止
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- 流量图表 -->
<div class="row">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">流量趋势（最近24小时）</h5>
            </div>
            <div class="card-body">
                <canvas id="trafficChart" height="100"></canvas>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    let trafficChart = null;
    
    // 刷新统计数据
    function refreshStats() {
        $.get('/api/stats', function(data) {
            // 更新代理统计
            $('#total-proxies').text(data.proxies.total);
            $('#active-proxies').text(data.proxies.active);
            $('#traffic-today').text(formatBytes(data.proxies.traffic_today));
            $('#online-connections').text(data.proxies.online || 0);
            
            // 更新系统资源
            const cpu = data.system.cpu_percent;
            const memory = data.system.memory.percent;
            const disk = data.system.disk.percent;
            
            $('#cpu-percent').text(cpu.toFixed(1) + '%');
            $('#cpu-progress').css('width', cpu + '%');
            
            $('#memory-percent').text(memory.toFixed(1) + '%');
            $('#memory-progress').css('width', memory + '%');
            
            $('#disk-percent').text(disk.toFixed(1) + '%');
            $('#disk-progress').css('width', disk + '%');
            
            // 更新 Xray 状态
            if (data.system.xray.running) {
                $('#xray-status').text('运行中');
                $('#xray-status-icon').css('color', '#28a745');
                $('#xray-pid').text(data.system.xray.pid || '-');
                $('#xray-memory').text(formatBytes(data.system.xray.memory || 0));
                $('#xray-connections').text(data.system.xray.connections || 0);
            } else {
                $('#xray-status').text('未运行');
                $('#xray-status-icon').css('color', '#dc3545');
                $('#xray-pid').text('-');
                $('#xray-memory').text('-');
                $('#xray-connections').text('-');
            }
        });
    }
    
    // 重载 Xray 配置
    function reloadXray() {
        $.post('/api/config/reload', function(data) {
            if (data.success) {
                showToast(data.message);
                setTimeout(refreshStats, 1000);
            } else {
                showToast(data.message, 'error');
            }
        });
    }
    
    // 启动 Xray
    function startXray() {
        $.post('/api/xray/start', function(data) {
            showToast(data.message);
            setTimeout(refreshStats, 1000);
        });
    }
    
    // 停止 Xray
    function stopXray() {
        if (confirm('确定要停止 Xray 服务吗？这将中断所有代理连接。')) {
            $.post('/api/xray/stop', function(data) {
                showToast(data.message);
                setTimeout(refreshStats, 1000);
            });
        }
    }
    
    // 初始化流量图表
    function initTrafficChart() {
        const ctx = document.getElementById('trafficChart').getContext('2d');
        trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: '上传流量',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.1)',
                    tension: 0.4
                }, {
                    label: '下载流量',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return formatBytes(value);
                            }
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': ' + formatBytes(context.parsed.y);
                            }
                        }
                    }
                }
            }
        });
    }
    
    // 页面加载完成后执行
    $(document).ready(function() {
        initTrafficChart();
        refreshStats();
        
        // 每5秒刷新一次
        setInterval(refreshStats, 5000);
    });
</script>
{% endblock %}
HTMLEOF

    # ========== 创建 systemd 服务 ==========
    cat > /etc/systemd/system/xray.service << 'EOF'
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000
LimitNPROC=1000000

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/xray-manager.service << 'EOF'
[Unit]
Description=Xray Manager Web Service
After=network.target redis.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/xray-manager
Environment="PATH=/opt/xray-manager/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/xray-manager/venv/bin/gunicorn --workers 4 --threads 2 --bind 0.0.0.0:8080 app:app
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # 创建日志轮转配置
    cat > /etc/logrotate.d/xray << 'EOF'
/var/log/xray/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload xray > /dev/null 2>&1 || true
    endscript
}
EOF

    print_success "Web应用创建完成"
}

function initialize_system() {
    print_info "初始化系统..."
    
    cd $WORKDIR
    
    # 设置环境变量
    export ADMIN_USER="${ADMIN_USER:-admin}"
    export ADMIN_PASS="${ADMIN_PASS:-$(openssl rand -base64 12)}"
    
    # 初始化数据库
    source venv/bin/activate
    python init_db.py
    deactivate
    
    # 创建初始配置
    cat > $XRAY_CONFIG_PATH << 'EOF'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    
    # 保存凭据
    cat > $CREDS_FILE << EOF
========================================
Xray 代理管理系统安装成功！
========================================
访问地址: http://$(get_local_ip):8080
管理员账号: $ADMIN_USER
管理员密码: $ADMIN_PASS
安装时间: $(date)
========================================
EOF
    
    chmod 600 $CREDS_FILE
    
    # 重载 systemd
    systemctl daemon-reload
    
    # 启动服务
    systemctl enable xray
    systemctl enable xray-manager
    systemctl start xray
    systemctl start xray-manager
    
    print_success "系统初始化完成"
}

function setup_nginx() {
    print_info "配置 Nginx（可选）..."
    
    read -p "是否配置 Nginx 反向代理？[y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi
    
    read -p "请输入域名（例如: proxy.example.com）: " DOMAIN
    
    cat > /etc/nginx/sites-available/xray-manager << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/xray-manager /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx
    
    print_success "Nginx 配置完成"
    
    read -p "是否配置 SSL 证书？[y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        certbot --nginx -d $DOMAIN
    fi
}

function uninstall_system() {
    print_warning "开始卸载 Xray 管理系统..."
    
    # 停止服务
    systemctl stop xray-manager 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true
    
    # 禁用服务
    systemctl disable xray-manager 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    
    # 删除服务文件
    rm -f /etc/systemd/system/xray.service
    rm -f /etc/systemd/system/xray-manager.service
    
    # 删除文件
    rm -rf $WORKDIR
    rm -rf /usr/local/etc/xray
    rm -rf $XRAY_LOG_PATH
    rm -f $XRAY_PATH
    rm -f /usr/local/share/xray/*.dat
    
    # 删除日志轮转配置
    rm -f /etc/logrotate.d/xray
    
    # 删除 Nginx 配置
    rm -f /etc/nginx/sites-available/xray-manager
    rm -f /etc/nginx/sites-enabled/xray-manager
    
    systemctl daemon-reload
    
    print_success "卸载完成"
}

# 主函数
function main() {
    case "$1" in
        "uninstall")
            uninstall_system
            exit 0
            ;;
        "show")
            show_credentials
            exit 0
            ;;
        "update")
            print_info "更新功能开发中..."
            exit 0
            ;;
    esac
    
    print_info "开始安装 Xray 代理管理系统..."
    
    # 检查系统
    check_system
    
    # 优化系统
    optimize_system
    
    # 安装依赖
    install_dependencies
    
    # 安装 Xray
    install_xray
    
    # 创建目录
    setup_directories
    
    # 配置 Python 环境
    setup_python_env
    
    # 创建 Web 应用
    create_webapp
    
    # 初始化系统
    initialize_system
    
    # 配置 Nginx（可选）
    setup_nginx
    
    # 显示安装信息
    echo
    cat $CREDS_FILE
    echo
    print_success "安装完成！"
    print_info "使用以下命令管理系统："
    print_info "  查看登录信息: $0 show"
    print_info "  卸载系统: $0 uninstall"
    print_info "  更新系统: $0 update"
}

# 执行主函数
main "$@"
