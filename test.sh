#!/bin/bash
set -e

WORKDIR=/opt/xray-web
XRAY_PATH=/usr/local/bin/xray
XRAY_CONFIG=/usr/local/etc/xray/config.json
XRAY_LOG_DIR=/var/log/xray
CREDS_FILE=/opt/xray-web/.credentials

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

function show_credentials() {
    if [ -f "$CREDS_FILE" ]; then
        echo -e "\n========= Xray Web管理系统登录信息 ========="
        cat "$CREDS_FILE"
        echo -e "============================================\n"
    else
        echo -e "\033[31m未找到登录凭据文件。请运行安装脚本。\033[0m"
    fi
}

function optimize_system() {
    echo -e "\n========= 系统性能优化 =========\n"
    
    if grep -q "# Xray 性能优化" /etc/sysctl.conf 2>/dev/null; then
        echo -e "\033[33m系统已经优化过，跳过...\033[0m"
        return
    fi
    
    cat >> /etc/sysctl.conf <<EOF

# Xray 性能优化 - 支持百万级并发
# 基础网络优化
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1

# TCP 连接优化
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 65536
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3

# 端口范围
net.ipv4.ip_local_port_range = 1024 65535

# 连接跟踪优化
net.netfilter.nf_conntrack_max = 3000000
net.netfilter.nf_conntrack_tcp_timeout_established = 1200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 60

# 套接字优化
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.core.optmem_max = 25165824
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP 拥塞控制
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# 文件句柄
fs.file-max = 6000000
fs.nr_open = 6000000

# 内存优化
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.overcommit_memory = 1
EOF
    
    sysctl -p >/dev/null 2>&1
    modprobe nf_conntrack >/dev/null 2>&1
    
    if ! grep -q "# Xray limits" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf <<EOF

# Xray limits
* soft nofile 3000000
* hard nofile 3000000
* soft nproc 3000000
* hard nproc 3000000
root soft nofile 3000000
root hard nofile 3000000
root soft nproc 3000000
root hard nproc 3000000
EOF
    fi
    
    if [ -f /etc/systemd/system.conf ]; then
        sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=3000000/' /etc/systemd/system.conf
        sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=3000000/' /etc/systemd/system.conf
    fi
    
    echo -e "\033[32m系统优化完成！支持百万级代理并发\033[0m"
}

function setup_backup() {
    echo -e "\n========= 设置自动备份 =========\n"
    
    mkdir -p $WORKDIR/backups
    
    cat > $WORKDIR/backup.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/opt/xray-web/backups"
DB_FILE="/opt/xray-web/xray.db"
CONFIG_FILE="/usr/local/etc/xray/config.json"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

if [ ! -f "$DB_FILE" ] || [ ! -f "$CONFIG_FILE" ]; then
    echo "Warning: Some files not found for backup"
    exit 0
fi

cd "$BACKUP_DIR"
find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +7 -delete 2>/dev/null || true
tar -czf "backup_$DATE.tar.gz" "$DB_FILE" "$CONFIG_FILE" 2>/dev/null || true
echo "Backup completed: backup_$DATE.tar.gz"
EOF
    
    chmod +x $WORKDIR/backup.sh
    echo "0 2 * * * root $WORKDIR/backup.sh > /dev/null 2>&1" > /etc/cron.d/xray-backup
    echo -e "\033[32m自动备份已设置（每天凌晨2点）\033[0m"
}

function install_xray() {
    echo -e "\n========= 安装 Xray =========\n"
    
    if [ -f "$XRAY_PATH" ]; then
        echo "Xray 已安装，跳过..."
        return
    fi
    
    # 下载最新版 Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # 创建必要目录
    mkdir -p /usr/local/etc/xray
    mkdir -p $XRAY_LOG_DIR
    
    # 移动二进制文件到标准位置
    if [ -f "/usr/local/bin/xray" ]; then
        XRAY_PATH="/usr/local/bin/xray"
    elif [ -f "/usr/bin/xray" ]; then
        cp /usr/bin/xray /usr/local/bin/xray
        XRAY_PATH="/usr/local/bin/xray"
    fi
    
    chmod +x $XRAY_PATH
}

function uninstall_xray_web() {
    systemctl stop xray-web 2>/dev/null || true
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray-web 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    rm -rf $WORKDIR
    rm -f /etc/systemd/system/xray-web.service
    rm -f /usr/local/bin/xray
    rm -rf /usr/local/etc/xray
    rm -f /etc/cron.d/xray-backup
    systemctl daemon-reload
    echo -e "\033[31mXray Web管理及全部相关内容已卸载。\033[0m"
}

# 处理命令行参数
case "$1" in
    "uninstall")
        uninstall_xray_web
        exit 0
        ;;
    "reinstall")
        uninstall_xray_web
        echo -e "\033[32m正在重新安装...\033[0m"
        ;;
    "show")
        show_credentials
        exit 0
        ;;
esac

PORT=$((RANDOM%55534+10000))
ADMINUSER="admin$RANDOM"
ADMINPASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
API_PORT=$((PORT + 1))

echo -e "\n========= 1. 自动安装依赖 =========\n"

# 检测系统版本
if [ -f /etc/debian_version ]; then
    DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1)
    echo "检测到 Debian $DEBIAN_VERSION"
fi

apt update
apt install -y gcc make git wget curl python3 python3-pip python3-venv sqlite3 cron redis-server

# 启动Redis
systemctl enable redis-server
systemctl start redis-server

# 安装 Xray
install_xray

# 执行系统优化
optimize_system

echo -e "\n========= 2. 部署 Python Web 管理环境 =========\n"
mkdir -p $WORKDIR/templates $WORKDIR/static $WORKDIR/backups
cd $WORKDIR

# 设置自动备份
setup_backup

python3 -m venv venv
source venv/bin/activate

# 兼容Debian 11和12的pip安装
if [ "$DEBIAN_VERSION" == "11" ]; then
    pip install flask flask_login flask_wtf wtforms Werkzeug psutil redis celery gevent gunicorn requests grpcio grpcio-tools
else
    pip install flask flask_login flask_wtf wtforms Werkzeug psutil redis celery gevent gunicorn requests grpcio grpcio-tools --break-system-packages
fi

# ------------------- xray_manage.py (主后端) -------------------
cat > $WORKDIR/xray_manage.py << 'EOF'
import os, sqlite3, random, string, re, collections, json, psutil, datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import threading
import queue
import time
import subprocess
from contextlib import contextmanager
import redis
import pickle
import requests

DB = 'xray.db'
SECRET = 'changeme_xray_secret_key'
import sys
PORT = int(sys.argv[1]) if len(sys.argv)>1 else 9999
API_PORT = int(sys.argv[2]) if len(sys.argv)>2 else 10085
XRAY_PATH = '/usr/local/bin/xray'
XRAY_CONFIG = '/usr/local/etc/xray/config.json'

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = SECRET
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 数据库连接池
class DatabasePool:
    def __init__(self, db_path, pool_size=20):
        self.db_path = db_path
        self.pool = queue.Queue(maxsize=pool_size)
        for _ in range(pool_size):
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            self.pool.put(conn)
    
    @contextmanager
    def get_connection(self):
        conn = self.pool.get()
        try:
            yield conn
        finally:
            self.pool.put(conn)

# 初始化数据库池
db_pool = DatabasePool(DB)

# Redis连接
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=False)

# 任务队列
task_queue = queue.Queue(maxsize=1000)

def detect_nic():
    for nic in os.listdir('/sys/class/net'):
        if nic.startswith('e') or nic.startswith('en') or nic.startswith('eth'):
            return nic
    return 'eth0'

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password_hash = password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    with db_pool.get_connection() as conn:
        cur = conn.execute("SELECT id,username,password FROM users WHERE id=?", (user_id,))
        row = cur.fetchone()
        if row:
            return User(row[0], row[1], row[2])
    return None

class XrayConfigManager:
    def __init__(self):
        self.api_port = API_PORT
        
    def generate_config(self, proxies):
        """生成Xray配置"""
        config = {
            "log": {
                "loglevel": "warning",
                "access": "/var/log/xray/access.log",
                "error": "/var/log/xray/error.log"
            },
            "api": {
                "tag": "api",
                "services": ["HandlerService", "StatsService"]
            },
            "stats": {},
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": True,
                        "statsUserDownlink": True,
                        "handshake": 4,
                        "connIdle": 300,
                        "uplinkOnly": 2,
                        "downlinkOnly": 5,
                        "bufferSize": 512
                    }
                },
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True
                }
            },
            "inbounds": [],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "tag": "direct",
                    "settings": {
                        "domainStrategy": "UseIP"
                    }
                },
                {
                    "protocol": "blackhole",
                    "tag": "blocked"
                }
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api"
                    }
                ]
            },
            "transport": {
                "sockopt": {
                    "tcpFastOpen": True,
                    "tcpNoDelay": True,
                    "tcpKeepAliveInterval": 30
                }
            }
        }
        
        # 按IP和端口分组
        grouped = collections.defaultdict(list)
        for proxy in proxies:
            key = (proxy['ip'], proxy['port'])
            grouped[key].append({
                'user': proxy['username'],
                'pass': proxy['password']
            })
        
        # 生成入站配置
        for (ip, port), users in grouped.items():
            inbound = {
                "tag": f"http-{ip.replace('.', '_')}-{port}",
                "protocol": "http",
                "listen": ip,
                "port": port,
                "settings": {
                    "accounts": users,
                    "allowTransparent": False,
                    "userLevel": 0,
                    "timeout": 300
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                },
                "streamSettings": {
                    "sockopt": {
                        "acceptProxyProtocol": False
                    }
                }
            }
            config['inbounds'].append(inbound)
        
        # API入站
        config['inbounds'].append({
            "tag": "api",
            "protocol": "dokodemo-door",
            "listen": "127.0.0.1",
            "port": self.api_port,
            "settings": {
                "address": "127.0.0.1"
            }
        })
        
        return config

class XrayAPIClient:
    def __init__(self, api_addr=f"127.0.0.1:{API_PORT}"):
        self.api_url = f"http://{api_addr}"
        
    def get_stats(self, pattern="", reset=False):
        """获取统计信息"""
        try:
            # 使用 Xray 的 API
            cmd = [XRAY_PATH, "api", "statsquery", f"--server={self.api_url}"]
            if pattern:
                cmd.extend(["--pattern", pattern])
            if reset:
                cmd.append("--reset")
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return json.loads(result.stdout)
            return None
        except Exception as e:
            print(f"API error: {e}")
            return None

xray_config_manager = XrayConfigManager()
xray_api_client = XrayAPIClient()

def reload_xray_async():
    """异步重载Xray配置"""
    task_queue.put(('reload', None))

def generate_xray_config():
    """生成Xray配置文件"""
    with db_pool.get_connection() as conn:
        cursor = conn.execute('''
            SELECT ip, port, username, password 
            FROM proxy 
            WHERE enabled=1 
            ORDER BY ip, port
        ''')
        
        proxies = []
        for ip, port, username, password in cursor:
            proxies.append({
                'ip': ip,
                'port': port,
                'username': username,
                'password': password
            })
    
    config = xray_config_manager.generate_config(proxies)
    
    # 确保目录存在
    os.makedirs(os.path.dirname(XRAY_CONFIG), exist_ok=True)
    
    # 写入配置文件
    with open(XRAY_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)
    
    return len(proxies)

# 后台任务处理线程
def task_worker():
    """后台任务处理器"""
    while True:
        try:
            task_type, data = task_queue.get(timeout=1)
            if task_type == 'reload':
                count = generate_xray_config()
                # 使用后台进程重载Xray，避免阻塞
                subprocess.Popen(['systemctl', 'reload', 'xray'], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL)
                print(f"Reloaded Xray with {count} proxies")
            task_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Task worker error: {e}")

# 启动后台任务线程
worker_thread = threading.Thread(target=task_worker, daemon=True)
worker_thread.start()

# 定期流量统计线程
def traffic_stats_worker():
    """定期更新流量统计"""
    while True:
        try:
            # 获取所有用户的流量统计
            stats = xray_api_client.get_stats(pattern="user>>>", reset=False)
            if stats:
                # 更新到数据库
                with db_pool.get_connection() as conn:
                    for stat in stats.get('stat', []):
                        # 解析统计名称: user>>>username>>>traffic>>>uplink/downlink
                        parts = stat['name'].split('>>>')
                        if len(parts) >= 4:
                            username = parts[1]
                            direction = parts[3]
                            value = stat['value']
                            
                            if direction == 'uplink':
                                conn.execute('''
                                    UPDATE proxy 
                                    SET traffic_up = ?, last_used = datetime('now')
                                    WHERE username = ?
                                ''', (value, username))
                            elif direction == 'downlink':
                                conn.execute('''
                                    UPDATE proxy 
                                    SET traffic_down = ?, last_used = datetime('now')
                                    WHERE username = ?
                                ''', (value, username))
                    conn.commit()
        except Exception as e:
            print(f"Traffic stats error: {e}")
        
        time.sleep(60)  # 60秒更新一次

# 启动流量统计线程
traffic_thread = threading.Thread(target=traffic_stats_worker, daemon=True)
traffic_thread.start()

# 注释掉过期检查线程（按要求取消）
# def expire_check_worker():
#     """检查并禁用过期代理"""
#     while True:
#         try:
#             with db_pool.get_connection() as conn:
#                 # 禁用过期代理
#                 result = conn.execute('''
#                     UPDATE proxy 
#                     SET enabled = 0 
#                     WHERE enabled = 1 
#                     AND expire_at IS NOT NULL 
#                     AND expire_at < datetime('now')
#                 ''')
#                 
#                 if result.rowcount > 0:
#                     conn.commit()
#                     reload_xray_async()
#                     print(f"Disabled {result.rowcount} expired proxies")
#                 
#                 # 禁用超流量代理
#                 result = conn.execute('''
#                     UPDATE proxy 
#                     SET enabled = 0 
#                     WHERE enabled = 1
#                     AND traffic_limit > 0 
#                     AND (traffic_up + traffic_down) >= traffic_limit
#                 ''')
#                 
#                 if result.rowcount > 0:
#                     conn.commit()
#                     reload_xray_async()
#                     print(f"Disabled {result.rowcount} over-traffic proxies")
#                     
#         except Exception as e:
#             print(f"Expire check error: {e}")
#         
#         time.sleep(300)  # 5分钟检查一次
# 
# # 启动过期检查线程
# expire_thread = threading.Thread(target=expire_check_worker, daemon=True)
# expire_thread.start()

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        with db_pool.get_connection() as conn:
            cur = conn.execute('SELECT id,username,password FROM users WHERE username=?', (request.form['username'],))
            row = cur.fetchone()
            if row and check_password_hash(row[2], request.form['password']):
                user = User(row[0], row[1], row[2])
                login_user(user)
                return redirect('/')
        flash('登录失败')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html')

@app.route('/api/proxy_groups')
@login_required
def api_proxy_groups():
    # 尝试从缓存获取
    cached = redis_client.get('proxy_groups')
    if cached:
        return jsonify(pickle.loads(cached))
    
    with db_pool.get_connection() as conn:
        proxies = conn.execute('''
            SELECT id, ip, port, username, password, enabled, ip_range, port_range, 
                   user_prefix, created_at, expire_at, traffic_up, traffic_down, 
                   traffic_limit, last_used, notes
            FROM proxy 
            ORDER BY ip
        ''').fetchall()
    
    groups = collections.defaultdict(list)
    for p in proxies:
        c_seg = '.'.join(p[1].split('.')[:3])
        groups[c_seg].append({
            'id': p[0],
            'ip': p[1],
            'port': p[2],
            'username': p[3],
            'password': p[4],
            'enabled': p[5],
            'ip_range': p[6],
            'port_range': p[7],
            'user_prefix': p[8],
            'created_at': p[9],
            'expire_at': p[10],
            'traffic_up': p[11] or 0,
            'traffic_down': p[12] or 0,
            'traffic_limit': p[13] or 0,
            'last_used': p[14],
            'notes': p[15]
        })
    
    result = []
    for c_seg, proxies_list in groups.items():
        enabled_count = sum(1 for p in proxies_list if p['enabled'])
        total_traffic = sum(p['traffic_up'] + p['traffic_down'] for p in proxies_list)
        
        # 计算IP和端口范围
        ips = [p['ip'] for p in proxies_list]
        ports = sorted([p['port'] for p in proxies_list])
        
        if ips:
            ip_nums = sorted([int(ip.split('.')[-1]) for ip in ips])
            if len(ip_nums) > 1 and ip_nums[-1] - ip_nums[0] == len(ip_nums) - 1:
                actual_ip_range = f"{c_seg}.{ip_nums[0]}-{ip_nums[-1]}"
            else:
                actual_ip_range = f"{c_seg}.x ({len(ip_nums)} IPs)"
        else:
            actual_ip_range = proxies_list[0]['ip_range'] if proxies_list else ''
        
        if ports:
            if len(ports) == 1:
                actual_port_range = str(ports[0])
            else:
                actual_port_range = f"{ports[0]}-{ports[-1]}"
        else:
            actual_port_range = proxies_list[0]['port_range'] if proxies_list else ''
        
        # 检查即将过期的代理（7天内）
        expiring_soon = sum(1 for p in proxies_list 
                          if p['expire_at'] and 
                          p['expire_at'] > datetime.datetime.now().isoformat() and
                          p['expire_at'] < (datetime.datetime.now() + datetime.timedelta(days=7)).isoformat())
        
        # 获取最早创建时间
        created_dates = [p['created_at'] for p in proxies_list if p['created_at']]
        earliest_created = min(created_dates) if created_dates else None
        
        result.append({
            'c_segment': c_seg,
            'total': len(proxies_list),
            'enabled': enabled_count,
            'traffic': round(total_traffic / 1024 / 1024, 2),  # MB
            'ip_range': actual_ip_range,
            'port_range': actual_port_range,
            'user_prefix': proxies_list[0]['user_prefix'] if proxies_list else '',
            'created_at': earliest_created,
            'expiring_soon': expiring_soon
        })
    
    sorted_result = sorted(result, key=lambda x: x['c_segment'])
    # 缓存5秒
    redis_client.setex('proxy_groups', 5, pickle.dumps(sorted_result))
    
    return jsonify(sorted_result)

@app.route('/api/proxy_group/<c_segment>')
@login_required
def api_proxy_group_detail(c_segment):
    with db_pool.get_connection() as conn:
        proxies = conn.execute('''
            SELECT id, ip, port, username, password, enabled, ip_range, port_range, 
                   user_prefix, created_at, expire_at, traffic_up, traffic_down, 
                   traffic_limit, last_used, notes
            FROM proxy 
            WHERE ip LIKE ? 
            ORDER BY ip, port
        ''', (c_segment + '.%',)).fetchall()
    
    result = []
    for p in proxies:
        result.append({
            'id': p[0],
            'ip': p[1],
            'port': p[2],
            'username': p[3],
            'password': p[4],
            'enabled': p[5],
            'ip_range': p[6],
            'port_range': p[7],
            'user_prefix': p[8],
            'created_at': p[9],
            'expire_at': p[10],
            'traffic_up': p[11] or 0,
            'traffic_down': p[12] or 0,
            'traffic_limit': p[13] or 0,
            'traffic_total': (p[11] or 0) + (p[12] or 0),
            'last_used': p[14],
            'notes': p[15]
        })
    
    return jsonify(result)

@app.route('/api/delete_group/<c_segment>', methods=['POST'])
@login_required
def api_delete_group(c_segment):
    with db_pool.get_connection() as conn:
        conn.execute('DELETE FROM proxy WHERE ip LIKE ?', (c_segment + '.%',))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_xray_async()
    return jsonify({'status': 'success'})

@app.route('/api/toggle_group/<c_segment>/<action>', methods=['POST'])
@login_required
def api_toggle_group(c_segment, action):
    enabled = 1 if action == 'enable' else 0
    with db_pool.get_connection() as conn:
        conn.execute('UPDATE proxy SET enabled=? WHERE ip LIKE ?', (enabled, c_segment + '.%'))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_xray_async()
    return jsonify({'status': 'success'})

@app.route('/api/set_expire_group/<c_segment>', methods=['POST'])
@login_required
def api_set_expire_group(c_segment):
    expire_date = request.form.get('expire_date')
    with db_pool.get_connection() as conn:
        conn.execute('UPDATE proxy SET expire_at=? WHERE ip LIKE ?', (expire_date, c_segment + '.%'))
        conn.commit()
    redis_client.delete('proxy_groups')
    return jsonify({'status': 'success'})

@app.route('/api/system_status')
@login_required
def api_system_status():
    # 尝试从缓存获取
    cached = redis_client.get('system_status')
    if cached:
        return jsonify(pickle.loads(cached))
    
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # 获取网络流量
    net_io = psutil.net_io_counters()
    
    # 获取Xray进程信息
    xray_info = {'running': False, 'pid': None, 'memory': 0, 'connections': 0}
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'xray':
            xray_info['running'] = True
            xray_info['pid'] = proc.info['pid']
            try:
                p = psutil.Process(proc.info['pid'])
                xray_info['memory'] = p.memory_info().rss / 1024 / 1024  # MB
                xray_info['connections'] = len(p.connections())
            except:
                pass
            break
    
    result = {
        'cpu': cpu_percent,
        'memory': {
            'percent': memory.percent,
            'used': memory.used / 1024 / 1024 / 1024,  # GB
            'total': memory.total / 1024 / 1024 / 1024  # GB
        },
        'disk': {
            'percent': disk.percent,
            'used': disk.used / 1024 / 1024 / 1024,  # GB
            'total': disk.total / 1024 / 1024 / 1024  # GB
        },
        'network': {
            'bytes_sent': net_io.bytes_sent / 1024 / 1024,  # MB
            'bytes_recv': net_io.bytes_recv / 1024 / 1024   # MB
        },
        'xray': xray_info,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # 缓存2秒
    redis_client.setex('system_status', 2, pickle.dumps(result))
    
    return jsonify(result)

@app.route('/api/users')
@login_required
def api_users():
    with db_pool.get_connection() as conn:
        users = conn.execute('SELECT id,username FROM users').fetchall()
    return jsonify([{'id': u[0], 'username': u[1]} for u in users])

@app.route('/api/ip_configs')
@login_required
def api_ip_configs():
    with db_pool.get_connection() as conn:
        configs = conn.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC').fetchall()
    return jsonify([{
        'id': c[0],
        'ip_str': c[1],
        'type': c[2],
        'iface': c[3],
        'created': c[4]
    } for c in configs])

@app.route('/batchaddproxy', methods=['POST'])
@login_required
def batchaddproxy():
    iprange = request.form.get('iprange')
    portrange = request.form.get('portrange')
    userprefix = request.form.get('userprefix')
    expire_days = request.form.get('expire_days', type=int)
    traffic_limit_gb = request.form.get('traffic_limit', type=float)
    notes = request.form.get('notes', '')
    
    if iprange and userprefix:
        # 解析IP范围
        m = re.match(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", iprange.strip())
        if not m:
            return jsonify({'status': 'error', 'message': 'IP范围格式错误'})
        ip_base = m.group(1)
        start = int(m.group(2))
        end = int(m.group(3))
        ips = [f"{ip_base}{i}" for i in range(start, end+1)]
        
        # 如果IP数量太多，给出警告
        if len(ips) > 1000:
            return jsonify({'status': 'error', 'message': f'一次最多添加1000个代理，当前尝试添加{len(ips)}个'})
        
        with db_pool.get_connection() as conn:
            # 获取已使用的端口
            used_ports = set()
            cursor = conn.execute('SELECT port FROM proxy')
            for row in cursor:
                used_ports.add(row[0])
            
            # 解析或生成端口范围
            if portrange and portrange.strip():
                m2 = re.match(r"(\d+)-(\d+)", portrange.strip())
                if not m2:
                    return jsonify({'status': 'error', 'message': '端口范围格式错误'})
                port_start = int(m2.group(1))
                port_end = int(m2.group(2))
                if port_start < 1024 or port_end > 65535:
                    return jsonify({'status': 'error', 'message': '端口范围应在1024-65535之间'})
            else:
                port_start = 10000
                port_end = 65534
            
            # 生成可用端口列表
            all_ports = [p for p in range(port_start, port_end+1) if p not in used_ports]
            if len(all_ports) < len(ips):
                return jsonify({'status': 'error', 'message': f'可用端口不足，需要{len(ips)}个端口，但只有{len(all_ports)}个可用'})
            
            # 随机选择端口
            import random
            random.shuffle(all_ports)
            selected_ports = all_ports[:len(ips)]
            selected_ports.sort()
            
            # 计算实际使用的端口范围
            actual_port_range = f"{selected_ports[0]}-{selected_ports[-1]}"
            
            # 计算过期时间
            expire_at = None
            if expire_days and expire_days > 0:
                expire_at = (datetime.datetime.now() + datetime.timedelta(days=expire_days)).isoformat()
            
            # 计算流量限制（转换为字节）
            traffic_limit = 0
            if traffic_limit_gb and traffic_limit_gb > 0:
                traffic_limit = int(traffic_limit_gb * 1024 * 1024 * 1024)
            
            # 批量插入数据
            batch_data = []
            for i, ip in enumerate(ips):
                port = selected_ports[i]
                uname = userprefix + ''.join(random.choices(string.ascii_lowercase+string.digits, k=4))
                pw = ''.join(random.choices(string.ascii_letters+string.digits, k=12))
                batch_data.append((
                    ip, port, uname, pw, 1, iprange, actual_port_range, userprefix,
                    datetime.datetime.now().isoformat(), expire_at, 0, 0, traffic_limit, notes
                ))
            
            # 批量插入
            conn.executemany('''
                INSERT INTO proxy 
                (ip, port, username, password, enabled, ip_range, port_range, user_prefix,
                 created_at, expire_at, traffic_up, traffic_down, traffic_limit, notes) 
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', batch_data)
            conn.commit()
            count = len(batch_data)
        
        redis_client.delete('proxy_groups')
        # 异步重载配置，立即返回响应
        reload_xray_async()
        return jsonify({'status': 'success', 'message': f'批量范围添加完成，共添加{count}条代理，端口范围：{actual_port_range}，配置正在后台更新...'})
    
    # 处理手动批量添加
    batch_data = request.form.get('batchproxy','').strip().splitlines()
    
    if len(batch_data) > 1000:
        return jsonify({'status': 'error', 'message': f'一次最多添加1000个代理，当前尝试添加{len(batch_data)}个'})
    
    with db_pool.get_connection() as conn:
        count = 0
        base_idx = conn.execute("SELECT MAX(id) FROM proxy").fetchone()[0]
        if base_idx is None:
            base_idx = 0
        idx = 1
        
        batch_insert = []
        for line in batch_data:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ',' in line:
                parts = [x.strip() for x in line.split(',')]
            elif ':' in line:
                parts = [x.strip() for x in line.split(':')]
            else:
                parts = re.split(r'\s+', line)
            
            if len(parts) == 2:
                ip, port = parts
                username = f"user{base_idx + idx:03d}"
                password = ''.join(random.choices(string.ascii_letters+string.digits, k=12))
                idx += 1
            elif len(parts) == 3:
                ip, port, username = parts
                password = ''.join(random.choices(string.ascii_letters+string.digits, k=12))
            elif len(parts) >= 4:
                ip, port, username, password = parts[:4]
            else:
                continue
            
            batch_insert.append((
                ip, int(port), username, password, 1, ip, port, username,
                datetime.datetime.now().isoformat(), None, 0, 0, 0, ''
            ))
            count += 1
        
        if batch_insert:
            conn.executemany('''
                INSERT INTO proxy 
                (ip, port, username, password, enabled, ip_range, port_range, user_prefix,
                 created_at, expire_at, traffic_up, traffic_down, traffic_limit, notes) 
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', batch_insert)
            conn.commit()
    
    if count:
        redis_client.delete('proxy_groups')
        # 异步重载配置
        reload_xray_async()
    
    return jsonify({'status': 'success', 'message': f'批量添加完成，共添加{count}条代理，配置正在后台更新...'})

@app.route('/delproxy/<int:pid>')
@login_required
def delproxy(pid):
    with db_pool.get_connection() as conn:
        conn.execute('DELETE FROM proxy WHERE id=?', (pid,))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_xray_async()
    return jsonify({'status': 'success'})

@app.route('/batchdelproxy', methods=['POST'])
@login_required
def batchdelproxy():
    ids = request.form.getlist('ids')
    with db_pool.get_connection() as conn:
        conn.executemany('DELETE FROM proxy WHERE id=?', [(i,) for i in ids])
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_xray_async()
    return jsonify({'status': 'success', 'message': f'已批量删除 {len(ids)} 条代理'})

@app.route('/batch_enable', methods=['POST'])
@login_required
def batch_enable():
    ids = request.form.getlist('ids[]')
    if not ids:
        return jsonify({'status': 'error', 'message': 'No proxies selected'}), 400
    with db_pool.get_connection() as conn:
        conn.executemany('UPDATE proxy SET enabled=1 WHERE id=?', [(i,) for i in ids])
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_xray_async()
    return jsonify({'status': 'success'})

@app.route('/batch_disable', methods=['POST'])
@login_required
def batch_disable():
    ids = request.form.getlist('ids[]')
    if not ids:
        return jsonify({'status': 'error', 'message': 'No proxies selected'}), 400
    with db_pool.get_connection() as conn:
        conn.executemany('UPDATE proxy SET enabled=0 WHERE id=?', [(i,) for i in ids])
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_xray_async()
    return jsonify({'status': 'success'})

@app.route('/enableproxy/<int:pid>')
@login_required
def enableproxy(pid):
    with db_pool.get_connection() as conn:
        conn.execute('UPDATE proxy SET enabled=1 WHERE id=?', (pid,))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_xray_async()
    return jsonify({'status': 'success'})

@app.route('/disableproxy/<int:pid>')
@login_required
def disableproxy(pid):
    with db_pool.get_connection() as conn:
        conn.execute('UPDATE proxy SET enabled=0 WHERE id=?', (pid,))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_xray_async()
    return jsonify({'status': 'success'})

@app.route('/adduser', methods=['POST'])
@login_required
def adduser():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    try:
        with db_pool.get_connection() as conn:
            conn.execute('INSERT INTO users (username, password) VALUES (?,?)', (username, password))
            conn.commit()
        return jsonify({'status': 'success', 'message': '已添加用户'})
    except:
        return jsonify({'status': 'error', 'message': '用户名已存在'})

@app.route('/deluser/<int:uid>')
@login_required
def deluser(uid):
    with db_pool.get_connection() as conn:
        conn.execute('DELETE FROM users WHERE id=?', (uid,))
        conn.commit()
    return jsonify({'status': 'success'})

@app.route('/export_selected', methods=['POST'])
@login_required
def export_selected():
    csegs = request.form.getlist('csegs[]')
    export_format = request.form.get('format', 'txt')
    
    if not csegs:
        return jsonify({'status': 'error', 'message': '未选择C段'}), 400
    
    with db_pool.get_connection() as conn:
        if export_format == 'json':
            # JSON格式导出
            result = []
            for cseg in csegs:
                rows = conn.execute('''
                    SELECT ip, port, username, password, expire_at, traffic_limit, notes
                    FROM proxy WHERE ip LIKE ? ORDER BY ip, port
                ''', (cseg + '.%',)).fetchall()
                
                for row in rows:
                    result.append({
                        'proxy': f'http://{row[2]}:{row[3]}@{row[0]}:{row[1]}',
                        'expire_at': row[4],
                        'traffic_limit_gb': round(row[5] / 1024 / 1024 / 1024, 2) if row[5] else 0,
                        'notes': row[6]
                    })
            
            return jsonify(result)
        else:
            # 文本格式导出
            output = ""
            prefix_for_filename = None
            
            for cseg in csegs:
                rows = conn.execute('''
                    SELECT ip, port, username, password, user_prefix 
                    FROM proxy WHERE ip LIKE ? ORDER BY ip, port
                ''', (cseg + '.%',)).fetchall()
                
                if not prefix_for_filename and rows:
                    for row in rows:
                        if row[4]:
                            prefix_for_filename = row[4]
                            break
                
                for ip, port, user, pw, _ in rows:
                    output += f"{ip}:{port}:{user}:{pw}\n"
            
            if not prefix_for_filename:
                prefix_for_filename = 'proxy'
            
            cseg_names = []
            for cseg in sorted(csegs):
                cseg_names.append(cseg.replace('.', '_'))
            
            filename = f"{prefix_for_filename}_{'_'.join(cseg_names)}.txt"
            
            mem = BytesIO()
            mem.write(output.encode('utf-8'))
            mem.seek(0)
            
            return Response(
                mem.read(), 
                mimetype='text/plain', 
                headers={
                    'Content-Disposition': f'attachment; filename="{filename}"',
                    'Content-Type': 'text/plain; charset=utf-8'
                }
            )

@app.route('/api/usage_report')
@login_required
def api_usage_report():
    with db_pool.get_connection() as conn:
        # 按C段统计使用情况
        report = conn.execute('''
            SELECT 
                substr(ip, 1, instr(ip||'.', '.', 1, 3)-1) as c_segment,
                COUNT(*) as total,
                COUNT(CASE WHEN enabled = 1 THEN 1 END) as active,
                COUNT(CASE WHEN last_used > datetime('now', '-1 day') THEN 1 END) as used_24h,
                SUM(traffic_up + traffic_down) as total_traffic,
                MIN(created_at) as first_created,
                COUNT(CASE WHEN expire_at < datetime('now', '+7 day') THEN 1 END) as expiring_soon,
                COUNT(CASE WHEN traffic_limit > 0 AND (traffic_up + traffic_down) > traffic_limit * 0.8 THEN 1 END) as near_limit
            FROM proxy
            GROUP BY c_segment
            ORDER BY total_traffic DESC
        ''').fetchall()
    
    return jsonify([{
        'c_segment': r[0],
        'total': r[1],
        'active': r[2],
        'used_24h': r[3],
        'total_traffic_gb': round(r[4] / 1024 / 1024 / 1024, 2) if r[4] else 0,
        'first_created': r[5],
        'expiring_soon': r[6],
        'near_limit': r[7]
    } for r in report])

@app.route('/add_ip_config', methods=['POST'])
@login_required
def add_ip_config():
    ip_input = request.form.get('ip_input', '').strip()
    iface = request.form.get('iface', detect_nic())
    mode = request.form.get('mode', 'perm')
    pattern_full = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", ip_input)
    pattern_short = re.match(r"^(\d+)-(\d+)$", ip_input)
    
    if pattern_full:
        base = pattern_full.group(1)
        start = int(pattern_full.group(2))
        end = int(pattern_full.group(3))
        ip_range = f"{base}{{{start}..{end}}}"
        ip_list = [f"{base}{i}" for i in range(start, end+1)]
    elif pattern_short:
        base = "192.168.1."
        start = int(pattern_short.group(1))
        end = int(pattern_short.group(2))
        ip_range = f"{base}{{{start}..{end}}}"
        ip_list = [f"{base}{i}" for i in range(start, end+1)]
    elif '{' in ip_input and '..' in ip_input:
        ip_range = ip_input
        match = re.match(r"(\d+\.\d+\.\d+\.?)\{(\d+)\.\.(\d+)\}", ip_input)
        if match:
            base = match.group(1)
            s = int(match.group(2))
            e = int(match.group(3))
            ip_list = [f"{base}{i}" for i in range(s, e+1)]
        else:
            ip_list = []
    else:
        ip_range = ip_input
        ip_list = [ip.strip() for ip in re.split(r'[,\s]+', ip_input) if ip.strip()]
    
    with db_pool.get_connection() as conn:
        conn.execute('INSERT INTO ip_config (ip_str, type, iface, created) VALUES (?,?,?,datetime("now"))', (ip_range, 'range', iface))
        conn.commit()
    
    # 批量添加IP
    for i, ip in enumerate(ip_list):
        os.system(f"ip addr add {ip}/32 dev {iface} 2>/dev/null")
        os.system(f"ip route add {ip}/32 dev {iface} 2>/dev/null")
    
    # 永久添加
    if mode == 'perm':
        with open('/etc/network/interfaces', 'a+') as f:
            f.write(f"\n# Xray IP配置 - {ip_range}\n")
            for ip in ip_list:
                f.write(f"up ip addr add {ip}/32 dev {iface} 2>/dev/null || true\n")
                f.write(f"down ip addr del {ip}/32 dev {iface} 2>/dev/null || true\n")
    
    # 刷新ARP缓存
    os.system("ip neigh flush all")
    
    return jsonify({'status': 'success', 'message': '已添加IP配置'})

# 初始化时确保Xray运行
def ensure_xray_running():
    """确保Xray正在运行"""
    try:
        result = subprocess.run(['pgrep', 'xray'], capture_output=True)
        if result.returncode != 0:
            # Xray未运行，生成配置并启动
            generate_xray_config()
            subprocess.run(['systemctl', 'start', 'xray'])
            print("Xray started")
    except Exception as e:
        print(f"Error checking Xray: {e}")

# 在启动时确保Xray运行
ensure_xray_running()

if __name__ == '__main__':
    import sys
    from gevent.pywsgi import WSGIServer
    port = int(sys.argv[1]) if len(sys.argv)>1 else 9999
    
    # 使用gevent提供更好的并发性能
    print(f"Starting server on port {port}...")
    http_server = WSGIServer(('0.0.0.0', port), app, log=None)
    http_server.serve_forever()
EOF

# ------------------- init_db.py (数据库初始化) -------------------
cat > $WORKDIR/init_db.py << 'EOF'
import sqlite3
from werkzeug.security import generate_password_hash
import os

user = os.environ.get('ADMINUSER')
passwd = os.environ.get('ADMINPASS')

db = sqlite3.connect('xray.db')

# 启用WAL模式和优化
db.execute('PRAGMA journal_mode=WAL')
db.execute('PRAGMA synchronous=NORMAL')
db.execute('PRAGMA cache_size=10000')
db.execute('PRAGMA temp_store=MEMORY')

# 创建表
db.execute('''CREATE TABLE IF NOT EXISTS proxy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    ip_range TEXT,
    port_range TEXT,
    user_prefix TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expire_at DATETIME,
    last_used DATETIME,
    traffic_up INTEGER DEFAULT 0,
    traffic_down INTEGER DEFAULT 0,
    traffic_limit INTEGER DEFAULT 0,
    notes TEXT,
    UNIQUE(ip, port)
)''')

# 创建索引以提升查询性能
db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_ip ON proxy(ip)')
db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON proxy(enabled)')
db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_port ON proxy(port)')
db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_username ON proxy(username)')
db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_expire ON proxy(expire_at)')

db.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)''')

db.execute('''CREATE TABLE IF NOT EXISTS ip_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_str TEXT,
    type TEXT,
    iface TEXT,
    created TEXT
)''')

# 创建API密钥表
db.execute('''CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME,
    enabled INTEGER DEFAULT 1
)''')

db.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?,?)', (user, generate_password_hash(passwd)))
db.commit()

print("WebAdmin: "+user)
print("Webpassword:  "+passwd)
EOF

# 复制原有的HTML模板文件（使用相同的前端）
cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>Xray 登录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            backdrop-filter: blur(10px);
            background: rgba(255, 255, 255, 0.95);
            border: none;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            animation: slideIn 0.5s ease-out;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            transition: transform 0.2s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
    </style>
</head>
<body>
<div class="container" style="max-width:400px;">
    <div class="card login-card">
        <div class="card-body p-5">
            <h3 class="mb-4 text-center">Xray 管理系统</h3>
            <form method="post">
                <div class="mb-3">
                    <label class="form-label">用户名</label>
                    <input type="text" class="form-control" name="username" autofocus required>
                </div>
                <div class="mb-3">
                    <label class="form-label">密码</label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <button class="btn btn-primary btn-login w-100 mt-4" type="submit">登录</button>
            </form>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-danger mt-3 mb-0">{{ messages[0] }}</div>
              {% endif %}
            {% endwith %}
        </div>
    </div>
</div>
</body>
</html>
EOF

# 创建index.html（修改版本，适配Xray）
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>Xray 代理管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --warning-gradient: linear-gradient(135deg, #f2994a 0%, #f2c94c 100%);
            --danger-gradient: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
            --info-gradient: linear-gradient(135deg, #2196f3 0%, #21cbf3 100%);
            --card-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            --hover-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            --btn-radius: 8px;
        }
        
        body {
            background: #f5f7fa;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .navbar {
            background: var(--primary-gradient);
            box-shadow: var(--card-shadow);
        }
        
        .nav-tabs {
            border: none;
            background: white;
            border-radius: 10px;
            padding: 5px;
            box-shadow: var(--card-shadow);
            margin-bottom: 25px;
        }
        
        .nav-tabs .nav-link {
            border: none;
            color: #666;
            padding: 12px 24px;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .nav-tabs .nav-link:hover {
            background: #f8f9fa;
            color: #667eea;
        }
        
        .nav-tabs .nav-link.active {
            background: var(--primary-gradient);
            color: white;
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
            overflow: hidden;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: var(--hover-shadow);
        }
        
        .proxy-card {
            cursor: pointer;
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .proxy-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: var(--primary-gradient);
        }
        
        .proxy-card:hover {
            transform: translateX(10px);
            box-shadow: var(--hover-shadow);
        }
        
        .proxy-card.selected {
            background: #f0f0ff;
            border: 2px solid #667eea;
        }
        
        .proxy-card-footer {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #eee;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: scale(1.05);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .btn-gradient {
            background: var(--primary-gradient);
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: var(--btn-radius);
            transition: all 0.3s ease;
            font-weight: 500;
            box-shadow: 0 2px 10px rgba(102, 126, 234, 0.3);
        }
        
        .btn-gradient:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            color: white;
        }
        
        /* 统一按钮样式 */
        .btn {
            border-radius: var(--btn-radius);
            transition: all 0.2s ease;
            font-weight: 500;
            border: none;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.2);
            transition: left 0.3s ease;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn-success {
            background: var(--success-gradient);
            box-shadow: 0 2px 10px rgba(17, 153, 142, 0.3);
        }
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(17, 153, 142, 0.4);
            background: var(--success-gradient);
        }
        
        .btn-warning {
            background: var(--warning-gradient);
            box-shadow: 0 2px 10px rgba(242, 153, 74, 0.3);
            color: white;
        }
        
        .btn-warning:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(242, 153, 74, 0.4);
            background: var(--warning-gradient);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger-gradient);
            box-shadow: 0 2px 10px rgba(235, 51, 73, 0.3);
        }
        
        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(235, 51, 73, 0.4);
            background: var(--danger-gradient);
        }
        
        .btn-info {
            background: var(--info-gradient);
            box-shadow: 0 2px 10px rgba(33, 150, 243, 0.3);
        }
        
        .btn-info:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(33, 150, 243, 0.4);
            background: var(--info-gradient);
        }
        
        .btn-primary {
            background: var(--primary-gradient);
            box-shadow: 0 2px 10px rgba(102, 126, 234, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            background: var(--primary-gradient);
        }
        
        .btn-outline-secondary {
            background: white;
            border: 1px solid #e0e0e0;
            color: #666;
        }
        
        .btn-outline-secondary:hover {
            background: #f8f9fa;
            border-color: #667eea;
            color: #667eea;
            transform: translateY(-1px);
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 0.875rem;
        }
        
        .btn-group .btn {
            border-radius: 0;
        }
        
        .btn-group .btn:first-child {
            border-radius: var(--btn-radius) 0 0 var(--btn-radius);
        }
        
        .btn-group .btn:last-child {
            border-radius: 0 var(--btn-radius) var(--btn-radius) 0;
        }
        
        /* 徽章样式统一 */
        .badge {
            font-weight: 500;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
        }
        
        .badge.bg-secondary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        }
        
        .badge.bg-success {
            background: var(--success-gradient) !important;
        }
        
        .badge.bg-primary {
            background: var(--primary-gradient) !important;
        }
        
        .badge.bg-info {
            background: var(--info-gradient) !important;
        }
        
        .badge.bg-warning {
            background: var(--warning-gradient) !important;
            color: white;
        }
        
        /* 输入框美化 */
        .form-control {
            border-radius: var(--btn-radius);
            border: 1px solid #e0e0e0;
            padding: 12px 15px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .form-control-sm {
            padding: 6px 10px;
            font-size: 0.875rem;
        }
        
        /* 复选框美化 */
        .form-check-input {
            width: 1.2em;
            height: 1.2em;
            border-radius: 4px;
            border: 2px solid #ddd;
            transition: all 0.2s ease;
        }
        
        .form-check-input:checked {
            background-color: #667eea;
            border-color: #667eea;
        }
        
        .form-check-input:hover {
            border-color: #667eea;
            cursor: pointer;
        }
        
        .form-control, .form-select {
            border-radius: 10px;
            border: 1px solid #e0e0e0;
            padding: 12px 15px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .modal-content {
            border-radius: 20px;
            border: none;
        }
        
        .modal-header {
            background: var(--primary-gradient);
            color: white;
            border-radius: 20px 20px 0 0;
            border: none;
        }
        
        .badge-status {
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: normal;
            font-size: 0.85rem;
        }
        
        .loading-spinner {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 9999;
        }
        
        .loading-spinner.show {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .animate-fade-in {
            animation: fadeIn 0.5s ease-out;
        }
        
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1050;
        }
        
        .system-monitor {
            background: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .progress {
            height: 10px;
            border-radius: 5px;
            overflow: hidden;
        }
        
        .progress-bar {
            background: var(--primary-gradient);
            transition: width 0.6s ease;
        }
        
        .dark-mode {
            background: #1a1a2e;
            color: #eee;
        }
        
        .dark-mode .card, .dark-mode .nav-tabs {
            background: #16213e;
            color: #eee;
        }
        
        .dark-mode .form-control, .dark-mode .form-select {
            background: #0f3460;
            color: #eee;
            border-color: #2a2a3e;
        }
        
        .switch-mode {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--primary-gradient);
            color: white;
            border: none;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
        }
        
        .switch-mode:hover {
            transform: scale(1.1);
            box-shadow: var(--hover-shadow);
        }
        
        .detail-header {
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .info-row {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 10px;
        }
        
        .info-item {
            display: flex;
            align-items: center;
            gap: 5px;
            color: #666;
        }
        
        .action-bar {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .proxy-row:hover {
            background: #f8f9fa;
        }
        
        .traffic-info {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            font-size: 0.9rem;
        }
        
        .traffic-up {
            color: #28a745;
        }
        
        .traffic-down {
            color: #dc3545;
        }
        
        .expire-badge {
            font-size: 0.8rem;
            padding: 4px 10px;
        }
        
        .expire-soon {
            background: var(--warning-gradient) !important;
            color: white;
        }
        
        .expired {
            background: var(--danger-gradient) !important;
            color: white;
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-dark mb-4">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="bi bi-shield-check"></i> Xray 代理管理系统
            </span>
            <div class="d-flex align-items-center">
                <span class="text-white me-3" id="currentTime"></span>
                <a href="/logout" class="btn btn-outline-light btn-sm">
                    <i class="bi bi-box-arrow-right"></i> 退出
                </a>
            </div>
        </div>
    </nav>

    <!-- 主内容区 -->
    <div class="container-fluid px-4">
        <!-- 系统监控 -->
        <div class="system-monitor animate-fade-in">
            <h5 class="mb-3"><i class="bi bi-speedometer2"></i> 系统监控</h5>
            <div class="row g-3">
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number" id="cpuUsage">0%</div>
                        <small>CPU 使用率</small>
                        <div class="progress mt-2">
                            <div class="progress-bar" id="cpuProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number" id="memUsage">0%</div>
                        <small>内存使用率</small>
                        <div class="progress mt-2">
                            <div class="progress-bar" id="memProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number" id="diskUsage">0%</div>
                        <small>磁盘使用率</small>
                        <div class="progress mt-2">
                            <div class="progress-bar" id="diskProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number" id="proxyStatus">
                            <i class="bi bi-circle-fill text-danger"></i>
                        </div>
                        <small>Xray 状态</small>
                        <div class="mt-1">
                            <small id="proxyInfo">未运行</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 标签页 -->
        <ul class="nav nav-tabs" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane">
                    <i class="bi bi-hdd-network"></i> 代理管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="report-tab" data-bs-toggle="tab" data-bs-target="#report-pane">
                    <i class="bi bi-graph-up"></i> 使用报表
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane">
                    <i class="bi bi-people"></i> 用户管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-pane">
                    <i class="bi bi-diagram-3"></i> IP管理
                </button>
            </li>
        </ul>

        <!-- 标签内容 -->
        <div class="tab-content">
            <!-- 代理管理 -->
            <div class="tab-pane fade show active animate-fade-in" id="proxy-pane" role="tabpanel">
                <div class="row">
                    <div class="col-lg-4">
                        <div class="card mb-3">
                            <div class="card-body">
                                <h5 class="card-title"><i class="bi bi-plus-circle"></i> 批量添加代理</h5>
                                <form id="batchAddForm">
                                    <div class="mb-3">
                                        <label class="form-label">IP范围</label>
                                        <input type="text" class="form-control" name="iprange" placeholder="192.168.1.2-254" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">端口范围（可选）</label>
                                        <input type="text" class="form-control" name="portrange" placeholder="20000-30000">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">用户名前缀</label>
                                        <input type="text" class="form-control" name="userprefix" placeholder="user" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">有效期（天）</label>
                                        <input type="number" class="form-control" name="expire_days" placeholder="0表示永久">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">流量限制（GB）</label>
                                        <input type="number" class="form-control" name="traffic_limit" step="0.1" placeholder="0表示无限">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">备注</label>
                                        <input type="text" class="form-control" name="notes" placeholder="可选">
                                    </div>
                                    <button type="submit" class="btn btn-gradient w-100">
                                        <i class="bi bi-cloud-upload"></i> 批量添加
                                    </button>
                                </form>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title"><i class="bi bi-file-text"></i> 手动批量添加</h5>
                                <form id="manualBatchForm">
                                    <div class="mb-3">
                                        <textarea name="batchproxy" class="form-control" rows="6" 
                                                  placeholder="每行一个：ip,端口 或 ip:端口"></textarea>
                                    </div>
                                    <button type="submit" class="btn btn-gradient w-100">
                                        <i class="bi bi-upload"></i> 添加
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                    <div class="col-lg-8">
                        <div class="card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <h5 class="card-title mb-0">
                                        <i class="bi bi-list-ul"></i> 代理组列表
                                    </h5>
                                    <div>
                                        <button class="btn btn-sm btn-outline-primary" id="refreshGroups">
                                            <i class="bi bi-arrow-clockwise"></i> 刷新
                                        </button>
                                        <button class="btn btn-sm btn-outline-success" id="exportGroups">
                                            <i class="bi bi-download"></i> 导出选中
                                        </button>
                                    </div>
                                </div>
                                
                                <div id="proxyGroups" class="overflow-auto" style="max-height: 600px;">
                                    <!-- 代理组卡片将在这里动态生成 -->
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 使用报表 -->
            <div class="tab-pane fade" id="report-pane" role="tabpanel">
                <div class="card animate-fade-in">
                    <div class="card-body">
                        <h5 class="card-title"><i class="bi bi-graph-up"></i> 使用情况报表</h5>
                        <div id="usageReport">
                            <!-- 报表内容将在这里动态生成 -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- 用户管理 -->
            <div class="tab-pane fade" id="user-pane" role="tabpanel">
                <div class="card animate-fade-in">
                    <div class="card-body">
                        <h5 class="card-title"><i class="bi bi-person-plus"></i> Web用户管理</h5>
                        <form id="addUserForm" class="row g-3 mb-4">
                            <div class="col-md-5">
                                <input type="text" name="username" class="form-control" placeholder="用户名" required>
                            </div>
                            <div class="col-md-5">
                                <input type="password" name="password" class="form-control" placeholder="密码" required>
                            </div>
                            <div class="col-md-2">
                                <button type="submit" class="btn btn-gradient w-100">添加</button>
                            </div>
                        </form>
                        <div id="usersList">
                            <!-- 用户列表将在这里动态生成 -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- IP管理 -->
            <div class="tab-pane fade" id="ip-pane" role="tabpanel">
                <div class="card animate-fade-in">
                    <div class="card-body">
                        <h5 class="card-title"><i class="bi bi-diagram-3"></i> IP批量管理</h5>
                        <form id="addIpForm" class="row g-3 mb-4">
                            <div class="col-md-2">
                                <input type="text" name="iface" class="form-control" placeholder="网卡" value="eth0">
                            </div>
                            <div class="col-md-5">
                                <input type="text" name="ip_input" class="form-control" 
                                       placeholder="192.168.1.2-254 或 192.168.1.2,192.168.1.3" required>
                            </div>
                            <div class="col-md-3">
                                <select name="mode" class="form-select">
                                    <option value="perm">永久</option>
                                    <option value="temp">临时</option>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <button type="submit" class="btn btn-gradient w-100">添加</button>
                            </div>
                        </form>
                        <div id="ipConfigsList">
                            <!-- IP配置列表将在这里动态生成 -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 代理详情模态框 -->
    <div class="modal fade" id="proxyDetailModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">代理详情</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="proxyDetailContent">
                        <!-- 代理详情将在这里动态生成 -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 设置过期时间模态框 -->
    <div class="modal fade" id="setExpireModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">设置过期时间</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="setExpireForm">
                        <input type="hidden" id="expireSegment" name="segment">
                        <div class="mb-3">
                            <label class="form-label">过期时间</label>
                            <input type="datetime-local" class="form-control" name="expire_date" required>
                        </div>
                        <button type="submit" class="btn btn-primary">确定</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast 通知容器 -->
    <div class="toast-container"></div>

    <!-- 加载动画 -->
    <div class="loading-spinner">
        <div class="spinner-border text-primary" style="width: 3rem; height: 3rem;">
            <span class="visually-hidden">Loading...</span>
        </div>
    </div>

    <!-- 深色模式切换 -->
    <button class="switch-mode" id="darkModeToggle">
        <i class="bi bi-moon-fill"></i>
    </button>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 全局变量
        let selectedGroups = new Set();
        let selectedProxies = new Set();

        // 工具函数
        function showLoading() {
            document.querySelector('.loading-spinner').classList.add('show');
        }

        function hideLoading() {
            document.querySelector('.loading-spinner').classList.remove('show');
        }

        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = `toast align-items-center text-white bg-${type} border-0`;
            toast.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">${message}</div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            document.querySelector('.toast-container').appendChild(toast);
            const bsToast = new bootstrap.Toast(toast);
            bsToast.show();
            toast.addEventListener('hidden.bs.toast', () => toast.remove());
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatDateTime(dateStr) {
            if (!dateStr) return '永久';
            const date = new Date(dateStr);
            const now = new Date();
            const diff = date - now;
            
            if (diff < 0) return '<span class="text-danger">已过期</span>';
            if (diff < 7 * 24 * 60 * 60 * 1000) {
                const days = Math.floor(diff / (24 * 60 * 60 * 1000));
                return `<span class="text-warning">${days}天后过期</span>`;
            }
            
            return date.toLocaleString('zh-CN');
        }

        // 时间更新
        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = 
                now.toLocaleString('zh-CN', { hour12: false });
        }
        setInterval(updateTime, 1000);
        updateTime();

        // 系统监控
        function updateSystemStatus() {
            fetch('/api/system_status')
                .then(res => res.json())
                .then(data => {
                    // CPU
                    document.getElementById('cpuUsage').textContent = data.cpu.toFixed(1) + '%';
                    document.getElementById('cpuProgress').style.width = data.cpu + '%';
                    
                    // 内存
                    document.getElementById('memUsage').textContent = data.memory.percent.toFixed(1) + '%';
                    document.getElementById('memProgress').style.width = data.memory.percent + '%';
                    
                    // 磁盘
                    document.getElementById('diskUsage').textContent = data.disk.percent.toFixed(1) + '%';
                    document.getElementById('diskProgress').style.width = data.disk.percent + '%';
                    
                    // Xray状态
                    const statusIcon = document.getElementById('proxyStatus');
                    const statusInfo = document.getElementById('proxyInfo');
                    if (data.xray.running) {
                        statusIcon.innerHTML = '<i class="bi bi-circle-fill text-success"></i>';
                        statusInfo.textContent = `PID: ${data.xray.pid} | 连接: ${data.xray.connections}`;
                    } else {
                        statusIcon.innerHTML = '<i class="bi bi-circle-fill text-danger"></i>';
                        statusInfo.textContent = '未运行';
                    }
                });
        }
        setInterval(updateSystemStatus, 5000);
        updateSystemStatus();

        // 加载代理组
        function loadProxyGroups() {
            const currentSelected = new Set(selectedGroups);
            
            showLoading();
            fetch('/api/proxy_groups')
                .then(res => res.json())
                .then(groups => {
                    const container = document.getElementById('proxyGroups');
                    container.innerHTML = '';
                    
                    const existingSegments = new Set(groups.map(g => g.c_segment));
                    
                    currentSelected.forEach(cseg => {
                        if (!existingSegments.has(cseg)) {
                            selectedGroups.delete(cseg);
                        }
                    });
                    
                    groups.forEach(group => {
                        const card = document.createElement('div');
                        card.className = 'proxy-card';
                        
                        if (selectedGroups.has(group.c_segment)) {
                            card.classList.add('selected');
                        }
                        
                        // 过期提示
                        let expireInfo = '';
                        if (group.expiring_soon > 0) {
                            expireInfo = `<span class="badge expire-badge expire-soon">
                                <i class="bi bi-exclamation-triangle"></i> ${group.expiring_soon} 个即将过期
                            </span>`;
                        }
                        
                        card.innerHTML = `
                            <div class="row align-items-center">
                                <div class="col-md-7">
                                    <h6 class="mb-2 d-flex align-items-center">
                                        <input type="checkbox" class="form-check-input me-2" 
                                               data-group="${group.c_segment}" onclick="event.stopPropagation();">
                                        <i class="bi bi-hdd-network text-primary me-2"></i>
                                        <strong>${group.c_segment}.x</strong>
                                        ${expireInfo}
                                    </h6>
                                    <div class="d-flex flex-wrap gap-2 mb-2">
                                        <span class="badge rounded-pill bg-primary">
                                            <i class="bi bi-layers"></i> ${group.total} 个
                                        </span>
                                        <span class="badge rounded-pill bg-success">
                                            <i class="bi bi-check-circle"></i> ${group.enabled} 启用
                                        </span>
                                        <span class="badge rounded-pill bg-info">
                                            <i class="bi bi-arrow-down-up"></i> ${group.traffic} MB
                                        </span>
                                    </div>
                                    <small class="text-muted d-block">
                                        ${group.ip_range ? `<i class="bi bi-diagram-3"></i> ${group.ip_range}` : ''}
                                        ${group.port_range ? `<i class="bi bi-ethernet"></i> ${group.port_range}` : ''}
                                        ${group.user_prefix ? `<i class="bi bi-person"></i> ${group.user_prefix}` : ''}
                                    </small>
                                    <div class="proxy-card-footer">
                                        <small class="text-muted">
                                            ${group.created_at ? `<i class="bi bi-calendar"></i> 创建: ${new Date(group.created_at).toLocaleDateString()}` : ''}
                                        </small>
                                    </div>
                                </div>
                                <div class="col-md-5 text-end">
                                    <div class="btn-toolbar justify-content-end" role="toolbar">
                                        <div class="btn-group btn-group-sm me-2" role="group">
                                            <button class="btn btn-primary" 
                                                    onclick="event.stopPropagation(); viewProxyGroup('${group.c_segment}')"
                                                    title="查看详情">
                                                <i class="bi bi-eye"></i> 查看
                                            </button>
                                            <button class="btn btn-warning" 
                                                    onclick="event.stopPropagation(); showSetExpireModal('${group.c_segment}')"
                                                    title="设置过期">
                                                <i class="bi bi-clock"></i> 过期
                                            </button>
                                        </div>
                                        <div class="btn-group btn-group-sm" role="group">
                                            <button class="btn btn-success" 
                                                    onclick="event.stopPropagation(); toggleGroup('${group.c_segment}', 'enable')"
                                                    title="启用全部">
                                                <i class="bi bi-play-circle"></i> 启用
                                            </button>
                                            <button class="btn btn-warning" 
                                                    onclick="event.stopPropagation(); toggleGroup('${group.c_segment}', 'disable')"
                                                    title="禁用全部">
                                                <i class="bi bi-pause-circle"></i> 禁用
                                            </button>
                                            <button class="btn btn-danger" 
                                                    onclick="event.stopPropagation(); deleteGroup('${group.c_segment}')"
                                                    title="删除整组">
                                                <i class="bi bi-trash"></i> 删除
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `;
                        
                        // 点击卡片切换选中状态
                        card.addEventListener('click', (e) => {
                            if (e.target.closest('button') || e.target.closest('input')) {
                                return;
                            }
                            
                            const checkbox = card.querySelector('input[type="checkbox"]');
                            checkbox.checked = !checkbox.checked;
                            
                            if (checkbox.checked) {
                                selectedGroups.add(group.c_segment);
                                card.classList.add('selected');
                            } else {
                                selectedGroups.delete(group.c_segment);
                                card.classList.remove('selected');
                            }
                        });
                        
                        // 复选框事件
                        const checkbox = card.querySelector('input[type="checkbox"]');
                        
                        if (selectedGroups.has(group.c_segment)) {
                            checkbox.checked = true;
                        }
                        
                        checkbox.addEventListener('change', (e) => {
                            e.stopPropagation();
                            if (e.target.checked) {
                                selectedGroups.add(group.c_segment);
                                card.classList.add('selected');
                            } else {
                                selectedGroups.delete(group.c_segment);
                                card.classList.remove('selected');
                            }
                        });
                        
                        container.appendChild(card);
                    });
                    hideLoading();
                })
                .catch(err => {
                    hideLoading();
                    showToast('加载失败: ' + err.message, 'danger');
                });
        }

        // 查看代理组详情
        function viewProxyGroup(cSegment) {
            selectedProxies.clear();
            
            showLoading();
            fetch(`/api/proxy_group/${cSegment}`)
                .then(res => res.json())
                .then(proxies => {
                    const content = document.getElementById('proxyDetailContent');
                    const firstProxy = proxies[0] || {};
                    
                    let html = `
                        <div class="detail-header">
                            <h5>${cSegment}.x 段代理详情</h5>
                            <div class="info-row">
                                ${firstProxy.ip_range ? `<span class="info-item"><i class="bi bi-diagram-3"></i> IP范围: <strong>${firstProxy.ip_range}</strong></span>` : ''}
                                ${firstProxy.port_range ? `<span class="info-item"><i class="bi bi-ethernet"></i> 端口范围: <strong>${firstProxy.port_range}</strong></span>` : ''}
                                ${firstProxy.user_prefix ? `<span class="info-item"><i class="bi bi-person"></i> 用户前缀: <strong>${firstProxy.user_prefix}</strong></span>` : ''}
                                <span class="info-item"><i class="bi bi-list"></i> 代理总数: <strong>${proxies.length}</strong></span>
                            </div>
                        </div>
                        
                        <div class="action-bar">
                            <div class="d-flex align-items-center justify-content-between">
                                <div class="d-flex align-items-center gap-3">
                                    <input type="checkbox" class="form-check-input" id="selectAllCheck">
                                    <label for="selectAllCheck" class="mb-0">全选</label>
                                    <span class="text-muted">已选择 <span id="selectedCount">0</span> 项</span>
                                </div>
                                <div class="d-flex gap-2">
                                    <button class="btn btn-sm btn-success" onclick="batchEnableProxies()">
                                        <i class="bi bi-check-circle-fill"></i> 启用
                                    </button>
                                    <button class="btn btn-sm btn-warning" onclick="batchDisableProxies()">
                                        <i class="bi bi-pause-circle-fill"></i> 禁用
                                    </button>
                                    <button class="btn btn-sm btn-danger" onclick="batchDeleteProxies()">
                                        <i class="bi bi-trash-fill"></i> 删除
                                    </button>
                                    <button class="btn btn-sm btn-info" onclick="exportSelectedProxies()">
                                        <i class="bi bi-download"></i> 导出
                                    </button>
                                    <input type="text" class="form-control form-control-sm" style="width:200px; border-radius: 8px;"
                                           placeholder="搜索..." onkeyup="filterProxyTable(this.value)">
                                </div>
                            </div>
                        </div>
                        
                        <div style="overflow-x: auto;">
                            <table class="table table-sm" style="width: 100%; min-width: 1200px;">
                                <thead style="background: #343a40; color: white;">
                                    <tr>
                                        <th style="width: 40px; text-align: center;">选</th>
                                        <th style="width: 60px;">ID</th>
                                        <th style="width: 120px;">IP地址</th>
                                        <th style="width: 80px; text-align: center;">端口</th>
                                        <th style="width: 120px;">用户名</th>
                                        <th style="width: 200px;">密码</th>
                                        <th style="width: 150px; text-align: center;">流量</th>
                                        <th style="width: 120px; text-align: center;">过期时间</th>
                                        <th style="width: 70px; text-align: center;">状态</th>
                                        <th style="width: 100px; text-align: center;">操作</th>
                                    </tr>
                                </thead>
                                <tbody>`;
                    
                    proxies.forEach((proxy, index) => {
                        const rowClass = index % 2 === 0 ? 'table-light' : '';
                        const trafficPercent = proxy.traffic_limit > 0 ? 
                            ((proxy.traffic_total / proxy.traffic_limit) * 100).toFixed(1) : 0;
                        
                        html += `
                            <tr class="proxy-row ${rowClass}">
                                <td style="text-align: center; padding: 8px 4px;">
                                    <input type="checkbox" class="form-check-input proxy-check" 
                                           data-id="${proxy.id}" onchange="updateSelectedCount()">
                                </td>
                                <td style="padding: 8px 4px;">
                                    <small class="text-muted">#${proxy.id}</small>
                                </td>
                                <td style="padding: 8px 4px;">
                                    <span class="font-monospace" style="font-size: 0.9rem;">${proxy.ip}</span>
                                </td>
                                <td style="padding: 8px 4px; text-align: center;">
                                    <span class="badge bg-info" style="font-family: monospace;">${proxy.port}</span>
                                </td>
                                <td style="padding: 8px 4px;">
                                    <code style="color: #d63384; font-size: 0.9rem;">${proxy.username}</code>
                                </td>
                                <td style="padding: 8px 4px;">
                                    <div style="display: flex; align-items: center; gap: 4px;">
                                        <input type="text" class="form-control form-control-sm" 
                                               value="${proxy.password}" readonly 
                                               style="font-family: monospace; font-size: 0.85rem; background: #f8f9fa; border-radius: 6px;">
                                        <button class="btn btn-sm btn-outline-secondary" 
                                                style="padding: 4px 10px; border-radius: 6px;"
                                                onclick="copyPassword('${proxy.password.replace(/'/g, "\\'")}', ${proxy.id})"
                                                title="复制密码">
                                            <i class="bi bi-clipboard" style="font-size: 0.9rem;"></i>
                                        </button>
                                    </div>
                                </td>
                                <td style="padding: 8px 4px;">
                                    <div class="traffic-info">
                                        <span class="traffic-up" title="上传">
                                            <i class="bi bi-arrow-up"></i> ${formatBytes(proxy.traffic_up)}
                                        </span>
                                        <span class="traffic-down" title="下载">
                                            <i class="bi bi-arrow-down"></i> ${formatBytes(proxy.traffic_down)}
                                        </span>
                                    </div>
                                    ${proxy.traffic_limit > 0 ? `
                                        <div class="progress mt-1" style="height: 5px;">
                                            <div class="progress-bar ${trafficPercent > 80 ? 'bg-warning' : ''}" 
                                                 style="width: ${trafficPercent}%"></div>
                                        </div>
                                        <small class="text-muted">${trafficPercent}% / ${formatBytes(proxy.traffic_limit)}</small>
                                    ` : ''}
                                </td>
                                <td style="padding: 8px 4px; text-align: center;">
                                    <small>${formatDateTime(proxy.expire_at)}</small>
                                </td>
                                <td style="text-align: center; padding: 8px 4px;">
                                    ${proxy.enabled ? 
                                        '<span class="badge bg-success" style="font-size: 0.8rem;"><i class="bi bi-check-circle-fill me-1"></i>启用</span>' : 
                                        '<span class="badge bg-secondary" style="font-size: 0.8rem;"><i class="bi bi-x-circle-fill me-1"></i>禁用</span>'}
                                </td>
                                <td style="text-align: center; padding: 8px 4px;">
                                    <button class="btn btn-sm ${proxy.enabled ? 'btn-warning' : 'btn-success'}" 
                                            style="padding: 4px 10px; margin-right: 4px; border-radius: 6px;"
                                            onclick="toggleProxy(${proxy.id}, ${!proxy.enabled})"
                                            title="${proxy.enabled ? '禁用' : '启用'}">
                                        <i class="bi bi-${proxy.enabled ? 'pause-circle' : 'play-circle'}-fill" style="font-size: 0.9rem;"></i>
                                    </button>
                                    <button class="btn btn-sm btn-danger" 
                                            style="padding: 4px 10px; border-radius: 6px;"
                                            onclick="deleteProxy(${proxy.id})"
                                            title="删除">
                                        <i class="bi bi-trash-fill" style="font-size: 0.9rem;"></i>
                                    </button>
                                </td>
                            </tr>`;
                    });
                    
                    html += `
                                </tbody>
                            </table>
                        </div>
                    `;
                    
                    content.innerHTML = html;
                    
                    // 绑定事件
                    document.getElementById('selectAllCheck').addEventListener('change', (e) => {
                        document.querySelectorAll('.proxy-check').forEach(cb => {
                            cb.checked = e.target.checked;
                            const id = cb.getAttribute('data-id');
                            if (e.target.checked) {
                                selectedProxies.add(id);
                            } else {
                                selectedProxies.delete(id);
                            }
                        });
                        updateSelectedCount();
                    });
                    
                    updateSelectedCount();
                    
                    hideLoading();
                    const modal = new bootstrap.Modal(document.getElementById('proxyDetailModal'));
                    
                    document.getElementById('proxyDetailModal').addEventListener('hidden.bs.modal', function () {
                        selectedProxies.clear();
                        updateSelectedCount();
                    }, { once: true });
                    
                    modal.show();
                })
                .catch(err => {
                    hideLoading();
                    showToast('加载失败: ' + err.message, 'danger');
                });
        }

        // 更新选中数量
        function updateSelectedCount() {
            const count = document.querySelectorAll('.proxy-check:checked').length;
            const countElement = document.getElementById('selectedCount');
            if (countElement) {
                countElement.textContent = count;
            }
        }

        // 过滤代理表格
        function filterProxyTable(value) {
            const rows = document.querySelectorAll('.proxy-row');
            const searchTerm = value.toLowerCase();
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        }

        // 复制密码
        function copyPassword(password, id) {
            navigator.clipboard.writeText(password).then(() => {
                showToast('密码已复制到剪贴板');
            });
        }

        // 代理组操作
        function deleteGroup(cSegment) {
            if (!confirm(`确定要删除 ${cSegment}.x 段的所有代理吗？`)) return;
            
            showLoading();
            fetch(`/api/delete_group/${cSegment}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    showToast(`已删除 ${cSegment}.x 段代理组`);
                    selectedGroups.delete(cSegment);
                    loadProxyGroups();
                })
                .catch(err => {
                    hideLoading();
                    showToast('删除失败: ' + err.message, 'danger');
                });
        }

        function toggleGroup(cSegment, action) {
            showLoading();
            fetch(`/api/toggle_group/${cSegment}/${action}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    showToast(`已${action === 'enable' ? '启用' : '禁用'} ${cSegment}.x 段代理组`);
                    loadProxyGroups();
                })
                .catch(err => {
                    hideLoading();
                    showToast('操作失败: ' + err.message, 'danger');
                });
        }

        // 显示设置过期时间模态框
        function showSetExpireModal(cSegment) {
            document.getElementById('expireSegment').value = cSegment;
            const modal = new bootstrap.Modal(document.getElementById('setExpireModal'));
            modal.show();
        }

        // 设置过期时间表单提交
        document.getElementById('setExpireForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const cSegment = formData.get('segment');
            
            showLoading();
            fetch(`/api/set_expire_group/${cSegment}`, { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    showToast(`已设置 ${cSegment}.x 段过期时间`);
                    bootstrap.Modal.getInstance(document.getElementById('setExpireModal')).hide();
                    loadProxyGroups();
                })
                .catch(err => {
                    hideLoading();
                    showToast('设置失败: ' + err.message, 'danger');
                });
        });

        // 单个代理操作
        function toggleProxy(id, enable) {
            const action = enable ? 'enableproxy' : 'disableproxy';
            fetch(`/${action}/${id}`)
                .then(res => res.json())
                .then(data => {
                    showToast(`代理已${enable ? '启用' : '禁用'}`);
                    const modal = bootstrap.Modal.getInstance(document.getElementById('proxyDetailModal'));
                    if (modal) {
                        const detailHeader = document.querySelector('.detail-header h5');
                        if (detailHeader) {
                            const cSegment = detailHeader.textContent.split('.')[0].trim();
                            viewProxyGroup(cSegment);
                        }
                    }
                })
                .catch(err => {
                    showToast('操作失败: ' + err.message, 'danger');
                });
        }

        function deleteProxy(id) {
            if (!confirm('确定要删除此代理吗？')) return;
            
            fetch(`/delproxy/${id}`)
                .then(res => res.json())
                .then(data => {
                    showToast('代理已删除');
                    const modal = bootstrap.Modal.getInstance(document.getElementById('proxyDetailModal'));
                    if (modal) {
                        const detailHeader = document.querySelector('.detail-header h5');
                        if (detailHeader) {
                            const cSegment = detailHeader.textContent.split('.')[0].trim();
                            viewProxyGroup(cSegment);
                        }
                    }
                    loadProxyGroups();
                })
                .catch(err => {
                    showToast('删除失败: ' + err.message, 'danger');
                });
        }

        // 批量操作函数
        function batchEnableProxies() {
            if (selectedProxies.size === 0) {
                showToast('请先选择代理', 'warning');
                return;
            }
            
            const formData = new FormData();
            selectedProxies.forEach(id => formData.append('ids[]', id));
            
            fetch('/batch_enable', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    showToast('批量启用成功');
                    selectedProxies.clear();
                    updateSelectedCount();
                    const cSegment = document.querySelector('.detail-header h5').textContent.split('.')[0];
                    viewProxyGroup(cSegment);
                });
        }

        function batchDisableProxies() {
            if (selectedProxies.size === 0) {
                showToast('请先选择代理', 'warning');
                return;
            }
            
            const formData = new FormData();
            selectedProxies.forEach(id => formData.append('ids[]', id));
            
            fetch('/batch_disable', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    showToast('批量禁用成功');
                    selectedProxies.clear();
                    updateSelectedCount();
                    const cSegment = document.querySelector('.detail-header h5').textContent.split('.')[0];
                    viewProxyGroup(cSegment);
                });
        }

        function batchDeleteProxies() {
            if (selectedProxies.size === 0) {
                showToast('请先选择代理', 'warning');
                return;
            }
            
            if (!confirm(`确定要删除选中的 ${selectedProxies.size} 个代理吗？`)) return;
            
            const formData = new FormData();
            selectedProxies.forEach(id => formData.append('ids', id));
            
            fetch('/batchdelproxy', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    showToast('批量删除成功');
                    selectedProxies.clear();
                    updateSelectedCount();
                    bootstrap.Modal.getInstance(document.getElementById('proxyDetailModal')).hide();
                    loadProxyGroups();
                });
        }

        function exportSelectedProxies() {
            if (selectedProxies.size === 0) {
                showToast('请先选择代理', 'warning');
                return;
            }
            
            const formData = new FormData();
            selectedProxies.forEach(id => formData.append('ids[]', id));
            
            fetch('/export_selected_proxy', { method: 'POST', body: formData })
                .then(res => res.blob())
                .then(blob => {
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'proxy_export.txt';
                    a.click();
                    URL.revokeObjectURL(a.href);
                    showToast('导出成功');
                    selectedProxies.clear();
                    updateSelectedCount();
                    const selectAllCheck = document.getElementById('selectAllCheck');
                    if (selectAllCheck) selectAllCheck.checked = false;
                });
        }

        // 导出选中的代理组
        document.getElementById('exportGroups').addEventListener('click', () => {
            if (selectedGroups.size === 0) {
                                    showToast('请先选择代理组', 'warning');
                return;
            }
            
            const formData = new FormData();
            selectedGroups.forEach(cseg => formData.append('csegs[]', cseg));
            
            showLoading();
            fetch('/export_selected', { method: 'POST', body: formData })
                .then(res => {
                    if (!res.ok) throw new Error('Export failed');
                    
                    const contentDisposition = res.headers.get('Content-Disposition');
                    let filename = 'proxy_export.txt';
                    if (contentDisposition) {
                        const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
                        if (filenameMatch && filenameMatch[1]) {
                            filename = filenameMatch[1].replace(/['"]/g, '');
                        }
                    }
                    
                    return res.blob().then(blob => ({ blob, filename }));
                })
                .then(({ blob, filename }) => {
                    hideLoading();
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = filename;
                    a.click();
                    URL.revokeObjectURL(a.href);
                    showToast(`导出成功: ${filename}`);
                    
                    selectedGroups.clear();
                    document.querySelectorAll('.proxy-card input[type="checkbox"]').forEach(cb => {
                        cb.checked = false;
                    });
                    document.querySelectorAll('.proxy-card.selected').forEach(card => {
                        card.classList.remove('selected');
                    });
                })
                .catch(err => {
                    hideLoading();
                    showToast('导出失败: ' + err.message, 'danger');
                });
        });

        // 表单提交
        document.getElementById('batchAddForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            showLoading();
            fetch('/batchaddproxy', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    if (data.status === 'success') {
                        showToast(data.message);
                        e.target.reset();
                        loadProxyGroups();
                    } else {
                        showToast(data.message, 'danger');
                    }
                });
        });

        document.getElementById('manualBatchForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            showLoading();
            fetch('/batchaddproxy', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    if (data.status === 'success') {
                        showToast(data.message);
                        e.target.reset();
                        loadProxyGroups();
                    } else {
                        showToast(data.message, 'danger');
                    }
                });
        });

        // 使用报表
        function loadUsageReport() {
            fetch('/api/usage_report')
                .then(res => res.json())
                .then(reports => {
                    const container = document.getElementById('usageReport');
                    let html = `
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>C段</th>
                                        <th>总数</th>
                                        <th>活跃</th>
                                        <th>24小时使用</th>
                                        <th>总流量</th>
                                        <th>即将过期</th>
                                        <th>接近限制</th>
                                        <th>创建时间</th>
                                    </tr>
                                </thead>
                                <tbody>
                    `;
                    
                    reports.forEach(report => {
                        const usageRate = report.total > 0 ? (report.used_24h / report.total * 100).toFixed(1) : 0;
                        html += `
                            <tr>
                                <td><strong>${report.c_segment}.x</strong></td>
                                <td>${report.total}</td>
                                <td>
                                    <span class="badge bg-success">${report.active}</span>
                                </td>
                                <td>
                                    <div class="progress" style="width: 100px;">
                                        <div class="progress-bar ${usageRate > 50 ? 'bg-success' : 'bg-warning'}" 
                                             style="width: ${usageRate}%"></div>
                                    </div>
                                    <small>${report.used_24h} (${usageRate}%)</small>
                                </td>
                                <td>${report.total_traffic_gb} GB</td>
                                <td>
                                    ${report.expiring_soon > 0 ? 
                                        `<span class="badge bg-warning">${report.expiring_soon}</span>` : 
                                        '<span class="text-muted">-</span>'}
                                </td>
                                <td>
                                    ${report.near_limit > 0 ? 
                                        `<span class="badge bg-danger">${report.near_limit}</span>` : 
                                        '<span class="text-muted">-</span>'}
                                </td>
                                <td>
                                    ${report.first_created ? 
                                        new Date(report.first_created).toLocaleDateString() : 
                                        '<span class="text-muted">-</span>'}
                                </td>
                            </tr>
                        `;
                    });
                    
                    html += '</tbody></table></div>';
                    container.innerHTML = html;
                });
        }

        // 用户管理
        function loadUsers() {
            fetch('/api/users')
                .then(res => res.json())
                .then(users => {
                    const container = document.getElementById('usersList');
                    container.innerHTML = `
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>用户名</th>
                                        <th>操作</th>
                                    </tr>
                                </thead>
                                <tbody>
                    `;
                    
                    users.forEach(user => {
                        container.innerHTML += `
                            <tr>
                                <td>${user.id}</td>
                                <td>${user.username}</td>
                                <td>
                                    ${user.username !== 'admin' ? 
                                        `<button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id})">
                                            <i class="bi bi-trash"></i> 删除
                                        </button>` : 
                                        '<span class="text-muted">系统用户</span>'}
                                </td>
                            </tr>
                        `;
                    });
                    
                    container.innerHTML += '</tbody></table></div>';
                });
        }

        document.getElementById('addUserForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            fetch('/adduser', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        showToast(data.message);
                        e.target.reset();
                        loadUsers();
                    } else {
                        showToast(data.message, 'danger');
                    }
                });
        });

        function deleteUser(id) {
            if (!confirm('确定要删除此用户吗？')) return;
            
            fetch(`/deluser/${id}`)
                .then(res => res.json())
                .then(data => {
                    showToast('用户已删除');
                    loadUsers();
                });
        }

        // IP配置管理
        function loadIpConfigs() {
            fetch('/api/ip_configs')
                .then(res => res.json())
                .then(configs => {
                    const container = document.getElementById('ipConfigsList');
                    container.innerHTML = `
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>IP配置</th>
                                        <th>类型</th>
                                        <th>网卡</th>
                                        <th>创建时间</th>
                                    </tr>
                                </thead>
                                <tbody>
                    `;
                    
                    configs.forEach(config => {
                        container.innerHTML += `
                            <tr>
                                <td>${config.id}</td>
                                <td><code>${config.ip_str}</code></td>
                                <td>${config.type}</td>
                                <td>${config.iface}</td>
                                <td>${config.created}</td>
                            </tr>
                        `;
                    });
                    
                    container.innerHTML += '</tbody></table></div>';
                });
        }

        document.getElementById('addIpForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            showLoading();
            fetch('/add_ip_config', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    if (data.status === 'success') {
                        showToast(data.message);
                        e.target.reset();
                        loadIpConfigs();
                    } else {
                        showToast(data.message, 'danger');
                    }
                });
        });

        // 深色模式
        document.getElementById('darkModeToggle').addEventListener('click', () => {
            document.body.classList.toggle('dark-mode');
            const icon = document.querySelector('#darkModeToggle i');
            if (document.body.classList.contains('dark-mode')) {
                icon.className = 'bi bi-sun-fill';
                localStorage.setItem('darkMode', 'true');
            } else {
                icon.className = 'bi bi-moon-fill';
                localStorage.setItem('darkMode', 'false');
            }
        });

        // 标签页切换事件
        document.getElementById('report-tab').addEventListener('shown.bs.tab', loadUsageReport);
        document.getElementById('user-tab').addEventListener('shown.bs.tab', loadUsers);
        document.getElementById('ip-tab').addEventListener('shown.bs.tab', loadIpConfigs);

        // 刷新按钮
        document.getElementById('refreshGroups').addEventListener('click', loadProxyGroups);

        // 初始化
        window.addEventListener('DOMContentLoaded', () => {
            // 恢复深色模式设置
            if (localStorage.getItem('darkMode') === 'true') {
                document.body.classList.add('dark-mode');
                document.querySelector('#darkModeToggle i').className = 'bi bi-sun-fill';
            }
            
            // 清空全局选择集合
            selectedGroups.clear();
            selectedProxies.clear();
            
            // 加载初始数据
            loadProxyGroups();
        });
    </script>
</body>
</html>
EOF

# ------------------- Xray systemd 服务 -------------------
cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=$XRAY_PATH run -config $XRAY_CONFIG
Restart=on-failure
RestartSec=10s
LimitNOFILE=3000000

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/xray-web.service <<EOF
[Unit]
Description=Xray Web管理后台
After=network.target redis-server.service

[Service]
Type=simple
WorkingDirectory=$WORKDIR
ExecStart=$WORKDIR/venv/bin/python3 $WORKDIR/xray_manage.py $PORT $API_PORT
Restart=always
User=root
Environment="PYTHONUNBUFFERED=1"
LimitNOFILE=3000000
LimitNPROC=3000000

[Install]
WantedBy=multi-user.target
EOF

# 初始化数据库
cd $WORKDIR
export ADMINUSER
export ADMINPASS
$WORKDIR/venv/bin/python3 init_db.py

# 创建日志目录
mkdir -p $XRAY_LOG_DIR
touch $XRAY_LOG_DIR/access.log
touch $XRAY_LOG_DIR/error.log
chmod 666 $XRAY_LOG_DIR/*.log

# 生成初始Xray配置
cat > $XRAY_CONFIG <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "$XRAY_LOG_DIR/access.log",
    "error": "$XRAY_LOG_DIR/error.log"
  },
  "api": {
    "tag": "api",
    "services": ["HandlerService", "StatsService"]
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "inbounds": [
    {
      "tag": "api",
      "protocol": "dokodemo-door",
      "listen": "127.0.0.1",
      "port": $API_PORT,
      "settings": {
        "address": "127.0.0.1"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["api"],
        "outboundTag": "api"
      }
    ]
  }
}
EOF

# 保存登录凭据
cat > $CREDS_FILE <<EOF
Web管理地址: http://$(get_local_ip):${PORT}
管理员用户名: $ADMINUSER
管理员密码: $ADMINPASS
API端口: $API_PORT
安装时间: $(date)
EOF
chmod 600 $CREDS_FILE

systemctl daemon-reload
systemctl enable xray
systemctl enable xray-web

# 先停止旧服务
systemctl stop xray 2>/dev/null || true
systemctl stop xray-web 2>/dev/null || true

# 杀死所有xray进程
pkill -9 xray 2>/dev/null || true
sleep 2

# 启动服务
systemctl start xray
sleep 2
systemctl start xray-web

# 验证Xray是否运行
sleep 3
if pgrep xray > /dev/null; then
    echo -e "\033[32mXray 已成功启动\033[0m"
else
    echo -e "\033[31m警告: Xray 未能启动，尝试手动启动...\033[0m"
    $XRAY_PATH run -config $XRAY_CONFIG &
fi

echo -e "\n========= 部署完成！========="
MYIP=$(get_local_ip)
echo -e "浏览器访问：\n  \033[36mhttp://$MYIP:${PORT}\033[0m"
echo "Web管理用户名: $ADMINUSER"
echo "Web管理密码:  $ADMINPASS"
echo -e "\n功能说明："
echo "1. 基于 Xray 的高性能代理管理系统"
echo "2. 支持过期时间和流量限制管理"
echo "3. 实时流量统计和使用报表"
echo "4. 支持百万级并发连接"
echo "5. 自动备份每天凌晨2点执行"
echo -e "\n新增功能："
echo "- 代理过期时间设置"
echo "- 流量限制和统计"
echo "- 使用情况报表"
echo "- 批量设置过期时间"
echo -e "\n常用命令："
echo "查看登录信息: bash $0 show"
echo "卸载系统: bash $0 uninstall"
echo "重新安装: bash $0 reinstall"
echo "查看Xray日志: tail -f $XRAY_LOG_DIR/access.log"
echo "查看系统状态: systemctl status xray xray-web"
