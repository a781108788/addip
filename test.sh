#!/bin/bash
set -e

WORKDIR=/opt/squid-web
SQUID_PATH=/usr/sbin/squid
SQUID_CONFIG_PATH=/etc/squid/squid.conf
SQUID_PASSWORD_FILE=/etc/squid/passwords
LOGFILE=/var/log/squid/access.log
CREDS_FILE=/opt/squid-web/.credentials

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
        echo -e "\n========= Squid Web管理系统登录信息 ========="
        cat "$CREDS_FILE"
        echo -e "============================================\n"
    else
        echo -e "\033[31m未找到登录凭据文件。请运行安装脚本。\033[0m"
    fi
}

function optimize_system() {
    echo -e "\n========= 系统性能优化 =========\n"
    
    # 检查是否已经优化过
    if grep -q "# Squid 性能优化" /etc/sysctl.conf 2>/dev/null; then
        echo -e "\033[33m系统已经优化过，跳过...\033[0m"
        return
    fi
    
    # 优化内核参数 - 支持大规模代理
    cat >> /etc/sysctl.conf <<EOF

# Squid 性能优化 - 支持万级并发
# 基础网络优化
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1

# TCP 连接优化
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 65536
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0

# 端口范围
net.ipv4.ip_local_port_range = 1024 65535

# 连接跟踪优化
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 1200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120

# 套接字优化
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.core.optmem_max = 25165824
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP 拥塞控制
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

# 文件句柄
fs.file-max = 4000000
fs.nr_open = 4000000

# 其他优化
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.route.flush = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1

# 内存优化
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.overcommit_memory = 1
EOF
    
    # 立即应用
    sysctl -p >/dev/null 2>&1
    
    # 加载 nf_conntrack 模块
    modprobe nf_conntrack >/dev/null 2>&1
    
    # 优化文件描述符限制
    if ! grep -q "# Squid limits" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf <<EOF

# Squid limits
* soft nofile 2000000
* hard nofile 2000000
* soft nproc 2000000
* hard nproc 2000000
root soft nofile 2000000
root hard nofile 2000000
root soft nproc 2000000
root hard nproc 2000000
proxy soft nofile 2000000
proxy hard nofile 2000000
EOF
    fi
    
    # 优化 systemd 限制
    if [ -f /etc/systemd/system.conf ]; then
        sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=2000000/' /etc/systemd/system.conf
        sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=2000000/' /etc/systemd/system.conf
    fi
    
    echo -e "\033[32m系统优化完成！支持万级代理并发\033[0m"
}

function setup_backup() {
    echo -e "\n========= 设置自动备份 =========\n"
    
    mkdir -p $WORKDIR/backups
    
    # 创建备份脚本
    cat > $WORKDIR/backup.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/opt/squid-web/backups"
DB_FILE="/opt/squid-web/squid.db"
CONFIG_FILE="/etc/squid/squid.conf"
PASSWORD_FILE="/etc/squid/passwords"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# 检查文件是否存在
if [ ! -f "$DB_FILE" ] || [ ! -f "$CONFIG_FILE" ]; then
    echo "Warning: Some files not found for backup"
    exit 0
fi

cd "$BACKUP_DIR"

# 保留最近7天的备份
find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +7 -delete 2>/dev/null || true

# 创建新备份
tar -czf "backup_$DATE.tar.gz" "$DB_FILE" "$CONFIG_FILE" "$PASSWORD_FILE" 2>/dev/null || true

echo "Backup completed: backup_$DATE.tar.gz"
EOF
    
    chmod +x $WORKDIR/backup.sh
    
    # 设置定时备份
    echo "0 2 * * * root $WORKDIR/backup.sh > /dev/null 2>&1" > /etc/cron.d/squid-backup
    
    echo -e "\033[32m自动备份已设置（每天凌晨2点）\033[0m"
}

function uninstall_squid_web() {
    systemctl stop squid-web 2>/dev/null || true
    systemctl stop squid 2>/dev/null || true
    systemctl disable squid-web 2>/dev/null || true
    systemctl disable squid 2>/dev/null || true
    rm -rf $WORKDIR
    rm -f /etc/systemd/system/squid-web.service
    rm -f /etc/cron.d/squid-logrotate
    rm -f /etc/cron.d/squid-backup
    systemctl daemon-reload
    echo -e "\033[31mSquid Web管理及全部相关内容已卸载。\033[0m"
}

# 处理命令行参数
case "$1" in
    "uninstall")
        uninstall_squid_web
        exit 0
        ;;
    "reinstall")
        uninstall_squid_web
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

echo -e "\n========= 1. 自动安装 Squid =========\n"

# 检测系统版本
if [ -f /etc/debian_version ]; then
    DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1)
    echo "检测到 Debian $DEBIAN_VERSION"
fi

apt update
apt install -y squid apache2-utils gcc make git wget python3 python3-pip python3-venv sqlite3 cron redis-server

# 启动Redis
systemctl enable redis-server
systemctl start redis-server

# 备份原始Squid配置
if [ -f "$SQUID_CONFIG_PATH" ] && [ ! -f "$SQUID_CONFIG_PATH.original" ]; then
    cp $SQUID_CONFIG_PATH $SQUID_CONFIG_PATH.original
fi

# 创建基础Squid配置
cat > $SQUID_CONFIG_PATH <<'EOF'
# Squid 企业级配置
# 基础设置
visible_hostname proxy-server

# 监听默认端口
http_port 3128

# 性能优化
cache_mem 2048 MB
maximum_object_size_in_memory 512 KB
memory_pools on
memory_pools_limit 2048 MB

# 文件描述符
max_filedescriptors 2000000

# DNS优化
dns_v4_first on
positive_dns_ttl 6 hours
negative_dns_ttl 1 minute
dns_nameservers 8.8.8.8 1.1.1.1

# 缓存设置（可选）
cache_dir ufs /var/spool/squid 10000 16 256
maximum_object_size 100 MB
cache_swap_low 90
cache_swap_high 95

# 日志
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
cache_store_log none

# 核心转储
coredump_dir /var/spool/squid

# 刷新模式
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# ACL定义
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

# 安全限制
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# 认证配置
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
auth_param basic children 100 startup=10 idle=5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours

# 需要认证
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all

# 转发设置
forwarded_for off
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Cache-Control deny all

# 性能调优
workers 4

# 关闭不需要的功能
shutdown_lifetime 3 seconds
EOF

# 创建密码文件
touch $SQUID_PASSWORD_FILE
chmod 644 $SQUID_PASSWORD_FILE
chown proxy:proxy $SQUID_PASSWORD_FILE

# 创建Squid目录
mkdir -p /var/spool/squid
mkdir -p /var/log/squid
chown -R proxy:proxy /var/spool/squid
chown -R proxy:proxy /var/log/squid

# 检查并初始化Squid缓存目录
if [ ! -f /var/spool/squid/swap.state ]; then
    squid -z 2>/dev/null || true
fi

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
    pip install flask flask_login flask_wtf wtforms Werkzeug psutil redis celery gevent gunicorn passlib
else
    pip install flask flask_login flask_wtf wtforms Werkzeug psutil redis celery gevent gunicorn passlib --break-system-packages
fi

# ------------------- manage.py (主后端 - Squid版本) -------------------
cat > $WORKDIR/manage.py << 'EOF'
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
from passlib.hash import sha256_crypt

DB = 'squid.db'
SECRET = 'changeme_this_is_secret'
import sys
PORT = int(sys.argv[1]) if len(sys.argv)>1 else 9999
SQUID_CONFIG_PATH = '/etc/squid/squid.conf'
SQUID_PASSWORD_FILE = '/etc/squid/passwords'
LOGFILE = '/var/log/squid/access.log'
INTERFACES_FILE = '/etc/network/interfaces'

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

def get_db():
    """兼容旧代码的数据库获取函数"""
    return sqlite3.connect(DB)

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

def reload_squid_async():
    """异步重载Squid配置"""
    task_queue.put(('reload', None))

def reload_squid():
    """同步重载Squid配置"""
    generate_squid_config()
    generate_squid_passwords()
    
    # 测试配置文件是否有效
    result = os.system('squid -k parse 2>/dev/null')
    if result != 0:
        print("Squid configuration error, using fallback config")
        # 使用备份配置
        os.system('cp /etc/squid/squid.conf.template /etc/squid/squid.conf 2>/dev/null')
    
    # Squid使用 -k reconfigure 进行平滑重载
    result = os.system('squid -k reconfigure 2>/dev/null')
    if result != 0:
        # 如果重载失败，尝试重启
        os.system('systemctl restart squid')
    
    # 等待 Squid 启动
    time.sleep(2)

def generate_squid_config():
    """生成Squid配置文件"""
    with db_pool.get_connection() as conn:
        # 获取所有启用的代理
        cursor = conn.execute('SELECT DISTINCT ip, port FROM proxy WHERE enabled=1 ORDER BY ip, port')
        
        # 读取原始配置模板
        base_config = """# Squid 企业级配置
# 基础设置
visible_hostname proxy-server

# 性能优化
cache_mem 2048 MB
maximum_object_size_in_memory 512 KB
memory_pools on
memory_pools_limit 2048 MB

# 文件描述符
max_filedescriptors 2000000

# DNS优化
dns_v4_first on
positive_dns_ttl 6 hours
negative_dns_ttl 1 minute
dns_nameservers 8.8.8.8 1.1.1.1

# 缓存设置（可选）
cache_dir ufs /var/spool/squid 10000 16 256
maximum_object_size 100 MB
cache_swap_low 90
cache_swap_high 95

# 日志
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
cache_store_log none

# 核心转储
coredump_dir /var/spool/squid

# 刷新模式
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# ACL定义
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

# 安全限制
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# 认证配置
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
auth_param basic children 100 startup=10 idle=5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours

# 性能调优
workers 4
shutdown_lifetime 3 seconds

"""
        
        # 添加监听端口配置
        port_configs = []
        proxies = []
        
        for ip, port in cursor:
            port_configs.append(f"http_port {ip}:{port} name=port{port}")
            proxies.append((ip, port))
        
        # 如果没有代理，添加默认端口
        if not port_configs:
            port_configs.append("http_port 3128")
        
        # 生成ACL和访问控制规则
        acl_configs = []
        access_configs = []
        
        # 获取所有用户和对应的代理
        cursor2 = conn.execute('''
            SELECT DISTINCT username, ip, port 
            FROM proxy 
            WHERE enabled=1 
            ORDER BY username, ip, port
        ''')
        
        user_proxies = {}
        for username, ip, port in cursor2:
            if username not in user_proxies:
                user_proxies[username] = []
            user_proxies[username].append((ip, port))
        
        # 为每个用户生成ACL
        for username, proxy_list in user_proxies.items():
            # 用户认证ACL
            acl_configs.append(f"acl {username}_user proxy_auth {username}")
            
            # 为该用户的每个代理创建规则
            for ip, port in proxy_list:
                port_acl = f"port{port}"
                acl_configs.append(f"acl {port_acl} myportname port{port}")
                access_configs.append(f"http_access allow {username}_user {port_acl}")
                access_configs.append(f"tcp_outgoing_address {ip} {username}_user {port_acl}")
        
        # 如果没有用户配置，允许所有认证用户
        if not access_configs:
            access_configs.append("acl authenticated proxy_auth REQUIRED")
            access_configs.append("http_access allow authenticated")
        
        # 最后拒绝所有
        access_configs.append("http_access deny all")
        
        # 组合最终配置
        final_config = base_config + "\n# 监听端口\n" + "\n".join(port_configs) + "\n"
        
        if acl_configs:
            final_config += "\n# 动态生成的ACL\n" + "\n".join(acl_configs) + "\n"
        
        final_config += "\n# 访问控制规则\n" + "\n".join(access_configs) + "\n"
        
        # 写入配置文件
        with open(SQUID_CONFIG_PATH, 'w') as f:
            f.write(final_config)
        
        # 备份原始配置
        if not os.path.exists(SQUID_CONFIG_PATH + '.template'):
            with open(SQUID_CONFIG_PATH + '.template', 'w') as f:
                f.write(base_config)

def generate_squid_passwords():
    """生成Squid密码文件"""
    with db_pool.get_connection() as conn:
        cursor = conn.execute('SELECT DISTINCT username, password FROM proxy WHERE enabled=1')
        
        # 使用 htpasswd 命令生成密码文件
        # 先清空密码文件
        open(SQUID_PASSWORD_FILE, 'w').close()
        
        for username, password in cursor:
            # 使用 htpasswd 命令添加用户
            # -b: 批处理模式，从命令行获取密码
            # -c: 创建新文件（只在第一个用户时使用）
            cmd = f"htpasswd -b {SQUID_PASSWORD_FILE} {username} {password}"
            os.system(cmd + " 2>/dev/null")
        
        # 设置权限 - 必须让 Squid (proxy用户) 能读取
        os.chmod(SQUID_PASSWORD_FILE, 0o644)
        os.system(f'chown proxy:proxy {SQUID_PASSWORD_FILE}')

# 后台任务处理线程
def task_worker():
    """后台任务处理器"""
    while True:
        try:
            task_type, data = task_queue.get(timeout=1)
            if task_type == 'reload':
                generate_squid_config()
                generate_squid_passwords()
                os.system('squid -k reconfigure 2>/dev/null || systemctl restart squid')
            task_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Task worker error: {e}")

# 启动后台任务线程
worker_thread = threading.Thread(target=task_worker, daemon=True)
worker_thread.start()

# 初始启动Squid（如果还没启动）
def ensure_squid_running():
    """确保Squid正在运行"""
    try:
        # 检查Squid是否运行
        result = subprocess.run(['pgrep', 'squid'], capture_output=True)
        if result.returncode != 0:
            # Squid未运行，启动它
            os.system('systemctl start squid')
            print("Squid started")
    except Exception as e:
        print(f"Error checking squid: {e}")

# 在启动时确保Squid运行
ensure_squid_running()

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
        proxies = conn.execute('SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix FROM proxy ORDER BY ip').fetchall()
    
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
            'user_prefix': p[8]
        })
    
    # 获取流量统计
    traffic_stats = get_traffic_stats()
    
    result = []
    for c_seg, proxies in groups.items():
        enabled_count = sum(1 for p in proxies if p['enabled'])
        
        # 计算实际的IP范围和端口范围
        ips = [p['ip'] for p in proxies]
        ports = sorted([p['port'] for p in proxies])
        
        # IP范围
        if ips:
            ip_nums = sorted([int(ip.split('.')[-1]) for ip in ips])
            if len(ip_nums) > 1 and ip_nums[-1] - ip_nums[0] == len(ip_nums) - 1:
                actual_ip_range = f"{c_seg}.{ip_nums[0]}-{ip_nums[-1]}"
            else:
                actual_ip_range = f"{c_seg}.x ({len(ip_nums)} IPs)"
        else:
            actual_ip_range = proxies[0]['ip_range'] if proxies else ''
        
        # 端口范围
        if ports:
            if len(ports) == 1:
                actual_port_range = str(ports[0])
            else:
                actual_port_range = f"{ports[0]}-{ports[-1]}"
        else:
            actual_port_range = proxies[0]['port_range'] if proxies else ''
        
        result.append({
            'c_segment': c_seg,
            'total': len(proxies),
            'enabled': enabled_count,
            'traffic': traffic_stats.get(c_seg, 0),
            'ip_range': actual_ip_range,
            'port_range': actual_port_range,
            'user_prefix': proxies[0]['user_prefix'] if proxies else ''
        })
    
    sorted_result = sorted(result, key=lambda x: x['c_segment'])
    # 缓存5秒
    redis_client.setex('proxy_groups', 5, pickle.dumps(sorted_result))
    
    return jsonify(sorted_result)

@app.route('/api/proxy_group/<c_segment>')
@login_required
def api_proxy_group_detail(c_segment):
    with db_pool.get_connection() as conn:
        proxies = conn.execute('SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port', 
                            (c_segment + '.%',)).fetchall()
    
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
            'user_prefix': p[8]
        })
    
    return jsonify(result)

@app.route('/api/delete_group/<c_segment>', methods=['POST'])
@login_required
def api_delete_group(c_segment):
    with db_pool.get_connection() as conn:
        conn.execute('DELETE FROM proxy WHERE ip LIKE ?', (c_segment + '.%',))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_squid_async()
    return jsonify({'status': 'success'})

@app.route('/api/toggle_group/<c_segment>/<action>', methods=['POST'])
@login_required
def api_toggle_group(c_segment, action):
    enabled = 1 if action == 'enable' else 0
    with db_pool.get_connection() as conn:
        conn.execute('UPDATE proxy SET enabled=? WHERE ip LIKE ?', (enabled, c_segment + '.%'))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_squid_async()
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
    
    # 获取Squid进程信息
    proxy_info = {'running': False, 'pid': None, 'memory': 0, 'connections': 0}
    squid_found = False
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Squid 可能显示为 squid 或 (squid-1)
            if 'squid' in proc.info['name'].lower():
                if not squid_found:  # 只统计主进程
                    proxy_info['running'] = True
                    proxy_info['pid'] = proc.info['pid']
                    squid_found = True
                    try:
                        p = psutil.Process(proc.info['pid'])
                        proxy_info['memory'] = p.memory_info().rss / 1024 / 1024  # MB
                        # 统计所有 squid 相关进程的连接数
                        connections = 0
                        for squid_proc in psutil.process_iter(['name']):
                            if 'squid' in squid_proc.info['name'].lower():
                                try:
                                    sp = psutil.Process(squid_proc.pid)
                                    connections += len(sp.connections(kind='inet'))
                                except:
                                    pass
                        proxy_info['connections'] = connections
                    except Exception as e:
                        print(f"Error getting process info: {e}")
        except:
            pass
    
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
        'proxy': proxy_info,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # 缓存2秒
    redis_client.setex('system_status', 2, pickle.dumps(result))
    
    return jsonify(result)

def get_traffic_stats():
    """优化的流量统计函数"""
    stats = collections.defaultdict(int)
    if not os.path.exists(LOGFILE):
        return stats
    
    try:
        # 只读取最后10MB的日志
        file_size = os.path.getsize(LOGFILE)
        read_size = min(file_size, 10 * 1024 * 1024)
        
        with open(LOGFILE, 'rb') as f:
            if file_size > read_size:
                f.seek(file_size - read_size)
                f.readline()  # 跳过可能不完整的行
            
            for line in f:
                try:
                    line = line.decode('utf-8', errors='ignore')
                    # Squid日志格式：timestamp elapsed client action/code bytes method URL user
                    parts = line.split()
                    if len(parts) >= 5:
                        client_ip = parts[2].split(':')[0]
                        bytes_transferred = int(parts[4])
                        cseg = '.'.join(client_ip.split('.')[:3])
                        stats[cseg] += bytes_transferred
                except:
                    pass
    except:
        pass
    
    return {k: round(v/1024/1024, 2) for k, v in stats.items()}

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

@app.route('/addproxy', methods=['POST'])
@login_required
def addproxy():
    ip = request.form['ip']
    port = int(request.form['port'])
    username = request.form['username']
    password = request.form['password'] or ''.join(random.choices(string.ascii_letters+string.digits, k=12))
    user_prefix = request.form.get('userprefix','')
    
    with db_pool.get_connection() as conn:
        conn.execute('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?,?,?,?,1,?,?,?)', 
            (ip, port, username, password, ip, port, user_prefix))
        conn.commit()
    
    redis_client.delete('proxy_groups')
    reload_squid_async()
    return jsonify({'status': 'success', 'message': '已添加代理'})

@app.route('/batchaddproxy', methods=['POST'])
@login_required
def batchaddproxy():
    iprange = request.form.get('iprange')
    portrange = request.form.get('portrange')
    userprefix = request.form.get('userprefix')
    
    if iprange and userprefix:
        # 解析IP范围
        m = re.match(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", iprange.strip())
        if not m:
            return jsonify({'status': 'error', 'message': 'IP范围格式错误'})
        ip_base = m.group(1)
        start = int(m.group(2))
        end = int(m.group(3))
        ips = [f"{ip_base}{i}" for i in range(start, end+1)]
        
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
                port_start = 5000
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
            
            # 批量插入数据
            batch_data = []
            for i, ip in enumerate(ips):
                port = selected_ports[i]
                uname = userprefix + ''.join(random.choices(string.ascii_lowercase+string.digits, k=4))
                pw = ''.join(random.choices(string.ascii_letters+string.digits, k=12))
                batch_data.append((ip, port, uname, pw, 1, iprange, actual_port_range, userprefix))
            
            # 批量插入
            conn.executemany('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?,?,?,?,?,?,?,?)', 
                           batch_data)
            conn.commit()
            count = len(batch_data)
        
        redis_client.delete('proxy_groups')
        reload_squid_async()
        return jsonify({'status': 'success', 'message': f'批量范围添加完成，共添加{count}条代理，端口范围：{actual_port_range}'})
    
    # 处理手动批量添加
    batch_data = request.form.get('batchproxy','').strip().splitlines()
    
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
            
            batch_insert.append((ip, int(port), username, password, 1, ip, port, username))
            count += 1
        
        if batch_insert:
            conn.executemany('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?,?,?,?,?,?,?,?)',
                           batch_insert)
            conn.commit()
    
    if count:
        redis_client.delete('proxy_groups')
        reload_squid_async()
    
    return jsonify({'status': 'success', 'message': f'批量添加完成，共添加{count}条代理'})

@app.route('/delproxy/<int:pid>')
@login_required
def delproxy(pid):
    with db_pool.get_connection() as conn:
        conn.execute('DELETE FROM proxy WHERE id=?', (pid,))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_squid_async()
    return jsonify({'status': 'success'})

@app.route('/batchdelproxy', methods=['POST'])
@login_required
def batchdelproxy():
    ids = request.form.getlist('ids')
    with db_pool.get_connection() as conn:
        conn.executemany('DELETE FROM proxy WHERE id=?', [(i,) for i in ids])
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_squid_async()
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
    reload_squid_async()
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
    reload_squid_async()
    return jsonify({'status': 'success'})

@app.route('/enableproxy/<int:pid>')
@login_required
def enableproxy(pid):
    with db_pool.get_connection() as conn:
        conn.execute('UPDATE proxy SET enabled=1 WHERE id=?', (pid,))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_squid_async()
    return jsonify({'status': 'success'})

@app.route('/disableproxy/<int:pid>')
@login_required
def disableproxy(pid):
    with db_pool.get_connection() as conn:
        conn.execute('UPDATE proxy SET enabled=0 WHERE id=?', (pid,))
        conn.commit()
    redis_client.delete('proxy_groups')
    reload_squid_async()
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
    if not csegs:
        return jsonify({'status': 'error', 'message': '未选择C段'}), 400
    
    with db_pool.get_connection() as conn:
        output = ""
        prefix_for_filename = None
        
        for cseg in csegs:
            rows = conn.execute("SELECT ip,port,username,password,user_prefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port", 
                             (cseg + '.%',)).fetchall()
            
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

@app.route('/export_selected_proxy', methods=['POST'])
@login_required
def export_selected_proxy():
    ids = request.form.getlist('ids[]')
    if not ids:
        return jsonify({'status': 'error', 'message': 'No proxies selected'}), 400
    
    with db_pool.get_connection() as conn:
        placeholders = ','.join('?' * len(ids))
        rows = conn.execute(f'SELECT ip, port, username, password FROM proxy WHERE id IN ({placeholders})', ids).fetchall()
    
    output = ''
    for ip, port, user, pw in rows:
        output += f"{ip}:{port}:{user}:{pw}\n"
    
    mem = BytesIO()
    mem.write(output.encode('utf-8'))
    mem.seek(0)
    filename = "proxy_export.txt"
    return Response(mem.read(), mimetype='text/plain', headers={'Content-Disposition': f'attachment; filename={filename}'})

@app.route('/add_ip_config', methods=['POST'])
@login_required
def add_ip_config():
    try:
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
        
        # 批量添加IP - 优化命令执行
        success_count = 0
        for ip in ip_list:
            # 检查IP是否已存在
            result = os.system(f"ip addr show dev {iface} | grep -q ' {ip}/'")
            if result != 0:  # IP不存在，添加它
                # 添加IP地址
                if os.system(f"ip addr add {ip}/32 dev {iface} 2>/dev/null") == 0:
                    success_count += 1
                # 添加路由
                os.system(f"ip route add {ip}/32 dev {iface} 2>/dev/null")
        
        # 永久添加
        if mode == 'perm' and success_count > 0:
            with open(INTERFACES_FILE, 'a+') as f:
                f.write(f"\n# Squid IP配置 - {ip_range}\n")
                for ip in ip_list:
                    f.write(f"up ip addr add {ip}/32 dev {iface} 2>/dev/null || true\n")
                    f.write(f"down ip addr del {ip}/32 dev {iface} 2>/dev/null || true\n")
        
        # 刷新网络设置
        os.system(f"ip link set {iface} up")
        
        # 重载Squid配置（如果有代理使用这些IP）
        with db_pool.get_connection() as conn:
            affected = conn.execute('SELECT COUNT(*) FROM proxy WHERE ip IN ({})'.format(
                ','.join(['?'] * len(ip_list))
            ), ip_list).fetchone()[0]
            
            if affected > 0:
                reload_squid_async()
        
        return jsonify({
            'status': 'success', 
            'message': f'已添加IP配置，成功添加 {success_count}/{len(ip_list)} 个IP'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    import sys
    from gevent.pywsgi import WSGIServer
    port = int(sys.argv[1]) if len(sys.argv)>1 else 9999
    
    # 使用gevent提供更好的并发性能
    print(f"Starting server on port {port}...")
    http_server = WSGIServer(('0.0.0.0', port), app, log=None)
    http_server.serve_forever()
EOF

# --------- init_db.py（DB初始化） ---------
cat > $WORKDIR/init_db.py << 'EOF'
import sqlite3
from werkzeug.security import generate_password_hash
import os

user = os.environ.get('ADMINUSER')
passwd = os.environ.get('ADMINPASS')

db = sqlite3.connect('squid.db')

# 启用WAL模式和优化
db.execute('PRAGMA journal_mode=WAL')
db.execute('PRAGMA synchronous=NORMAL')
db.execute('PRAGMA cache_size=10000')
db.execute('PRAGMA temp_store=MEMORY')

# 创建表
db.execute('''CREATE TABLE IF NOT EXISTS proxy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, port INTEGER, username TEXT, password TEXT, enabled INTEGER DEFAULT 1,
    ip_range TEXT, port_range TEXT, user_prefix TEXT
)''')

# 创建索引以提升查询性能
db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_ip ON proxy(ip)')
db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON proxy(enabled)')
db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_port ON proxy(port)')

db.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, password TEXT
)''')

db.execute('''CREATE TABLE IF NOT EXISTS ip_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_str TEXT, type TEXT, iface TEXT, created TEXT
)''')

db.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?,?)', (user, generate_password_hash(passwd)))
db.commit()

print("WebAdmin: "+user)
print("Webpassword:  "+passwd)
EOF

# 复制原有的HTML模板文件（与3proxy版本相同）
cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>Squid 登录</title>
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
            <h3 class="mb-4 text-center">Squid 管理系统</h3>
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

# 复制index.html（与3proxy版本相同，只需要改标题）
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>Squid 管理面板</title>
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
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-dark mb-4">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="bi bi-shield-check"></i> Squid 管理系统
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
                        <small>Squid 状态</small>
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
                                        <input type="text" class="form-control" name="iprange" placeholder="192.168.1.2-254">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">端口范围</label>
                                        <input type="text" class="form-control" name="portrange" placeholder="20000-30000">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">用户名前缀</label>
                                        <input type="text" class="form-control" name="userprefix" placeholder="user">
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

        // 时间更新
        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = 
                now.toLocaleString('zh-CN', { hour12: false });
        }
        setInterval(updateTime, 1000);
        updateTime();

        // 系统监控 - 注意这里检查的是squid而不是3proxy
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
                    
                    // Squid状态
                    const statusIcon = document.getElementById('proxyStatus');
                    const statusInfo = document.getElementById('proxyInfo');
                    if (data.proxy.running) {
                        statusIcon.innerHTML = '<i class="bi bi-circle-fill text-success"></i>';
                        statusInfo.textContent = `PID: ${data.proxy.pid} | 连接: ${data.proxy.connections}`;
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
            // 加载前先验证选中的组是否还存在
            const currentSelected = new Set(selectedGroups);
            
            showLoading();
            fetch('/api/proxy_groups')
                .then(res => res.json())
                .then(groups => {
                    const container = document.getElementById('proxyGroups');
                    container.innerHTML = '';
                    
                    // 获取当前存在的C段列表
                    const existingSegments = new Set(groups.map(g => g.c_segment));
                    
                    // 清理已不存在的选中项
                    currentSelected.forEach(cseg => {
                        if (!existingSegments.has(cseg)) {
                            selectedGroups.delete(cseg);
                        }
                    });
                    
                    groups.forEach(group => {
                        const card = document.createElement('div');
                        card.className = 'proxy-card';
                        
                        // 如果这个组在选中集合中，添加选中样式
                        if (selectedGroups.has(group.c_segment)) {
                            card.classList.add('selected');
                        }
                        card.innerHTML = `
                            <div class="row align-items-center">
                                <div class="col-md-7">
                                    <h6 class="mb-2 d-flex align-items-center">
                                        <input type="checkbox" class="form-check-input me-2" 
                                               data-group="${group.c_segment}" onclick="event.stopPropagation();">
                                        <i class="bi bi-hdd-network text-primary me-2"></i>
                                        <strong>${group.c_segment}.x</strong>
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
                                </div>
                                <div class="col-md-5 text-end">
                                    <div class="btn-toolbar justify-content-end" role="toolbar">
                                        <div class="btn-group btn-group-sm" role="group">
                                            <button class="btn btn-primary" 
                                                    onclick="event.stopPropagation(); viewProxyGroup('${group.c_segment}')"
                                                    title="查看详情">
                                                <i class="bi bi-eye"></i> 查看
                                            </button>
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
                            // 如果点击的是按钮或输入框，不处理
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
                        
                        // 复选框事件（阻止冒泡）
                        const checkbox = card.querySelector('input[type="checkbox"]');
                        
                        // 如果这个组在选中集合中，勾选复选框
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
            // 清空之前的选择
            selectedProxies.clear();
            
            showLoading();
            fetch(`/api/proxy_group/${cSegment}`)
                .then(res => res.json())
                .then(proxies => {
                    const content = document.getElementById('proxyDetailContent');
                    const firstProxy = proxies[0] || {};
                    
                    // 构建完整的HTML，确保表格结构正确
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
                            <table class="table table-sm" style="width: 100%; min-width: 900px;">
                                <thead style="background: #343a40; color: white;">
                                    <tr>
                                        <th style="width: 40px; text-align: center;">选</th>
                                        <th style="width: 60px;">ID</th>
                                        <th style="width: 120px;">IP地址</th>
                                        <th style="width: 80px; text-align: center;">端口</th>
                                        <th style="width: 120px;">用户名</th>
                                        <th style="width: 200px;">密码</th>
                                        <th style="width: 70px; text-align: center;">状态</th>
                                        <th style="width: 100px; text-align: center;">操作</th>
                                    </tr>
                                </thead>
                                <tbody>`;
                    
                    // 逐行构建表格内容
                    proxies.forEach((proxy, index) => {
                        const rowClass = index % 2 === 0 ? 'table-light' : '';
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
                                <td style="padding: 8px 4px;">
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
                    
                    // 一次性设置内容
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
                    
                    // 初始化选中数量
                    updateSelectedCount();
                    
                    hideLoading();
                    const modal = new bootstrap.Modal(document.getElementById('proxyDetailModal'));
                    
                    // 监听模态框关闭事件，清空选择
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
            document.getElementById('selectedCount').textContent = count;
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

        // 代理组操作
        function deleteGroup(cSegment) {
            if (!confirm(`确定要删除 ${cSegment}.x 段的所有代理吗？`)) return;
            
            showLoading();
            fetch(`/api/delete_group/${cSegment}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    showToast(`已删除 ${cSegment}.x 段代理组`);
                    // 从选中集合中移除已删除的组
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

        // 单个代理操作
        function toggleProxy(id, enable) {
            const action = enable ? 'enableproxy' : 'disableproxy';
            fetch(`/${action}/${id}`)
                .then(res => res.json())
                .then(data => {
                    showToast(`代理已${enable ? '启用' : '禁用'}`);
                    // 刷新当前模态框内容
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
                    // 重新加载当前代理组
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
                    // 导出后清空选择
                    selectedProxies.clear();
                    updateSelectedCount();
                    // 取消全选
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
                    
                    // 从响应头获取文件名
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
                    
                    // 导出后清空选择
                    selectedGroups.clear();
                    // 取消所有复选框的选中状态
                    document.querySelectorAll('.proxy-card input[type="checkbox"]').forEach(cb => {
                        cb.checked = false;
                    });
                    // 移除所有卡片的选中样式
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
        
        // 复制密码功能
        function copyPassword(password, id) {
            const tempInput = document.createElement('input');
            tempInput.style = 'position: absolute; left: -9999px';
            tempInput.value = password;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand('copy');
            document.body.removeChild(tempInput);
            
            showToast('密码已复制到剪贴板', 'success');
            
            // 可选：更改按钮图标表示已复制
            const btn = event.target.closest('button');
            const icon = btn.querySelector('i');
            icon.className = 'bi bi-check';
            setTimeout(() => {
                icon.className = 'bi bi-clipboard';
            }, 2000);
        }
    </script>
</body>
</html>
EOF

# --------- Systemd服务 ---------
cat > /etc/systemd/system/squid-web.service <<EOF
[Unit]
Description=Squid Web管理后台
After=network.target redis-server.service squid.service

[Service]
Type=simple
WorkingDirectory=$WORKDIR
ExecStart=$WORKDIR/venv/bin/python3 $WORKDIR/manage.py $PORT
Restart=always
User=root
Environment="PYTHONUNBUFFERED=1"
LimitNOFILE=2000000
LimitNPROC=2000000

[Install]
WantedBy=multi-user.target
EOF

# 确保Squid服务配置正确
mkdir -p /etc/systemd/system/squid.service.d
cat > /etc/systemd/system/squid.service.d/override.conf <<EOF
[Service]
LimitNOFILE=2000000
LimitNPROC=2000000
EOF

# 初始化数据库
cd $WORKDIR
export ADMINUSER
export ADMINPASS
$WORKDIR/venv/bin/python3 init_db.py

# 保存登录凭据
cat > $CREDS_FILE <<EOF
Web管理地址: http://$(get_local_ip):${PORT}
管理员用户名: $ADMINUSER
管理员密码: $ADMINPASS
安装时间: $(date)
EOF
chmod 600 $CREDS_FILE

# 启动服务
systemctl daemon-reload
systemctl enable squid
systemctl enable squid-web

# 停止旧服务
systemctl stop squid 2>/dev/null || true
systemctl stop squid-web 2>/dev/null || true

# 启动Squid和Web服务
systemctl start squid
sleep 2
systemctl start squid-web

# 验证服务状态
sleep 3
if pgrep squid > /dev/null; then
    echo -e "\033[32mSquid 已成功启动\033[0m"
else
    echo -e "\033[31m警告: Squid 未能启动，请检查配置\033[0m"
fi

echo -e "\n========= 部署完成！========="
MYIP=$(get_local_ip)
echo -e "浏览器访问：\n  \033[36mhttp://$MYIP:${PORT}\033[0m"
echo "Web管理用户名: $ADMINUSER"
echo "Web管理密码:  $ADMINPASS"
echo -e "\n功能说明："
echo "1. 基于 Squid 实现，性能更强大"
echo "2. 支持每个代理独立的IP和端口"
echo "3. 动态生成ACL规则，精确控制访问"
echo "4. 支持万级代理规模"
echo -e "\nSquid 优势："
echo "- 更强大的缓存功能"
echo "- 更好的性能和稳定性"
echo "- 更丰富的访问控制"
echo "- 企业级特性支持"
echo -e "\n常用命令："
echo "查看登录信息: bash $0 show"
echo "卸载系统: bash $0 uninstall"
echo "重新安装: bash $0 reinstall"
echo "查看Squid状态: systemctl status squid"
echo "查看Squid日志: tail -f /var/log/squid/access.log"
