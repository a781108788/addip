#!/bin/bash
set -e

WORKDIR=/opt/3proxy-web
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_PATH=/usr/local/etc/3proxy/3proxy.cfg
LOGFILE=/usr/local/etc/3proxy/3proxy.log
BACKUP_DIR=/opt/3proxy-backup

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

function show_admin_info() {
    if [[ -f "$WORKDIR/.admin_info" ]]; then
        echo -e "\n========= 管理员信息 ========="
        cat "$WORKDIR/.admin_info"
        echo -e "\n============================="
    else
        echo "未找到管理员信息文件"
    fi
}

function uninstall_3proxy_web() {
    systemctl stop 3proxy-web 2>/dev/null || true
    systemctl stop 3proxy-autostart 2>/dev/null || true
    systemctl stop 3proxy-health-check 2>/dev/null || true
    systemctl disable 3proxy-web 2>/dev/null || true
    systemctl disable 3proxy-autostart 2>/dev/null || true
    systemctl disable 3proxy-health-check 2>/dev/null || true
    rm -rf $WORKDIR
    rm -f /etc/systemd/system/3proxy-web.service
    rm -f /etc/systemd/system/3proxy-autostart.service
    rm -f /etc/systemd/system/3proxy-health-check.timer
    rm -f /etc/systemd/system/3proxy-health-check.service
    rm -f /usr/local/bin/3proxy
    rm -rf /usr/local/etc/3proxy
    rm -f /etc/cron.d/3proxy-backup
    rm -f /etc/logrotate.d/3proxy
    rm -rf $BACKUP_DIR
    systemctl daemon-reload
    echo -e "\033[31m3proxy Web管理及全部相关内容已卸载。\033[0m"
}

if [[ "$1" == "uninstall" ]]; then
    uninstall_3proxy_web
    exit 0
fi

if [[ "$1" == "info" ]]; then
    show_admin_info
    exit 0
fi

if [[ "$1" == "reinstall" ]]; then
    uninstall_3proxy_web
    echo -e "\033[32m正在重新安装...\033[0m"
fi

PORT=$((RANDOM%55534+10000))
ADMINUSER="admin$RANDOM"
ADMINPASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)

echo -e "\n========= 1. 自动安装 3proxy 和依赖 =========\n"
apt update
apt install -y gcc make git wget python3 python3-pip python3-venv sqlite3 cron logrotate \
    python3-dev libssl-dev libffi-dev build-essential \
    htop iotop nethogs vnstat redis-server

# 系统优化
echo -e "\n========= 优化系统参数 =========\n"
cat >> /etc/sysctl.conf <<EOF
# 3proxy 优化参数
net.ipv4.ip_forward=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=8192
net.core.somaxconn=65535
net.ipv4.tcp_fastopen=3
net.core.netdev_max_backlog=5000
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.ip_local_port_range=10000 65535
EOF
sysctl -p

# 文件描述符限制
cat >> /etc/security/limits.conf <<EOF
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF

if [ ! -f "$THREEPROXY_PATH" ]; then
    cd /tmp
    rm -rf 3proxy
    git clone --depth=1 https://github.com/z3APA3A/3proxy.git
    cd 3proxy
    make -f Makefile.Linux
    mkdir -p /usr/local/bin /usr/local/etc/3proxy
    cp bin/3proxy /usr/local/bin/3proxy
    chmod +x /usr/local/bin/3proxy
fi

if [ ! -f "$PROXYCFG_PATH" ]; then
cat > $PROXYCFG_PATH <<EOF
daemon
maxconn 10000
nserver 8.8.8.8
nserver 1.1.1.1
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
auth none
proxy -p3128
log $LOGFILE D
logformat "L%Y-%m-%d %H:%M:%S %z %N.%p %E %U %C:%c %R:%r %O %I %h %T"
rotate 10
EOF
fi

# 创建备份目录
mkdir -p $BACKUP_DIR

# 日志轮换配置
cat > /etc/logrotate.d/3proxy <<EOF
$LOGFILE {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        /usr/bin/killall -USR1 3proxy 2>/dev/null || true
    endscript
}
EOF

# 自动备份配置
cat > /etc/cron.d/3proxy-backup <<EOF
# 每天凌晨2点备份数据库
0 2 * * * root cd $WORKDIR && sqlite3 3proxy.db ".backup '$BACKUP_DIR/3proxy-\$(date +\%Y\%m\%d).db'" 2>/dev/null
# 保留最近7天的备份
0 3 * * * root find $BACKUP_DIR -name "3proxy-*.db" -mtime +7 -delete
# 每小时更新流量统计
0 * * * * root cd $WORKDIR && /opt/3proxy-web/venv/bin/python3 update_traffic.py
EOF

echo -e "\n========= 2. 部署 Python Web 管理环境 =========\n"
mkdir -p $WORKDIR/templates $WORKDIR/static
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate
pip install flask flask_login flask_wtf wtforms Werkzeug \
    psutil requests pandas openpyxl redis flask-caching \
    flask-limiter apscheduler --break-system-packages

# ------------------- manage.py (修复版主后端) -------------------
cat > $WORKDIR/manage.py << 'EOF'
import os, sqlite3, random, string, re, collections, json, time
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from io import BytesIO
import psutil
import requests
import pandas as pd
import redis
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import threading
import subprocess

DB = '3proxy.db'
SECRET = 'changeme_this_is_secret_' + os.urandom(16).hex()
import sys
PORT = int(sys.argv[1]) if len(sys.argv)>1 else 9999
THREEPROXY_PATH = '/usr/local/bin/3proxy'
PROXYCFG_PATH = '/usr/local/etc/3proxy/3proxy.cfg'
LOGFILE = '/usr/local/etc/3proxy/3proxy.log'
INTERFACES_FILE = '/etc/network/interfaces'

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = SECRET
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 缓存配置
cache = Cache(app, config={'CACHE_TYPE': 'redis', 'CACHE_REDIS_URL': 'redis://localhost:6379/0'})

# 速率限制
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Redis连接
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# 后台调度器
scheduler = BackgroundScheduler()
scheduler.start()

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def detect_nic():
    for nic in os.listdir('/sys/class/net'):
        if nic.startswith('e') or nic.startswith('en') or nic.startswith('eth'):
            return nic
    return 'eth0'

# 初始化数据库表
def init_enhanced_db():
    db = get_db()
    # 流量统计表
    db.execute('''CREATE TABLE IF NOT EXISTS traffic_stats (
        cseg TEXT PRIMARY KEY,
        total_requests INTEGER DEFAULT 0,
        total_bytes BIGINT DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    db.execute('''CREATE TABLE IF NOT EXISTS system_stats (
        timestamp TIMESTAMP PRIMARY KEY,
        cpu_percent REAL,
        memory_percent REAL,
        disk_percent REAL,
        network_in BIGINT,
        network_out BIGINT,
        active_proxies INTEGER,
        total_connections INTEGER
    )''')
    
    db.execute('''CREATE TABLE IF NOT EXISTS log_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date DATE,
        cseg TEXT,
        top_destinations TEXT,
        total_requests INTEGER,
        total_bytes BIGINT,
        unique_users INTEGER,
        anomalies TEXT
    )''')
    
    # 添加新字段到proxy表
    try:
        db.execute('ALTER TABLE proxy ADD COLUMN health_status TEXT DEFAULT "unknown"')
        db.execute('ALTER TABLE proxy ADD COLUMN last_health_check TIMESTAMP')
        db.execute('ALTER TABLE proxy ADD COLUMN response_time REAL DEFAULT 0')
        db.execute('ALTER TABLE proxy ADD COLUMN connection_count INTEGER DEFAULT 0')
        db.execute('ALTER TABLE proxy ADD COLUMN total_traffic BIGINT DEFAULT 0')
    except:
        pass
    
    db.commit()
    db.close()

init_enhanced_db()

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password_hash = password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cur = db.execute("SELECT id,username,password FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    db.close()
    if row:
        return User(row[0], row[1], row[2])
    return None

def reload_3proxy():
    os.system(f'python3 {os.path.join(os.path.dirname(__file__), "config_gen.py")}')
    os.system(f'pkill -USR1 3proxy || (pkill 3proxy; {THREEPROXY_PATH} {PROXYCFG_PATH} &)')

# 获取已有代理的C段列表
@app.route('/api/available_csegs')
@login_required
def available_csegs():
    db = get_db()
    rows = db.execute("SELECT DISTINCT SUBSTR(ip, 1, LENGTH(ip) - LENGTH(SUBSTR(ip, LENGTH(REPLACE(ip, '.', '')) - LENGTH(REPLACE(ip, '.', '')) + 2))) as cseg FROM proxy ORDER BY cseg").fetchall()
    csegs = [row[0] for row in rows]
    db.close()
    return jsonify(csegs)

# 系统监控
@app.route('/api/system_stats')
@login_required
@cache.cached(timeout=5)
def system_stats():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()
    
    # 获取活跃代理数
    db = get_db()
    active_proxies = db.execute("SELECT COUNT(*) FROM proxy WHERE enabled=1").fetchone()[0]
    
    # 获取当前连接数
    try:
        connections = len([conn for conn in psutil.net_connections() if conn.laddr.port in get_proxy_ports()])
    except:
        connections = 0
    
    # 保存到数据库
    db.execute('''INSERT INTO system_stats 
        (timestamp, cpu_percent, memory_percent, disk_percent, network_in, network_out, active_proxies, total_connections)
        VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)''',
        (cpu_percent, memory.percent, disk.percent, net_io.bytes_recv, net_io.bytes_sent, active_proxies, connections))
    db.commit()
    db.close()
    
    return jsonify({
        'cpu': cpu_percent,
        'memory': memory.percent,
        'disk': disk.percent,
        'network_in': net_io.bytes_recv,
        'network_out': net_io.bytes_sent,
        'active_proxies': active_proxies,
        'connections': connections,
        'uptime': time.time() - psutil.boot_time()
    })

# 手动代理健康检查
@app.route('/api/check_proxy_health', methods=['POST'])
@login_required
def check_proxy_health_api():
    proxy_ids = request.json.get('proxy_ids', [])
    
    db = get_db()
    if proxy_ids:
        # 检查指定代理
        placeholders = ','.join('?' * len(proxy_ids))
        proxies = db.execute(f"SELECT id, ip, port, username, password FROM proxy WHERE id IN ({placeholders}) AND enabled=1", proxy_ids).fetchall()
    else:
        # 检查所有代理
        proxies = db.execute("SELECT id, ip, port, username, password FROM proxy WHERE enabled=1").fetchall()
    
    results = []
    for proxy in proxies:
        try:
            start_time = time.time()
            proxy_url = f"http://{proxy['username']}:{proxy['password']}@{proxy['ip']}:{proxy['port']}"
            response = requests.get('http://httpbin.org/ip', 
                                  proxies={'http': proxy_url, 'https': proxy_url}, 
                                  timeout=10)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                status = 'healthy'
            else:
                status = 'unhealthy'
        except:
            status = 'dead'
            response_time = 999
        
        # 更新健康状态
        db.execute('''UPDATE proxy SET health_status=?, last_health_check=datetime('now'), response_time=? 
                     WHERE id=?''', (status, response_time, proxy['id']))
        
        results.append({
            'id': proxy['id'],
            'ip': proxy['ip'],
            'port': proxy['port'],
            'status': status,
            'response_time': response_time
        })
    
    db.commit()
    db.close()
    
    return jsonify({'results': results, 'total_checked': len(results)})

# 批量测试代理连通性
@app.route('/api/test_proxy_connectivity', methods=['POST'])
@login_required
def test_proxy_connectivity():
    proxy_ids = request.json.get('proxy_ids', [])
    test_url = request.json.get('test_url', 'http://httpbin.org/ip')
    
    db = get_db()
    placeholders = ','.join('?' * len(proxy_ids))
    proxies = db.execute(f"SELECT id, ip, port, username, password FROM proxy WHERE id IN ({placeholders})", proxy_ids).fetchall()
    
    results = []
    for proxy in proxies:
        try:
            start_time = time.time()
            proxy_url = f"http://{proxy['username']}:{proxy['password']}@{proxy['ip']}:{proxy['port']}"
            response = requests.get(test_url, 
                                  proxies={'http': proxy_url, 'https': proxy_url}, 
                                  timeout=10)
            response_time = time.time() - start_time
            
            results.append({
                'id': proxy['id'],
                'ip': proxy['ip'],
                'port': proxy['port'],
                'success': response.status_code == 200,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_text': response.text[:200] if response.status_code == 200 else ''
            })
        except Exception as e:
            results.append({
                'id': proxy['id'],
                'ip': proxy['ip'],
                'port': proxy['port'],
                'success': False,
                'error': str(e)
            })
    
    db.close()
    return jsonify({'results': results})

# 按C段分组的健康检查
@app.route('/api/cseg_health/<cseg>')
@login_required
def cseg_health(cseg):
    db = get_db()
    proxies = db.execute('''SELECT id, ip, health_status, response_time 
                           FROM proxy WHERE ip LIKE ? AND enabled=1''', 
                        (cseg + '.%',)).fetchall()
    
    health_stats = {
        'total': len(proxies),
        'healthy': sum(1 for p in proxies if p['health_status'] == 'healthy'),
        'unhealthy': sum(1 for p in proxies if p['health_status'] == 'unhealthy'),
        'dead': sum(1 for p in proxies if p['health_status'] == 'dead'),
        'unknown': sum(1 for p in proxies if p['health_status'] == 'unknown'),
        'avg_response_time': sum(p['response_time'] for p in proxies) / len(proxies) if proxies else 0
    }
    
    db.close()
    return jsonify(health_stats)

# 流量统计（改为读取已有代理的C段）
@app.route('/api/cseg_traffic_stats')
@login_required
def cseg_traffic_stats():
    db = get_db()
    
    # 获取所有C段
    csegs = db.execute('''SELECT DISTINCT SUBSTR(ip, 1, LENGTH(ip) - LENGTH(SUBSTR(ip, LENGTH(REPLACE(ip, '.', '')) - LENGTH(REPLACE(ip, '.', '')) + 2))) as cseg 
                         FROM proxy ORDER BY cseg''').fetchall()
    
    stats = []
    for row in csegs:
        cseg = row[0]
        # 获取该C段的代理数量
        proxy_count = db.execute("SELECT COUNT(*) FROM proxy WHERE ip LIKE ?", (cseg + '.%',)).fetchone()[0]
        enabled_count = db.execute("SELECT COUNT(*) FROM proxy WHERE ip LIKE ? AND enabled=1", (cseg + '.%',)).fetchone()[0]
        
        # 获取流量统计
        traffic_row = db.execute("SELECT total_requests, total_bytes, last_updated FROM traffic_stats WHERE cseg=?", (cseg,)).fetchone()
        
        stats.append({
            'cseg': cseg,
            'proxy_count': proxy_count,
            'enabled_count': enabled_count,
            'total_requests': traffic_row[0] if traffic_row else 0,
            'total_bytes': traffic_row[1] if traffic_row else 0,
            'last_updated': traffic_row[2] if traffic_row else None
        })
    
    db.close()
    return jsonify(stats)

# 批量导入改进
@app.route('/import_proxies', methods=['POST'])
@login_required
def import_proxies():
    if 'file' not in request.files:
        flash('没有选择文件')
        return redirect('/')
    
    file = request.files['file']
    if file.filename == '':
        flash('没有选择文件')
        return redirect('/')
    
    count = 0
    db = get_db()
    
    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
            for _, row in df.iterrows():
                db.execute('''INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix, health_status) 
                             VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)''',
                           (row['ip'], row['port'], row['username'], row['password'], 
                            row.get('ip_range', ''), row.get('port_range', ''), row.get('user_prefix', ''), 'unknown'))
                count += 1
                
        elif file.filename.endswith('.json'):
            data = json.load(file)
            for item in data:
                db.execute('''INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix, health_status) 
                             VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)''',
                           (item['ip'], item['port'], item['username'], item['password'],
                            item.get('ip_range', ''), item.get('port_range', ''), item.get('user_prefix', ''), 'unknown'))
                count += 1
                
        elif file.filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file)
            for _, row in df.iterrows():
                db.execute('''INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix, health_status) 
                             VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)''',
                           (row['ip'], row['port'], row['username'], row['password'],
                            row.get('ip_range', ''), row.get('port_range', ''), row.get('user_prefix', ''), 'unknown'))
                count += 1
        
        db.commit()
        reload_3proxy()
        flash(f'成功导入 {count} 个代理')
        
    except Exception as e:
        db.rollback()
        flash(f'导入失败: {str(e)}')
    finally:
        db.close()
    
    return redirect('/')

# 日志分析
@app.route('/api/log_analysis')
@login_required
def log_analysis():
    try:
        # 分析最近的日志
        analysis = analyze_3proxy_logs()
        return jsonify(analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def analyze_3proxy_logs():
    """分析3proxy日志文件"""
    analysis = {
        'top_destinations': {},
        'traffic_by_cseg': {},
        'hourly_distribution': {},
        'anomalies': [],
        'total_requests': 0,
        'total_bytes': 0
    }
    
    if not os.path.exists(LOGFILE):
        return analysis
    
    # 使用subprocess读取最近的日志
    try:
        # 获取最近10000行日志
        result = subprocess.run(['tail', '-n', '10000', LOGFILE], 
                              capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        for line in lines:
            if not line:
                continue
            
            parts = line.split()
            if len(parts) < 10:
                continue
            
            try:
                # 解析日志格式
                timestamp = f"{parts[0][1:]} {parts[1]}"
                user = parts[5]
                src_ip = parts[6].split(':')[0]
                dest = parts[7]
                status = parts[8]
                bytes_transferred = int(parts[9]) if parts[9].isdigit() else 0
                
                # 统计
                analysis['total_requests'] += 1
                analysis['total_bytes'] += bytes_transferred
                
                # 按目标统计
                dest_host = dest.split(':')[0]
                analysis['top_destinations'][dest_host] = analysis['top_destinations'].get(dest_host, 0) + 1
                
                # 按C段统计流量
                cseg = '.'.join(src_ip.split('.')[:3])
                if cseg not in analysis['traffic_by_cseg']:
                    analysis['traffic_by_cseg'][cseg] = {'requests': 0, 'bytes': 0}
                analysis['traffic_by_cseg'][cseg]['requests'] += 1
                analysis['traffic_by_cseg'][cseg]['bytes'] += bytes_transferred
                
                # 按小时统计
                hour = timestamp.split()[1].split(':')[0]
                analysis['hourly_distribution'][hour] = analysis['hourly_distribution'].get(hour, 0) + 1
                
                # 检测异常
                if status != '200' or bytes_transferred > 100 * 1024 * 1024:  # 100MB
                    analysis['anomalies'].append({
                        'time': timestamp,
                        'user': user,
                        'src': src_ip,
                        'dest': dest,
                        'status': status,
                        'bytes': bytes_transferred
                    })
                    
            except Exception as e:
                continue
        
        # 只保留前10个目标
        analysis['top_destinations'] = dict(sorted(analysis['top_destinations'].items(), 
                                                  key=lambda x: x[1], reverse=True)[:10])
        
        # 只保留最近10个异常
        analysis['anomalies'] = analysis['anomalies'][-10:]
        
    except Exception as e:
        analysis['error'] = str(e)
    
    return analysis

# 导出报告
@app.route('/export_report/<report_type>')
@login_required
def export_report(report_type):
    db = get_db()
    
    if report_type == 'health':
        # 导出健康检查报告
        data = db.execute('''SELECT p.id, p.ip, p.port, p.username, p.health_status, 
                            p.response_time, p.last_health_check
                            FROM proxy p ORDER BY p.ip''').fetchall()
        df = pd.DataFrame(data)
        
    elif report_type == 'traffic':
        # 导出流量统计报告
        data = db.execute('''SELECT * FROM traffic_stats''').fetchall()
        df = pd.DataFrame(data)
        
    elif report_type == 'system':
        # 导出系统监控报告
        data = db.execute('''SELECT * FROM system_stats 
                            WHERE timestamp > datetime('now', '-7 days')
                            ORDER BY timestamp DESC''').fetchall()
        df = pd.DataFrame(data)
    
    elif report_type == 'full':
        # 综合报告
        with pd.ExcelWriter('/tmp/3proxy_report.xlsx', engine='openpyxl') as writer:
            # 代理列表
            proxies = db.execute('SELECT * FROM proxy').fetchall()
            pd.DataFrame(proxies).to_excel(writer, sheet_name='代理列表', index=False)
            
            # 流量统计
            traffic = db.execute('SELECT * FROM traffic_stats').fetchall()
            pd.DataFrame(traffic).to_excel(writer, sheet_name='流量统计', index=False)
            
            # 系统监控
            system = db.execute('''SELECT * FROM system_stats 
                                  WHERE timestamp > datetime('now', '-7 days')''').fetchall()
            pd.DataFrame(system).to_excel(writer, sheet_name='系统监控', index=False)
        
        db.close()
        return send_file('/tmp/3proxy_report.xlsx', as_attachment=True, 
                        download_name=f'3proxy_report_{datetime.now().strftime("%Y%m%d")}.xlsx')
    
    db.close()
    
    # 导出为Excel
    output = BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)
    
    return send_file(output, as_attachment=True, 
                     download_name=f'{report_type}_report_{datetime.now().strftime("%Y%m%d")}.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# 获取代理端口列表
def get_proxy_ports():
    db = get_db()
    ports = [row[0] for row in db.execute("SELECT DISTINCT port FROM proxy WHERE enabled=1").fetchall()]
    db.close()
    return ports

# 原有的路由保持不变...
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        db = get_db()
        cur = db.execute('SELECT id,username,password FROM users WHERE username=?', (request.form['username'],))
        row = cur.fetchone()
        db.close()
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
    db = get_db()
    proxies = db.execute('SELECT * FROM proxy ORDER BY ip, port').fetchall()
    users = db.execute('SELECT id,username FROM users').fetchall()
    ip_configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC').fetchall()
    
    db.close()
    return render_template('index.html', 
                         proxies=proxies, 
                         users=users, 
                         ip_configs=ip_configs,
                         default_iface=detect_nic())

@app.route('/addproxy', methods=['POST'])
@login_required
def addproxy():
    ip = request.form['ip']
    port = int(request.form['port'])
    username = request.form['username']
    password = request.form['password'] or ''.join(random.choices(string.ascii_letters+string.digits, k=12))
    user_prefix = request.form.get('userprefix','')
    db = get_db()
    db.execute('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix, health_status) VALUES (?,?,?,?,1,?,?,?,?)', 
        (ip, port, username, password, ip, port, user_prefix, 'unknown'))
    db.commit()
    db.close()
    reload_3proxy()
    flash('已添加代理')
    return redirect('/')

@app.route('/batchaddproxy', methods=['POST'])
@login_required
def batchaddproxy():
    iprange = request.form.get('iprange')
    portrange = request.form.get('portrange')
    userprefix = request.form.get('userprefix')
    if iprange and portrange and userprefix:
        m = re.match(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", iprange.strip())
        if not m:
            flash("IP范围格式错误。例：192.168.1.2-254")
            return redirect('/')
        ip_base = m.group(1)
        start = int(m.group(2))
        end = int(m.group(3))
        ips = [f"{ip_base}{i}" for i in range(start, end+1)]
        m2 = re.match(r"(\d+)-(\d+)", portrange.strip())
        if not m2:
            flash("端口范围格式错误。例：20000-30000")
            return redirect('/')
        port_start = int(m2.group(1))
        port_end = int(m2.group(2))
        all_ports = list(range(port_start, port_end+1))
        if len(all_ports) < len(ips):
            flash("端口区间不足以分配全部IP")
            return redirect('/')
        random.shuffle(all_ports)
        db = get_db()
        count = 0
        for i, ip in enumerate(ips):
            port = all_ports[i]
            uname = userprefix + ''.join(random.choices(string.ascii_lowercase+string.digits, k=4))
            pw = ''.join(random.choices(string.ascii_letters+string.digits, k=12))
            db.execute('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix, health_status) VALUES (?,?,?,?,1,?,?,?,?)', 
                (ip, port, uname, pw, iprange, portrange, userprefix, 'unknown'))
            count += 1
        db.commit()
        db.close()
        reload_3proxy()
        flash(f'批量范围添加完成，共添加{count}条代理')
        return redirect('/')
    batch_data = request.form.get('batchproxy','').strip().splitlines()
    db = get_db()
    count = 0
    base_idx = db.execute("SELECT MAX(id) FROM proxy").fetchone()[0]
    if base_idx is None:
        base_idx = 0
    idx = 1
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
        db.execute('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix, health_status) VALUES (?,?,?,?,1,?,?,?,?)',
            (ip, int(port), username, password, ip, port, username, 'unknown'))
        count += 1
    db.commit()
    db.close()
    if count:
        reload_3proxy()
        flash(f'批量添加完成，共添加{count}条代理')
    return redirect('/')

@app.route('/delproxy/<int:pid>')
@login_required
def delproxy(pid):
    db = get_db()
    db.execute('DELETE FROM proxy WHERE id=?', (pid,))
    db.commit()
    db.close()
    reload_3proxy()
    flash('已删除代理')
    return redirect('/')

@app.route('/batchdelproxy', methods=['POST'])
@login_required
def batchdelproxy():
    ids = request.form.getlist('ids')
    db = get_db()
    db.executemany('DELETE FROM proxy WHERE id=?', [(i,) for i in ids])
    db.commit()
    db.close()
    reload_3proxy()
    flash(f'已批量删除 {len(ids)} 条代理')
    return redirect('/')

@app.route('/batch_enable', methods=['POST'])
@login_required
def batch_enable():
    ids = request.form.getlist('ids[]')
    if not ids:
        return "No proxies selected.", 400
    db = get_db()
    db.executemany('UPDATE proxy SET enabled=1 WHERE id=?', [(i,) for i in ids])
    db.commit()
    db.close()
    reload_3proxy()
    return '', 204

@app.route('/batch_disable', methods=['POST'])
@login_required
def batch_disable():
    ids = request.form.getlist('ids[]')
    if not ids:
        return "No proxies selected.", 400
    db = get_db()
    db.executemany('UPDATE proxy SET enabled=0 WHERE id=?', [(i,) for i in ids])
    db.commit()
    db.close()
    reload_3proxy()
    return '', 204

@app.route('/enableproxy/<int:pid>')
@login_required
def enableproxy(pid):
    db = get_db()
    db.execute('UPDATE proxy SET enabled=1 WHERE id=?', (pid,))
    db.commit()
    db.close()
    reload_3proxy()
    flash('已启用')
    return redirect('/')

@app.route('/disableproxy/<int:pid>')
@login_required
def disableproxy(pid):
    db = get_db()
    db.execute('UPDATE proxy SET enabled=0 WHERE id=?', (pid,))
    db.commit()
    db.close()
    reload_3proxy()
    flash('已禁用')
    return redirect('/')

@app.route('/adduser', methods=['POST'])
@login_required
def adduser():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    db = get_db()
    db.execute('INSERT INTO users (username, password) VALUES (?,?)', (username, password))
    db.commit()
    db.close()
    flash('已添加用户')
    return redirect('/')

@app.route('/deluser/<int:uid>')
@login_required
def deluser(uid):
    db = get_db()
    db.execute('DELETE FROM users WHERE id=?', (uid,))
    db.commit()
    db.close()
    flash('已删除用户')
    return redirect('/')

@app.route('/export_selected', methods=['POST'])
@login_required
def export_selected():
    csegs = request.form.getlist('csegs[]')
    if not csegs:
        flash("未选择C段")
        return redirect('/')
    db = get_db()
    output = ""
    export_prefix = ""
    for cseg in csegs:
        rows = db.execute("SELECT ip,port,username,password,user_prefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port", (cseg+'.%',)).fetchall()
        if rows and not export_prefix:
            export_prefix = rows[0][4] or ''
        for ip,port,user,pw,_ in rows:
            output += f"{ip}:{port}:{user}:{pw}\n"
    db.close()
    mem = BytesIO()
    mem.write(output.encode('utf-8'))
    mem.seek(0)
    filename = f"{export_prefix or 'export'}_{'_'.join(csegs)}.txt"
    return Response(mem.read(), mimetype='text/plain', headers={'Content-Disposition': f'attachment; filename={filename}'})

@app.route('/export_selected_proxy', methods=['POST'])
@login_required
def export_selected_proxy():
    ids = request.form.getlist('ids[]')
    if not ids:
        return "No proxies selected.", 400
    db = get_db()
    rows = db.execute('SELECT ip, port, username, password FROM proxy WHERE id IN (%s)' %
                      ','.join('?'*len(ids)), tuple(ids)).fetchall()
    db.close()
    output = ''
    for ip, port, user, pw in rows:
        output += f"{ip}:{port}:{user}:{pw}\n"
    mem = BytesIO()
    mem.write(output.encode('utf-8'))
    mem.seek(0)
    filename = "proxy_export.txt"
    return Response(mem.read(), mimetype='text/plain', headers={'Content-Disposition': f'attachment; filename={filename}'})

@app.route('/cnet_traffic')
@login_required
def cnet_traffic():
    stats = collections.defaultdict(int)
    if not os.path.exists(LOGFILE):
        return jsonify({})
    
    try:
        # 使用tail获取最近的日志
        result = subprocess.run(['tail', '-n', '5000', LOGFILE], 
                              capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        for line in lines:
            parts = line.split()
            if len(parts) > 9:
                try:
                    src_ip = parts[6].split(':')[0]
                    bytes_sent = int(parts[9]) if parts[9].isdigit() else 0
                    cseg = '.'.join(src_ip.split('.')[:3])
                    stats[cseg] += bytes_sent
                except:
                    pass
    except:
        pass
    
    stats_mb = {k:round(v/1024/1024,2) for k,v in stats.items()}
    
    # 更新流量统计表
    db = get_db()
    for cseg, mb in stats_mb.items():
        db.execute('''INSERT OR REPLACE INTO traffic_stats 
                     (cseg, total_bytes, last_updated)
                     VALUES (?, ?, datetime('now'))''', (cseg, mb * 1024 * 1024))
    db.commit()
    db.close()
    
    return jsonify(stats_mb)

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
    db = get_db()
    db.execute('INSERT INTO ip_config (ip_str, type, iface, created) VALUES (?,?,?,datetime("now"))', (ip_range, 'range', iface))
    db.commit()
    db.close()
    for ip in ip_list:
        os.system(f"ip addr add {ip}/24 dev {iface}")
    if mode == 'perm':
        with open(INTERFACES_FILE, 'a+') as f:
            f.write(f"\nup bash -c 'for ip in {ip_range};do ip addr add $ip/24 dev {iface}; done'\n")
            f.write(f"down bash -c 'for ip in {ip_range};do ip addr del $ip/24 dev {iface}; done'\n")
    flash("已添加IP配置")
    return redirect('/')

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv)>1 else 9999
    app.run('0.0.0.0', port, debug=False)
EOF

# --------- config_gen.py（3proxy配置生成） ---------
cat > $WORKDIR/config_gen.py << 'EOF'
import sqlite3
db = sqlite3.connect('3proxy.db')
cursor = db.execute('SELECT ip, port, username, password, enabled FROM proxy')
cfg = [
"daemon",
"maxconn 10000",
"nserver 8.8.8.8",
"nserver 1.1.1.1",
"nscache 65536",
"timeouts 1 5 30 60 180 1800 15 60",
"log /usr/local/etc/3proxy/3proxy.log D",
"logformat \"L%Y-%m-%d %H:%M:%S %z %N.%p %E %U %C:%c %R:%r %O %I %h %T\"",
"rotate 10",
"auth strong"
]
users = []
user_set = set()
for ip, port, user, pw, en in cursor:
    if en and (user, pw) not in user_set:
        users.append(f"{user}:CL:{pw}")
        user_set.add((user, pw))
cfg.append(f"users {' '.join(users)}")
db2 = sqlite3.connect('3proxy.db')
for ip, port, user, pw, en in db2.execute('SELECT ip, port, username, password, enabled FROM proxy'):
    if en:
        cfg.append(f"auth strong\nallow {user}\nproxy -n -a -p{port} -i{ip} -e{ip}")
open("/usr/local/etc/3proxy/3proxy.cfg", "w").write('\n'.join(cfg))
EOF

# --------- update_traffic.py（流量更新脚本） ---------
cat > $WORKDIR/update_traffic.py << 'EOF'
import sqlite3
import subprocess
import collections
import os

LOGFILE = '/usr/local/etc/3proxy/3proxy.log'
DB = '3proxy.db'

def update_traffic_stats():
    if not os.path.exists(LOGFILE):
        return
    
    stats = collections.defaultdict(int)
    
    try:
        # 读取最近一小时的日志
        result = subprocess.run(['tail', '-n', '10000', LOGFILE], 
                              capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        for line in lines:
            parts = line.split()
            if len(parts) > 9:
                try:
                    src_ip = parts[6].split(':')[0]
                    bytes_sent = int(parts[9]) if parts[9].isdigit() else 0
                    cseg = '.'.join(src_ip.split('.')[:3])
                    stats[cseg] += bytes_sent
                except:
                    pass
    except:
        return
    
    # 更新数据库
    db = sqlite3.connect(DB)
    for cseg, bytes_count in stats.items():
        db.execute('''INSERT OR REPLACE INTO traffic_stats 
                     (cseg, total_bytes, last_updated)
                     VALUES (?, ?, datetime('now'))''',
                   (cseg, bytes_count))
    db.commit()
    db.close()

if __name__ == '__main__':
    update_traffic_stats()
EOF

# --------- init_db.py（DB初始化） ---------
cat > $WORKDIR/init_db.py << 'EOF'
import sqlite3
from werkzeug.security import generate_password_hash
import os
user = os.environ.get('ADMINUSER')
passwd = os.environ.get('ADMINPASS')
db = sqlite3.connect('3proxy.db')
db.execute('''CREATE TABLE IF NOT EXISTS proxy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, port INTEGER, username TEXT, password TEXT, enabled INTEGER DEFAULT 1,
    ip_range TEXT, port_range TEXT, user_prefix TEXT,
    health_status TEXT DEFAULT 'unknown',
    last_health_check TIMESTAMP,
    response_time REAL DEFAULT 0,
    connection_count INTEGER DEFAULT 0,
    total_traffic BIGINT DEFAULT 0
)''')
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
print("WebPassword: "+passwd)

# 保存管理员信息到文件
with open('.admin_info', 'w') as f:
    f.write(f"Web管理地址: http://$(hostname -I | awk '{{print $1}}'):9999\n")
    f.write(f"管理员用户名: {user}\n")
    f.write(f"管理员密码: {passwd}\n")
    f.write(f"创建时间: $(date)\n")
EOF

# --------- login.html (保持美化版) ---------
cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>3proxy 登录</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --bg-gradient: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            background: var(--bg-gradient);
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            position: relative;
            overflow: hidden;
        }

        /* 动态背景粒子 */
        body::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(102, 126, 234, 0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .login-container {
            width: 100%;
            max-width: 400px;
            z-index: 1;
        }

        .login-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 3rem;
            transition: transform 0.3s ease;
        }

        .login-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
        }

        .logo-container {
            text-align: center;
            margin-bottom: 2rem;
        }

        .logo {
            width: 80px;
            height: 80px;
            background: var(--primary-gradient);
            border-radius: 20px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            color: white;
            font-weight: bold;
            margin-bottom: 1rem;
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }

        h3 {
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .subtitle {
            color: #6c757d;
            font-size: 0.9rem;
            margin-bottom: 2rem;
        }

        .form-control {
            border: 2px solid transparent;
            border-radius: 12px;
            padding: 0.75rem 1rem;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: #f8f9fa;
        }

        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
            background: white;
        }

        .form-label {
            font-weight: 600;
            color: #495057;
            margin-bottom: 0.5rem;
        }

        .btn-login {
            background: var(--primary-gradient);
            border: none;
            border-radius: 12px;
            padding: 0.75rem;
            font-size: 1rem;
            font-weight: 600;
            color: white;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .btn-login::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }

        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }

        .btn-login:active::before {
            width: 300px;
            height: 300px;
        }

        .alert {
            border-radius: 12px;
            border: none;
            padding: 1rem;
            font-weight: 500;
            background: #f8d7da;
            color: #721c24;
            animation: shake 0.5s ease-in-out;
        }

        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-10px); }
            75% { transform: translateX(10px); }
        }

        .input-group {
            position: relative;
        }

        .input-icon {
            position: absolute;
            right: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: #6c757d;
            font-size: 1.2rem;
        }

        @media (max-width: 576px) {
            .login-card {
                padding: 2rem;
                margin: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <div class="logo-container">
                <div class="logo">3P</div>
                <h3>3proxy 管理面板</h3>
                <p class="subtitle">请登录以继续</p>
            </div>
            <form method="post">
                <div class="mb-4">
                    <label class="form-label">用户名</label>
                    <div class="input-group">
                        <input type="text" class="form-control" name="username" placeholder="请输入用户名" autofocus required>
                        <span class="input-icon">👤</span>
                    </div>
                </div>
                <div class="mb-4">
                    <label class="form-label">密码</label>
                    <div class="input-group">
                        <input type="password" class="form-control" name="password" placeholder="请输入密码" required>
                        <span class="input-icon">🔒</span>
                    </div>
                </div>
                <button class="btn btn-login w-100" type="submit">登录</button>
            </form>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert mt-3">
                    <strong>⚠️</strong> {{ messages[0] }}
                </div>
              {% endif %}
            {% endwith %}
        </div>
    </div>
</body>
</html>
EOF

# --------- index.html（修复版主界面） ---------
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>3proxy 管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --danger-gradient: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
            --warning-gradient: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --info-gradient: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            --bg-light: #f8f9fa;
            --bg-dark: #0f0f1e;
            --card-light: #ffffff;
            --card-dark: #1a1a2e;
            --text-light: #212529;
            --text-dark: #e9ecef;
            --border-light: rgba(0,0,0,0.1);
            --border-dark: rgba(255,255,255,0.1);
        }

        * {
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        html, body {
            background: var(--bg-light);
            color: var(--text-light);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 300px;
            background: var(--primary-gradient);
            z-index: -1;
            opacity: 0.1;
            transform: skewY(-3deg);
            transform-origin: top left;
        }

        /* 暗色模式 */
        .dark-mode {
            background: var(--bg-dark);
            color: var(--text-dark);
        }

        .dark-mode::before {
            opacity: 0.05;
        }

        .dark-mode .card {
            background: var(--card-dark);
            border: 1px solid var(--border-dark);
            color: var(--text-dark);
        }

        .dark-mode .table {
            color: var(--text-dark);
        }

        .dark-mode .table-light {
            background: rgba(255,255,255,0.05) !important;
            color: var(--text-dark);
        }

        .dark-mode .form-control,
        .dark-mode .form-select {
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border-dark);
            color: var(--text-dark);
        }

        .dark-mode .form-control:focus,
        .dark-mode .form-select:focus {
            background: rgba(255,255,255,0.08);
            border-color: #667eea;
            color: var(--text-dark);
        }

        .dark-mode .nav-tabs {
            border-bottom-color: var(--border-dark);
        }

        .dark-mode .nav-link {
            color: var(--text-dark);
        }

        .dark-mode .nav-link.active {
            background: var(--card-dark);
            border-color: var(--border-dark) var(--border-dark) var(--card-dark);
            color: var(--text-dark);
        }

        .dark-mode .ip-group-header {
            background: rgba(102, 126, 234, 0.1);
        }

        .dark-mode .ip-group-header:hover {
            background: rgba(102, 126, 234, 0.2);
        }

        /* 卡片样式 */
        .card {
            border: none;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            overflow: hidden;
            backdrop-filter: blur(10px);
            background: rgba(255,255,255,0.9);
        }

        .dark-mode .card {
            background: rgba(26,26,46,0.9);
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.12);
        }

        /* 按钮样式 */
        .btn {
            border-radius: 10px;
            font-weight: 500;
            padding: 0.5rem 1.5rem;
            position: relative;
            overflow: hidden;
            border: none;
        }

        .btn::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255,255,255,0.3);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }

        .btn:active::before {
            width: 300px;
            height: 300px;
        }

        .btn-primary {
            background: var(--primary-gradient);
            color: white;
        }

        .btn-success {
            background: var(--success-gradient);
            color: white;
        }

        .btn-danger {
            background: var(--danger-gradient);
            color: white;
        }

        .btn-warning {
            background: var(--warning-gradient);
            color: white;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        /* 表单控件 */
        .form-control, .form-select {
            border-radius: 10px;
            border: 2px solid transparent;
            background: rgba(0,0,0,0.05);
            padding: 0.75rem 1rem;
        }

        .form-control:focus, .form-select:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
            background: white;
        }

        .dark-mode .form-control:focus,
        .dark-mode .form-select:focus {
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.5);
        }

        /* 标签页样式 */
        .nav-tabs {
            border: none;
            background: rgba(255,255,255,0.8);
            padding: 0.5rem;
            border-radius: 16px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
        }

        .dark-mode .nav-tabs {
            background: rgba(26,26,46,0.8);
        }

        .nav-link {
            border: none !important;
            border-radius: 10px;
            color: #6c757d;
            font-weight: 500;
            padding: 0.75rem 1.5rem;
            margin: 0 0.25rem;
        }

        .nav-link:hover {
            background: rgba(102, 126, 234, 0.1);
            color: #667eea;
        }

        .nav-link.active {
            background: var(--primary-gradient);
            color: white !important;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }

        /* 表格样式 */
        .table {
            border-radius: 12px;
            overflow: hidden;
        }

        .table thead th {
            background: rgba(102, 126, 234, 0.1);
            border: none;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
            padding: 1rem;
        }

        .table tbody tr {
            border-bottom: 1px solid var(--border-light);
        }

        .dark-mode .table tbody tr {
            border-bottom: 1px solid var(--border-dark);
        }

        .table tbody tr:hover {
            background: rgba(102, 126, 234, 0.05);
        }

        /* IP组头部样式 - 修复版 */
        .ip-group-header {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.15), rgba(118, 75, 162, 0.15));
            font-weight: 600;
            cursor: pointer;
            position: relative;
            border-radius: 12px !important;
            margin-bottom: 0.5rem;
        }

        .ip-group-header:hover {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.25), rgba(118, 75, 162, 0.25));
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.2);
        }

        .ip-group-header td {
            padding: 1.5rem 1.25rem !important;
            border: none !important;
        }

        .ip-group-body {
            animation: slideDown 0.3s ease-out;
        }

        .ip-group-body.collapsed {
            display: none !important;
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* 徽章样式 */
        .badge {
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-weight: 500;
            font-size: 0.85rem;
        }

        .text-bg-success {
            background: var(--success-gradient) !important;
        }

        .text-bg-secondary {
            background: linear-gradient(135deg, #667eea, #764ba2) !important;
        }

        .bg-info {
            background: var(--info-gradient) !important;
        }

        .bg-secondary {
            background: linear-gradient(135deg, #8e9eab, #eef2f3) !important;
            color: #333 !important;
        }

        /* 切换模式按钮 */
        .switch-mode {
            position: fixed;
            top: 2rem;
            right: 2rem;
            z-index: 1000;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: rgba(255,255,255,0.9);
            border: none;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        .dark-mode .switch-mode {
            background: rgba(26,26,46,0.9);
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }

        .switch-mode:hover {
            transform: rotate(180deg) scale(1.1);
        }

        /* 提示框样式 */
        .alert {
            border-radius: 12px;
            border: none;
            padding: 1.25rem;
            font-weight: 500;
            animation: slideInUp 0.5s ease-out;
        }

        .alert-success {
            background: linear-gradient(135deg, rgba(17, 153, 142, 0.2), rgba(56, 239, 125, 0.2));
            color: #0f5132;
            border-left: 4px solid #38ef7d;
        }

        @keyframes slideInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* 滚动条样式 */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.05);
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb {
            background: var(--primary-gradient);
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(135deg, #764ba2, #667eea);
        }

        /* 加载动画 */
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* 搜索框样式 */
        #searchBox {
            background: rgba(255,255,255,0.9);
            border: 2px solid transparent;
            padding-left: 2.5rem;
            position: relative;
        }

        #searchBox:focus {
            background: white;
            border-color: #667eea;
        }

        /* 搜索图标 */
        .search-wrapper {
            position: relative;
        }

        .search-wrapper::before {
            content: '🔍';
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            opacity: 0.5;
        }

        /* 复选框样式 */
        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
            position: relative;
            -webkit-appearance: none;
            appearance: none;
            background: rgba(0,0,0,0.1);
            border-radius: 4px;
            transition: all 0.3s;
        }

        input[type="checkbox"]:checked {
            background: var(--primary-gradient);
        }

        input[type="checkbox"]:checked::after {
            content: '✓';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            color: white;
            font-weight: bold;
        }

        /* 标题渐变 */
        h5 {
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
        }

        .text-success h5 {
            background: var(--success-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .text-warning h5 {
            background: var(--warning-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        /* 响应式优化 */
        @media (max-width: 768px) {
            .card {
                margin-bottom: 1rem;
            }
            
            .nav-link {
                padding: 0.5rem 1rem;
                font-size: 0.9rem;
            }
            
            .switch-mode {
                top: 1rem;
                right: 1rem;
                width: 40px;
                height: 40px;
                font-size: 1.2rem;
            }
        }

        /* 组选择框增强 */
        .group-select {
            margin-left: auto;
            margin-right: 1rem;
        }

        /* 固定表头毛玻璃效果 */
        .sticky-top {
            backdrop-filter: blur(10px);
            background: rgba(255,255,255,0.9) !important;
        }

        .dark-mode .sticky-top {
            background: rgba(26,26,46,0.9) !important;
        }

        /* 箭头动画 */
        .arrow-icon {
            display: inline-block;
            transition: transform 0.3s ease;
            font-size: 1.2rem;
            color: #667eea;
        }

        .ip-group-header.expanded .arrow-icon {
            transform: rotate(90deg);
        }

        /* 流量统计样式 */
        .cnet-traffic {
            position: relative;
            min-width: 100px;
        }

        /* 表单标签样式 */
        .form-label {
            font-weight: 600;
            color: #495057;
            margin-bottom: 0.5rem;
        }

        .dark-mode .form-label {
            color: #adb5bd;
        }

        /* 系统监控仪表板样式 */
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: rgba(255,255,255,0.1);
            transform: rotate(45deg);
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            margin: 0.5rem 0;
        }

        .stat-label {
            font-size: 0.9rem;
            opacity: 0.9;
        }

        /* 健康状态指示器 */
        .health-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 0.5rem;
            animation: pulse 2s ease-in-out infinite;
        }

        .health-healthy {
            background: #38ef7d;
            box-shadow: 0 0 10px rgba(56, 239, 125, 0.5);
        }

        .health-unhealthy {
            background: #f5576c;
            box-shadow: 0 0 10px rgba(245, 87, 108, 0.5);
        }

        .health-dead {
            background: #eb3349;
            box-shadow: 0 0 10px rgba(235, 51, 73, 0.5);
        }

        .health-unknown {
            background: #8e9eab;
            box-shadow: 0 0 10px rgba(142, 158, 171, 0.5);
        }

        /* 图表容器 */
        .chart-container {
            position: relative;
            height: 300px;
            margin: 1rem 0;
        }

        /* 分组信息卡片 */
        .group-info-card {
            background: rgba(255,255,255,0.95);
            border-radius: 12px;
            padding: 1rem;
            margin: 0.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .dark-mode .group-info-card {
            background: rgba(26,26,46,0.95);
        }

        .group-info-icon {
            font-size: 2rem;
            opacity: 0.7;
        }

        /* 连通性测试结果 */
        .connectivity-result {
            max-height: 400px;
            overflow-y: auto;
            background: rgba(0,0,0,0.05);
            border-radius: 8px;
            padding: 1rem;
        }

        .dark-mode .connectivity-result {
            background: rgba(255,255,255,0.05);
        }

        /* C段卡片样式 */
        .cseg-card {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 0.5rem;
            border: 1px solid rgba(102, 126, 234, 0.2);
            transition: all 0.3s ease;
        }

        .cseg-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.2);
        }

        .dark-mode .cseg-card {
            background: rgba(102, 126, 234, 0.1);
            border-color: rgba(102, 126, 234, 0.3);
        }
    </style>
</head>
<body>
<button class="switch-mode">🌙</button>
<div class="container py-4">
    <ul class="nav nav-tabs" id="mainTabs" role="tablist">
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane" type="button" role="tab">
          <i class="fas fa-network-wired me-1"></i>代理管理
        </button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="monitor-tab" data-bs-toggle="tab" data-bs-target="#monitor-pane" type="button" role="tab">
          <i class="fas fa-chart-line me-1"></i>系统监控
        </button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="traffic-tab" data-bs-toggle="tab" data-bs-target="#traffic-pane" type="button" role="tab">
          <i class="fas fa-chart-bar me-1"></i>流量统计
        </button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="log-tab" data-bs-toggle="tab" data-bs-target="#log-pane" type="button" role="tab">
          <i class="fas fa-file-alt me-1"></i>日志分析
        </button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane" type="button" role="tab">
          <i class="fas fa-users me-1"></i>用户管理
        </button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-pane" type="button" role="tab">
          <i class="fas fa-server me-1"></i>IP批量管理
        </button>
      </li>
    </ul>
    <div class="tab-content">
        <!-- 代理管理tab -->
        <div class="tab-pane fade show active" id="proxy-pane" role="tabpanel">
            <div class="row mt-4 gy-4">
                <div class="col-lg-6">
                    <div class="card p-4">
                        <h5 class="fw-bold mb-4 text-success">批量添加代理</h5>
                        <form method="post" action="/batchaddproxy" id="rangeAddForm" class="mb-4">
                            <div class="row g-3">
                                <div class="col-12 col-md-4">
                                    <label class="form-label">IP范围</label>
                                    <input type="text" class="form-control" name="iprange" placeholder="192.168.1.2-254">
                                </div>
                                <div class="col-12 col-md-4">
                                    <label class="form-label">端口范围</label>
                                    <input type="text" class="form-control" name="portrange" placeholder="20000-30000">
                                </div>
                                <div class="col-12 col-md-4">
                                    <label class="form-label">用户名前缀</label>
                                    <input type="text" class="form-control" name="userprefix" placeholder="user">
                                </div>
                            </div>
                            <button type="submit" class="btn btn-success w-100 mt-3">
                                <i class="fas fa-plus me-2"></i>范围添加
                            </button>
                        </form>
                        <form method="post" action="/batchaddproxy">
                            <label class="form-label">手动批量添加</label>
                            <small class="text-muted d-block mb-2">每行一个，支持 ip,端口 或 ip:端口，也支持 ip,端口,用户名,密码</small>
                            <textarea name="batchproxy" class="form-control mb-3" rows="8" style="font-family:'Courier New',monospace;resize:vertical;min-height:120px;" placeholder="每行一个：&#10;192.168.1.2,8080&#10;192.168.1.3:8081&#10;192.168.1.4,8082,user1,pass1"></textarea>
                            <button type="submit" class="btn btn-success w-100">
                                <i class="fas fa-upload me-2"></i>批量添加
                            </button>
                        </form>
                        <!-- 批量导入功能 -->
                        <hr class="my-4">
                        <h6 class="fw-bold mb-3">文件导入</h6>
                        <form method="post" action="/import_proxies" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label class="form-label">选择文件 (支持CSV, JSON, Excel)</label>
                                <input type="file" class="form-control" name="file" accept=".csv,.json,.xlsx,.xls" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-file-import me-2"></i>导入文件
                            </button>
                        </form>
                    </div>
                </div>
                <div class="col-lg-6">
                    <div class="card p-4">
                        <h5 class="fw-bold mb-4 text-primary">新增单个代理</h5>
                        <form class="row g-3" method="post" action="/addproxy">
                            <div class="col-12 col-md-6">
                                <label class="form-label">IP地址</label>
                                <input name="ip" class="form-control" placeholder="192.168.1.100" required>
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label">端口</label>
                                <input name="port" class="form-control" placeholder="8080" required>
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label">用户名</label>
                                <input name="username" class="form-control" placeholder="输入用户名" required>
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label">密码</label>
                                <input name="password" class="form-control" placeholder="留空自动生成">
                            </div>
                            <div class="col-12">
                                <label class="form-label">用户前缀 <small class="text-muted">(可选)</small></label>
                                <input name="userprefix" class="form-control" placeholder="前缀">
                            </div>
                            <div class="col-12">
                                <button class="btn btn-primary w-100" type="submit">
                                    <i class="fas fa-plus me-2"></i>新增代理
                                </button>
                            </div>
                        </form>
                        <!-- 快速操作 -->
                        <hr class="my-4">
                        <h6 class="fw-bold mb-3">快速操作</h6>
                        <div class="d-grid gap-2">
                            <button class="btn btn-outline-info" onclick="checkAllHealth()">
                                <i class="fas fa-heartbeat me-2"></i>检查所有代理健康状态
                            </button>
                            <button class="btn btn-outline-warning" onclick="testSelectedConnectivity()">
                                <i class="fas fa-wifi me-2"></i>测试选中代理连通性
                            </button>
                            <a href="/export_report/full" class="btn btn-outline-success">
                                <i class="fas fa-download me-2"></i>导出综合报告
                            </a>
                        </div>
                    </div>
                </div>
                <div class="col-12">
                    <div class="card p-4">
                        <div class="d-flex mb-3 align-items-center flex-wrap gap-2">
                            <h5 class="fw-bold flex-grow-1 mb-0">代理列表（按C段分组）</h5>
                            <select id="exportCseg" class="form-select" multiple size="5" style="width:240px;max-height:120px;"></select>
                            <button id="exportSelected" class="btn btn-outline-info btn-sm">
                                <i class="fas fa-download me-1"></i>导出所选C段
                            </button>
                            <button type="button" id="exportSelectedProxy" class="btn btn-outline-success btn-sm">
                                <i class="fas fa-file-export me-1"></i>导出选中代理
                            </button>
                            <div class="search-wrapper">
                                <input id="searchBox" class="form-control form-control-sm" style="width:220px;padding-left:2.5rem;" placeholder="搜索IP/端口/用户">
                            </div>
                        </div>
                        <form method="post" action="/batchdelproxy" id="proxyForm">
                        <div style="max-height:60vh;overflow-y:auto;border-radius:12px;overflow:hidden;">
                        <table class="table table-hover align-middle mb-0" id="proxyTable">
                            <thead class="table-light sticky-top">
                                <tr>
                                    <th style="width:50px;"><input type="checkbox" id="selectAll"></th>
                                    <th>ID</th>
                                    <th>IP</th>
                                    <th>端口</th>
                                    <th>用户名</th>
                                    <th>密码</th>
                                    <th>状态</th>
                                    <th>健康</th>
                                    <th>响应时间</th>
                                    <th>IP范围</th>
                                    <th>端口范围</th>
                                    <th>前缀</th>
                                    <th style="width:180px;">操作</th>
                                </tr>
                            </thead>
                            <tbody id="proxyTableBody"></tbody>
                        </table>
                        </div>
                        <div class="mt-3 d-flex gap-2 flex-wrap">
                            <button type="submit" class="btn btn-danger" onclick="return confirm('确定批量删除选中项?')">
                                <i class="fas fa-trash me-1"></i>批量删除
                            </button>
                            <button type="button" class="btn btn-warning" id="batchEnable">
                                <i class="fas fa-play me-1"></i>批量启用
                            </button>
                            <button type="button" class="btn btn-secondary" id="batchDisable">
                                <i class="fas fa-pause me-1"></i>批量禁用
                            </button>
                            <button type="button" class="btn btn-info" onclick="checkSelectedHealth()">
                                <i class="fas fa-stethoscope me-1"></i>检查选中健康
                            </button>
                        </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- 系统监控tab -->
        <div class="tab-pane fade" id="monitor-pane" role="tabpanel">
            <div class="row">
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-label">CPU 使用率</div>
                        <div class="stat-value" id="cpu-stat">0%</div>
                        <small>系统负载</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: var(--success-gradient);">
                        <div class="stat-label">内存使用率</div>
                        <div class="stat-value" id="memory-stat">0%</div>
                        <small>RAM 占用</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: var(--info-gradient);">
                        <div class="stat-label">活跃代理</div>
                        <div class="stat-value" id="active-stat">0</div>
                        <small>在线数量</small>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: var(--warning-gradient);">
                        <div class="stat-label">当前连接</div>
                        <div class="stat-value" id="conn-stat">0</div>
                        <small>活跃连接数</small>
                    </div>
                </div>
            </div>
            
            <div class="card mt-4 p-4">
                <h5 class="fw-bold mb-3">系统性能图表</h5>
                <div class="chart-container">
                    <canvas id="systemChart"></canvas>
                </div>
                <div class="mt-3">
                    <button class="btn btn-outline-primary" onclick="exportSystemReport()">
                        <i class="fas fa-download me-2"></i>导出系统报告
                    </button>
                </div>
            </div>
        </div>
        
        <!-- 流量统计tab -->
        <div class="tab-pane fade" id="traffic-pane" role="tabpanel">
            <div class="card p-4">
                <h5 class="fw-bold mb-4">C段流量统计</h5>
                <div class="row" id="csegTrafficContainer">
                    <!-- 动态加载C段流量卡片 -->
                </div>
                
                <div class="mt-4">
                    <button class="btn btn-primary" onclick="refreshTrafficStats()">
                        <i class="fas fa-sync me-2"></i>刷新统计
                    </button>
                    <button class="btn btn-outline-success" onclick="exportTrafficReport()">
                        <i class="fas fa-download me-2"></i>导出流量报告
                    </button>
                </div>
            </div>
        </div>
        
        <!-- 日志分析tab -->
        <div class="tab-pane fade" id="log-pane" role="tabpanel">
            <div class="card p-4">
                <h5 class="fw-bold mb-4">日志分析报告</h5>
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="card p-3">
                            <h6 class="fw-bold mb-3">Top 10 访问目标</h6>
                            <div id="topDestinations"></div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card p-3">
                            <h6 class="fw-bold mb-3">按小时流量分布</h6>
                            <canvas id="hourlyChart" height="200"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="card p-3">
                    <h6 class="fw-bold mb-3">异常检测</h6>
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>时间</th>
                                    <th>用户</th>
                                    <th>源IP</th>
                                    <th>目标</th>
                                    <th>状态</th>
                                    <th>流量</th>
                                </tr>
                            </thead>
                            <tbody id="anomaliesBody">
                                <!-- 动态加载 -->
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="mt-3">
                    <button class="btn btn-primary" onclick="refreshLogAnalysis()">
                        <i class="fas fa-sync me-2"></i>刷新分析
                    </button>
                </div>
            </div>
        </div>
        
        <!-- 用户管理tab -->
        <div class="tab-pane fade" id="user-pane" role="tabpanel">
            <div class="card p-4">
                <h5 class="fw-bold mb-4 text-warning">Web用户管理</h5>
                <form class="row g-3 align-items-end mb-4" method="post" action="/adduser">
                    <div class="col-12 col-md-5">
                        <label class="form-label">用户名</label>
                        <input name="username" class="form-control" placeholder="输入用户名" required>
                    </div>
                    <div class="col-12 col-md-5">
                        <label class="form-label">密码</label>
                        <input name="password" class="form-control" type="password" placeholder="输入密码" required>
                    </div>
                    <div class="col-12 col-md-2">
                        <button class="btn btn-primary w-100" type="submit">
                            <i class="fas fa-user-plus me-1"></i>添加用户
                        </button>
                    </div>
                </form>
                <div class="table-responsive" style="border-radius:12px;overflow:hidden;">
                <table class="table table-hover mb-0">
                    <thead class="table-light">
                        <tr>
                            <th style="width:80px;">ID</th>
                            <th>用户名</th>
                            <th style="width:120px;">操作</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for u in users %}
                    <tr>
                        <td>{{u[0]}}</td>
                        <td class="fw-semibold">{{u[1]}}</td>
                        <td>
                            {% if u[1]!='admin' %}
                            <a href="/deluser/{{u[0]}}" class="btn btn-sm btn-danger" onclick="return confirm('确认删除此用户?')">
                                <i class="fas fa-trash"></i>删除
                            </a>
                            {% else %}
                            <span class="badge bg-secondary">系统用户</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                    </tbody>
                </table>
                </div>
            </div>
        </div>
        
        <!-- IP批量管理tab -->
        <div class="tab-pane fade" id="ip-pane" role="tabpanel">
            <div class="card p-4">
                <h5 class="fw-bold mb-4 text-primary">IP批量管理</h5>
                <form class="row g-3 align-items-end mb-4" method="post" action="/add_ip_config">
                    <div class="col-12 col-md-2">
                        <label class="form-label">网卡名</label>
                        <input name="iface" class="form-control" value="{{default_iface}}" required>
                    </div>
                    <div class="col-12 col-md-5">
                        <label class="form-label">IP区间/单IP</label>
                        <input name="ip_input" class="form-control" placeholder="192.168.1.2-254 或 192.168.1.2,192.168.1.3" required>
                    </div>
                    <div class="col-12 col-md-3">
                        <label class="form-label">模式</label>
                        <select name="mode" class="form-select">
                            <option value="perm">永久(写入interfaces)</option>
                            <option value="temp">临时(仅当前生效)</option>
                        </select>
                    </div>
                    <div class="col-12 col-md-2">
                        <button class="btn btn-success w-100" type="submit">
                            <i class="fas fa-plus me-1"></i>添加
                        </button>
                    </div>
                </form>
                <div class="table-responsive" style="border-radius:12px;overflow:hidden;">
                <table class="table table-hover mb-0">
                    <thead class="table-light">
                        <tr>
                            <th style="width:80px;">ID</th>
                            <th>IP区间/单IP</th>
                            <th>类型</th>
                            <th>网卡</th>
                            <th>添加时间</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for c in ip_configs %}
                    <tr>
                        <td>{{c[0]}}</td>
                        <td class="fw-semibold">{{c[1]}}</td>
                        <td>
                            {% if c[2] == 'perm' %}
                            <span class="badge bg-success">永久</span>
                            {% else %}
                            <span class="badge bg-warning">临时</span>
                            {% endif %}
                        </td>
                        <td>{{c[3]}}</td>
                        <td>{{c[4]}}</td>
                    </tr>
                    {% endfor %}
                    </tbody>
                </table>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 连通性测试结果模态框 -->
    <div class="modal fade" id="connectivityModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">连通性测试结果</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="connectivityResults" class="connectivity-result">
                        <!-- 测试结果将在这里显示 -->
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                </div>
            </div>
        </div>
    </div>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="alert alert-success mt-4" role="alert">
            <strong>✅ 成功!</strong> {{ messages[0] }}
        </div>
      {% endif %}
    {% endwith %}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js"></script>
<script>
const proxyData = [
{% for p in proxies %}
    {id:{{p['id']}},ip:"{{p['ip']}}",port:"{{p['port']}}",user:"{{p['username']}}",pw:"{{p['password']}}",enabled:{{'true' if p['enabled'] else 'false'}},ip_range:"{{p['ip_range'] or ''}}",port_range:"{{p['port_range'] or ''}}",user_prefix:"{{p['user_prefix'] or ''}}",health_status:"{{p['health_status'] or 'unknown'}}",response_time:{{p['response_time'] or 0}}},
{% endfor %}
];

function getC(ip) {
    let m = ip.match(/^(\d+\.\d+\.\d+)\./);
    return m ? m[1] : ip;
}

function buildTable(data, filterVal="") {
    let tbody = document.getElementById('proxyTableBody');
    tbody.innerHTML = "";
    let groups = {};
    data.forEach(p => {
        if(filterVal && !(p.ip+p.port+p.user+p.pw).toLowerCase().includes(filterVal)) return;
        let c = getC(p.ip);
        if(!groups[c]) groups[c]=[];
        groups[c].push(p);
    });
    
    Object.keys(groups).sort().forEach((cseg,i)=>{
        let gid = "cgroup"+i;
        let th = document.createElement('tr');
        th.className = "ip-group-header";
        th.setAttribute("data-cgroup",gid);
        th.setAttribute("data-cseg",cseg);
        let first = groups[cseg][0];
        let groupInfo = "";
        if(first.ip_range && first.port_range && first.user_prefix){
            groupInfo = `<span class="badge bg-secondary ms-3">范围: ${first.ip_range} | 端口: ${first.port_range} | 前缀: ${first.user_prefix}</span>`;
        }
        
        // 计算健康统计
        let healthStats = {
            healthy: groups[cseg].filter(p => p.health_status === 'healthy').length,
            unhealthy: groups[cseg].filter(p => p.health_status === 'unhealthy').length,
            dead: groups[cseg].filter(p => p.health_status === 'dead').length,
            unknown: groups[cseg].filter(p => p.health_status === 'unknown').length
        };
        
        th.innerHTML = `<td colspan="13" class="pointer">
            <div class="d-flex align-items-center">
                <span class="arrow-icon me-2">▶</span>
                <strong>${cseg}.x 段</strong> 
                <span class="badge bg-primary ms-2">共 ${groups[cseg].length} 条</span>
                ${groupInfo}
                <span class="badge bg-info ms-3 cnet-traffic" data-cseg="${cseg}">
                    <span class="loading"></span> 统计中...
                </span>
                <div class="ms-3">
                    <span class="health-indicator health-healthy" title="健康"></span>${healthStats.healthy}
                    <span class="health-indicator health-unhealthy ms-2" title="异常"></span>${healthStats.unhealthy}
                    <span class="health-indicator health-dead ms-2" title="失效"></span>${healthStats.dead}
                </div>
                <input type="checkbox" class="group-select ms-auto me-3" data-gid="${gid}" title="全选本组" onclick="event.stopPropagation()">
            </div>
        </td>`;
        tbody.appendChild(th);
        
        groups[cseg].forEach(p=>{
            let tr = document.createElement('tr');
            tr.className = "ip-group-body " + gid + " collapsed";
            
            let healthBadge = '';
            if(p.health_status === 'healthy') {
                healthBadge = '<span class="badge bg-success">健康</span>';
            } else if(p.health_status === 'unhealthy') {
                healthBadge = '<span class="badge bg-warning">异常</span>';
            } else if(p.health_status === 'dead') {
                healthBadge = '<span class="badge bg-danger">失效</span>';
            } else {
                healthBadge = '<span class="badge bg-secondary">未知</span>';
            }
            
            tr.innerHTML = `<td><input type="checkbox" name="ids" value="${p.id}"></td>
            <td>${p.id}</td>
            <td><strong>${p.ip}</strong></td>
            <td>${p.port}</td>
            <td>${p.user}</td>
            <td><code style="font-size:0.85rem;">${p.pw}</code></td>
            <td>${p.enabled ? '<span class="badge text-bg-success">启用</span>' : '<span class="badge text-bg-secondary">禁用</span>'}</td>
            <td>${healthBadge}</td>
            <td>${p.response_time > 0 ? p.response_time.toFixed(2) + 's' : '-'}</td>
            <td>${p.ip_range||'-'}</td>
            <td>${p.port_range||'-'}</td>
            <td>${p.user_prefix||'-'}</td>
            <td>
                ${p.enabled ? 
                    `<a href="/disableproxy/${p.id}" class="btn btn-sm btn-warning me-1">禁用</a>` : 
                    `<a href="/enableproxy/${p.id}" class="btn btn-sm btn-success me-1">启用</a>`
                }
                <a href="/delproxy/${p.id}" class="btn btn-sm btn-danger" onclick="return confirm('确认删除此代理?')">删除</a>
            </td>`;
            tbody.appendChild(tr);
        });
    });
    
    // 获取流量统计
    fetch('/cnet_traffic').then(r=>r.json()).then(data=>{
        document.querySelectorAll('.cnet-traffic').forEach(span=>{
            let c = span.getAttribute('data-cseg');
            let traffic = data[c] ? `${data[c]} MB` : '0 MB';
            span.innerHTML = `💾 ${traffic}`;
        });
    }).catch(()=>{
        document.querySelectorAll('.cnet-traffic').forEach(span=>{
            span.innerHTML = '💾 统计失败';
        });
    });
    
    fillCsegSelect();
}

function fillCsegSelect() {
    let csegs = Array.from(new Set(proxyData.map(p=>getC(p.ip)))).sort();
    let sel = document.getElementById('exportCseg');
    sel.innerHTML = "";
    csegs.forEach(c=> {
        let opt = document.createElement('option');
        opt.value = c;
        opt.textContent = c + ".x";
        sel.appendChild(opt);
    });
}

// 初始化表格
buildTable(proxyData);

// 全选功能
document.getElementById('selectAll').onclick = function() {
    var cbs = document.querySelectorAll('#proxyTableBody input[type="checkbox"]');
    for(var i=0;i<cbs.length;++i) cbs[i].checked = this.checked;
};

// 表格点击事件 - 修复版
document.getElementById('proxyTableBody').onclick = function(e){
    let row = e.target.closest('tr.ip-group-header');
    if(row && !e.target.classList.contains('group-select')) {
        let gid = row.getAttribute('data-cgroup');
        let isExpanded = row.classList.contains('expanded');
        
        // 切换状态
        if(isExpanded) {
            row.classList.remove('expanded');
            row.querySelector('.arrow-icon').style.transform = 'rotate(0deg)';
            document.querySelectorAll('.ip-group-body.' + gid).forEach(tr => {
                tr.classList.add('collapsed');
            });
        } else {
            row.classList.add('expanded');
            row.querySelector('.arrow-icon').style.transform = 'rotate(90deg)';
            document.querySelectorAll('.ip-group-body.' + gid).forEach(tr => {
                tr.classList.remove('collapsed');
            });
        }
        return;
    }
    
    if(e.target.classList.contains('group-select')){
        let gid = e.target.getAttribute('data-gid');
        let checked = e.target.checked;
        document.querySelectorAll('.ip-group-body.' + gid + ' input[type="checkbox"]').forEach(cb=>cb.checked=checked);
    }
};

// 搜索功能（带防抖）
let searchTimeout;
document.getElementById('searchBox').oninput = function() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        let val = this.value.trim().toLowerCase();
        buildTable(proxyData, val);
    }, 300);
};

// 导出选中C段
document.getElementById('exportSelected').onclick = function(){
    let selected = Array.from(document.getElementById('exportCseg').selectedOptions).map(o=>o.value);
    if(selected.length==0) { 
        alert("请先选择要导出的C段"); 
        return; 
    }
    
    let form = new FormData();
    selected.forEach(c=>form.append('csegs[]',c));
    
    fetch('/export_selected', {method:'POST', body:form})
        .then(resp=>resp.blob())
        .then(blob=>{
            let a = document.createElement('a');
            let name = 'proxy_' + selected.join('_') + '.txt';
            a.href = URL.createObjectURL(blob);
            a.download = name;
            a.click();
        });
};

// 导出选中代理
document.getElementById('exportSelectedProxy').onclick = function(){
    let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
    if(ids.length === 0) { 
        alert("请先选择要导出的代理"); 
        return; 
    }
    
    let form = new FormData();
    ids.forEach(id=>form.append('ids[]',id));
    
    fetch('/export_selected_proxy', {method:'POST', body:form})
        .then(resp=>resp.blob())
        .then(blob=>{
            let a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'proxy_export_' + new Date().toISOString().slice(0,10) + '.txt';
            a.click();
        });
};

// 批量启用
document.getElementById('batchEnable').onclick = function(){
    let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
    if(ids.length === 0) { 
        alert("请先选择要启用的代理"); 
        return; 
    }
    
    if(confirm(`确定要启用选中的 ${ids.length} 个代理吗？`)) {
        let form = new FormData();
        ids.forEach(id=>form.append('ids[]',id));
        fetch('/batch_enable', {method:'POST', body:form}).then(()=>location.reload());
    }
};

// 批量禁用
document.getElementById('batchDisable').onclick = function(){
    let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
    if(ids.length === 0) { 
        alert("请先选择要禁用的代理"); 
        return; 
    }
    
    if(confirm(`确定要禁用选中的 ${ids.length} 个代理吗？`)) {
        let form = new FormData();
        ids.forEach(id=>form.append('ids[]',id));
        fetch('/batch_disable', {method:'POST', body:form}).then(()=>location.reload());
    }
};

// 暗色模式切换
const btn = document.querySelector('.switch-mode');
const isDarkMode = localStorage.getItem('darkMode') === 'true';

if(isDarkMode) {
    document.body.classList.add('dark-mode');
    btn.textContent = '☀️';
}

btn.onclick = ()=>{
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    btn.textContent = isDark ? '☀️' : '🌙';
    localStorage.setItem('darkMode', isDark);
};

// 页面加载完成后的初始化
window.onload = () => {
    // 添加平滑滚动
    document.documentElement.style.scrollBehavior = 'smooth';
    
    // 初始化系统监控
    updateSystemStats();
    setInterval(updateSystemStats, 5000);
    
    // 初始化流量统计
    loadTrafficStats();
    
    // 初始化日志分析
    refreshLogAnalysis();
};

// 系统监控功能
let systemChart;
const chartData = {
    labels: [],
    datasets: [{
        label: 'CPU %',
        data: [],
        borderColor: '#667eea',
        tension: 0.3
    }, {
        label: '内存 %',
        data: [],
        borderColor: '#38ef7d',
        tension: 0.3
    }]
};

function updateSystemStats() {
    fetch('/api/system_stats')
        .then(r => r.json())
        .then(data => {
            document.getElementById('cpu-stat').textContent = data.cpu.toFixed(1) + '%';
            document.getElementById('memory-stat').textContent = data.memory.toFixed(1) + '%';
            document.getElementById('active-stat').textContent = data.active_proxies;
            document.getElementById('conn-stat').textContent = data.connections;
            
            // 更新图表
            if(systemChart) {
                const now = new Date().toLocaleTimeString();
                chartData.labels.push(now);
                chartData.datasets[0].data.push(data.cpu);
                chartData.datasets[1].data.push(data.memory);
                
                // 保持最近50个数据点
                if(chartData.labels.length > 50) {
                    chartData.labels.shift();
                    chartData.datasets[0].data.shift();
                    chartData.datasets[1].data.shift();
                }
                
                systemChart.update();
            }
        });
}

// 初始化系统图表
const ctx = document.getElementById('systemChart');
if(ctx) {
    systemChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
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
}

// 健康检查功能
function checkAllHealth() {
    if(confirm('这将检查所有代理的健康状态，可能需要一些时间。继续吗？')) {
        const btn = event.target;
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="loading"></span> 检查中...';
        
        fetch('/api/check_proxy_health', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({proxy_ids: []})
        })
        .then(r => r.json())
        .then(data => {
            alert(`健康检查完成！共检查 ${data.total_checked} 个代理`);
            location.reload();
        })
        .catch(err => {
            alert('健康检查失败: ' + err.message);
        })
        .finally(() => {
            btn.disabled = false;
            btn.innerHTML = originalText;
        });
    }
}

function checkSelectedHealth() {
    let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
    if(ids.length === 0) { 
        alert("请先选择要检查的代理"); 
        return; 
    }
    
    const btn = event.target;
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span> 检查中...';
    
    fetch('/api/check_proxy_health', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({proxy_ids: ids})
    })
    .then(r => r.json())
    .then(data => {
        alert(`健康检查完成！共检查 ${data.total_checked} 个代理`);
        location.reload();
    })
    .catch(err => {
        alert('健康检查失败: ' + err.message);
    })
    .finally(() => {
        btn.disabled = false;
        btn.innerHTML = originalText;
    });
}

// 测试代理连通性
function testSelectedConnectivity() {
    let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
    if(ids.length === 0) { 
        alert("请先选择要测试的代理"); 
        return; 
    }
    
    const modal = new bootstrap.Modal(document.getElementById('connectivityModal'));
    const resultsDiv = document.getElementById('connectivityResults');
    resultsDiv.innerHTML = '<div class="text-center"><span class="loading"></span> 测试中，请稍候...</div>';
    modal.show();
    
    fetch('/api/test_proxy_connectivity', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            proxy_ids: ids,
            test_url: 'http://httpbin.org/ip'
        })
    })
    .then(r => r.json())
    .then(data => {
        let html = '<div class="row g-2">';
        data.results.forEach(result => {
            const statusClass = result.success ? 'success' : 'danger';
            const statusIcon = result.success ? '✅' : '❌';
            html += `
                <div class="col-md-6">
                    <div class="card border-${statusClass}">
                        <div class="card-body p-2">
                            <div class="d-flex align-items-center">
                                <span class="me-2">${statusIcon}</span>
                                <div class="flex-grow-1">
                                    <strong>${result.ip}:${result.port}</strong>
                                    ${result.success ? 
                                        `<small class="text-success d-block">响应时间: ${result.response_time.toFixed(2)}s</small>` :
                                        `<small class="text-danger d-block">${result.error || '连接失败'}</small>`
                                    }
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        resultsDiv.innerHTML = html;
    })
    .catch(err => {
        resultsDiv.innerHTML = `<div class="alert alert-danger">测试失败: ${err.message}</div>`;
    });
}

// 流量统计管理
function loadTrafficStats() {
    fetch('/api/cseg_traffic_stats')
        .then(r => r.json())
        .then(data => {
            const container = document.getElementById('csegTrafficContainer');
            if(!container) return;
            
            container.innerHTML = '';
            data.forEach(item => {
                const trafficMB = (item.total_bytes / 1024 / 1024).toFixed(2);
                const enabledPercent = item.proxy_count > 0 ? (item.enabled_count / item.proxy_count * 100).toFixed(1) : 0;
                
                const cardHtml = `
                    <div class="col-md-4 mb-3">
                        <div class="cseg-card">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <h6 class="fw-bold mb-0">${item.cseg}.x</h6>
                                <span class="badge bg-primary">${item.proxy_count} 代理</span>
                            </div>
                            <div class="row text-center">
                                <div class="col-4">
                                    <div class="fw-bold text-success">${item.enabled_count}</div>
                                    <small class="text-muted">已启用</small>
                                </div>
                                <div class="col-4">
                                    <div class="fw-bold text-info">${item.total_requests}</div>
                                    <small class="text-muted">请求数</small>
                                </div>
                                <div class="col-4">
                                    <div class="fw-bold text-warning">${trafficMB} MB</div>
                                    <small class="text-muted">流量</small>
                                </div>
                            </div>
                            <div class="progress mt-2" style="height: 6px;">
                                <div class="progress-bar" style="width: ${enabledPercent}%"></div>
                            </div>
                            <small class="text-muted">${enabledPercent}% 代理已启用</small>
                        </div>
                    </div>
                `;
                container.innerHTML += cardHtml;
            });
        });
}

function refreshTrafficStats() {
    loadTrafficStats();
    // 同时刷新C段流量统计
    fetch('/cnet_traffic').then(r=>r.json()).then(data=>{
        console.log('流量统计已刷新');
    });
}

function exportTrafficReport() {
    window.location.href = '/export_report/traffic';
}

// 日志分析功能
let hourlyChart;

function refreshLogAnalysis() {
    fetch('/api/log_analysis')
        .then(r => r.json())
        .then(data => {
            // 显示Top目标
            const topDest = document.getElementById('topDestinations');
            if(topDest) {
                topDest.innerHTML = '';
                Object.entries(data.top_destinations || {}).forEach(([dest, count]) => {
                    const div = document.createElement('div');
                    div.className = 'd-flex justify-content-between mb-2 p-2 bg-light rounded';
                    div.innerHTML = `
                        <span class="text-truncate" style="max-width: 200px;" title="${dest}">${dest}</span>
                        <span class="badge bg-primary">${count}</span>
                    `;
                    topDest.appendChild(div);
                });
            }
            
            // 显示异常
            const anomaliesBody = document.getElementById('anomaliesBody');
            if(anomaliesBody) {
                anomaliesBody.innerHTML = '';
                (data.anomalies || []).forEach(item => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><small>${item.time}</small></td>
                        <td>${item.user}</td>
                        <td>${item.src}</td>
                        <td class="text-truncate" style="max-width: 150px;" title="${item.dest}">${item.dest}</td>
                        <td><span class="badge bg-warning">${item.status}</span></td>
                        <td>${(item.bytes / 1024 / 1024).toFixed(2)} MB</td>
                    `;
                    anomaliesBody.appendChild(tr);
                });
            }
            
            // 更新小时分布图
            if(hourlyChart && data.hourly_distribution) {
                const hours = Object.keys(data.hourly_distribution).sort();
                const counts = hours.map(h => data.hourly_distribution[h]);
                
                hourlyChart.data.labels = hours;
                hourlyChart.data.datasets[0].data = counts;
                hourlyChart.update();
            }
        });
}

// 初始化小时分布图
const hourlyCtx = document.getElementById('hourlyChart');
if(hourlyCtx) {
    hourlyChart = new Chart(hourlyCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: '请求次数',
                data: [],
                backgroundColor: 'rgba(102, 126, 234, 0.5)',
                borderColor: 'rgba(102, 126, 234, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// 导出系统报告
function exportSystemReport() {
    window.location.href = '/export_report/system';
}

// 表单提交动画
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        const submitBtn = this.querySelector('button[type="submit"]');
        if(submitBtn && !submitBtn.disabled) {
            submitBtn.disabled = true;
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<span class="loading"></span> 处理中...';
            
            // 如果表单提交失败，恢复按钮状态
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            }, 5000);
        }
    });
});

// 添加键盘快捷键
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K 聚焦搜索框
    if((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        document.getElementById('searchBox').focus();
    }
    
    // Escape 清空搜索
    if(e.key === 'Escape' && document.activeElement.id === 'searchBox') {
        document.getElementById('searchBox').value = '';
        buildTable(proxyData);
    }
});

// 添加提示和帮助信息
document.addEventListener('DOMContentLoaded', function() {
    // 为主要功能添加提示
    const tooltips = [
        {selector: '#searchBox', title: '支持搜索IP、端口、用户名。快捷键: Ctrl+K'},
        {selector: '.group-select', title: '点击全选/取消选择本组所有代理'},
        {selector: '.arrow-icon', title: '点击展开/收起代理组'},
        {selector: '.cnet-traffic', title: '显示该C段的实时流量统计'}
    ];
    
    tooltips.forEach(tip => {
        document.querySelectorAll(tip.selector).forEach(el => {
            el.setAttribute('title', tip.title);
        });
    });
});

console.log('3proxy管理面板已加载完成');
</script>
</body>
</html>
EOF

# --------- Systemd服务启动 ---------
cat > /etc/systemd/system/3proxy-web.service <<EOF
[Unit]
Description=3proxy Web管理后台
After=network.target redis.service

[Service]
WorkingDirectory=$WORKDIR
Environment="PATH=$WORKDIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$WORKDIR/venv/bin/python3 $WORKDIR/manage.py $PORT
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/3proxy-autostart.service <<EOF
[Unit]
Description=3proxy代理自动启动
After=network.target

[Service]
Type=simple
WorkingDirectory=$WORKDIR
ExecStartPre=/bin/bash -c 'cd $WORKDIR && $WORKDIR/venv/bin/python3 $WORKDIR/config_gen.py'
ExecStart=$THREEPROXY_PATH $PROXYCFG_PATH
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --------- Dockerfile ---------
cat > $WORKDIR/Dockerfile << 'EOF'
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc make git wget python3 python3-pip python3-venv \
    python3-dev libssl-dev libffi-dev build-essential \
    htop iotop nethogs vnstat redis-server \
    cron logrotate sqlite3 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/3proxy-web

# 复制应用文件
COPY . .

# 安装Python依赖
RUN python3 -m venv venv && \
    ./venv/bin/pip install --upgrade pip && \
    ./venv/bin/pip install flask flask_login flask_wtf wtforms Werkzeug \
    psutil requests pandas openpyxl redis flask-caching \
    flask-limiter apscheduler

# 编译3proxy
RUN cd /tmp && \
    git clone --depth=1 https://github.com/z3APA3A/3proxy.git && \
    cd 3proxy && \
    make -f Makefile.Linux && \
    cp bin/3proxy /usr/local/bin/3proxy && \
    chmod +x /usr/local/bin/3proxy && \
    rm -rf /tmp/3proxy

# 创建必要的目录
RUN mkdir -p /usr/local/etc/3proxy /opt/3proxy-backup

# 暴露端口
EXPOSE 9999 3128-65535

# 启动脚本
RUN echo '#!/bin/bash\n\
redis-server --daemonize yes\n\
service cron start\n\
cd /opt/3proxy-web\n\
./venv/bin/python3 init_db.py\n\
./venv/bin/python3 config_gen.py\n\
/usr/local/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg &\n\
exec ./venv/bin/python3 manage.py 9999\n' > /start.sh && \
    chmod +x /start.sh

CMD ["/start.sh"]
EOF

# --------- docker-compose.yml ---------
cat > $WORKDIR/docker-compose.yml << 'EOF'
version: '3.8'

services:
  3proxy-web:
    build: .
    container_name: 3proxy-management
    restart: always
    ports:
      - "9999:9999"
      - "3128-65535:3128-65535"
    volumes:
      - ./data:/opt/3proxy-web
      - ./backup:/opt/3proxy-backup
      - ./logs:/usr/local/etc/3proxy
    environment:
      - ADMINUSER=admin
      - ADMINPASS=changeme123
    networks:
      - 3proxy-net
    cap_add:
      - NET_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.tcp_syncookies=1
      - net.core.somaxconn=65535

  redis:
    image: redis:7-alpine
    container_name: 3proxy-redis
    restart: always
    volumes:
      - redis-data:/data
    networks:
      - 3proxy-net

volumes:
  redis-data:

networks:
  3proxy-net:
    driver: bridge
EOF

cd $WORKDIR
export ADMINUSER
export ADMINPASS
$WORKDIR/venv/bin/python3 init_db.py

# 启动Redis
systemctl enable redis-server
systemctl start redis-server

systemctl daemon-reload
systemctl enable 3proxy-web
systemctl enable 3proxy-autostart
systemctl restart 3proxy-web
systemctl restart 3proxy-autostart

echo -e "\n========= 部署完成！========="
MYIP=$(get_local_ip)
echo -e "浏览器访问：\n  \033[36mhttp://$MYIP:${PORT}\033[0m"
echo "Web管理用户名: $ADMINUSER"
echo "Web管理密码:  $ADMINPASS"
echo -e "\n功能说明："
echo "1. 系统监控仪表板 - 实时查看CPU、内存、连接数"
echo "2. 手动代理健康检查 - 支持全部或选中代理检查"
echo "3. C段流量统计 - 自动读取已添加代理的C段"
echo "4. 日志分析功能 - 查看访问统计和异常检测"
echo "5. 批量导入支持 - CSV/JSON/Excel文件导入"
echo "6. 代理连通性测试 - 一键测试代理是否可用"
echo "7. 自动备份 - 每天凌晨2点自动备份数据库"
echo "8. Docker支持 - 可使用docker-compose up -d部署"
echo -e "\n修复和优化："
echo "✅ 移除了自动健康检查，改为手动触发"
echo "✅ 修复了C段分组展开/收起功能"
echo "✅ 优化了分组界面显示效果"
echo "✅ 流量限制改为读取已有代理C段"
echo "✅ 添加了代理连通性测试功能"
echo -e "\n管理员信息已保存到 $WORKDIR/.admin_info"
echo -e "\n常用命令："
echo "查看管理员信息：bash $0 info"
echo "如需卸载：bash $0 uninstall"
echo "如需重装：bash $0 reinstall"
