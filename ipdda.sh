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

function show_credentials() {
    if [ -f "$WORKDIR/credentials.txt" ]; then
        echo -e "\n========= 3proxy Web管理面板登录信息 ========="
        cat $WORKDIR/credentials.txt
        echo -e "\n浏览器访问：\033[36mhttp://$(get_local_ip):$(cat $WORKDIR/port.txt 2>/dev/null || echo 9999)\033[0m"
    else
        echo -e "\033[31m未找到登录信息文件，请检查安装是否完整。\033[0m"
    fi
}

function uninstall_3proxy_web() {
    systemctl stop 3proxy-web 2>/dev/null || true
    systemctl stop 3proxy-autostart 2>/dev/null || true
    systemctl disable 3proxy-web 2>/dev/null || true
    systemctl disable 3proxy-autostart 2>/dev/null || true
    rm -rf $WORKDIR
    rm -f /etc/systemd/system/3proxy-web.service
    rm -f /etc/systemd/system/3proxy-autostart.service
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

if [[ "$1" == "reinstall" ]]; then
    uninstall_3proxy_web
    echo -e "\033[32m正在重新安装...\033[0m"
fi

if [[ "$1" == "show" ]]; then
    show_credentials
    exit 0
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
EOF

echo -e "\n========= 2. 部署 Python Web 管理环境 =========\n"
mkdir -p $WORKDIR/templates $WORKDIR/static
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate
pip install flask flask_login flask_wtf wtforms Werkzeug \
    psutil requests pandas openpyxl redis flask-caching \
    flask-limiter --break-system-packages

# 保存端口信息
echo $PORT > $WORKDIR/port.txt

# ------------------- manage.py (优化版主后端) -------------------
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
    # 简化的表结构
    db.execute('''CREATE TABLE IF NOT EXISTS proxy_health (
        proxy_id INTEGER PRIMARY KEY,
        last_check TIMESTAMP,
        status TEXT,
        response_time REAL,
        success_rate REAL
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
    
    # 添加新字段到proxy表
    try:
        db.execute('ALTER TABLE proxy ADD COLUMN health_status TEXT DEFAULT "unknown"')
        db.execute('ALTER TABLE proxy ADD COLUMN last_health_check TIMESTAMP')
        db.execute('ALTER TABLE proxy ADD COLUMN response_time REAL DEFAULT 0')
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

# 手动代理健康检查（单个或批量）
@app.route('/api/check_proxy_health', methods=['POST'])
@login_required
def check_proxy_health_api():
    data = request.json
    proxy_ids = data.get('proxy_ids', [])
    
    if not proxy_ids:
        return jsonify({'error': '请选择要检查的代理'}), 400
    
    db = get_db()
    results = []
    
    for proxy_id in proxy_ids:
        proxy = db.execute("SELECT id, ip, port, username, password FROM proxy WHERE id=? AND enabled=1", 
                          (proxy_id,)).fetchone()
        
        if proxy:
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
                'status': status,
                'response_time': response_time
            })
    
    db.commit()
    db.close()
    
    return jsonify({'results': results})

# C段详情页面（解决性能问题）
@app.route('/cseg_detail/<cseg>')
@login_required
def cseg_detail(cseg):
    db = get_db()
    
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = 50  # 每页显示50条
    
    # 获取该C段的代理总数
    total = db.execute("SELECT COUNT(*) FROM proxy WHERE ip LIKE ?", (cseg + '.%',)).fetchone()[0]
    
    # 分页查询
    offset = (page - 1) * per_page
    proxies = db.execute('''SELECT * FROM proxy WHERE ip LIKE ? 
                           ORDER BY ip, port LIMIT ? OFFSET ?''', 
                        (cseg + '.%', per_page, offset)).fetchall()
    
    # 计算总页数
    total_pages = (total + per_page - 1) // per_page
    
    # 获取该C段的范围信息
    range_info = db.execute('''SELECT DISTINCT ip_range, port_range, user_prefix 
                              FROM proxy WHERE ip LIKE ? 
                              AND ip_range IS NOT NULL 
                              AND ip_range != '' LIMIT 1''', 
                           (cseg + '.%',)).fetchone()
    
    db.close()
    
    return render_template('cseg_detail.html', 
                         cseg=cseg, 
                         proxies=proxies, 
                         page=page, 
                         total_pages=total_pages,
                         total=total,
                         range_info=range_info)

# 获取C段统计信息（改进版）
@app.route('/api/cseg_stats')
@login_required
def cseg_stats():
    db = get_db()
    
    # 使用更准确的方法提取C段
    cursor = db.execute('''
        SELECT DISTINCT 
            SUBSTR(ip, 1, LENGTH(ip) - LENGTH(LTRIM(SUBSTR(ip, LENGTH(ip) - LENGTH(REPLACE(ip, '.', '')) + 1), '0123456789'))) as cseg
        FROM proxy
    ''')
    
    csegs = [row[0] for row in cursor.fetchall()]
    
    stats = []
    for cseg in csegs:
        stat = db.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled,
                SUM(CASE WHEN health_status = 'healthy' THEN 1 ELSE 0 END) as healthy,
                SUM(CASE WHEN health_status = 'unhealthy' THEN 1 ELSE 0 END) as unhealthy,
                SUM(CASE WHEN health_status = 'dead' THEN 1 ELSE 0 END) as dead,
                MIN(ip_range) as ip_range,
                MIN(port_range) as port_range,
                MIN(user_prefix) as user_prefix
            FROM proxy
            WHERE ip LIKE ?
        ''', (cseg + '.%',)).fetchone()
        
        if stat and stat['total'] > 0:
            stats.append({
                'cseg': cseg,
                'total': stat['total'],
                'enabled': stat['enabled'],
                'healthy': stat['healthy'],
                'unhealthy': stat['unhealthy'],
                'dead': stat['dead'],
                'ip_range': stat['ip_range'] or '',
                'port_range': stat['port_range'] or '',
                'user_prefix': stat['user_prefix'] or ''
            })
    
    db.close()
    
    # 按C段排序
    stats.sort(key=lambda x: [int(n) for n in x['cseg'].split('.')])
    
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
                db.execute('''INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) 
                             VALUES (?, ?, ?, ?, 1, ?, ?, ?)''',
                           (row['ip'], row['port'], row['username'], row['password'], 
                            row.get('ip_range', ''), row.get('port_range', ''), row.get('user_prefix', '')))
                count += 1
                
        elif file.filename.endswith('.json'):
            data = json.load(file)
            for item in data:
                db.execute('''INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) 
                             VALUES (?, ?, ?, ?, 1, ?, ?, ?)''',
                           (item['ip'], item['port'], item['username'], item['password'],
                            item.get('ip_range', ''), item.get('port_range', ''), item.get('user_prefix', '')))
                count += 1
                
        elif file.filename.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file)
            for _, row in df.iterrows():
                db.execute('''INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) 
                             VALUES (?, ?, ?, ?, 1, ?, ?, ?)''',
                           (row['ip'], row['port'], row['username'], row['password'],
                            row.get('ip_range', ''), row.get('port_range', ''), row.get('user_prefix', '')))
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
            
            # 健康状态
            health = db.execute('SELECT * FROM proxy_health').fetchall()
            pd.DataFrame(health).to_excel(writer, sheet_name='健康状态', index=False)
            
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

# 原有的路由保持不变
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
    users = db.execute('SELECT id,username FROM users').fetchall()
    ip_configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC').fetchall()
    db.close()
    
    return render_template('index.html', 
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
    
    # 用于存储文件名组成部分
    file_parts = []
    user_prefix = ""
    
    for cseg in csegs:
        rows = db.execute("SELECT ip,port,username,password,user_prefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port", (cseg+'.%',)).fetchall()
        if rows:
            # 获取用户前缀（只取第一个）
            if not user_prefix and rows[0][4]:
                user_prefix = rows[0][4]
            
            # 添加C段到文件名，格式如 192.168.1.x
            file_parts.append(f"{cseg}.x")
            
            for ip,port,user,pw,_ in rows:
                output += f"{ip}:{port}:{user}:{pw}\n"
    
    db.close()
    mem = BytesIO()
    mem.write(output.encode('utf-8'))
    mem.seek(0)
    
    # 生成文件名：用户前缀_C段名称
    if user_prefix and file_parts:
        filename = f"{user_prefix}_{'_'.join(file_parts)}.txt"
    else:
        filename = f"{'_'.join(file_parts)}.txt" if file_parts else "export.txt"
    
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
    response_time REAL DEFAULT 0
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
print("Webpassword:  "+passwd)
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

# --------- index.html（优化版主界面） ---------
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

        /* C段卡片样式 */
        .cseg-card {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .cseg-card:hover {
            transform: translateX(10px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.2);
        }

        .cseg-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--primary-gradient);
            transform: scaleY(0);
            transition: transform 0.3s ease;
        }

        .cseg-card:hover::before {
            transform: scaleY(1);
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

        /* 表单标签样式 */
        .form-label {
            font-weight: 600;
            color: #495057;
            margin-bottom: 0.5rem;
        }

        .dark-mode .form-label {
            color: #adb5bd;
        }

        /* C段信息样式 */
        .cseg-info {
            font-size: 0.9rem;
            color: #6c757d;
            margin-top: 0.5rem;
        }

        .dark-mode .cseg-info {
            color: #adb5bd;
        }
    </style>
</head>
<body>
<button class="switch-mode">🌙</button>
<div class="container py-4">
    <ul class="nav nav-tabs" id="mainTabs" role="tablist">
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane" type="button" role="tab">代理管理</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="monitor-tab" data-bs-toggle="tab" data-bs-target="#monitor-pane" type="button" role="tab">
          <i class="fas fa-chart-line me-1"></i>系统监控
        </button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane" type="button" role="tab">用户管理</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-pane" type="button" role="tab">IP批量管理</button>
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
                                <span>范围添加</span>
                            </button>
                        </form>
                        <form method="post" action="/batchaddproxy">
                            <label class="form-label">手动批量添加</label>
                            <small class="text-muted d-block mb-2">每行一个，支持 ip,端口 或 ip:端口，也支持 ip,端口,用户名,密码</small>
                            <textarea name="batchproxy" class="form-control mb-3" rows="8" style="font-family:'Courier New',monospace;resize:vertical;min-height:120px;" placeholder="每行一个：&#10;192.168.1.2,8080&#10;192.168.1.3:8081&#10;192.168.1.4,8082,user1,pass1"></textarea>
                            <button type="submit" class="btn btn-success w-100">
                                <span>批量添加</span>
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
                                    <span>新增代理</span>
                                </button>
                            </div>
                        </form>
                        <!-- 快速操作 -->
                        <hr class="my-4">
                        <h6 class="fw-bold mb-3">快速操作</h6>
                        <div class="d-grid gap-2">
                            <a href="/export_report/full" class="btn btn-outline-success">
                                <i class="fas fa-download me-2"></i>导出综合报告
                            </a>
                        </div>
                    </div>
                </div>
                <div class="col-12">
                    <div class="card p-4">
                        <div class="d-flex mb-3 align-items-center flex-wrap gap-2">
                            <h5 class="fw-bold flex-grow-1 mb-0">C段管理</h5>
                            <select id="exportCseg" class="form-select" multiple size="5" style="width:240px;max-height:120px;"></select>
                            <button id="exportSelected" class="btn btn-outline-info btn-sm">导出所选C段</button>
                            <div class="search-wrapper">
                                <input id="searchBox" class="form-control form-control-sm" style="width:220px;padding-left:2.5rem;" placeholder="搜索C段">
                            </div>
                        </div>
                        <div id="csegList">
                            <!-- C段列表动态加载 -->
                        </div>
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
                        <button class="btn btn-primary w-100" type="submit">添加用户</button>
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
                            <a href="/deluser/{{u[0]}}" class="btn btn-sm btn-danger" onclick="return confirm('确认删除此用户?')">删除</a>
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
                        <button class="btn btn-success w-100" type="submit">添加</button>
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
// 存储C段统计信息
let csegStatsData = [];

// 获取并构建C段列表
function loadCsegStats() {
    fetch('/api/cseg_stats')
        .then(r => r.json())
        .then(data => {
            csegStatsData = data;
            buildCsegList();
            fillCsegSelect();
        });
}

// 构建C段列表
function buildCsegList(filterVal="") {
    let container = document.getElementById('csegList');
    container.innerHTML = "";
    
    let filteredStats = csegStatsData;
    if(filterVal) {
        filteredStats = csegStatsData.filter(s => s.cseg.includes(filterVal));
    }
    
    filteredStats.forEach(stat => {
        let card = document.createElement('div');
        card.className = 'cseg-card';
        card.onclick = () => window.location.href = `/cseg_detail/${stat.cseg}`;
        
        // 构建详细信息
        let rangeInfo = '';
        if(stat.ip_range && stat.port_range && stat.user_prefix) {
            rangeInfo = `
                <div class="cseg-info">
                    <small>
                        <i class="fas fa-network-wired me-1"></i>IP: ${stat.ip_range} | 
                        <i class="fas fa-plug me-1"></i>端口: ${stat.port_range} | 
                        <i class="fas fa-user me-1"></i>前缀: ${stat.user_prefix}
                    </small>
                </div>
            `;
        }
        
        card.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h6 class="mb-1"><strong>${stat.cseg}.x</strong></h6>
                    <small class="text-muted">共 ${stat.total} 个代理</small>
                    ${rangeInfo}
                </div>
                <div class="text-end">
                    <span class="badge bg-primary">${stat.enabled} 启用</span>
                    <span class="badge bg-success ms-1">${stat.healthy} 健康</span>
                    <span class="badge bg-warning ms-1">${stat.unhealthy} 异常</span>
                    <span class="badge bg-danger ms-1">${stat.dead} 失效</span>
                </div>
            </div>
        `;
        
        container.appendChild(card);
    });
}

function fillCsegSelect() {
    let sel = document.getElementById('exportCseg');
    sel.innerHTML = "";
    csegStatsData.forEach(stat => {
        let opt = document.createElement('option');
        opt.value = stat.cseg;
        opt.textContent = stat.cseg + ".x";
        opt.setAttribute('data-prefix', stat.user_prefix || '');
        sel.appendChild(opt);
    });
}

// 初始化
loadCsegStats();

// 搜索功能（带防抖）
let searchTimeout;
document.getElementById('searchBox').oninput = function() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        let val = this.value.trim().toLowerCase();
        buildCsegList(val);
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
            a.href = URL.createObjectURL(blob);
            a.download = 'proxy_export.txt'; // 服务器会返回正确的文件名
            a.click();
        });
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

// 页面加载完成后的初始化
window.onload = () => {
    // 添加平滑滚动
    document.documentElement.style.scrollBehavior = 'smooth';
    
    // 初始化系统监控
    updateSystemStats();
    setInterval(updateSystemStats, 5000);
    
    // 定期刷新C段统计
    setInterval(loadCsegStats, 30000);
};

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
        buildCsegList();
    }
});

// 导出系统报告
function exportSystemReport() {
    window.location.href = '/export_report/system';
}
</script>
</body>
</html>
EOF

# --------- cseg_detail.html (C段详情页面) ---------
cat > $WORKDIR/templates/cseg_detail.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>{{cseg}}.x 段详情 - 3proxy管理</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --danger-gradient: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
            --warning-gradient: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --bg-light: #f8f9fa;
        }

        body {
            background: var(--bg-light);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }

        .card {
            border: none;
            border-radius: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
        }

        .btn {
            border-radius: 10px;
            font-weight: 500;
            padding: 0.5rem 1.5rem;
            border: none;
        }

        .btn-primary {
            background: var(--primary-gradient);
        }

        .btn-success {
            background: var(--success-gradient);
        }

        .btn-danger {
            background: var(--danger-gradient);
        }

        .btn-warning {
            background: var(--warning-gradient);
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        .table thead th {
            background: rgba(102, 126, 234, 0.1);
            border: none;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }

        .badge {
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-weight: 500;
        }

        h2 {
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
        }

        .health-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 0.5rem;
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

        .pagination {
            --bs-pagination-active-bg: #667eea;
            --bs-pagination-active-border-color: #667eea;
        }

        .pagination .page-link {
            border-radius: 8px;
            margin: 0 2px;
        }

        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }

        .info-card {
            background: rgba(102, 126, 234, 0.1);
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 1rem;
        }

        .info-card h6 {
            margin-bottom: 0.5rem;
            color: #667eea;
            font-weight: 600;
        }
    </style>
</head>
<body>
<div class="container py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>{{cseg}}.x 段详情</h2>
        <div>
            <a href="/" class="btn btn-outline-secondary">
                <i class="fas fa-arrow-left me-2"></i>返回主页
            </a>
        </div>
    </div>

    {% if range_info %}
    <div class="info-card">
        <h6>C段配置信息</h6>
        <div class="row">
            <div class="col-md-4">
                <small class="text-muted">IP范围</small>
                <p class="mb-0"><strong>{{range_info['ip_range']}}</strong></p>
            </div>
            <div class="col-md-4">
                <small class="text-muted">端口范围</small>
                <p class="mb-0"><strong>{{range_info['port_range']}}</strong></p>
            </div>
            <div class="col-md-4">
                <small class="text-muted">用户名前缀</small>
                <p class="mb-0"><strong>{{range_info['user_prefix']}}</strong></p>
            </div>
        </div>
    </div>
    {% endif %}

    <div class="card p-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <div>
                <h5 class="mb-0">代理列表</h5>
                <small class="text-muted">共 {{total}} 个代理</small>
            </div>
            <div class="d-flex gap-2">
                <button type="button" class="btn btn-info btn-sm" onclick="checkSelectedHealth()">
                    <i class="fas fa-heartbeat me-1"></i>检查选中健康
                </button>
                <button type="button" class="btn btn-success btn-sm" onclick="exportSelected()">
                    <i class="fas fa-download me-1"></i>导出选中
                </button>
                <button type="button" class="btn btn-warning btn-sm" onclick="batchEnable()">批量启用</button>
                <button type="button" class="btn btn-secondary btn-sm" onclick="batchDisable()">批量禁用</button>
                <button type="button" class="btn btn-danger btn-sm" onclick="batchDelete()">批量删除</button>
            </div>
        </div>

        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
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
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                {% for p in proxies %}
                <tr>
                    <td><input type="checkbox" name="ids" value="{{p['id']}}"></td>
                    <td>{{p['id']}}</td>
                    <td><strong>{{p['ip']}}</strong></td>
                    <td>{{p['port']}}</td>
                    <td>{{p['username']}}</td>
                    <td><code style="font-size:0.85rem;">{{p['password']}}</code></td>
                    <td>
                        {% if p['enabled'] %}
                        <span class="badge bg-success">启用</span>
                        {% else %}
                        <span class="badge bg-secondary">禁用</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if p['health_status'] == 'healthy' %}
                            <span class="health-indicator health-healthy"></span>健康
                        {% elif p['health_status'] == 'unhealthy' %}
                            <span class="health-indicator health-unhealthy"></span>异常
                        {% elif p['health_status'] == 'dead' %}
                            <span class="health-indicator health-dead"></span>失效
                        {% else %}
                            <span class="health-indicator health-unknown"></span>未知
                        {% endif %}
                    </td>
                    <td>{{p['response_time']|round(2) if p['response_time'] else '-'}}s</td>
                    <td>
                        {% if p['enabled'] %}
                        <a href="/disableproxy/{{p['id']}}" class="btn btn-sm btn-warning">禁用</a>
                        {% else %}
                        <a href="/enableproxy/{{p['id']}}" class="btn btn-sm btn-success">启用</a>
                        {% endif %}
                        <a href="/delproxy/{{p['id']}}" class="btn btn-sm btn-danger" onclick="return confirm('确认删除?')">删除</a>
                    </td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- 分页 -->
        {% if total_pages > 1 %}
        <nav aria-label="分页导航" class="mt-4">
            <ul class="pagination justify-content-center">
                {% if page > 1 %}
                <li class="page-item">
                    <a class="page-link" href="?page={{page-1}}">上一页</a>
                </li>
                {% endif %}
                
                {% for p in range(1, total_pages + 1) %}
                    {% if p == page %}
                    <li class="page-item active">
                        <span class="page-link">{{p}}</span>
                    </li>
                    {% elif p == 1 or p == total_pages or (p > page - 3 and p < page + 3) %}
                    <li class="page-item">
                        <a class="page-link" href="?page={{p}}">{{p}}</a>
                    </li>
                    {% elif p == page - 3 or p == page + 3 %}
                    <li class="page-item disabled">
                        <span class="page-link">...</span>
                    </li>
                    {% endif %}
                {% endfor %}
                
                {% if page < total_pages %}
                <li class="page-item">
                    <a class="page-link" href="?page={{page+1}}">下一页</a>
                </li>
                {% endif %}
            </ul>
        </nav>
        {% endif %}
    </div>
</div>

<script>
// 全选功能
document.getElementById('selectAll').onclick = function() {
    var cbs = document.querySelectorAll('input[name="ids"]');
    for(var i=0;i<cbs.length;++i) cbs[i].checked = this.checked;
};

// 获取选中的ID
function getSelectedIds() {
    return Array.from(document.querySelectorAll('input[name="ids"]:checked')).map(cb=>cb.value);
}

// 检查选中健康
function checkSelectedHealth() {
    let ids = getSelectedIds();
    if(ids.length === 0) {
        alert('请先选择要检查的代理');
        return;
    }
    
    if(confirm(`确定要检查选中的 ${ids.length} 个代理的健康状态吗？`)) {
        fetch('/api/check_proxy_health', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({proxy_ids: ids})
        }).then(r => r.json()).then(data => {
            alert('健康检查完成！');
            location.reload();
        });
    }
}

// 导出选中
function exportSelected() {
    let ids = getSelectedIds();
    if(ids.length === 0) {
        alert('请先选择要导出的代理');
        return;
    }
    
    let form = new FormData();
    ids.forEach(id=>form.append('ids[]',id));
    
    fetch('/export_selected_proxy', {method:'POST', body:form})
        .then(resp=>resp.blob())
        .then(blob=>{
            let a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'proxy_export_{{cseg}}.txt';
            a.click();
        });
}

// 批量启用
function batchEnable() {
    let ids = getSelectedIds();
    if(ids.length === 0) {
        alert('请先选择要启用的代理');
        return;
    }
    
    if(confirm(`确定要启用选中的 ${ids.length} 个代理吗？`)) {
        let form = new FormData();
        ids.forEach(id=>form.append('ids[]',id));
        fetch('/batch_enable', {method:'POST', body:form}).then(()=>location.reload());
    }
}

// 批量禁用
function batchDisable() {
    let ids = getSelectedIds();
    if(ids.length === 0) {
        alert('请先选择要禁用的代理');
        return;
    }
    
    if(confirm(`确定要禁用选中的 ${ids.length} 个代理吗？`)) {
        let form = new FormData();
        ids.forEach(id=>form.append('ids[]',id));
        fetch('/batch_disable', {method:'POST', body:form}).then(()=>location.reload());
    }
}

// 批量删除
function batchDelete() {
    let ids = getSelectedIds();
    if(ids.length === 0) {
        alert('请先选择要删除的代理');
        return;
    }
    
    if(confirm(`确定要删除选中的 ${ids.length} 个代理吗？此操作不可恢复！`)) {
        let form = document.createElement('form');
        form.method = 'POST';
        form.action = '/batchdelproxy';
        ids.forEach(id => {
            let input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'ids';
            input.value = id;
            form.appendChild(input);
        });
        document.body.appendChild(form);
        form.submit();
    }
}
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

cd $WORKDIR
export ADMINUSER
export ADMINPASS
$WORKDIR/venv/bin/python3 init_db.py

# 保存登录信息到文件
cat > $WORKDIR/credentials.txt <<EOF
Web管理用户名: $ADMINUSER
Web管理密码:  $ADMINPASS
EOF

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
echo -e "\n优化说明："
echo "1. C段管理明确显示 192.168.1.x 格式"
echo "2. 显示端口范围和用户名前缀信息"
echo "3. 导出文件名格式：用户前缀_C段数字.txt"
echo "4. 支持分页显示，避免大量IP时卡顿"
echo "5. 每天凌晨2点自动备份数据库"
echo -e "\n使用说明："
echo "查看登录信息: bash $0 show"
echo "卸载: bash $0 uninstall"
echo "重装: bash $0 reinstall"
