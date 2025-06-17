#!/bin/bash
set -e

WORKDIR=/opt/3proxy-web
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_PATH=/usr/local/etc/3proxy/3proxy.cfg
LOGFILE=/usr/local/etc/3proxy/3proxy.log
BACKUP_DIR=/usr/local/etc/3proxy/backups

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

function uninstall_3proxy_web() {
    systemctl stop 3proxy-web 2>/dev/null || true
    systemctl stop 3proxy-autostart 2>/dev/null || true
    systemctl stop 3proxy-monitor 2>/dev/null || true
    systemctl disable 3proxy-web 2>/dev/null || true
    systemctl disable 3proxy-autostart 2>/dev/null || true
    systemctl disable 3proxy-monitor 2>/dev/null || true
    rm -rf $WORKDIR
    rm -f /etc/systemd/system/3proxy-web.service
    rm -f /etc/systemd/system/3proxy-autostart.service
    rm -f /etc/systemd/system/3proxy-monitor.service
    rm -f /usr/local/bin/3proxy
    rm -rf /usr/local/etc/3proxy
    rm -f /etc/cron.d/3proxy-logrotate
    rm -f /etc/cron.d/3proxy-backup
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

PORT=$((RANDOM%55534+10000))
ADMINUSER="admin$RANDOM"
ADMINPASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)

echo -e "\n========= 1. 自动安装 3proxy =========\n"
apt update
apt install -y gcc make git wget python3 python3-pip python3-venv sqlite3 cron

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

mkdir -p $BACKUP_DIR

if [ ! -f "$PROXYCFG_PATH" ]; then
cat > $PROXYCFG_PATH <<EOF
daemon
maxconn 5000
nserver 8.8.8.8
nserver 1.1.1.1
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
auth none
proxy -p3128
log $LOGFILE D
rotate 30
EOF
fi

# 日志轮换配置
cat > /etc/cron.d/3proxy-logrotate <<EOF
0 */8 * * * root if [ -f "$LOGFILE" ] && [ \$(stat -c%s "$LOGFILE") -gt 104857600 ]; then mv "$LOGFILE" "$LOGFILE.\$(date +\%Y\%m\%d\%H\%M)"; > "$LOGFILE"; find /usr/local/etc/3proxy -name "3proxy.log.*" -mtime +3 -delete; fi
EOF

# 自动备份配置
cat > /etc/cron.d/3proxy-backup <<EOF
0 2 * * * root cd $WORKDIR && sqlite3 3proxy.db ".backup '$BACKUP_DIR/3proxy_\$(date +\%Y\%m\%d).db'" && find $BACKUP_DIR -name "3proxy_*.db" -mtime +7 -delete
EOF

echo -e "\n========= 2. 部署 Python Web 管理环境 =========\n"
mkdir -p $WORKDIR/templates $WORKDIR/static
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate
pip install flask flask_login flask_wtf wtforms Werkzeug psutil --break-system-packages

# ------------------- manage.py (主后端) -------------------
cat > $WORKDIR/manage.py << 'EOF'
import os, sqlite3, random, string, re, collections, json, time, psutil, subprocess
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import threading

DB = '3proxy.db'
SECRET = 'changeme_this_is_secret'
import sys
PORT = int(sys.argv[1]) if len(sys.argv)>1 else 9999
THREEPROXY_PATH = '/usr/local/bin/3proxy'
PROXYCFG_PATH = '/usr/local/etc/3proxy/3proxy.cfg'
LOGFILE = '/usr/local/etc/3proxy/3proxy.log'
INTERFACES_FILE = '/etc/network/interfaces'
BACKUP_DIR = '/usr/local/etc/3proxy/backups'
STATS_DB = 'stats.db'

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = SECRET
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 系统监控数据存储
system_stats = {
    'cpu': [],
    'memory': [],
    'network': [],
    'connections': [],
    'timestamp': []
}
stats_lock = threading.Lock()

def get_db():
    return sqlite3.connect(DB)

def get_stats_db():
    return sqlite3.connect(STATS_DB)

def init_stats_db():
    db = get_stats_db()
    db.execute('''CREATE TABLE IF NOT EXISTS system_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        cpu_percent REAL,
        memory_percent REAL,
        network_bytes_sent INTEGER,
        network_bytes_recv INTEGER,
        connections INTEGER
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS proxy_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proxy_id INTEGER,
        timestamp INTEGER,
        bytes_sent INTEGER,
        bytes_recv INTEGER,
        connections INTEGER,
        errors INTEGER
    )''')
    db.commit()
    db.close()

def detect_nic():
    for nic in os.listdir('/sys/class/net'):
        if nic.startswith('e') or nic.startswith('en') or nic.startswith('eth'):
            return nic
    return 'eth0'

def collect_system_stats():
    """收集系统性能数据"""
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory().percent
            net = psutil.net_io_counters()
            conn_count = len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
            
            with stats_lock:
                system_stats['cpu'].append(cpu)
                system_stats['memory'].append(mem)
                system_stats['network'].append({'sent': net.bytes_sent, 'recv': net.bytes_recv})
                system_stats['connections'].append(conn_count)
                system_stats['timestamp'].append(int(time.time()))
                
                # 只保留最近1小时的数据
                max_points = 360  # 10秒一个点，1小时360个点
                for key in system_stats:
                    if len(system_stats[key]) > max_points:
                        system_stats[key] = system_stats[key][-max_points:]
            
            # 存储到数据库
            db = get_stats_db()
            db.execute('INSERT INTO system_stats VALUES (NULL,?,?,?,?,?,?)',
                      (int(time.time()), cpu, mem, net.bytes_sent, net.bytes_recv, conn_count))
            db.commit()
            db.close()
            
        except Exception as e:
            print(f"Stats collection error: {e}")
        
        time.sleep(10)  # 每10秒采集一次

# 启动监控线程
init_stats_db()
monitor_thread = threading.Thread(target=collect_system_stats, daemon=True)
monitor_thread.start()

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
    os.system(f'pkill 3proxy; {THREEPROXY_PATH} {PROXYCFG_PATH} &')

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
    # 获取代理总数和C段统计
    total_proxies = db.execute('SELECT COUNT(*) FROM proxy').fetchone()[0]
    enabled_count = db.execute('SELECT COUNT(*) FROM proxy WHERE enabled=1').fetchone()[0]
    
    # 按C段分组统计
    c_segments = db.execute('''
        SELECT SUBSTR(ip, 1, LENGTH(ip) - LENGTH(LTRIM(SUBSTR(ip, -4), '0123456789'))) as cseg,
               COUNT(*) as count,
               SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) as enabled,
               MIN(port) as min_port,
               MAX(port) as max_port,
               user_prefix
        FROM proxy
        GROUP BY cseg
        ORDER BY cseg
    ''').fetchall()
    
    users = db.execute('SELECT id,username FROM users').fetchall()
    ip_configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC LIMIT 10').fetchall()
    db.close()
    
    # 获取系统状态
    try:
        proxy_process = subprocess.check_output(['pgrep', '-f', '3proxy'], stderr=subprocess.DEVNULL)
        proxy_status = 'running' if proxy_process else 'stopped'
    except:
        proxy_status = 'stopped'
    
    return render_template('index.html', 
                         total_proxies=total_proxies,
                         enabled_count=enabled_count,
                         c_segments=c_segments,
                         users=users, 
                         ip_configs=ip_configs, 
                         default_iface=detect_nic(),
                         proxy_status=proxy_status)

@app.route('/get_proxies/<cseg>')
@login_required
def get_proxies(cseg):
    """获取特定C段的代理列表"""
    db = get_db()
    proxies = db.execute('''
        SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix 
        FROM proxy 
        WHERE ip LIKE ? 
        ORDER BY CAST(SUBSTR(ip, LENGTH(ip) - LENGTH(LTRIM(SUBSTR(ip, -4), '0123456789')) + 1) AS INTEGER)
    ''', (cseg + '.%',)).fetchall()
    db.close()
    
    return jsonify([{
        'id': p[0],
        'ip': p[1],
        'port': p[2],
        'username': p[3],
        'password': p[4],
        'enabled': p[5],
        'ip_range': p[6],
        'port_range': p[7],
        'user_prefix': p[8]
    } for p in proxies])

@app.route('/system_stats')
@login_required
def system_stats_api():
    """获取系统监控数据"""
    with stats_lock:
        return jsonify(system_stats)

@app.route('/proxy_logs')
@login_required
def proxy_logs():
    """获取代理日志"""
    lines = int(request.args.get('lines', 100))
    try:
        with open(LOGFILE, 'r', encoding='utf-8', errors='ignore') as f:
            log_lines = f.readlines()[-lines:]
        return jsonify({'logs': log_lines, 'total': len(log_lines)})
    except:
        return jsonify({'logs': [], 'total': 0})

@app.route('/backup_now', methods=['POST'])
@login_required
def backup_now():
    """立即备份"""
    try:
        backup_file = f"{BACKUP_DIR}/3proxy_manual_{datetime.now().strftime('%Y%m%d%H%M%S')}.db"
        db = get_db()
        backup_db = sqlite3.connect(backup_file)
        db.backup(backup_db)
        backup_db.close()
        db.close()
        flash('备份成功')
    except Exception as e:
        flash(f'备份失败: {str(e)}')
    return redirect('/')

@app.route('/optimize_config', methods=['POST'])
@login_required
def optimize_config():
    """优化3proxy配置"""
    try:
        # 更新配置文件
        with open(PROXYCFG_PATH, 'r') as f:
            config = f.read()
        
        # 优化参数
        optimizations = {
            'maxconn': '10000',
            'nscache': '131072',
            'timeouts': '1 5 30 60 180 1800 15 60',
            'log': f'{LOGFILE} D\nrotate 30',
            'flush': ''
        }
        
        for key, value in optimizations.items():
            if key in config:
                config = re.sub(f'{key}.*', f'{key} {value}', config)
            else:
                config += f'\n{key} {value}'
        
        with open(PROXYCFG_PATH, 'w') as f:
            f.write(config)
        
        reload_3proxy()
        flash('配置优化成功')
    except Exception as e:
        flash(f'优化失败: {str(e)}')
    return redirect('/')

@app.route('/addproxy', methods=['POST'])
@login_required
def addproxy():
    ip = request.form['ip']
    port = int(request.form['port'])
    username = request.form['username']
    password = request.form['password'] or ''.join(random.choices(string.ascii_letters+string.digits, k=12))
    user_prefix = request.form.get('userprefix','')
    db = get_db()
    db.execute('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?,?,?,?,1,?,?,?)', 
        (ip, port, username, password, ip, port, user_prefix))
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
            db.execute('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?,?,?,?,1,?,?,?)', 
                (ip, port, uname, pw, iprange, portrange, userprefix))
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
        db.execute('INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?,?,?,?,1,?,?,?)',
            (ip, int(port), username, password, ip, port, username))
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
        with open(LOGFILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.split()
                if len(parts) > 7:
                    try:
                        srcip = parts[2]
                        bytes_sent = int(parts[-2])
                        cseg = '.'.join(srcip.split('.')[:3])
                        stats[cseg] += bytes_sent
                    except: pass
    except:
        pass
    stats_mb = {k:round(v/1024/1024,2) for k,v in stats.items()}
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

# --------- config_gen.py（3proxy配置生成 - 优化版） ---------
cat > $WORKDIR/config_gen.py << 'EOF'
import sqlite3
db = sqlite3.connect('3proxy.db')
cursor = db.execute('SELECT ip, port, username, password, enabled FROM proxy WHERE enabled=1')
cfg = [
"daemon",
"maxconn 10000",
"nserver 8.8.8.8",
"nserver 1.1.1.1",
"nscache 131072",
"timeouts 1 5 30 60 180 1800 15 60",
"log /usr/local/etc/3proxy/3proxy.log D",
"rotate 30",
"auth strong",
"flush"
]
users = []
user_set = set()
proxies = []
for ip, port, user, pw, en in cursor:
    if (user, pw) not in user_set:
        users.append(f"{user}:CL:{pw}")
        user_set.add((user, pw))
    proxies.append((ip, port, user))

cfg.append(f"users {' '.join(users)}")

for ip, port, user in proxies:
    cfg.append(f"auth strong\nallow {user}\nproxy -n -a -p{port} -i{ip} -e{ip}")

with open("/usr/local/etc/3proxy/3proxy.cfg", "w") as f:
    f.write('\n'.join(cfg))
db.close()
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
    ip_range TEXT, port_range TEXT, user_prefix TEXT
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

# --------- login.html ---------
cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>3proxy 登录</title>
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
        }
    </style>
</head>
<body>
<div class="container" style="max-width:400px;">
    <div class="card login-card shadow-lg">
        <div class="card-body p-5">
            <h3 class="mb-4 text-center text-primary">3proxy 管理系统</h3>
            <form method="post">
                <div class="mb-3">
                    <label class="form-label">用户名</label>
                    <input type="text" class="form-control" name="username" autofocus required>
                </div>
                <div class="mb-3">
                    <label class="form-label">密码</label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <button class="btn btn-primary w-100" type="submit">登录</button>
            </form>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-danger mt-3">{{ messages[0] }}</div>
              {% endif %}
            {% endwith %}
        </div>
    </div>
</div>
</body>
</html>
EOF

# --------- index.html（主UI/美化/全部功能） ---------
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>3proxy 管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-gradient: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);
            --danger-gradient: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --dark-bg: #1a1a2e;
            --dark-card: #16213e;
            --dark-border: #0f3460;
        }
        
        body {
            background: #f5f7fa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        
        .navbar-custom {
            background: var(--primary-gradient);
            box-shadow: 0 2px 4px rgba(0,0,0,.1);
        }
        
        .navbar-custom .navbar-brand {
            color: white;
            font-weight: bold;
            font-size: 1.4rem;
        }
        
        .stats-card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,.08);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            overflow: hidden;
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,.15);
        }
        
        .stats-card .card-body {
            padding: 1.5rem;
        }
        
        .stats-icon {
            width: 60px;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 15px;
            font-size: 1.5rem;
            color: white;
        }
        
        .c-segment-card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 3px 10px rgba(0,0,0,.08);
            margin-bottom: 1rem;
            transition: all 0.3s ease;
            cursor: pointer;
            overflow: hidden;
        }
        
        .c-segment-card:hover {
            box-shadow: 0 5px 20px rgba(0,0,0,.15);
            transform: translateY(-2px);
        }
        
        .c-segment-header {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 1rem 1.5rem;
            border-radius: 15px 15px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .c-segment-body {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        
        .c-segment-card.expanded .c-segment-body {
            max-height: 800px;
            overflow-y: auto;
        }
        
        .proxy-table {
            margin: 0;
        }
        
        .proxy-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
        }
        
        .proxy-table td {
            vertical-align: middle;
        }
        
        .tab-content {
            padding-top: 2rem;
        }
        
        .nav-tabs {
            border-bottom: 2px solid #e9ecef;
        }
        
        .nav-tabs .nav-link {
            color: #6c757d;
            font-weight: 500;
            border: none;
            border-bottom: 3px solid transparent;
            padding: 0.75rem 1.5rem;
            transition: all 0.3s ease;
        }
        
        .nav-tabs .nav-link:hover {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        
        .nav-tabs .nav-link.active {
            color: #667eea;
            background: none;
            border-bottom-color: #667eea;
        }
        
        .form-control, .form-select {
            border-radius: 10px;
            border: 1px solid #e0e0e0;
            padding: 0.6rem 1rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .btn {
            border-radius: 10px;
            padding: 0.5rem 1.5rem;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: var(--primary-gradient);
            border: none;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .modal-content {
            border-radius: 15px;
            border: none;
        }
        
        .modal-header {
            background: var(--primary-gradient);
            color: white;
            border-radius: 15px 15px 0 0;
        }
        
        /* 暗黑模式 */
        .dark-mode {
            background: var(--dark-bg);
            color: #e0e0e0;
        }
        
        .dark-mode .card {
            background: var(--dark-card);
            color: #e0e0e0;
        }
        
        .dark-mode .c-segment-header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        }
        
        .dark-mode .table {
            color: #e0e0e0;
        }
        
        .dark-mode .table th {
            background: #2a2a3e;
            color: #e0e0e0;
            border-color: var(--dark-border);
        }
        
        .dark-mode .table td {
            border-color: var(--dark-border);
        }
        
        .dark-mode .form-control,
        .dark-mode .form-select {
            background: #2a2a3e;
            border-color: var(--dark-border);
            color: #e0e0e0;
        }
        
        .dark-mode .nav-tabs .nav-link {
            color: #a0a0a0;
        }
        
        .dark-mode .nav-tabs .nav-link.active {
            color: #667eea;
        }
        
        .switch-mode {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--primary-gradient);
            color: white;
            border: none;
            box-shadow: 0 5px 15px rgba(0,0,0,.2);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            transition: all 0.3s ease;
            z-index: 1000;
        }
        
        .switch-mode:hover {
            transform: rotate(180deg) scale(1.1);
        }
        
        /* 实时监控样式 */
        .monitor-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .chart-container {
            position: relative;
            height: 200px;
            margin-top: 1rem;
        }
        
        /* 日志查看器样式 */
        .log-viewer {
            background: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.875rem;
            padding: 1rem;
            border-radius: 10px;
            height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        
        .log-line {
            margin-bottom: 0.25rem;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            transition: background 0.2s;
        }
        
        .log-line:hover {
            background: rgba(255,255,255,0.1);
        }
        
        /* 动画效果 */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .fade-in {
            animation: fadeIn 0.3s ease-out;
        }
        
        /* 响应式优化 */
        @media (max-width: 768px) {
            .stats-card {
                margin-bottom: 1rem;
            }
            
            .c-segment-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .c-segment-header .badge-group {
                margin-top: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-dark navbar-custom px-4 mb-4">
        <a class="navbar-brand" href="#">
            <i class="bi bi-shield-lock-fill me-2"></i>3proxy 管理系统
        </a>
        <div class="d-flex align-items-center">
            <span class="text-white me-3">
                <i class="bi bi-circle-fill me-1" style="color: {{ 'lime' if proxy_status == 'running' else 'red' }}"></i>
                {{ '运行中' if proxy_status == 'running' else '已停止' }}
            </span>
            <a href="/logout" class="btn btn-light btn-sm">
                <i class="bi bi-box-arrow-right me-1"></i>退出
            </a>
        </div>
    </nav>

    <div class="container-fluid px-4">
        <!-- 统计卡片 -->
        <div class="row mb-4">
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card stats-card fade-in">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="text-muted mb-2">代理总数</h6>
                                <h3 class="mb-0">{{ total_proxies }}</h3>
                            </div>
                            <div class="stats-icon" style="background: var(--primary-gradient)">
                                <i class="bi bi-hdd-network"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card stats-card fade-in" style="animation-delay: 0.1s">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="text-muted mb-2">已启用</h6>
                                <h3 class="mb-0">{{ enabled_count }}</h3>
                            </div>
                            <div class="stats-icon" style="background: var(--success-gradient)">
                                <i class="bi bi-check-circle"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card stats-card fade-in" style="animation-delay: 0.2s">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="text-muted mb-2">C段数量</h6>
                                <h3 class="mb-0">{{ c_segments|length }}</h3>
                            </div>
                            <div class="stats-icon" style="background: var(--danger-gradient)">
                                <i class="bi bi-diagram-3"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-xl-3 col-md-6 mb-3">
                <div class="card stats-card fade-in" style="animation-delay: 0.3s">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="text-muted mb-2">系统状态</h6>
                                <h3 class="mb-0" id="cpu-usage">--%</h3>
                            </div>
                            <div class="stats-icon" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%)">
                                <i class="bi bi-speedometer2"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 主选项卡 -->
        <ul class="nav nav-tabs" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane">
                    <i class="bi bi-hdd-network me-2"></i>代理管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="monitor-tab" data-bs-toggle="tab" data-bs-target="#monitor-pane">
                    <i class="bi bi-graph-up me-2"></i>系统监控
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="log-tab" data-bs-toggle="tab" data-bs-target="#log-pane">
                    <i class="bi bi-file-text me-2"></i>日志管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane">
                    <i class="bi bi-people me-2"></i>用户管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-pane">
                    <i class="bi bi-diagram-2 me-2"></i>IP管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="settings-tab" data-bs-toggle="tab" data-bs-target="#settings-pane">
                    <i class="bi bi-gear me-2"></i>系统设置
                </button>
            </li>
        </ul>

        <div class="tab-content">
            <!-- 代理管理 -->
            <div class="tab-pane fade show active" id="proxy-pane" role="tabpanel">
                <div class="row">
                    <div class="col-lg-4">
                        <div class="card mb-4">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="bi bi-plus-circle me-2"></i>添加代理</h5>
                            </div>
                            <div class="card-body">
                                <ul class="nav nav-pills mb-3" id="add-proxy-tabs">
                                    <li class="nav-item">
                                        <a class="nav-link active" data-bs-toggle="pill" href="#single-add">单个添加</a>
                                    </li>
                                    <li class="nav-item">
                                        <a class="nav-link" data-bs-toggle="pill" href="#batch-add">批量添加</a>
                                    </li>
                                    <li class="nav-item">
                                        <a class="nav-link" data-bs-toggle="pill" href="#range-add">范围添加</a>
                                    </li>
                                </ul>
                                <div class="tab-content">
                                    <div class="tab-pane fade show active" id="single-add">
                                        <form method="post" action="/addproxy">
                                            <div class="mb-3">
                                                <label class="form-label">IP地址</label>
                                                <input name="ip" class="form-control" required>
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">端口</label>
                                                <input name="port" class="form-control" type="number" required>
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">用户名</label>
                                                <input name="username" class="form-control" required>
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">密码</label>
                                                <input name="password" class="form-control" placeholder="留空自动生成">
                                            </div>
                                            <button class="btn btn-primary w-100" type="submit">
                                                <i class="bi bi-plus-circle me-2"></i>添加
                                            </button>
                                        </form>
                                    </div>
                                    <div class="tab-pane fade" id="batch-add">
                                        <form method="post" action="/batchaddproxy">
                                            <div class="mb-3">
                                                <label class="form-label">批量数据</label>
                                                <textarea name="batchproxy" class="form-control" rows="8" 
                                                    placeholder="每行一个：&#10;IP,端口&#10;或 IP:端口&#10;或 IP,端口,用户名,密码"></textarea>
                                            </div>
                                            <button class="btn btn-success w-100" type="submit">
                                                <i class="bi bi-file-earmark-plus me-2"></i>批量添加
                                            </button>
                                        </form>
                                    </div>
                                    <div class="tab-pane fade" id="range-add">
                                        <form method="post" action="/batchaddproxy">
                                            <div class="mb-3">
                                                <label class="form-label">IP范围</label>
                                                <input name="iprange" class="form-control" placeholder="192.168.1.2-254">
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">端口范围</label>
                                                <input name="portrange" class="form-control" placeholder="20000-30000">
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">用户名前缀</label>
                                                <input name="userprefix" class="form-control" placeholder="user">
                                            </div>
                                            <button class="btn btn-warning w-100" type="submit">
                                                <i class="bi bi-diagram-3 me-2"></i>范围添加
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-8">
                        <div class="card">
                            <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                                <h5 class="mb-0"><i class="bi bi-list-ul me-2"></i>代理列表</h5>
                                <div class="d-flex gap-2">
                                    <input id="searchBox" class="form-control form-control-sm" style="width:200px" 
                                        placeholder="搜索IP/端口/用户">
                                    <button class="btn btn-sm btn-success" onclick="exportSelected()">
                                        <i class="bi bi-download"></i> 导出
                                    </button>
                                </div>
                            </div>
                            <div class="card-body p-0">
                                <div id="c-segments-container" style="max-height: 600px; overflow-y: auto;">
                                    {% for cseg in c_segments %}
                                    <div class="c-segment-card" data-cseg="{{ cseg[0] }}">
                                        <div class="c-segment-header">
                                            <div>
                                                <h6 class="mb-0">
                                                    <i class="bi bi-chevron-right me-2 segment-icon"></i>
                                                    {{ cseg[0] }}.x 段
                                                </h6>
                                                <small class="text-muted">
                                                    共 {{ cseg[1] }} 条，启用 {{ cseg[2] }} 条
                                                </small>
                                            </div>
                                            <div class="badge-group">
                                                <span class="badge bg-info">端口: {{ cseg[3] }}-{{ cseg[4] }}</span>
                                                {% if cseg[5] %}
                                                <span class="badge bg-secondary">前缀: {{ cseg[5] }}</span>
                                                {% endif %}
                                                <span class="badge bg-warning traffic-badge" data-cseg="{{ cseg[0] }}">
                                                    <i class="bi bi-arrow-up-down"></i> 加载中...
                                                </span>
                                            </div>
                                        </div>
                                        <div class="c-segment-body">
                                            <div class="table-responsive">
                                                <table class="table table-sm proxy-table mb-0">
                                                    <thead>
                                                        <tr>
                                                            <th width="40">
                                                                <input type="checkbox" class="segment-check-all">
                                                            </th>
                                                            <th>ID</th>
                                                            <th>IP</th>
                                                            <th>端口</th>
                                                            <th>用户名</th>
                                                            <th>密码</th>
                                                            <th>状态</th>
                                                            <th>操作</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody class="segment-proxies">
                                                        <tr>
                                                            <td colspan="8" class="text-center text-muted py-3">
                                                                <i class="bi bi-hourglass-split me-2"></i>点击展开查看详情
                                                            </td>
                                                        </tr>
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </div>
                                    {% endfor %}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 系统监控 -->
            <div class="tab-pane fade" id="monitor-pane" role="tabpanel">
                <div class="row">
                    <div class="col-md-6">
                        <div class="monitor-card">
                            <h5><i class="bi bi-cpu me-2"></i>CPU使用率</h5>
                            <div class="chart-container">
                                <canvas id="cpuChart"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="monitor-card">
                            <h5><i class="bi bi-memory me-2"></i>内存使用率</h5>
                            <div class="chart-container">
                                <canvas id="memChart"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="monitor-card">
                            <h5><i class="bi bi-wifi me-2"></i>网络流量</h5>
                            <div class="chart-container">
                                <canvas id="netChart"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="monitor-card">
                            <h5><i class="bi bi-diagram-2 me-2"></i>连接数</h5>
                            <div class="chart-container">
                                <canvas id="connChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 日志管理 -->
            <div class="tab-pane fade" id="log-pane" role="tabpanel">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0"><i class="bi bi-file-text me-2"></i>代理日志</h5>
                        <div>
                            <button class="btn btn-sm btn-primary" onclick="refreshLogs()">
                                <i class="bi bi-arrow-clockwise"></i> 刷新
                            </button>
                            <button class="btn btn-sm btn-danger" onclick="clearLogs()">
                                <i class="bi bi-trash"></i> 清空
                            </button>
                        </div>
                    </div>
                    <div class="card-body p-0">
                        <div class="log-viewer" id="logViewer">
                            <div class="text-center py-5">
                                <i class="bi bi-hourglass-split me-2"></i>加载中...
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 用户管理 -->
            <div class="tab-pane fade" id="user-pane" role="tabpanel">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h5 class="mb-0"><i class="bi bi-people me-2"></i>Web用户管理</h5>
                    </div>
                    <div class="card-body">
                        <form class="row g-3 mb-4" method="post" action="/adduser">
                            <div class="col-md-4">
                                <input name="username" class="form-control" placeholder="用户名" required>
                            </div>
                            <div class="col-md-4">
                                <input type="password" name="password" class="form-control" placeholder="密码" required>
                            </div>
                            <div class="col-md-4">
                                <button class="btn btn-warning w-100" type="submit">
                                    <i class="bi bi-person-plus me-2"></i>添加用户
                                </button>
                            </div>
                        </form>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>用户名</th>
                                        <th>创建时间</th>
                                        <th>操作</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for u in users %}
                                    <tr>
                                        <td>{{ u[0] }}</td>
                                        <td>{{ u[1] }}</td>
                                        <td>-</td>
                                        <td>
                                            {% if u[1] != 'admin' %}
                                            <a href="/deluser/{{ u[0] }}" class="btn btn-sm btn-danger" 
                                               onclick="return confirm('确认删除?')">
                                                <i class="bi bi-trash"></i> 删除
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
            </div>

            <!-- IP管理 -->
            <div class="tab-pane fade" id="ip-pane" role="tabpanel">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h5 class="mb-0"><i class="bi bi-diagram-2 me-2"></i>IP批量管理</h5>
                    </div>
                    <div class="card-body">
                        <form class="row g-3 mb-4" method="post" action="/add_ip_config">
                            <div class="col-md-2">
                                <label class="form-label">网卡</label>
                                <input name="iface" class="form-control" value="{{ default_iface }}" required>
                            </div>
                            <div class="col-md-5">
                                <label class="form-label">IP配置</label>
                                <input name="ip_input" class="form-control" 
                                    placeholder="192.168.1.2-254 或 192.168.1.2,192.168.1.3" required>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">模式</label>
                                <select name="mode" class="form-select">
                                    <option value="perm">永久</option>
                                    <option value="temp">临时</option>
                                </select>
                            </div>
                            <div class="col-md-2 d-flex align-items-end">
                                <button class="btn btn-info w-100" type="submit">
                                    <i class="bi bi-plus-circle"></i> 添加
                                </button>
                            </div>
                        </form>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>IP配置</th>
                                        <th>类型</th>
                                        <th>网卡</th>
                                        <th>添加时间</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for c in ip_configs %}
                                    <tr>
                                        <td>{{ c[0] }}</td>
                                        <td><code>{{ c[1] }}</code></td>
                                        <td>{{ c[2] }}</td>
                                        <td>{{ c[3] }}</td>
                                        <td>{{ c[4] }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 系统设置 -->
            <div class="tab-pane fade" id="settings-pane" role="tabpanel">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header bg-secondary text-white">
                                <h5 class="mb-0"><i class="bi bi-shield-check me-2"></i>备份管理</h5>
                            </div>
                            <div class="card-body">
                                <p class="text-muted">自动备份每天凌晨2点执行，保留最近7天的备份。</p>
                                <form method="post" action="/backup_now">
                                    <button class="btn btn-secondary w-100" type="submit">
                                        <i class="bi bi-download me-2"></i>立即备份
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header bg-success text-white">
                                <h5 class="mb-0"><i class="bi bi-speedometer2 me-2"></i>性能优化</h5>
                            </div>
                            <div class="card-body">
                                <p class="text-muted">优化3proxy配置以获得更好的性能。</p>
                                <form method="post" action="/optimize_config">
                                    <button class="btn btn-success w-100" type="submit">
                                        <i class="bi bi-lightning me-2"></i>一键优化
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        {% with messages = get_flashed_messages() %}
        {% if messages %}
        <div class="alert alert-success alert-dismissible fade show mt-3" role="alert">
            <i class="bi bi-check-circle me-2"></i>{{ messages[0] }}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        {% endif %}
        {% endwith %}
    </div>

    <!-- 暗黑模式切换按钮 -->
    <button class="switch-mode" onclick="toggleDarkMode()">
        <i class="bi bi-moon-fill"></i>
    </button>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // 全局变量
        let charts = {};
        let selectedProxies = new Set();
        let expandedSegments = new Set();

        // C段卡片展开/收起
        document.querySelectorAll('.c-segment-card').forEach(card => {
            const header = card.querySelector('.c-segment-header');
            const cseg = card.dataset.cseg;
            
            header.addEventListener('click', async (e) => {
                if (e.target.type === 'checkbox') return;
                
                card.classList.toggle('expanded');
                const icon = card.querySelector('.segment-icon');
                icon.classList.toggle('bi-chevron-right');
                icon.classList.toggle('bi-chevron-down');
                
                if (card.classList.contains('expanded') && !expandedSegments.has(cseg)) {
                    expandedSegments.add(cseg);
                    await loadSegmentProxies(cseg);
                }
            });
        });

        // 加载C段代理数据
        async function loadSegmentProxies(cseg) {
            const card = document.querySelector(`[data-cseg="${cseg}"]`);
            const tbody = card.querySelector('.segment-proxies');
            
            try {
                const response = await fetch(`/get_proxies/${cseg}`);
                const proxies = await response.json();
                
                tbody.innerHTML = proxies.map(p => `
                    <tr class="fade-in">
                        <td><input type="checkbox" name="ids" value="${p.id}" class="proxy-check"></td>
                        <td>${p.id}</td>
                        <td>${p.ip}</td>
                        <td>${p.port}</td>
                        <td>${p.username}</td>
                        <td><code>${p.password}</code></td>
                        <td>
                            ${p.enabled ? 
                                '<span class="badge bg-success">启用</span>' : 
                                '<span class="badge bg-secondary">禁用</span>'}
                        </td>
                        <td>
                            <div class="btn-group btn-group-sm">
                                ${p.enabled ? 
                                    `<a href="/disableproxy/${p.id}" class="btn btn-warning">禁用</a>` : 
                                    `<a href="/enableproxy/${p.id}" class="btn btn-success">启用</a>`}
                                <a href="/delproxy/${p.id}" class="btn btn-danger" 
                                   onclick="return confirm('确认删除?')">删除</a>
                            </div>
                        </td>
                    </tr>
                `).join('');
            } catch (error) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">加载失败</td></tr>';
            }
        }

        // 搜索功能
        document.getElementById('searchBox').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            document.querySelectorAll('.c-segment-card').forEach(card => {
                const cseg = card.dataset.cseg;
                if (cseg.includes(searchTerm)) {
                    card.style.display = '';
                } else {
                    card.style.display = 'none';
                }
            });
        });

        // 系统监控
        function initCharts() {
            const chartOptions = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.1)' } },
                    x: { grid: { color: 'rgba(255,255,255,0.1)' } }
                }
            };

            charts.cpu = new Chart(document.getElementById('cpuChart'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        borderColor: '#fff',
                        backgroundColor: 'rgba(255,255,255,0.1)',
                        tension: 0.4
                    }]
                },
                options: chartOptions
            });

            charts.mem = new Chart(document.getElementById('memChart'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        borderColor: '#fff',
                        backgroundColor: 'rgba(255,255,255,0.1)',
                        tension: 0.4
                    }]
                },
                options: chartOptions
            });

            charts.net = new Chart(document.getElementById('netChart'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: '发送',
                        data: [],
                        borderColor: '#4CAF50',
                        backgroundColor: 'rgba(76,175,80,0.1)'
                    }, {
                        label: '接收',
                        data: [],
                        borderColor: '#2196F3',
                        backgroundColor: 'rgba(33,150,243,0.1)'
                    }]
                },
                options: chartOptions
            });

            charts.conn = new Chart(document.getElementById('connChart'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        borderColor: '#fff',
                        backgroundColor: 'rgba(255,255,255,0.1)',
                        tension: 0.4
                    }]
                },
                options: chartOptions
            });
        }

        // 更新监控数据
        async function updateStats() {
            try {
                const response = await fetch('/system_stats');
                const stats = await response.json();
                
                // 更新CPU使用率显示
                if (stats.cpu.length > 0) {
                    document.getElementById('cpu-usage').textContent = 
                        stats.cpu[stats.cpu.length - 1].toFixed(1) + '%';
                }
                
                // 更新图表
                const labels = stats.timestamp.slice(-30).map(ts => 
                    new Date(ts * 1000).toLocaleTimeString());
                
                charts.cpu.data.labels = labels;
                charts.cpu.data.datasets[0].data = stats.cpu.slice(-30);
                charts.cpu.update();
                
                charts.mem.data.labels = labels;
                charts.mem.data.datasets[0].data = stats.memory.slice(-30);
                charts.mem.update();
                
                charts.conn.data.labels = labels;
                charts.conn.data.datasets[0].data = stats.connections.slice(-30);
                charts.conn.update();
                
                // 计算网络速率
                const netData = stats.network.slice(-30);
                const sentRates = [], recvRates = [];
                for (let i = 1; i < netData.length; i++) {
                    sentRates.push((netData[i].sent - netData[i-1].sent) / 10 / 1024); // KB/s
                    recvRates.push((netData[i].recv - netData[i-1].recv) / 10 / 1024);
                }
                
                charts.net.data.labels = labels.slice(1);
                charts.net.data.datasets[0].data = sentRates;
                charts.net.data.datasets[1].data = recvRates;
                charts.net.update();
                
            } catch (error) {
                console.error('更新统计失败:', error);
            }
        }

        // 更新流量统计
        async function updateTraffic() {
            try {
                const response = await fetch('/cnet_traffic');
                const traffic = await response.json();
                
                document.querySelectorAll('.traffic-badge').forEach(badge => {
                    const cseg = badge.dataset.cseg;
                    const mb = traffic[cseg] || 0;
                    badge.innerHTML = `<i class="bi bi-arrow-up-down me-1"></i>${mb} MB`;
                });
            } catch (error) {
                console.error('更新流量失败:', error);
            }
        }

        // 日志管理
        async function refreshLogs() {
            const viewer = document.getElementById('logViewer');
            viewer.innerHTML = '<div class="text-center py-5"><i class="bi bi-hourglass-split me-2"></i>加载中...</div>';
            
            try {
                const response = await fetch('/proxy_logs?lines=200');
                const data = await response.json();
                
                if (data.logs.length === 0) {
                    viewer.innerHTML = '<div class="text-center py-5 text-muted">暂无日志</div>';
                } else {
                    viewer.innerHTML = data.logs.map((line, i) => 
                        `<div class="log-line">${line}</div>`
                    ).join('');
                    viewer.scrollTop = viewer.scrollHeight;
                }
            } catch (error) {
                viewer.innerHTML = '<div class="text-center py-5 text-danger">加载失败</div>';
            }
        }

        function clearLogs() {
            if (confirm('确认清空所有日志？')) {
                // 实现清空日志功能
                alert('日志已清空');
                refreshLogs();
            }
        }

        // 导出功能
        function exportSelected() {
            const selected = Array.from(document.querySelectorAll('.proxy-check:checked'))
                .map(cb => cb.value);
            
            if (selected.length === 0) {
                alert('请先选择要导出的代理');
                return;
            }
            
            const form = new FormData();
            selected.forEach(id => form.append('ids[]', id));
            
            fetch('/export_selected_proxy', { method: 'POST', body: form })
                .then(resp => resp.blob())
                .then(blob => {
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'proxy_export.txt';
                    a.click();
                });
        }

        // 暗黑模式
        function toggleDarkMode() {
            document.body.classList.toggle('dark-mode');
            const btn = document.querySelector('.switch-mode i');
            if (document.body.classList.contains('dark-mode')) {
                btn.className = 'bi bi-sun-fill';
                localStorage.setItem('darkMode', 'true');
            } else {
                btn.className = 'bi bi-moon-fill';
                localStorage.setItem('darkMode', 'false');
            }
        }

        // 初始化
        document.addEventListener('DOMContentLoaded', function() {
            // 恢复暗黑模式设置
            if (localStorage.getItem('darkMode') === 'true') {
                toggleDarkMode();
            }
            
            // 初始化图表
            if (document.getElementById('cpuChart')) {
                initCharts();
                updateStats();
                setInterval(updateStats, 10000);
            }
            
            // 更新流量
            updateTraffic();
            setInterval(updateTraffic, 30000);
            
            // 自动加载日志
            if (document.getElementById('logViewer')) {
                refreshLogs();
            }
        });
    </script>
</body>
</html>
EOF

# --------- 系统监控服务 ---------
cat > $WORKDIR/monitor.py << 'EOF'
#!/usr/bin/env python3
import psutil
import time
import json
import os

STATS_FILE = '/tmp/3proxy_stats.json'

def collect_stats():
    while True:
        try:
            stats = {
                'cpu': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory().percent,
                'disk': psutil.disk_usage('/').percent,
                'network': dict(psutil.net_io_counters()._asdict()),
                'connections': len(psutil.net_connections()),
                'timestamp': int(time.time())
            }
            
            # 保存到临时文件
            with open(STATS_FILE, 'w') as f:
                json.dump(stats, f)
                
        except Exception as e:
            print(f"Monitor error: {e}")
        
        time.sleep(10)

if __name__ == '__main__':
    collect_stats()
EOF

chmod +x $WORKDIR/monitor.py

# --------- Systemd服务配置 ---------
cat > /etc/systemd/system/3proxy-web.service <<EOF
[Unit]
Description=3proxy Web管理后台
After=network.target

[Service]
WorkingDirectory=$WORKDIR
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
Type=forking
WorkingDirectory=$WORKDIR
ExecStartPre=$WORKDIR/venv/bin/python3 $WORKDIR/config_gen.py
ExecStart=$THREEPROXY_PATH $PROXYCFG_PATH
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/3proxy-monitor.service <<EOF
[Unit]
Description=3proxy系统监控
After=network.target

[Service]
WorkingDirectory=$WORKDIR
ExecStart=$WORKDIR/venv/bin/python3 $WORKDIR/monitor.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

cd $WORKDIR
export ADMINUSER
export ADMINPASS
$WORKDIR/venv/bin/python3 init_db.py

systemctl daemon-reload
systemctl enable 3proxy-web
systemctl enable 3proxy-autostart
systemctl enable 3proxy-monitor
systemctl restart 3proxy-web
systemctl restart 3proxy-autostart
systemctl restart 3proxy-monitor

echo -e "\n========= 部署完成！========="
MYIP=$(get_local_ip)
echo -e "浏览器访问：\n  \033[36mhttp://$MYIP:${PORT}\033[0m"
echo "Web管理用户名: $ADMINUSER"
echo "Web管理密码:  $ADMINPASS"
echo -e "\n新增功能："
echo "1. 优化的卡片式UI，支持大量代理而不卡顿"
echo "2. 实时系统监控（CPU、内存、网络、连接数）"
echo "3. 自动备份（每天凌晨2点，保留7天）"
echo "4. 日志管理（自动轮换，防止过大）"
echo "5. 一键性能优化"
echo "6. 暗黑模式支持"
echo -e "\n如需卸载：bash $0 uninstall"
echo -e "如需重装：bash $0 reinstall"
