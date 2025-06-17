#!/bin/bash
set -e

WORKDIR=/opt/3proxy-web
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_PATH=/usr/local/etc/3proxy/3proxy.cfg
LOGFILE=/usr/local/etc/3proxy/3proxy.log
BACKUP_DIR=/var/backups/3proxy

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

PORT=$((RANDOM%55534+10000))
ADMINUSER="admin$RANDOM"
ADMINPASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)

echo -e "\n========= 1. 自动安装 3proxy =========\n"
apt update
apt install -y gcc make git wget python3 python3-pip python3-venv sqlite3 cron sysstat

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
maxconn 2000
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
auth none
proxy -p3128
log $LOGFILE D
EOF
fi

# 创建备份目录
mkdir -p $BACKUP_DIR

# 日志轮转和备份计划任务
cat > /etc/cron.d/3proxy-logrotate <<EOF
0 3 */3 * * root [ -f "$LOGFILE" ] && > "$LOGFILE"
EOF

cat > /etc/cron.d/3proxy-backup <<EOF
0 2 * * * root cd $WORKDIR && /usr/bin/python3 backup_manager.py auto
EOF

echo -e "\n========= 2. 部署 Python Web 管理环境 =========\n"
mkdir -p $WORKDIR/templates $WORKDIR/static/css $WORKDIR/static/js
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate
pip install flask flask_login flask_wtf wtforms Werkzeug psutil --break-system-packages

# ------------------- manage.py (主后端 - 增强版) -------------------
cat > $WORKDIR/manage.py << 'EOF'
import os, sqlite3, random, string, re, collections, json, time, psutil, datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO

DB = '3proxy.db'
SECRET = 'changeme_this_is_secret'
import sys
PORT = int(sys.argv[1]) if len(sys.argv)>1 else 9999
THREEPROXY_PATH = '/usr/local/bin/3proxy'
PROXYCFG_PATH = '/usr/local/etc/3proxy/3proxy.cfg'
LOGFILE = '/usr/local/etc/3proxy/3proxy.log'
INTERFACES_FILE = '/etc/network/interfaces'
MONITOR_DB = 'monitor.db'

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = SECRET
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def get_db():
    return sqlite3.connect(DB)

def get_monitor_db():
    return sqlite3.connect(MONITOR_DB)

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

def get_system_stats():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()
    
    # 获取3proxy进程信息
    proxy_proc = None
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
        if proc.info['name'] == '3proxy':
            proxy_proc = proc.info
            break
    
    return {
        'cpu': cpu,
        'memory': {
            'percent': mem.percent,
            'used': mem.used // (1024**3),
            'total': mem.total // (1024**3)
        },
        'disk': {
            'percent': disk.percent,
            'used': disk.used // (1024**3),
            'total': disk.total // (1024**3)
        },
        'network': {
            'bytes_sent': net.bytes_sent // (1024**2),
            'bytes_recv': net.bytes_recv // (1024**2)
        },
        'proxy_process': proxy_proc,
        'timestamp': time.time()
    }

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
    # 获取C段统计信息
    cursor = db.execute('SELECT ip FROM proxy ORDER BY ip')
    c_segments = {}
    for row in cursor:
        ip = row[0]
        c_seg = '.'.join(ip.split('.')[:3])
        if c_seg not in c_segments:
            c_segments[c_seg] = {'count': 0, 'enabled': 0, 'disabled': 0}
        c_segments[c_seg]['count'] += 1
    
    # 获取启用/禁用统计
    cursor = db.execute('SELECT ip, enabled FROM proxy')
    for row in cursor:
        ip, enabled = row
        c_seg = '.'.join(ip.split('.')[:3])
        if c_seg in c_segments:
            if enabled:
                c_segments[c_seg]['enabled'] += 1
            else:
                c_segments[c_seg]['disabled'] += 1
    
    users = db.execute('SELECT id,username FROM users').fetchall()
    ip_configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC LIMIT 10').fetchall()
    
    # 获取总体统计
    total_proxies = db.execute('SELECT COUNT(*) FROM proxy').fetchone()[0]
    enabled_proxies = db.execute('SELECT COUNT(*) FROM proxy WHERE enabled=1').fetchone()[0]
    
    db.close()
    
    return render_template('index.html', 
        c_segments=c_segments, 
        users=users, 
        ip_configs=ip_configs, 
        default_iface=detect_nic(),
        total_proxies=total_proxies,
        enabled_proxies=enabled_proxies)

@app.route('/c_segment/<cseg>')
@login_required
def c_segment_detail(cseg):
    db = get_db()
    proxies = db.execute('SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port', 
                        (cseg+'.%',)).fetchall()
    db.close()
    return render_template('c_segment_detail.html', cseg=cseg, proxies=proxies)

@app.route('/system_monitor')
@login_required
def system_monitor():
    return render_template('system_monitor.html')

@app.route('/api/system_stats')
@login_required
def api_system_stats():
    stats = get_system_stats()
    
    # 存储到监控数据库
    db = get_monitor_db()
    db.execute('''INSERT INTO system_stats 
                  (timestamp, cpu, memory_percent, disk_percent, network_sent, network_recv) 
                  VALUES (?,?,?,?,?,?)''',
               (stats['timestamp'], stats['cpu'], stats['memory']['percent'], 
                stats['disk']['percent'], stats['network']['bytes_sent'], 
                stats['network']['bytes_recv']))
    db.commit()
    db.close()
    
    return jsonify(stats)

@app.route('/api/history_stats')
@login_required
def api_history_stats():
    hours = int(request.args.get('hours', 24))
    db = get_monitor_db()
    since = time.time() - (hours * 3600)
    rows = db.execute('''SELECT timestamp, cpu, memory_percent, disk_percent, network_sent, network_recv 
                        FROM system_stats WHERE timestamp > ? ORDER BY timestamp''', (since,)).fetchall()
    db.close()
    
    data = {
        'timestamps': [],
        'cpu': [],
        'memory': [],
        'disk': [],
        'network_sent': [],
        'network_recv': []
    }
    
    for row in rows:
        data['timestamps'].append(row[0])
        data['cpu'].append(row[1])
        data['memory'].append(row[2])
        data['disk'].append(row[3])
        data['network_sent'].append(row[4])
        data['network_recv'].append(row[5])
    
    return jsonify(data)

@app.route('/backup_restore')
@login_required
def backup_restore():
    backup_dir = '/var/backups/3proxy'
    backups = []
    if os.path.exists(backup_dir):
        for f in sorted(os.listdir(backup_dir), reverse=True):
            if f.endswith('.tar.gz'):
                path = os.path.join(backup_dir, f)
                size = os.path.getsize(path) / 1024  # KB
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
                backups.append({
                    'filename': f,
                    'size': f'{size:.1f} KB',
                    'time': mtime.strftime('%Y-%m-%d %H:%M:%S')
                })
    return render_template('backup_restore.html', backups=backups[:20])

@app.route('/create_backup', methods=['POST'])
@login_required
def create_backup():
    os.system('python3 backup_manager.py manual')
    flash('备份创建成功')
    return redirect('/backup_restore')

@app.route('/restore_backup/<filename>')
@login_required
def restore_backup(filename):
    os.system(f'python3 backup_manager.py restore {filename}')
    flash('备份恢复成功')
    reload_3proxy()
    return redirect('/backup_restore')

@app.route('/performance_optimize')
@login_required
def performance_optimize():
    # 获取当前配置
    config = {}
    if os.path.exists(PROXYCFG_PATH):
        with open(PROXYCFG_PATH, 'r') as f:
            for line in f:
                if line.startswith('maxconn'):
                    config['maxconn'] = line.split()[1]
                elif line.startswith('nscache'):
                    config['nscache'] = line.split()[1]
    return render_template('performance_optimize.html', config=config)

@app.route('/apply_optimization', methods=['POST'])
@login_required
def apply_optimization():
    maxconn = request.form.get('maxconn', '2000')
    nscache = request.form.get('nscache', '65536')
    
    # 更新配置文件
    lines = []
    with open(PROXYCFG_PATH, 'r') as f:
        for line in f:
            if line.startswith('maxconn'):
                lines.append(f'maxconn {maxconn}\n')
            elif line.startswith('nscache'):
                lines.append(f'nscache {nscache}\n')
            else:
                lines.append(line)
    
    with open(PROXYCFG_PATH, 'w') as f:
        f.writelines(lines)
    
    reload_3proxy()
    flash('性能优化配置已应用')
    return redirect('/performance_optimize')

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
    return redirect(request.referrer or '/')

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
    return redirect(request.referrer or '/')

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
    return redirect(request.referrer or '/')

@app.route('/disableproxy/<int:pid>')
@login_required
def disableproxy(pid):
    db = get_db()
    db.execute('UPDATE proxy SET enabled=0 WHERE id=?', (pid,))
    db.commit()
    db.close()
    reload_3proxy()
    flash('已禁用')
    return redirect(request.referrer or '/')

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
    with open(LOGFILE,encoding='utf-8',errors='ignore') as f:
        for line in f:
            parts = line.split()
            if len(parts) > 7:
                try:
                    srcip = parts[2]
                    bytes_sent = int(parts[-2])
                    cseg = '.'.join(srcip.split('.')[:3])
                    stats[cseg] += bytes_sent
                except: pass
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

# --------- config_gen.py（3proxy配置生成） ---------
cat > $WORKDIR/config_gen.py << 'EOF'
import sqlite3
db = sqlite3.connect('3proxy.db')
cursor = db.execute('SELECT ip, port, username, password, enabled FROM proxy')
cfg = [
"daemon",
"maxconn 2000",
"nserver 8.8.8.8",
"nscache 65536",
"timeouts 1 5 30 60 180 1800 15 60",
"log /usr/local/etc/3proxy/3proxy.log D",
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

# --------- init_db.py（DB初始化 - 增强版） ---------
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

# 初始化监控数据库
monitor_db = sqlite3.connect('monitor.db')
monitor_db.execute('''CREATE TABLE IF NOT EXISTS system_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    cpu REAL,
    memory_percent REAL,
    disk_percent REAL,
    network_sent INTEGER,
    network_recv INTEGER
)''')
monitor_db.commit()

print("WebAdmin: "+user)
print("Webpassword:  "+passwd)
EOF

# --------- backup_manager.py（备份管理器） ---------
cat > $WORKDIR/backup_manager.py << 'EOF'
import os
import sys
import time
import tarfile
import sqlite3
from datetime import datetime

WORKDIR = '/opt/3proxy-web'
BACKUP_DIR = '/var/backups/3proxy'
CONFIG_PATH = '/usr/local/etc/3proxy/3proxy.cfg'

def create_backup(backup_type='auto'):
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'3proxy_backup_{backup_type}_{timestamp}.tar.gz'
    filepath = os.path.join(BACKUP_DIR, filename)
    
    with tarfile.open(filepath, 'w:gz') as tar:
        # 备份数据库
        tar.add(os.path.join(WORKDIR, '3proxy.db'), arcname='3proxy.db')
        # 备份配置文件
        if os.path.exists(CONFIG_PATH):
            tar.add(CONFIG_PATH, arcname='3proxy.cfg')
    
    # 清理旧备份（保留最近30个）
    backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith('.tar.gz')])
    if len(backups) > 30:
        for old_backup in backups[:-30]:
            os.remove(os.path.join(BACKUP_DIR, old_backup))
    
    print(f"Backup created: {filename}")
    return filename

def restore_backup(filename):
    filepath = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(filepath):
        print(f"Backup file not found: {filename}")
        return False
    
    with tarfile.open(filepath, 'r:gz') as tar:
        # 恢复数据库
        if '3proxy.db' in tar.getnames():
            tar.extract('3proxy.db', WORKDIR)
        # 恢复配置文件
        if '3proxy.cfg' in tar.getnames():
            tar.extract('3proxy.cfg', os.path.dirname(CONFIG_PATH))
    
    print(f"Backup restored: {filename}")
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: backup_manager.py [auto|manual|restore <filename>]")
        sys.exit(1)
    
    action = sys.argv[1]
    if action in ['auto', 'manual']:
        create_backup(action)
    elif action == 'restore' and len(sys.argv) == 3:
        restore_backup(sys.argv[2])
    else:
        print("Invalid action")
EOF

# --------- CSS样式文件 ---------
cat > $WORKDIR/static/css/style.css << 'EOF'
:root {
    --primary-color: #2c3e50;
    --secondary-color: #3498db;
    --success-color: #27ae60;
    --danger-color: #e74c3c;
    --warning-color: #f39c12;
    --info-color: #16a085;
    --light-bg: #ecf0f1;
    --dark-bg: #34495e;
    --card-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    --transition: all 0.3s ease;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: var(--light-bg);
    color: #333;
    line-height: 1.6;
}

/* 导航栏样式 */
.navbar {
    background: linear-gradient(135deg, var(--primary-color) 0%, var(--dark-bg) 100%);
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    padding: 1rem 0;
    position: sticky;
    top: 0;
    z-index: 1000;
}

.navbar-brand {
    color: white !important;
    font-size: 1.5rem;
    font-weight: bold;
    text-decoration: none;
}

.navbar-nav .nav-link {
    color: rgba(255, 255, 255, 0.9) !important;
    margin: 0 0.5rem;
    transition: var(--transition);
    position: relative;
}

.navbar-nav .nav-link:hover {
    color: white !important;
}

.navbar-nav .nav-link::after {
    content: '';
    position: absolute;
    width: 0;
    height: 2px;
    bottom: -5px;
    left: 50%;
    background-color: var(--secondary-color);
    transition: var(--transition);
    transform: translateX(-50%);
}

.navbar-nav .nav-link:hover::after,
.navbar-nav .nav-link.active::after {
    width: 80%;
}

/* 卡片样式 */
.stat-card {
    background: white;
    border-radius: 15px;
    padding: 2rem;
    box-shadow: var(--card-shadow);
    transition: var(--transition);
    height: 100%;
    position: relative;
    overflow: hidden;
}

.stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 5px;
    background: linear-gradient(90deg, var(--secondary-color), var(--info-color));
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
}

.stat-value {
    font-size: 2.5rem;
    font-weight: bold;
    color: var(--primary-color);
}

.stat-label {
    color: #7f8c8d;
    font-size: 1rem;
    margin-top: 0.5rem;
}

/* C段卡片样式 */
.c-segment-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: var(--card-shadow);
    transition: var(--transition);
    cursor: pointer;
}

.c-segment-card:hover {
    transform: translateX(5px);
    box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
}

.c-segment-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.c-segment-title {
    font-size: 1.25rem;
    font-weight: bold;
    color: var(--primary-color);
}

.c-segment-stats {
    display: flex;
    gap: 1rem;
}

.stat-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.875rem;
    font-weight: 500;
}

.badge-total {
    background-color: #e3f2fd;
    color: #1976d2;
}

.badge-enabled {
    background-color: #e8f5e9;
    color: #2e7d32;
}

.badge-disabled {
    background-color: #ffebee;
    color: #c62828;
}

/* 表单样式 */
.form-card {
    background: white;
    border-radius: 12px;
    padding: 2rem;
    box-shadow: var(--card-shadow);
    margin-bottom: 2rem;
}

.form-control, .form-select {
    border-radius: 8px;
    border: 1px solid #ddd;
    padding: 0.75rem;
    transition: var(--transition);
}

.form-control:focus, .form-select:focus {
    border-color: var(--secondary-color);
    box-shadow: 0 0 0 0.2rem rgba(52, 152, 219, 0.25);
}

/* 按钮样式 */
.btn {
    border-radius: 8px;
    padding: 0.75rem 1.5rem;
    font-weight: 500;
    transition: var(--transition);
    border: none;
    cursor: pointer;
}

.btn-primary {
    background: linear-gradient(135deg, var(--secondary-color) 0%, #2980b9 100%);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(52, 152, 219, 0.3);
}

.btn-success {
    background: linear-gradient(135deg, var(--success-color) 0%, #229954 100%);
    color: white;
}

.btn-danger {
    background: linear-gradient(135deg, var(--danger-color) 0%, #c0392b 100%);
    color: white;
}

/* 监控图表样式 */
.chart-container {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: var(--card-shadow);
    margin-bottom: 1.5rem;
}

/* 动画效果 */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.fade-in {
    animation: fadeIn 0.5s ease-out;
}

/* 响应式设计 */
@media (max-width: 768px) {
    .stat-card {
        margin-bottom: 1rem;
    }
    
    .c-segment-stats {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .navbar-nav {
        flex-direction: column;
    }
}

/* 深色模式 */
.dark-mode {
    background-color: #1a1a1a;
    color: #ecf0f1;
}

.dark-mode .stat-card,
.dark-mode .c-segment-card,
.dark-mode .form-card,
.dark-mode .chart-container {
    background-color: #2c3e50;
    color: #ecf0f1;
}

.dark-mode .form-control,
.dark-mode .form-select {
    background-color: #34495e;
    color: #ecf0f1;
    border-color: #495057;
}

/* 加载动画 */
.spinner {
    display: inline-block;
    width: 20px;
    height: 20px;
    border: 3px solid rgba(255,255,255,.3);
    border-radius: 50%;
    border-top-color: #fff;
    animation: spin 1s ease-in-out infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}
EOF

# --------- login.html（美化版登录页） ---------
cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3proxy 管理系统 - 登录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            overflow: hidden;
            width: 100%;
            max-width: 400px;
        }
        .login-header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        .login-body {
            padding: 2rem;
        }
        .login-title {
            font-size: 1.75rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        .login-subtitle {
            opacity: 0.8;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="login-card fade-in">
        <div class="login-header">
            <h1 class="login-title">3Proxy 管理系统</h1>
            <p class="login-subtitle">安全、高效的代理管理平台</p>
        </div>
        <div class="login-body">
            <form method="post">
                <div class="mb-4">
                    <label class="form-label">用户名</label>
                    <input type="text" class="form-control form-control-lg" name="username" placeholder="请输入用户名" autofocus required>
                </div>
                <div class="mb-4">
                    <label class="form-label">密码</label>
                    <input type="password" class="form-control form-control-lg" name="password" placeholder="请输入密码" required>
                </div>
                <button class="btn btn-primary btn-lg w-100" type="submit">
                    <span>登录系统</span>
                </button>
            </form>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-danger mt-3 fade-in">
                    <i class="bi bi-exclamation-circle"></i> {{ messages[0] }}
                </div>
              {% endif %}
            {% endwith %}
        </div>
    </div>
</body>
</html>
EOF

# --------- index.html（主页 - 卡片式C段展示） ---------
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>3proxy 管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock"></i> 3Proxy 管理系统
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="/"><i class="bi bi-house"></i> 主页</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/system_monitor"><i class="bi bi-speedometer2"></i> 系统监控</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/backup_restore"><i class="bi bi-archive"></i> 备份恢复</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/performance_optimize"><i class="bi bi-lightning"></i> 性能优化</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout"><i class="bi bi-box-arrow-right"></i> 退出</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <!-- 统计信息 -->
        <div class="row mb-4">
            <div class="col-md-3 mb-3">
                <div class="stat-card fade-in">
                    <div class="stat-value">{{ total_proxies }}</div>
                    <div class="stat-label">代理总数</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card fade-in">
                    <div class="stat-value text-success">{{ enabled_proxies }}</div>
                    <div class="stat-label">已启用</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card fade-in">
                    <div class="stat-value text-danger">{{ total_proxies - enabled_proxies }}</div>
                    <div class="stat-label">已禁用</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card fade-in">
                    <div class="stat-value text-info">{{ c_segments|length }}</div>
                    <div class="stat-label">C段数量</div>
                </div>
            </div>
        </div>

        <!-- Tab导航 -->
        <ul class="nav nav-tabs mb-4" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane" type="button">
                    <i class="bi bi-hdd-network"></i> 代理管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane" type="button">
                    <i class="bi bi-people"></i> 用户管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-pane" type="button">
                    <i class="bi bi-diagram-3"></i> IP批量管理
                </button>
            </li>
        </ul>

        <div class="tab-content">
            <!-- 代理管理tab -->
            <div class="tab-pane fade show active" id="proxy-pane" role="tabpanel">
                <div class="row">
                    <!-- 批量添加 -->
                    <div class="col-lg-6 mb-4">
                        <div class="form-card">
                            <h5 class="mb-4"><i class="bi bi-plus-circle"></i> 批量添加代理</h5>
                            <form method="post" action="/batchaddproxy">
                                <div class="row g-3 mb-3">
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
                                <button type="submit" class="btn btn-success w-100 mb-3">
                                    <i class="bi bi-plus-lg"></i> 范围添加
                                </button>
                            </form>
                            <form method="post" action="/batchaddproxy">
                                <label class="form-label">手动批量添加</label>
                                <textarea name="batchproxy" class="form-control mb-3" rows="6" placeholder="每行一个：ip,端口 或 ip:端口"></textarea>
                                <button type="submit" class="btn btn-success w-100">
                                    <i class="bi bi-file-earmark-plus"></i> 批量添加
                                </button>
                            </form>
                        </div>
                    </div>

                    <!-- 单个添加 -->
                    <div class="col-lg-6 mb-4">
                        <div class="form-card">
                            <h5 class="mb-4"><i class="bi bi-plus-square"></i> 新增单个代理</h5>
                            <form method="post" action="/addproxy">
                                <div class="mb-3">
                                    <label class="form-label">IP地址</label>
                                    <input name="ip" class="form-control" placeholder="192.168.1.100" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">端口</label>
                                    <input name="port" class="form-control" placeholder="8080" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">用户名</label>
                                    <input name="username" class="form-control" placeholder="用户名" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">密码</label>
                                    <input name="password" class="form-control" placeholder="留空自动生成">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">用户前缀</label>
                                    <input name="userprefix" class="form-control" placeholder="可选">
                                </div>
                                <button class="btn btn-primary w-100" type="submit">
                                    <i class="bi bi-check-circle"></i> 添加代理
                                </button>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- C段列表 -->
                <div class="form-card">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h5><i class="bi bi-list-ul"></i> C段代理列表</h5>
                        <div>
                            <select id="exportCseg" class="form-select form-select-sm d-inline-block" multiple style="width: 200px; height: 100px;">
                                {% for cseg in c_segments %}
                                <option value="{{ cseg }}">{{ cseg }}.x</option>
                                {% endfor %}
                            </select>
                            <button id="exportSelected" class="btn btn-sm btn-outline-info ms-2">
                                <i class="bi bi-download"></i> 导出选中
                            </button>
                        </div>
                    </div>
                    
                    <div class="row" id="cSegmentList">
                        {% for cseg, stats in c_segments.items() %}
                        <div class="col-md-6 col-lg-4 mb-3">
                            <div class="c-segment-card" onclick="location.href='/c_segment/{{ cseg }}'">
                                <div class="c-segment-header">
                                    <div class="c-segment-title">
                                        <i class="bi bi-folder"></i> {{ cseg }}.x
                                    </div>
                                    <div class="c-segment-stats">
                                        <span class="stat-badge badge-total">{{ stats.count }}个</span>
                                        <span class="stat-badge badge-enabled">{{ stats.enabled }}启用</span>
                                        <span class="stat-badge badge-disabled">{{ stats.disabled }}禁用</span>
                                    </div>
                                </div>
                                <div class="mt-2">
                                    <small class="text-muted">
                                        <span class="cnet-traffic" data-cseg="{{ cseg }}">
                                            <i class="bi bi-arrow-up-down"></i> 加载中...
                                        </span>
                                    </small>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>

            <!-- 用户管理tab -->
            <div class="tab-pane fade" id="user-pane" role="tabpanel">
                <div class="form-card">
                    <h5 class="mb-4"><i class="bi bi-person-plus"></i> Web用户管理</h5>
                    <form class="row g-3 mb-4" method="post" action="/adduser">
                        <div class="col-md-5">
                            <input name="username" class="form-control" placeholder="用户名" required>
                        </div>
                        <div class="col-md-5">
                            <input type="password" name="password" class="form-control" placeholder="密码" required>
                        </div>
                        <div class="col-md-2">
                            <button class="btn btn-primary w-100" type="submit">添加用户</button>
                        </div>
                    </form>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>用户名</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for u in users %}
                                <tr>
                                    <td>{{ u[0] }}</td>
                                    <td>{{ u[1] }}</td>
                                    <td>
                                        {% if u[1] != 'admin' %}
                                        <a href="/deluser/{{ u[0] }}" class="btn btn-sm btn-danger" onclick="return confirm('确认删除?')">
                                            <i class="bi bi-trash"></i> 删除
                                        </a>
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
                <div class="form-card">
                    <h5 class="mb-4"><i class="bi bi-diagram-3"></i> IP批量管理</h5>
                    <form class="row g-3 mb-4" method="post" action="/add_ip_config">
                        <div class="col-md-2">
                            <label class="form-label">网卡名</label>
                            <input name="iface" class="form-control" value="{{ default_iface }}" required>
                        </div>
                        <div class="col-md-5">
                            <label class="form-label">IP区间/单IP</label>
                            <input name="ip_input" class="form-control" placeholder="192.168.1.2-254" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">模式</label>
                            <select name="mode" class="form-select">
                                <option value="perm">永久</option>
                                <option value="temp">临时</option>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">&nbsp;</label>
                            <button class="btn btn-success w-100" type="submit">
                                <i class="bi bi-plus-circle"></i> 添加
                            </button>
                        </div>
                    </form>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>IP区间/单IP</th>
                                    <th>类型</th>
                                    <th>网卡</th>
                                    <th>添加时间</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for c in ip_configs %}
                                <tr>
                                    <td>{{ c[0] }}</td>
                                    <td>{{ c[1] }}</td>
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

        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="alert alert-success alert-dismissible fade show mt-3" role="alert">
                <i class="bi bi-check-circle"></i> {{ messages[0] }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
          {% endif %}
        {% endwith %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 加载C段流量信息
        fetch('/cnet_traffic').then(r=>r.json()).then(data=>{
            document.querySelectorAll('.cnet-traffic').forEach(span=>{
                let c = span.getAttribute('data-cseg');
                span.innerHTML = `<i class="bi bi-arrow-up-down"></i> ${data[c] ? data[c] + ' MB' : '0 MB'}`;
            });
        });

        // 导出选中C段
        document.getElementById('exportSelected').onclick = function(){
            let selected = Array.from(document.getElementById('exportCseg').selectedOptions).map(o=>o.value);
            if(selected.length==0) { 
                alert("请选择C段"); 
                return; 
            }
            let form = new FormData();
            selected.forEach(c=>form.append('csegs[]',c));
            fetch('/export_selected', {method:'POST', body:form})
                .then(resp=>resp.blob())
                .then(blob=>{
                    let a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'proxy_export.txt';
                    a.click();
                });
        };
    </script>
</body>
</html>
EOF

# --------- c_segment_detail.html（C段详情页） ---------
cat > $WORKDIR/templates/c_segment_detail.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>{{ cseg }}.x 代理详情 - 3proxy管理</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock"></i> 3Proxy 管理系统
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/"><i class="bi bi-house"></i> 主页</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/system_monitor"><i class="bi bi-speedometer2"></i> 系统监控</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/backup_restore"><i class="bi bi-archive"></i> 备份恢复</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/performance_optimize"><i class="bi bi-lightning"></i> 性能优化</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout"><i class="bi bi-box-arrow-right"></i> 退出</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="form-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h4><i class="bi bi-folder-open"></i> {{ cseg }}.x 段代理列表</h4>
                <div>
                    <button type="button" id="exportSelectedProxy" class="btn btn-outline-success btn-sm">
                        <i class="bi bi-download"></i> 导出选中
                    </button>
                    <a href="/" class="btn btn-outline-secondary btn-sm">
                        <i class="bi bi-arrow-left"></i> 返回主页
                    </a>
                </div>
            </div>

            <div class="mb-3">
                <input id="searchBox" class="form-control" placeholder="搜索IP/端口/用户名...">
            </div>

            <form method="post" action="/batchdelproxy" id="proxyForm">
                <div class="table-responsive">
                    <table class="table table-hover" id="proxyTable">
                        <thead>
                            <tr>
                                <th><input type="checkbox" id="selectAll"></th>
                                <th>ID</th>
                                <th>IP</th>
                                <th>端口</th>
                                <th>用户名</th>
                                <th>密码</th>
                                <th>状态</th>
                                <th>IP范围</th>
                                <th>端口范围</th>
                                <th>前缀</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="proxyTableBody">
                            {% for p in proxies %}
                            <tr class="proxy-row">
                                <td><input type="checkbox" name="ids" value="{{ p[0] }}"></td>
                                <td>{{ p[0] }}</td>
                                <td>{{ p[1] }}</td>
                                <td>{{ p[2] }}</td>
                                <td>{{ p[3] }}</td>
                                <td>{{ p[4] }}</td>
                                <td>
                                    {% if p[5] %}
                                        <span class="badge bg-success">启用</span>
                                    {% else %}
                                        <span class="badge bg-secondary">禁用</span>
                                    {% endif %}
                                </td>
                                <td>{{ p[6] or '' }}</td>
                                <td>{{ p[7] or '' }}</td>
                                <td>{{ p[8] or '' }}</td>
                                <td>
                                    {% if p[5] %}
                                        <a href="/disableproxy/{{ p[0] }}" class="btn btn-sm btn-warning">
                                            <i class="bi bi-pause"></i>
                                        </a>
                                    {% else %}
                                        <a href="/enableproxy/{{ p[0] }}" class="btn btn-sm btn-success">
                                            <i class="bi bi-play"></i>
                                        </a>
                                    {% endif %}
                                    <a href="/delproxy/{{ p[0] }}" class="btn btn-sm btn-danger" onclick="return confirm('确认删除?')">
                                        <i class="bi bi-trash"></i>
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                
                <div class="mt-3">
                    <button type="submit" class="btn btn-danger" onclick="return confirm('确定批量删除选中项?')">
                        <i class="bi bi-trash"></i> 批量删除
                    </button>
                    <button type="button" class="btn btn-warning ms-2" id="batchEnable">
                        <i class="bi bi-play-circle"></i> 批量启用
                    </button>
                    <button type="button" class="btn btn-secondary ms-2" id="batchDisable">
                        <i class="bi bi-pause-circle"></i> 批量禁用
                    </button>
                </div>
            </form>
        </div>

        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="alert alert-success alert-dismissible fade show mt-3" role="alert">
                <i class="bi bi-check-circle"></i> {{ messages[0] }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
          {% endif %}
        {% endwith %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 全选功能
        document.getElementById('selectAll').onclick = function() {
            var cbs = document.querySelectorAll('#proxyTableBody input[type="checkbox"]');
            for(var i=0; i<cbs.length; i++) cbs[i].checked = this.checked;
        };

        // 搜索功能
        document.getElementById('searchBox').oninput = function() {
            let val = this.value.toLowerCase();
            document.querySelectorAll('.proxy-row').forEach(row => {
                let text = row.textContent.toLowerCase();
                row.style.display = text.includes(val) ? '' : 'none';
            });
        };

        // 导出选中代理
        document.getElementById('exportSelectedProxy').onclick = function(){
            let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
            if(ids.length === 0) { 
                alert("请选择代理"); 
                return; 
            }
            let form = new FormData();
            ids.forEach(id=>form.append('ids[]',id));
            fetch('/export_selected_proxy', {method:'POST', body:form})
                .then(resp=>resp.blob())
                .then(blob=>{
                    let a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'proxy_export.txt';
                    a.click();
                });
        };

        // 批量启用
        document.getElementById('batchEnable').onclick = function(){
            let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
            if(ids.length === 0) { 
                alert("请选择代理"); 
                return; 
            }
            let form = new FormData();
            ids.forEach(id=>form.append('ids[]',id));
            fetch('/batch_enable', {method:'POST', body:form}).then(()=>location.reload());
        };

        // 批量禁用
        document.getElementById('batchDisable').onclick = function(){
            let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
            if(ids.length === 0) { 
                alert("请选择代理"); 
                return; 
            }
            let form = new FormData();
            ids.forEach(id=>form.append('ids[]',id));
            fetch('/batch_disable', {method:'POST', body:form}).then(()=>location.reload());
        };
    </script>
</body>
</html>
EOF

# --------- system_monitor.html（系统监控页） ---------
cat > $WORKDIR/templates/system_monitor.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>系统监控 - 3proxy管理</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock"></i> 3Proxy 管理系统
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/"><i class="bi bi-house"></i> 主页</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/system_monitor"><i class="bi bi-speedometer2"></i> 系统监控</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/backup_restore"><i class="bi bi-archive"></i> 备份恢复</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/performance_optimize"><i class="bi bi-lightning"></i> 性能优化</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout"><i class="bi bi-box-arrow-right"></i> 退出</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <!-- 实时状态 -->
        <div class="row mb-4">
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <h6 class="text-muted">CPU使用率</h6>
                    <div class="stat-value" id="cpu-stat">--%</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <h6 class="text-muted">内存使用</h6>
                    <div class="stat-value" id="mem-stat">--%</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <h6 class="text-muted">磁盘使用</h6>
                    <div class="stat-value" id="disk-stat">--%</div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <h6 class="text-muted">3proxy状态</h6>
                    <div class="stat-value text-success" id="proxy-stat">运行中</div>
                </div>
            </div>
        </div>

        <!-- 图表 -->
        <div class="row">
            <div class="col-lg-6 mb-4">
                <div class="chart-container">
                    <h5><i class="bi bi-cpu"></i> CPU使用率</h5>
                    <canvas id="cpuChart"></canvas>
                </div>
            </div>
            <div class="col-lg-6 mb-4">
                <div class="chart-container">
                    <h5><i class="bi bi-memory"></i> 内存使用率</h5>
                    <canvas id="memChart"></canvas>
                </div>
            </div>
            <div class="col-lg-6 mb-4">
                <div class="chart-container">
                    <h5><i class="bi bi-hdd"></i> 磁盘使用率</h5>
                    <canvas id="diskChart"></canvas>
                </div>
            </div>
            <div class="col-lg-6 mb-4">
                <div class="chart-container">
                    <h5><i class="bi bi-ethernet"></i> 网络流量</h5>
                    <canvas id="netChart"></canvas>
                </div>
            </div>
        </div>

        <!-- 时间选择器 -->
        <div class="text-center mt-3">
            <div class="btn-group" role="group">
                <button type="button" class="btn btn-outline-primary" onclick="changeTimeRange(1)">1小时</button>
                <button type="button" class="btn btn-outline-primary" onclick="changeTimeRange(6)">6小时</button>
                <button type="button" class="btn btn-outline-primary active" onclick="changeTimeRange(24)">24小时</button>
                <button type="button" class="btn btn-outline-primary" onclick="changeTimeRange(168)">7天</button>
            </div>
        </div>
    </div>

    <script>
        // 图表配置
        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    display: false
                },
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        };

        // 初始化图表
        const cpuChart = new Chart(document.getElementById('cpuChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.3
                }]
            },
            options: chartOptions
        });

        const memChart = new Chart(document.getElementById('memChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.3
                }]
            },
            options: chartOptions
        });

        const diskChart = new Chart(document.getElementById('diskChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    borderColor: '#f39c12',
                    backgroundColor: 'rgba(243, 156, 18, 0.1)',
                    tension: 0.3
                }]
            },
            options: chartOptions
        });

        const netChart = new Chart(document.getElementById('netChart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: '发送',
                    data: [],
                    borderColor: '#27ae60',
                    backgroundColor: 'rgba(39, 174, 96, 0.1)',
                    tension: 0.3
                }, {
                    label: '接收',
                    data: [],
                    borderColor: '#16a085',
                    backgroundColor: 'rgba(22, 160, 133, 0.1)',
                    tension: 0.3
                }]
            },
            options: {
                ...chartOptions,
                plugins: {
                    legend: {
                        display: true
                    }
                },
                scales: {
                    ...chartOptions.scales,
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        let currentTimeRange = 24;

        // 更新实时数据
        function updateStats() {
            fetch('/api/system_stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('cpu-stat').textContent = data.cpu.toFixed(1) + '%';
                    document.getElementById('mem-stat').textContent = data.memory.percent.toFixed(1) + '%';
                    document.getElementById('disk-stat').textContent = data.disk.percent.toFixed(1) + '%';
                    
                    if (data.proxy_process) {
                        document.getElementById('proxy-stat').innerHTML = '<span class="text-success">运行中</span>';
                    } else {
                        document.getElementById('proxy-stat').innerHTML = '<span class="text-danger">已停止</span>';
                    }
                });
        }

        // 更新历史数据
        function updateHistory() {
            fetch(`/api/history_stats?hours=${currentTimeRange}`)
                .then(r => r.json())
                .then(data => {
                    const labels = data.timestamps.map(t => new Date(t * 1000).toLocaleTimeString());
                    
                    cpuChart.data.labels = labels;
                    cpuChart.data.datasets[0].data = data.cpu;
                    cpuChart.update();
                    
                    memChart.data.labels = labels;
                    memChart.data.datasets[0].data = data.memory;
                    memChart.update();
                    
                    diskChart.data.labels = labels;
                    diskChart.data.datasets[0].data = data.disk;
                    diskChart.update();
                    
                    netChart.data.labels = labels;
                    netChart.data.datasets[0].data = data.network_sent;
                    netChart.data.datasets[1].data = data.network_recv;
                    netChart.update();
                });
        }

        // 改变时间范围
        function changeTimeRange(hours) {
            currentTimeRange = hours;
            document.querySelectorAll('.btn-group button').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            updateHistory();
        }

        // 定时更新
        updateStats();
        updateHistory();
        setInterval(updateStats, 5000);
        setInterval(updateHistory, 60000);
    </script>
</body>
</html>
EOF

# --------- backup_restore.html（备份恢复页） ---------
cat > $WORKDIR/templates/backup_restore.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>备份恢复 - 3proxy管理</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock"></i> 3Proxy 管理系统
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/"><i class="bi bi-house"></i> 主页</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/system_monitor"><i class="bi bi-speedometer2"></i> 系统监控</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/backup_restore"><i class="bi bi-archive"></i> 备份恢复</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/performance_optimize"><i class="bi bi-lightning"></i> 性能优化</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout"><i class="bi bi-box-arrow-right"></i> 退出</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="row">
            <div class="col-lg-4 mb-4">
                <div class="form-card">
                    <h5><i class="bi bi-plus-circle"></i> 创建备份</h5>
                    <p class="text-muted">立即创建一个新的备份文件</p>
                    <form method="post" action="/create_backup">
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-download"></i> 立即备份
                        </button>
                    </form>
                    <hr>
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle"></i> 自动备份已启用
                        <br>
                        <small>每天凌晨2点自动备份</small>
                    </div>
                </div>
            </div>

            <div class="col-lg-8 mb-4">
                <div class="form-card">
                    <h5><i class="bi bi-clock-history"></i> 备份历史</h5>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>文件名</th>
                                    <th>大小</th>
                                    <th>创建时间</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for backup in backups %}
                                <tr>
                                    <td>
                                        <i class="bi bi-file-earmark-zip"></i> {{ backup.filename }}
                                    </td>
                                    <td>{{ backup.size }}</td>
                                    <td>{{ backup.time }}</td>
                                    <td>
                                        <a href="/restore_backup/{{ backup.filename }}" 
                                           class="btn btn-sm btn-success"
                                           onclick="return confirm('确定要恢复此备份吗？当前数据将被覆盖！')">
                                            <i class="bi bi-arrow-counterclockwise"></i> 恢复
                                        </a>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        {% if not backups %}
                        <p class="text-center text-muted">暂无备份文件</p>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>

        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle"></i> {{ messages[0] }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
          {% endif %}
        {% endwith %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# --------- performance_optimize.html（性能优化页） ---------
cat > $WORKDIR/templates/performance_optimize.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>性能优化 - 3proxy管理</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock"></i> 3Proxy 管理系统
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/"><i class="bi bi-house"></i> 主页</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/system_monitor"><i class="bi bi-speedometer2"></i> 系统监控</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/backup_restore"><i class="bi bi-archive"></i> 备份恢复</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/performance_optimize"><i class="bi bi-lightning"></i> 性能优化</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout"><i class="bi bi-box-arrow-right"></i> 退出</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="row">
            <div class="col-lg-6 mb-4">
                <div class="form-card">
                    <h5><i class="bi bi-gear"></i> 3proxy 性能参数</h5>
                    <form method="post" action="/apply_optimization">
                        <div class="mb-3">
                            <label class="form-label">最大连接数 (maxconn)</label>
                            <input type="number" class="form-control" name="maxconn" 
                                   value="{{ config.get('maxconn', '2000') }}" min="100" max="100000">
                            <small class="text-muted">建议值：2000-10000，根据服务器配置调整</small>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">DNS缓存大小 (nscache)</label>
                            <input type="number" class="form-control" name="nscache" 
                                   value="{{ config.get('nscache', '65536') }}" min="1024" max="1048576">
                            <small class="text-muted">建议值：65536，可提高DNS解析性能</small>
                        </div>
                        
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-check-circle"></i> 应用优化配置
                        </button>
                    </form>
                </div>
            </div>

            <div class="col-lg-6 mb-4">
                <div class="form-card">
                    <h5><i class="bi bi-info-circle"></i> 优化建议</h5>
                    <div class="alert alert-info">
                        <h6>系统优化建议：</h6>
                        <ul>
                            <li>增加系统文件描述符限制</li>
                            <li>优化网络缓冲区大小</li>
                            <li>启用TCP快速打开</li>
                            <li>调整TCP连接超时参数</li>
                        </ul>
                    </div>
                    
                    <div class="alert alert-warning">
                        <h6>注意事项：</h6>
                        <ul>
                            <li>修改参数后会重启3proxy服务</li>
                            <li>建议在低峰期进行优化操作</li>
                            <li>请根据实际负载情况调整参数</li>
                        </ul>
                    </div>

                    <div class="mt-3">
                        <h6>快速优化命令：</h6>
                        <pre class="bg-dark text-light p-3 rounded">
# 增加文件描述符限制
echo "* soft nofile 65535" >> /etc/security/limits.conf
echo "* hard nofile 65535" >> /etc/security/limits.conf

# 优化网络参数
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w net.ipv4.tcp_fastopen=3</pre>
                    </div>
                </div>
            </div>
        </div>

        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="bi bi-check-circle"></i> {{ messages[0] }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
          {% endif %}
        {% endwith %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# --------- 系统监控服务 ---------
cat > /etc/systemd/system/3proxy-monitor.service <<EOF
[Unit]
Description=3proxy系统监控服务
After=network.target 3proxy-web.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do curl -s http://localhost:$PORT/api/system_stats > /dev/null; sleep 60; done'
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --------- Systemd服务启动 ---------
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
Type=simple
WorkingDirectory=$WORKDIR
ExecStart=/bin/bash -c "$WORKDIR/venv/bin/python3 $WORKDIR/config_gen.py && $THREEPROXY_PATH $PROXYCFG_PATH"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# 初始化数据库
cd $WORKDIR
export ADMINUSER
export ADMINPASS
$WORKDIR/venv/bin/python3 init_db.py

# 设置备份管理器权限
chmod +x $WORKDIR/backup_manager.py

# 启动服务
systemctl daemon-reload
systemctl enable 3proxy-web
systemctl enable 3proxy-autostart
systemctl enable 3proxy-monitor
systemctl restart 3proxy-web
systemctl restart 3proxy-autostart
systemctl restart 3proxy-monitor

echo -e "\n========= 增强版部署完成！========="
MYIP=$(get_local_ip)
echo -e "浏览器访问：\n  \033[36mhttp://$MYIP:${PORT}\033[0m"
echo "Web管理用户名: $ADMINUSER"
echo "Web管理密码:  $ADMINPASS"
echo -e "\n新增功能："
echo "- 美化的Web界面，统一的视觉风格"
echo "- C段卡片式展示，点击进入详情页"
echo "- 系统监控功能，实时查看系统状态"
echo "- 自动备份功能，每天凌晨2点自动备份"
echo "- 性能优化配置，可调整3proxy参数"
echo -e "\n如需卸载：bash $0 uninstall"
echo -e "如需重装：bash $0 reinstall"
