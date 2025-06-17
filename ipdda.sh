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
    systemctl disable 3proxy-web 2>/dev/null || true
    systemctl disable 3proxy-autostart 2>/dev/null || true
    rm -rf $WORKDIR
    rm -f /etc/systemd/system/3proxy-web.service
    rm -f /etc/systemd/system/3proxy-autostart.service
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
rotate 7
EOF
fi

# 创建备份目录
mkdir -p $BACKUP_DIR

# 日志轮换 - 每3天清空一次
cat > /etc/cron.d/3proxy-logrotate <<EOF
0 3 */3 * * root [ -f "$LOGFILE" ] && cp "$LOGFILE" "$LOGFILE.$(date +\%Y\%m\%d)" && > "$LOGFILE" && find /usr/local/etc/3proxy -name "3proxy.log.*" -mtime +7 -delete
EOF

# 自动备份 - 每天备份一次
cat > /etc/cron.d/3proxy-backup <<EOF
0 2 * * * root cd $WORKDIR && /usr/bin/sqlite3 3proxy.db ".backup '$BACKUP_DIR/3proxy_$(date +\%Y\%m\%d).db'" && find $BACKUP_DIR -name "*.db" -mtime +30 -delete
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

DB = '3proxy.db'
SECRET = 'changeme_this_is_secret'
import sys
PORT = int(sys.argv[1]) if len(sys.argv)>1 else 9999
THREEPROXY_PATH = '/usr/local/bin/3proxy'
PROXYCFG_PATH = '/usr/local/etc/3proxy/3proxy.cfg'
LOGFILE = '/usr/local/etc/3proxy/3proxy.log'
INTERFACES_FILE = '/etc/network/interfaces'
BACKUP_DIR = '/usr/local/etc/3proxy/backups'

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = SECRET
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def get_db():
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
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()
    
    # 获取3proxy进程信息
    proxy_stats = {'pid': 0, 'cpu': 0, 'memory': 0, 'connections': 0}
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        if proc.info['name'] == '3proxy':
            proxy_stats['pid'] = proc.info['pid']
            proxy_stats['cpu'] = proc.info['cpu_percent']
            proxy_stats['memory'] = proc.info['memory_percent']
            try:
                proxy_stats['connections'] = len(proc.connections())
            except:
                pass
    
    return {
        'cpu': cpu_percent,
        'memory': memory.percent,
        'disk': disk.percent,
        'network_sent': round(net_io.bytes_sent / 1024 / 1024 / 1024, 2),
        'network_recv': round(net_io.bytes_recv / 1024 / 1024 / 1024, 2),
        'proxy_stats': proxy_stats
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
    # 获取代理总数和C段统计
    total_proxies = db.execute('SELECT COUNT(*) FROM proxy').fetchone()[0]
    enabled_proxies = db.execute('SELECT COUNT(*) FROM proxy WHERE enabled=1').fetchone()[0]
    
    # 获取C段分组统计
    proxies = db.execute('SELECT id,ip FROM proxy ORDER BY ip').fetchall()
    c_segments = {}
    for p in proxies:
        c_seg = '.'.join(p[1].split('.')[:3])
        if c_seg not in c_segments:
            c_segments[c_seg] = {'count': 0, 'enabled': 0}
        c_segments[c_seg]['count'] += 1
    
    # 计算启用的代理数
    enabled = db.execute('SELECT ip FROM proxy WHERE enabled=1').fetchall()
    for p in enabled:
        c_seg = '.'.join(p[0].split('.')[:3])
        if c_seg in c_segments:
            c_segments[c_seg]['enabled'] += 1
    
    users = db.execute('SELECT id,username FROM users').fetchall()
    ip_configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC LIMIT 10').fetchall()
    db.close()
    
    return render_template('index.html', 
        total_proxies=total_proxies,
        enabled_proxies=enabled_proxies,
        c_segments=c_segments,
        users=users, 
        ip_configs=ip_configs, 
        default_iface=detect_nic())

@app.route('/c_segment/<segment>')
@login_required
def c_segment_detail(segment):
    db = get_db()
    proxies = db.execute('SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port', (segment + '.%',)).fetchall()
    db.close()
    return render_template('c_segment.html', segment=segment, proxies=proxies)

@app.route('/system_monitor')
@login_required
def system_monitor():
    return render_template('monitor.html')

@app.route('/api/system_stats')
@login_required
def api_system_stats():
    return jsonify(get_system_stats())

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')

@app.route('/api/logs/<log_type>')
@login_required
def api_logs(log_type):
    if log_type == 'proxy':
        log_file = LOGFILE
    elif log_type == 'web':
        log_file = os.path.join(WORKDIR, 'web.log')
    else:
        return jsonify({'error': 'Invalid log type'}), 400
    
    if not os.path.exists(log_file):
        return jsonify({'content': 'Log file not found', 'size': 0})
    
    # 只读取最后1000行
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-1000:]
        return jsonify({
            'content': ''.join(lines),
            'size': os.path.getsize(log_file)
        })
    except Exception as e:
        return jsonify({'content': f'Error reading log: {str(e)}', 'size': 0})

@app.route('/backup')
@login_required
def backup():
    backups = []
    if os.path.exists(BACKUP_DIR):
        for f in os.listdir(BACKUP_DIR):
            if f.endswith('.db'):
                path = os.path.join(BACKUP_DIR, f)
                size = os.path.getsize(path) / 1024 / 1024  # MB
                mtime = datetime.fromtimestamp(os.path.getmtime(path))
                backups.append({
                    'name': f,
                    'size': round(size, 2),
                    'date': mtime.strftime('%Y-%m-%d %H:%M:%S')
                })
    backups.sort(key=lambda x: x['date'], reverse=True)
    return render_template('backup.html', backups=backups)

@app.route('/backup/create')
@login_required
def create_backup():
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(BACKUP_DIR, f'3proxy_manual_{timestamp}.db')
    os.system(f'sqlite3 {DB} ".backup \'{backup_file}\'"')
    flash('备份创建成功')
    return redirect(url_for('backup'))

@app.route('/backup/restore/<filename>')
@login_required
def restore_backup(filename):
    if not filename.endswith('.db'):
        flash('无效的备份文件')
        return redirect(url_for('backup'))
    
    backup_file = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(backup_file):
        os.system(f'cp {backup_file} {DB}')
        reload_3proxy()
        flash('备份恢复成功')
    else:
        flash('备份文件不存在')
    return redirect(url_for('backup'))

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

# --------- config_gen.py（3proxy配置生成器 - 优化版） ---------
cat > $WORKDIR/config_gen.py << 'EOF'
import sqlite3
db = sqlite3.connect('3proxy.db')
cursor = db.execute('SELECT ip, port, username, password, enabled FROM proxy')
cfg = [
"daemon",
"maxconn 5000",
"nserver 8.8.8.8",
"nserver 8.8.4.4", 
"nscache 65536",
"timeouts 1 5 30 60 180 1800 15 60",
"log /usr/local/etc/3proxy/3proxy.log D",
"rotate 7",
"archiver gz /usr/bin/gzip %F",
"auth strong",
"dnspr"
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

# --------- init_db.py（数据库初始化） ---------
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

# --------- login.html (美化版登录页) ---------
cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3proxy 管理系统登录</title>
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
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            animation: slideUp 0.5s ease-out;
        }
        @keyframes slideUp {
            from {
                transform: translateY(30px);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header h3 {
            color: #667eea;
            font-weight: bold;
        }
        .form-control {
            border-radius: 10px;
            border: 2px solid #e0e0e0;
            padding: 12px 15px;
            transition: all 0.3s;
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 10px;
            padding: 12px;
            font-weight: bold;
            transition: all 0.3s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 40px;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-5 col-lg-4">
                <div class="login-card">
                    <div class="login-header">
                        <div class="logo">🔐</div>
                        <h3>3proxy 管理系统</h3>
                        <p class="text-muted">请登录以继续</p>
                    </div>
                    <form method="post">
                        <div class="mb-4">
                            <label class="form-label">用户名</label>
                            <input type="text" class="form-control" name="username" placeholder="请输入用户名" autofocus required>
                        </div>
                        <div class="mb-4">
                            <label class="form-label">密码</label>
                            <input type="password" class="form-control" name="password" placeholder="请输入密码" required>
                        </div>
                        <button class="btn btn-primary btn-login w-100" type="submit">登录</button>
                    </form>
                    {% with messages = get_flashed_messages() %}
                        {% if messages %}
                            <div class="alert alert-danger mt-3 mb-0" role="alert">
                                {{ messages[0] }}
                            </div>
                        {% endif %}
                    {% endwith %}
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF

# --------- index.html (美化版主页 - 卡片式设计) ---------
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>3proxy 管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --success-color: #48bb78;
            --danger-color: #f56565;
            --warning-color: #ed8936;
            --info-color: #4299e1;
            --dark-bg: #1a202c;
            --dark-card: #2d3748;
            --dark-text: #e2e8f0;
        }
        
        body {
            background-color: #f7fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .navbar-brand {
            font-weight: bold;
            font-size: 1.5rem;
        }
        
        .stat-card {
            border-radius: 15px;
            border: none;
            transition: all 0.3s ease;
            overflow: hidden;
            height: 100%;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .stat-card .card-body {
            padding: 1.5rem;
        }
        
        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: white;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin: 0;
        }
        
        .stat-label {
            color: #718096;
            font-size: 0.875rem;
            margin: 0;
        }
        
        .c-segment-card {
            border-radius: 15px;
            border: none;
            transition: all 0.3s ease;
            cursor: pointer;
            overflow: hidden;
        }
        
        .c-segment-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        }
        
        .c-segment-header {
            background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
            padding: 1.5rem;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .c-segment-body {
            padding: 1.5rem;
        }
        
        .progress {
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .feature-card {
            border-radius: 15px;
            border: none;
            padding: 2rem;
            height: 100%;
            transition: all 0.3s ease;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .feature-icon {
            width: 80px;
            height: 80px;
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            color: white;
            margin: 0 auto 1rem;
        }
        
        .btn-gradient {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            border: none;
            color: white;
            font-weight: 500;
            padding: 0.75rem 2rem;
            border-radius: 10px;
            transition: all 0.3s ease;
        }
        
        .btn-gradient:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            color: white;
        }
        
        /* Dark mode styles */
        .dark-mode {
            background-color: var(--dark-bg);
            color: var(--dark-text);
        }
        
        .dark-mode .card {
            background-color: var(--dark-card);
            color: var(--dark-text);
        }
        
        .dark-mode .navbar {
            background: linear-gradient(135deg, #4a5568 0%, #2d3748 100%);
        }
        
        .dark-mode .c-segment-header {
            background: linear-gradient(135deg, #4a5568 0%, #2d3748 100%);
        }
        
        .dark-mode .stat-label {
            color: #a0aec0;
        }
        
        .dark-mode .form-control, .dark-mode .form-select {
            background-color: #4a5568;
            border-color: #4a5568;
            color: var(--dark-text);
        }
        
        .dark-mode .form-control:focus, .dark-mode .form-select:focus {
            background-color: #4a5568;
            border-color: var(--primary-color);
            color: var(--dark-text);
        }
        
        .dark-mode .modal-content {
            background-color: var(--dark-card);
            color: var(--dark-text);
        }
        
        .dark-mode .modal-header {
            border-bottom-color: #4a5568;
        }
        
        .dark-mode .modal-footer {
            border-top-color: #4a5568;
        }
        
        .theme-toggle {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
        }
        
        .quick-actions {
            position: fixed;
            bottom: 80px;
            right: 20px;
            z-index: 999;
        }
        
        .quick-actions .btn {
            display: block;
            margin-bottom: 10px;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }
        
        @media (max-width: 768px) {
            .stat-card .card-body {
                padding: 1rem;
            }
            .stat-value {
                font-size: 1.5rem;
            }
            .feature-card {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-shield-lock-fill me-2"></i>3proxy 管理系统
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/system_monitor">
                            <i class="bi bi-speedometer2 me-1"></i>系统监控
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logs">
                            <i class="bi bi-file-text me-1"></i>日志
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/backup">
                            <i class="bi bi-archive me-1"></i>备份
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/logout">
                            <i class="bi bi-box-arrow-right me-1"></i>退出
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <!-- 统计卡片 -->
        <div class="row mb-4">
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                                <i class="bi bi-server"></i>
                            </div>
                            <div class="ms-3">
                                <p class="stat-value">{{ total_proxies }}</p>
                                <p class="stat-label">代理总数</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);">
                                <i class="bi bi-check-circle"></i>
                            </div>
                            <div class="ms-3">
                                <p class="stat-value">{{ enabled_proxies }}</p>
                                <p class="stat-label">已启用</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);">
                                <i class="bi bi-diagram-3"></i>
                            </div>
                            <div class="ms-3">
                                <p class="stat-value">{{ c_segments|length }}</p>
                                <p class="stat-label">C段数量</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);">
                                <i class="bi bi-people"></i>
                            </div>
                            <div class="ms-3">
                                <p class="stat-value">{{ users|length }}</p>
                                <p class="stat-label">管理员</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 快速操作 -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title mb-3">
                            <i class="bi bi-lightning-charge-fill text-warning me-2"></i>快速操作
                        </h5>
                        <div class="row">
                            <div class="col-md-3 col-sm-6 mb-3">
                                <button class="btn btn-gradient w-100" data-bs-toggle="modal" data-bs-target="#addProxyModal">
                                    <i class="bi bi-plus-circle me-2"></i>添加代理
                                </button>
                            </div>
                            <div class="col-md-3 col-sm-6 mb-3">
                                <button class="btn btn-success w-100" data-bs-toggle="modal" data-bs-target="#batchAddModal">
                                    <i class="bi bi-stack me-2"></i>批量添加
                                </button>
                            </div>
                            <div class="col-md-3 col-sm-6 mb-3">
                                <button class="btn btn-info w-100" data-bs-toggle="modal" data-bs-target="#userModal">
                                    <i class="bi bi-person-plus me-2"></i>用户管理
                                </button>
                            </div>
                            <div class="col-md-3 col-sm-6 mb-3">
                                <button class="btn btn-warning w-100" data-bs-toggle="modal" data-bs-target="#ipConfigModal">
                                    <i class="bi bi-hdd-network me-2"></i>IP配置
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- C段卡片 -->
        <div class="row">
            <div class="col-12">
                <h4 class="mb-3">
                    <i class="bi bi-collection me-2"></i>C段管理
                    <button class="btn btn-sm btn-outline-primary float-end" id="exportBtn">
                        <i class="bi bi-download me-1"></i>导出选中
                    </button>
                </h4>
            </div>
            {% for segment, data in c_segments.items() %}
            <div class="col-lg-4 col-md-6 mb-4">
                <div class="card c-segment-card" onclick="window.location.href='/c_segment/{{ segment }}'">
                    <div class="c-segment-header">
                        <div class="d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">
                                <i class="bi bi-diagram-2 me-2"></i>{{ segment }}.x
                            </h5>
                            <input type="checkbox" class="form-check-input segment-check" value="{{ segment }}" onclick="event.stopPropagation()">
                        </div>
                    </div>
                    <div class="c-segment-body">
                        <div class="row mb-3">
                            <div class="col-6">
                                <span class="text-muted">代理总数</span>
                                <h4 class="mb-0">{{ data.count }}</h4>
                            </div>
                            <div class="col-6">
                                <span class="text-muted">已启用</span>
                                <h4 class="mb-0 text-success">{{ data.enabled }}</h4>
                            </div>
                        </div>
                        <div class="progress mb-2">
                            <div class="progress-bar bg-success" style="width: {{ (data.enabled / data.count * 100) if data.count > 0 else 0 }}%"></div>
                        </div>
                        <div class="d-flex justify-content-between align-items-center">
                            <span class="badge bg-info cnet-traffic" data-cseg="{{ segment }}">
                                <i class="bi bi-arrow-down-up me-1"></i>加载中...
                            </span>
                            <span class="text-primary">
                                点击管理 <i class="bi bi-arrow-right"></i>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        <!-- Flash消息 -->
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <div class="position-fixed bottom-0 end-0 p-3" style="z-index: 11">
                    <div class="toast show align-items-center text-white bg-success border-0" role="alert">
                        <div class="d-flex">
                            <div class="toast-body">
                                <i class="bi bi-check-circle-fill me-2"></i>{{ messages[0] }}
                            </div>
                            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                        </div>
                    </div>
                </div>
            {% endif %}
        {% endwith %}
    </div>

    <!-- 添加代理模态框 -->
    <div class="modal fade" id="addProxyModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-plus-circle me-2"></i>添加单个代理
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="post" action="/addproxy">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">IP地址</label>
                            <input name="ip" class="form-control" placeholder="192.168.1.100" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">端口</label>
                            <input name="port" type="number" class="form-control" placeholder="8080" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">用户名</label>
                            <input name="username" class="form-control" placeholder="user001" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">密码（留空自动生成）</label>
                            <input name="password" class="form-control" placeholder="留空自动生成">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">用户前缀（可选）</label>
                            <input name="userprefix" class="form-control" placeholder="prefix_">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                        <button type="submit" class="btn btn-gradient">添加</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- 批量添加模态框 -->
    <div class="modal fade" id="batchAddModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-stack me-2"></i>批量添加代理
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <ul class="nav nav-tabs mb-3" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#rangeTab" type="button">范围添加</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#manualTab" type="button">手动批量</button>
                        </li>
                    </ul>
                    <div class="tab-content">
                        <div class="tab-pane fade show active" id="rangeTab">
                            <form method="post" action="/batchaddproxy">
                                <div class="row">
                                    <div class="col-md-4 mb-3">
                                        <label class="form-label">IP范围</label>
                                        <input type="text" class="form-control" name="iprange" placeholder="192.168.1.2-254">
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <label class="form-label">端口范围</label>
                                        <input type="text" class="form-control" name="portrange" placeholder="20000-30000">
                                    </div>
                                    <div class="col-md-4 mb-3">
                                        <label class="form-label">用户名前缀</label>
                                        <input type="text" class="form-control" name="userprefix" placeholder="user">
                                    </div>
                                </div>
                                <button type="submit" class="btn btn-gradient w-100">
                                    <i class="bi bi-plus-square me-2"></i>范围添加
                                </button>
                            </form>
                        </div>
                        <div class="tab-pane fade" id="manualTab">
                            <form method="post" action="/batchaddproxy">
                                <div class="mb-3">
                                    <label class="form-label">批量数据（每行一个）</label>
                                    <textarea name="batchproxy" class="form-control" rows="10" placeholder="格式示例：
192.168.1.100,8080
192.168.1.101:8081:user001
192.168.1.102,8082,user002,password123"></textarea>
                                </div>
                                <button type="submit" class="btn btn-success w-100">
                                    <i class="bi bi-upload me-2"></i>批量添加
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 用户管理模态框 -->
    <div class="modal fade" id="userModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-people me-2"></i>用户管理
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form method="post" action="/adduser" class="mb-3">
                        <div class="row g-2">
                            <div class="col">
                                <input name="username" class="form-control" placeholder="用户名" required>
                            </div>
                            <div class="col">
                                <input name="password" type="password" class="form-control" placeholder="密码" required>
                            </div>
                            <div class="col-auto">
                                <button type="submit" class="btn btn-primary">添加</button>
                            </div>
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
                                            <i class="bi bi-trash"></i>
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
        </div>
    </div>

    <!-- IP配置模态框 -->
    <div class="modal fade" id="ipConfigModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">
                        <i class="bi bi-hdd-network me-2"></i>IP批量配置
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form method="post" action="/add_ip_config" class="mb-3">
                        <div class="row g-2">
                            <div class="col-md-2">
                                <label class="form-label">网卡</label>
                                <input name="iface" class="form-control" value="{{ default_iface }}" required>
                            </div>
                            <div class="col-md-5">
                                <label class="form-label">IP配置</label>
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
                                <button type="submit" class="btn btn-primary w-100">添加</button>
                            </div>
                        </div>
                    </form>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>IP配置</th>
                                    <th>网卡</th>
                                    <th>添加时间</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for c in ip_configs %}
                                <tr>
                                    <td>{{ c[0] }}</td>
                                    <td><code>{{ c[1] }}</code></td>
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
    </div>

    <!-- 主题切换按钮 -->
    <button class="btn btn-primary theme-toggle" id="themeToggle">
        <i class="bi bi-moon-stars-fill"></i>
    </button>

    <!-- 快速操作按钮 -->
    <div class="quick-actions">
        <a href="/system_monitor" class="btn btn-info" title="系统监控">
            <i class="bi bi-speedometer2"></i>
        </a>
        <a href="/logs" class="btn btn-warning" title="查看日志">
            <i class="bi bi-file-text"></i>
        </a>
        <a href="/backup" class="btn btn-success" title="备份管理">
            <i class="bi bi-archive"></i>
        </a>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 主题切换
        const themeToggle = document.getElementById('themeToggle');
        const body = document.body;
        
        // 检查本地存储的主题设置
        if (localStorage.getItem('theme') === 'dark') {
            body.classList.add('dark-mode');
            themeToggle.innerHTML = '<i class="bi bi-sun-fill"></i>';
        }
        
        themeToggle.addEventListener('click', () => {
            body.classList.toggle('dark-mode');
            if (body.classList.contains('dark-mode')) {
                localStorage.setItem('theme', 'dark');
                themeToggle.innerHTML = '<i class="bi bi-sun-fill"></i>';
            } else {
                localStorage.setItem('theme', 'light');
                themeToggle.innerHTML = '<i class="bi bi-moon-stars-fill"></i>';
            }
        });
        
        // 加载C段流量统计
        fetch('/cnet_traffic')
            .then(response => response.json())
            .then(data => {
                document.querySelectorAll('.cnet-traffic').forEach(badge => {
                    const cseg = badge.getAttribute('data-cseg');
                    const traffic = data[cseg] || 0;
                    badge.innerHTML = `<i class="bi bi-arrow-down-up me-1"></i>${traffic} MB`;
                });
            });
        
        // 导出功能
        document.getElementById('exportBtn').addEventListener('click', () => {
            const selected = [];
            document.querySelectorAll('.segment-check:checked').forEach(cb => {
                selected.push(cb.value);
            });
            
            if (selected.length === 0) {
                alert('请选择要导出的C段');
                return;
            }
            
            const form = new FormData();
            selected.forEach(seg => form.append('csegs[]', seg));
            
            fetch('/export_selected', {
                method: 'POST',
                body: form
            })
            .then(response => response.blob())
            .then(blob => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = `proxy_export_${selected.join('_')}.txt`;
                a.click();
            });
        });
        
        // Toast自动消失
        const toastElList = document.querySelectorAll('.toast');
        const toastList = [...toastElList].map(toastEl => new bootstrap.Toast(toastEl, {
            autohide: true,
            delay: 3000
        }));
    </script>
</body>
</html>
EOF

# --------- c_segment.html (C段详情页) ---------
cat > $WORKDIR/templates/c_segment.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>{{ segment }}.x 段管理 - 3proxy</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --dark-bg: #1a202c;
            --dark-card: #2d3748;
            --dark-text: #e2e8f0;
        }
        
        body {
            background-color: #f7fafc;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .table-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        
        .table thead {
            background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
        }
        
        .dark-mode {
            background-color: var(--dark-bg);
            color: var(--dark-text);
        }
        
        .dark-mode .table-container {
            background-color: var(--dark-card);
        }
        
        .dark-mode .table {
            color: var(--dark-text);
        }
        
        .dark-mode .table thead {
            background: linear-gradient(135deg, #4a5568 0%, #2d3748 100%);
        }
        
        .search-box {
            border-radius: 10px;
            border: 2px solid #e2e8f0;
            padding: 10px 15px;
            transition: all 0.3s;
        }
        
        .search-box:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .action-buttons {
            display: flex;
            gap: 0.5rem;
        }
        
        .btn-icon {
            width: 35px;
            height: 35px;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 8px;
        }
        
        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .status-enabled {
            background-color: #d1fae5;
            color: #065f46;
        }
        
        .status-disabled {
            background-color: #fee2e2;
            color: #991b1b;
        }
        
        .dark-mode .status-enabled {
            background-color: #065f46;
            color: #d1fae5;
        }
        
        .dark-mode .status-disabled {
            background-color: #991b1b;
            color: #fee2e2;
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-arrow-left me-2"></i>返回主页
            </a>
            <span class="navbar-text text-white">
                <i class="bi bi-diagram-2 me-2"></i>{{ segment }}.x 段管理
            </span>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="row mb-4">
            <div class="col">
                <div class="card">
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-4">
                                <h5 class="mb-0">
                                    <i class="bi bi-server me-2"></i>共 {{ proxies|length }} 个代理
                                </h5>
                            </div>
                            <div class="col-md-4">
                                <input type="text" class="form-control search-box" id="searchBox" placeholder="搜索 IP/端口/用户名...">
                            </div>
                            <div class="col-md-4 text-end">
                                <button class="btn btn-danger me-2" id="batchDelete">
                                    <i class="bi bi-trash me-1"></i>批量删除
                                </button>
                                <button class="btn btn-success me-2" id="batchEnable">
                                    <i class="bi bi-check-circle me-1"></i>批量启用
                                </button>
                                <button class="btn btn-secondary me-2" id="batchDisable">
                                    <i class="bi bi-x-circle me-1"></i>批量禁用
                                </button>
                                <button class="btn btn-primary" id="exportSelected">
                                    <i class="bi bi-download me-1"></i>导出选中
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="table-container">
            <form id="proxyForm" method="post" action="/batchdelproxy">
                <table class="table table-hover mb-0">
                    <thead>
                        <tr>
                            <th width="50">
                                <input type="checkbox" class="form-check-input" id="selectAll">
                            </th>
                            <th>ID</th>
                            <th>IP地址</th>
                            <th>端口</th>
                            <th>用户名</th>
                            <th>密码</th>
                            <th>状态</th>
                            <th>IP范围</th>
                            <th>端口范围</th>
                            <th>前缀</th>
                            <th width="150">操作</th>
                        </tr>
                    </thead>
                    <tbody id="proxyTableBody">
                        {% for p in proxies %}
                        <tr data-search="{{ p[1] }}{{ p[2] }}{{ p[3] }}{{ p[4] }}">
                            <td>
                                <input type="checkbox" class="form-check-input proxy-check" name="ids" value="{{ p[0] }}">
                            </td>
                            <td>{{ p[0] }}</td>
                            <td><code>{{ p[1] }}</code></td>
                            <td>{{ p[2] }}</td>
                            <td>{{ p[3] }}</td>
                            <td>
                                <span class="text-muted" style="cursor: pointer;" onclick="copyToClipboard('{{ p[4] }}')">
                                    <i class="bi bi-eye-slash me-1"></i>点击复制
                                </span>
                            </td>
                            <td>
                                {% if p[5] %}
                                    <span class="status-badge status-enabled">启用</span>
                                {% else %}
                                    <span class="status-badge status-disabled">禁用</span>
                                {% endif %}
                            </td>
                            <td>{{ p[6] or '-' }}</td>
                            <td>{{ p[7] or '-' }}</td>
                            <td>{{ p[8] or '-' }}</td>
                            <td>
                                <div class="action-buttons">
                                    {% if p[5] %}
                                        <a href="/disableproxy/{{ p[0] }}" class="btn btn-warning btn-icon" title="禁用">
                                            <i class="bi bi-pause-circle"></i>
                                        </a>
                                    {% else %}
                                        <a href="/enableproxy/{{ p[0] }}" class="btn btn-success btn-icon" title="启用">
                                            <i class="bi bi-play-circle"></i>
                                        </a>
                                    {% endif %}
                                    <a href="/delproxy/{{ p[0] }}" class="btn btn-danger btn-icon" onclick="return confirm('确认删除?')" title="删除">
                                        <i class="bi bi-trash"></i>
                                    </a>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </form>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 复制密码
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                // 显示复制成功提示
                const toast = document.createElement('div');
                toast.className = 'position-fixed bottom-0 end-0 p-3';
                toast.style.zIndex = '11';
                toast.innerHTML = `
                    <div class="toast show align-items-center text-white bg-success border-0">
                        <div class="d-flex">
                            <div class="toast-body">密码已复制到剪贴板</div>
                        </div>
                    </div>
                `;
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 2000);
            });
        }
        
        // 全选/取消全选
        document.getElementById('selectAll').addEventListener('change', function() {
            const checkboxes = document.querySelectorAll('.proxy-check');
            checkboxes.forEach(cb => cb.checked = this.checked);
        });
        
        // 搜索功能
        document.getElementById('searchBox').addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const rows = document.querySelectorAll('#proxyTableBody tr');
            
            rows.forEach(row => {
                const searchData = row.getAttribute('data-search').toLowerCase();
                row.style.display = searchData.includes(searchTerm) ? '' : 'none';
            });
        });
        
        // 批量删除
        document.getElementById('batchDelete').addEventListener('click', function() {
            const checkedBoxes = document.querySelectorAll('.proxy-check:checked');
            if (checkedBoxes.length === 0) {
                alert('请选择要删除的代理');
                return;
            }
            if (confirm(`确定要删除选中的 ${checkedBoxes.length} 个代理吗？`)) {
                document.getElementById('proxyForm').submit();
            }
        });
        
        // 批量启用
        document.getElementById('batchEnable').addEventListener('click', function() {
            const ids = Array.from(document.querySelectorAll('.proxy-check:checked')).map(cb => cb.value);
            if (ids.length === 0) {
                alert('请选择要启用的代理');
                return;
            }
            
            const form = new FormData();
            ids.forEach(id => form.append('ids[]', id));
            
            fetch('/batch_enable', {
                method: 'POST',
                body: form
            }).then(() => location.reload());
        });
        
        // 批量禁用
        document.getElementById('batchDisable').addEventListener('click', function() {
            const ids = Array.from(document.querySelectorAll('.proxy-check:checked')).map(cb => cb.value);
            if (ids.length === 0) {
                alert('请选择要禁用的代理');
                return;
            }
            
            const form = new FormData();
            ids.forEach(id => form.append('ids[]', id));
            
            fetch('/batch_disable', {
                method: 'POST',
                body: form
            }).then(() => location.reload());
        });
        
        // 导出选中
        document.getElementById('exportSelected').addEventListener('click', function() {
            const ids = Array.from(document.querySelectorAll('.proxy-check:checked')).map(cb => cb.value);
            if (ids.length === 0) {
                alert('请选择要导出的代理');
                return;
            }
            
            const form = new FormData();
            ids.forEach(id => form.append('ids[]', id));
            
            fetch('/export_selected_proxy', {
                method: 'POST',
                body: form
            })
            .then(response => response.blob())
            .then(blob => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'proxy_export.txt';
                a.click();
            });
        });
        
        // 主题同步
        if (localStorage.getItem('theme') === 'dark') {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>
EOF

# --------- monitor.html (系统监控页) ---------
cat > $WORKDIR/templates/monitor.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>系统监控 - 3proxy</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --dark-bg: #1a202c;
            --dark-card: #2d3748;
            --dark-text: #e2e8f0;
        }
        
        body {
            background-color: #f7fafc;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
        }
        
        .stat-card {
            border-radius: 15px;
            border: none;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            height: 100%;
        }
        
        .stat-icon {
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            color: white;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
        }
        
        .dark-mode {
            background-color: var(--dark-bg);
            color: var(--dark-text);
        }
        
        .dark-mode .stat-card {
            background-color: var(--dark-card);
        }
        
        .metric-value {
            font-size: 2rem;
            font-weight: bold;
            margin: 0;
        }
        
        .metric-label {
            color: #718096;
            font-size: 0.875rem;
        }
        
        .dark-mode .metric-label {
            color: #a0aec0;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-arrow-left me-2"></i>返回主页
            </a>
            <span class="navbar-text text-white">
                <i class="bi bi-speedometer2 me-2"></i>系统监控
            </span>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <!-- 实时统计 -->
        <div class="row mb-4">
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                                <i class="bi bi-cpu"></i>
                            </div>
                            <div class="ms-3">
                                <p class="metric-value" id="cpu-usage">0%</p>
                                <p class="metric-label">CPU使用率</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);">
                                <i class="bi bi-memory"></i>
                            </div>
                            <div class="ms-3">
                                <p class="metric-value" id="memory-usage">0%</p>
                                <p class="metric-label">内存使用率</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);">
                                <i class="bi bi-hdd"></i>
                            </div>
                            <div class="ms-3">
                                <p class="metric-value" id="disk-usage">0%</p>
                                <p class="metric-label">磁盘使用率</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 col-sm-6 mb-3">
                <div class="card stat-card">
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="stat-icon" style="background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);">
                                <i class="bi bi-activity"></i>
                            </div>
                            <div class="ms-3">
                                <p class="metric-value" id="proxy-connections">0</p>
                                <p class="metric-label">代理连接数</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 图表 -->
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="bi bi-graph-up me-2"></i>系统负载趋势
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="systemChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="bi bi-arrow-down-up me-2"></i>网络流量
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="networkChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 3proxy进程信息 -->
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="bi bi-server me-2"></i>3proxy 进程信息
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <p class="mb-1">进程ID: <strong id="proxy-pid">-</strong></p>
                            </div>
                            <div class="col-md-3">
                                <p class="mb-1">CPU占用: <strong id="proxy-cpu">-</strong></p>
                            </div>
                            <div class="col-md-3">
                                <p class="mb-1">内存占用: <strong id="proxy-memory">-</strong></p>
                            </div>
                            <div class="col-md-3">
                                <p class="mb-1">连接数: <strong id="proxy-conn">-</strong></p>
                            </div>
                        </div>
                    </div>
                </div>
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
                    display: true,
                    position: 'bottom'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        };

        // 系统负载图表
        const systemCtx = document.getElementById('systemChart').getContext('2d');
        const systemChart = new Chart(systemCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU %',
                    data: [],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4
                }, {
                    label: '内存 %',
                    data: [],
                    borderColor: '#48bb78',
                    backgroundColor: 'rgba(72, 187, 120, 0.1)',
                    tension: 0.4
                }]
            },
            options: chartOptions
        });

        // 网络流量图表
        const networkCtx = document.getElementById('networkChart').getContext('2d');
        const networkChart = new Chart(networkCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: '发送 GB',
                    data: [],
                    borderColor: '#4299e1',
                    backgroundColor: 'rgba(66, 153, 225, 0.1)',
                    tension: 0.4
                }, {
                    label: '接收 GB',
                    data: [],
                    borderColor: '#ed8936',
                    backgroundColor: 'rgba(237, 137, 54, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // 数据更新函数
        function updateStats() {
            fetch('/api/system_stats')
                .then(response => response.json())
                .then(data => {
                    // 更新统计卡片
                    document.getElementById('cpu-usage').textContent = data.cpu.toFixed(1) + '%';
                    document.getElementById('memory-usage').textContent = data.memory.toFixed(1) + '%';
                    document.getElementById('disk-usage').textContent = data.disk.toFixed(1) + '%';
                    document.getElementById('proxy-connections').textContent = data.proxy_stats.connections;
                    
                    // 更新3proxy进程信息
                    document.getElementById('proxy-pid').textContent = data.proxy_stats.pid || '-';
                    document.getElementById('proxy-cpu').textContent = data.proxy_stats.cpu ? data.proxy_stats.cpu.toFixed(1) + '%' : '-';
                    document.getElementById('proxy-memory').textContent = data.proxy_stats.memory ? data.proxy_stats.memory.toFixed(1) + '%' : '-';
                    document.getElementById('proxy-conn').textContent = data.proxy_stats.connections || '0';
                    
                    // 更新图表
                    const now = new Date().toLocaleTimeString();
                    
                    // 系统负载图表
                    systemChart.data.labels.push(now);
                    systemChart.data.datasets[0].data.push(data.cpu);
                    systemChart.data.datasets[1].data.push(data.memory);
                    
                    // 保留最近20个数据点
                    if (systemChart.data.labels.length > 20) {
                        systemChart.data.labels.shift();
                        systemChart.data.datasets.forEach(dataset => dataset.data.shift());
                    }
                    systemChart.update();
                    
                    // 网络流量图表
                    networkChart.data.labels.push(now);
                    networkChart.data.datasets[0].data.push(data.network_sent);
                    networkChart.data.datasets[1].data.push(data.network_recv);
                    
                    if (networkChart.data.labels.length > 20) {
                        networkChart.data.labels.shift();
                        networkChart.data.datasets.forEach(dataset => dataset.data.shift());
                    }
                    networkChart.update();
                });
        }

        // 初始更新并设置定时器
        updateStats();
        setInterval(updateStats, 5000); // 每5秒更新一次
        
        // 主题同步
        if (localStorage.getItem('theme') === 'dark') {
            document.body.classList.add('dark-mode');
            
            // 更新图表主题
            Chart.defaults.color = '#e2e8f0';
            Chart.defaults.borderColor = '#4a5568';
            systemChart.update();
            networkChart.update();
        }
    </script>
</body>
</html>
EOF

# --------- logs.html (日志查看页) ---------
cat > $WORKDIR/templates/logs.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>日志查看 - 3proxy</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --dark-bg: #1a202c;
            --dark-card: #2d3748;
            --dark-text: #e2e8f0;
        }
        
        body {
            background-color: #f7fafc;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
        }
        
        .log-container {
            background: #1a202c;
            color: #e2e8f0;
            border-radius: 10px;
            padding: 1rem;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.875rem;
            height: 500px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        
        .log-header {
            background: white;
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .dark-mode {
            background-color: var(--dark-bg);
            color: var(--dark-text);
        }
        
        .dark-mode .log-header {
            background-color: var(--dark-card);
        }
        
        .log-controls {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        .log-size {
            font-size: 0.875rem;
            color: #718096;
        }
        
        .filter-input {
            border-radius: 8px;
            border: 2px solid #e2e8f0;
            padding: 8px 12px;
        }
        
        .btn-refresh {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            border: none;
            color: white;
            border-radius: 8px;
            padding: 8px 16px;
        }
        
        .btn-refresh:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            color: white;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-arrow-left me-2"></i>返回主页
            </a>
            <span class="navbar-text text-white">
                <i class="bi bi-file-text me-2"></i>系统日志
            </span>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="row">
            <div class="col-12">
                <div class="log-header">
                    <div class="row align-items-center">
                        <div class="col-md-6">
                            <ul class="nav nav-tabs" role="tablist">
                                <li class="nav-item">
                                    <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#proxy-log" onclick="loadLog('proxy')">
                                        3proxy日志
                                    </button>
                                </li>
                                <li class="nav-item">
                                    <button class="nav-link" data-bs-toggle="tab" data-bs-target="#web-log" onclick="loadLog('web')">
                                        Web日志
                                    </button>
                                </li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <div class="log-controls justify-content-end">
                                <input type="text" class="form-control filter-input" id="logFilter" placeholder="过滤日志..." style="max-width: 300px;">
                                <button class="btn btn-refresh" onclick="refreshLog()">
                                    <i class="bi bi-arrow-clockwise me-1"></i>刷新
                                </button>
                                <span class="log-size" id="logSize">0 KB</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="tab-content">
                    <div class="tab-pane fade show active" id="proxy-log">
                        <div class="log-container" id="proxyLogContent">
                            加载中...
                        </div>
                    </div>
                    <div class="tab-pane fade" id="web-log">
                        <div class="log-container" id="webLogContent">
                            加载中...
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentLogType = 'proxy';
        let logData = '';
        
        function loadLog(type) {
            currentLogType = type;
            fetch(`/api/logs/${type}`)
                .then(response => response.json())
                .then(data => {
                    logData = data.content;
                    const container = type === 'proxy' ? 'proxyLogContent' : 'webLogContent';
                    document.getElementById(container).textContent = data.content || '暂无日志内容';
                    document.getElementById('logSize').textContent = `${(data.size / 1024).toFixed(2)} KB`;
                    filterLog();
                });
        }
        
        function refreshLog() {
            loadLog(currentLogType);
        }
        
        function filterLog() {
            const filterText = document.getElementById('logFilter').value.toLowerCase();
            const container = currentLogType === 'proxy' ? 'proxyLogContent' : 'webLogContent';
            
            if (!filterText) {
                document.getElementById(container).textContent = logData;
                return;
            }
            
            const lines = logData.split('\n');
            const filteredLines = lines.filter(line => line.toLowerCase().includes(filterText));
            document.getElementById(container).textContent = filteredLines.join('\n') || '没有匹配的日志';
        }
        
        // 初始加载
        loadLog('proxy');
        
        // 过滤器事件
        document.getElementById('logFilter').addEventListener('input', filterLog);
        
        // 自动刷新
        setInterval(refreshLog, 30000); // 每30秒自动刷新
        
        // 主题同步
        if (localStorage.getItem('theme') === 'dark') {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>
EOF

# --------- backup.html (备份管理页) ---------
cat > $WORKDIR/templates/backup.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>备份管理 - 3proxy</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --dark-bg: #1a202c;
            --dark-card: #2d3748;
            --dark-text: #e2e8f0;
        }
        
        body {
            background-color: #f7fafc;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
        }
        
        .backup-card {
            border-radius: 15px;
            border: none;
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
        }
        
        .backup-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        }
        
        .backup-icon {
            width: 60px;
            height: 60px;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            color: white;
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
        }
        
        .dark-mode {
            background-color: var(--dark-bg);
            color: var(--dark-text);
        }
        
        .dark-mode .backup-card {
            background-color: var(--dark-card);
        }
        
        .btn-create-backup {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            border: none;
            color: white;
            font-weight: 500;
            padding: 0.75rem 2rem;
            border-radius: 10px;
            transition: all 0.3s ease;
        }
        
        .btn-create-backup:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            color: white;
        }
        
        .backup-item {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            transition: all 0.3s ease;
        }
        
        .backup-item:hover {
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .dark-mode .backup-item {
            background-color: #4a5568;
        }
        
        .backup-info {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .backup-meta {
            color: #718096;
            font-size: 0.875rem;
        }
        
        .dark-mode .backup-meta {
            color: #a0aec0;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="bi bi-arrow-left me-2"></i>返回主页
            </a>
            <span class="navbar-text text-white">
                <i class="bi bi-archive me-2"></i>备份管理
            </span>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card backup-card">
                    <div class="card-body text-center">
                        <div class="backup-icon mx-auto mb-3">
                            <i class="bi bi-cloud-upload"></i>
                        </div>
                        <h5 class="mb-3">创建新备份</h5>
                        <p class="text-muted mb-4">立即创建数据库备份，保护您的代理配置</p>
                        <a href="/backup/create" class="btn btn-create-backup">
                            <i class="bi bi-plus-circle me-2"></i>创建备份
                        </a>
                    </div>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="bi bi-clock-history me-2"></i>备份历史
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info mb-3">
                            <i class="bi bi-info-circle me-2"></i>
                            系统每天凌晨2点自动备份，保留最近30天的备份文件
                        </div>
                        
                        {% if backups %}
                            {% for backup in backups %}
                            <div class="backup-item">
                                <div class="backup-info">
                                    <div>
                                        <h6 class="mb-1">
                                            <i class="bi bi-file-earmark-zip me-2"></i>{{ backup.name }}
                                        </h6>
                                        <div class="backup-meta">
                                            <span class="me-3">
                                                <i class="bi bi-calendar3 me-1"></i>{{ backup.date }}
                                            </span>
                                            <span>
                                                <i class="bi bi-hdd me-1"></i>{{ backup.size }} MB
                                            </span>
                                        </div>
                                    </div>
                                    <div>
                                        <a href="/backup/restore/{{ backup.name }}" class="btn btn-warning btn-sm" 
                                           onclick="return confirm('确定要恢复这个备份吗？当前数据将被覆盖！')">
                                            <i class="bi bi-arrow-counterclockwise me-1"></i>恢复
                                        </a>
                                    </div>
                                </div>
                            </div>
                            {% endfor %}
                        {% else %}
                            <div class="text-center py-5 text-muted">
                                <i class="bi bi-inbox" style="font-size: 3rem;"></i>
                                <p class="mt-3">暂无备份记录</p>
                            </div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 主题同步
        if (localStorage.getItem('theme') === 'dark') {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>
EOF

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
StandardOutput=append:$WORKDIR/web.log
StandardError=append:$WORKDIR/web.log

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

cd $WORKDIR
export ADMINUSER
export ADMINPASS
$WORKDIR/venv/bin/python3 init_db.py

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
echo -e "\n新增功能："
echo "- 美化的Web界面，支持深色模式"
echo "- C段卡片式管理，点击进入二级页面"
echo "- 系统监控（CPU、内存、磁盘、网络）"
echo "- 日志查看和过滤"
echo "- 自动备份和恢复"
echo "- 代理性能优化"
echo -e "\n如需卸载：bash $0 uninstall"
echo -e "如需重装：bash $0 reinstall"
