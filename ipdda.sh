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
    systemctl stop 3proxy-backup 2>/dev/null || true
    systemctl disable 3proxy-web 2>/dev/null || true
    systemctl disable 3proxy-autostart 2>/dev/null || true
    systemctl disable 3proxy-backup 2>/dev/null || true
    rm -rf $WORKDIR
    rm -f /etc/systemd/system/3proxy-web.service
    rm -f /etc/systemd/system/3proxy-autostart.service
    rm -f /etc/systemd/system/3proxy-backup.service
    rm -f /usr/local/bin/3proxy
    rm -rf /usr/local/etc/3proxy
    rm -f /etc/cron.d/3proxy-logrotate
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
apt install -y gcc make git wget python3 python3-pip python3-venv sqlite3 cron python3-psutil

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
logformat "- +_L%t.%.  %N.%p %E %U %C:%c %R:%r %O %I %h %T"
rotate 30
EOF
fi

# 创建备份目录
mkdir -p $BACKUP_DIR

# 日志轮换脚本
cat > /etc/cron.d/3proxy-logrotate <<EOF
0 3 */3 * * root [ -f "$LOGFILE" ] && > "$LOGFILE"
EOF

echo -e "\n========= 2. 部署 Python Web 管理环境 =========\n"
mkdir -p $WORKDIR/templates $WORKDIR/static
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate
pip install flask flask_login flask_wtf wtforms Werkzeug psutil --break-system-packages

# ------------------- manage.py (主后端) -------------------
cat > $WORKDIR/manage.py << 'EOF'
import os, sqlite3, random, string, re, collections, psutil, json, datetime, shutil, gzip
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import subprocess

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
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    db = get_db()
    proxy_count = db.execute("SELECT COUNT(*) FROM proxy WHERE enabled=1").fetchone()[0]
    total_proxies = db.execute("SELECT COUNT(*) FROM proxy").fetchone()[0]
    db.close()
    return {
        'cpu': cpu,
        'memory': memory,
        'active_proxies': proxy_count,
        'total_proxies': total_proxies
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
    users = db.execute('SELECT id,username FROM users').fetchall()
    ip_configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC').fetchall()
    
    # 获取代理统计信息按C段分组
    proxy_groups = db.execute('''
        SELECT 
            SUBSTR(ip, 1, LENGTH(ip) - LENGTH(SUBSTR(ip, INSTR(ip, '.', INSTR(ip, '.', INSTR(ip, '.') + 1) + 1) + 1))) AS c_segment,
            COUNT(*) as count,
            MIN(port) as min_port,
            MAX(port) as max_port,
            user_prefix,
            SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled_count
        FROM proxy 
        GROUP BY c_segment, user_prefix
        ORDER BY c_segment
    ''').fetchall()
    
    db.close()
    return render_template('index.html', users=users, ip_configs=ip_configs, 
                         proxy_groups=proxy_groups, default_iface=detect_nic())

@app.route('/proxy_group/<cseg>')
@login_required
def proxy_group(cseg):
    db = get_db()
    proxies = db.execute('''
        SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix 
        FROM proxy 
        WHERE ip LIKE ? 
        ORDER BY CAST(SUBSTR(ip, LENGTH(ip) - LENGTH(SUBSTR(ip, INSTR(ip, '.', INSTR(ip, '.', INSTR(ip, '.') + 1) + 1) + 1)) + 1) AS INTEGER), port
    ''', (cseg + '.%',)).fetchall()
    db.close()
    return render_template('proxy_list.html', proxies=proxies, cseg=cseg)

@app.route('/system_stats')
@login_required
def system_stats():
    return jsonify(get_system_stats())

@app.route('/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    if not os.path.exists(LOGFILE):
        return render_template('logs.html', logs=[], total_pages=0, current_page=1)
    
    # 读取日志文件
    with open(LOGFILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # 分页
    total_lines = len(lines)
    total_pages = (total_lines + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    
    # 倒序显示最新日志
    page_logs = lines[-end:-start] if start > 0 else lines[-end:]
    page_logs.reverse()
    
    return render_template('logs.html', logs=page_logs, total_pages=total_pages, current_page=page)

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
    # 获取返回的C段
    cseg = request.args.get('cseg')
    db = get_db()
    db.execute('DELETE FROM proxy WHERE id=?', (pid,))
    db.commit()
    db.close()
    reload_3proxy()
    flash('已删除代理')
    if cseg:
        return redirect(f'/proxy_group/{cseg}')
    return redirect('/')

@app.route('/batchdelproxy', methods=['POST'])
@login_required
def batchdelproxy():
    ids = request.form.getlist('ids')
    cseg = request.form.get('cseg')
    db = get_db()
    db.executemany('DELETE FROM proxy WHERE id=?', [(i,) for i in ids])
    db.commit()
    db.close()
    reload_3proxy()
    flash(f'已批量删除 {len(ids)} 条代理')
    if cseg:
        return redirect(f'/proxy_group/{cseg}')
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
    cseg = request.args.get('cseg')
    db = get_db()
    db.execute('UPDATE proxy SET enabled=1 WHERE id=?', (pid,))
    db.commit()
    db.close()
    reload_3proxy()
    flash('已启用')
    if cseg:
        return redirect(f'/proxy_group/{cseg}')
    return redirect('/')

@app.route('/disableproxy/<int:pid>')
@login_required
def disableproxy(pid):
    cseg = request.args.get('cseg')
    db = get_db()
    db.execute('UPDATE proxy SET enabled=0 WHERE id=?', (pid,))
    db.commit()
    db.close()
    reload_3proxy()
    flash('已禁用')
    if cseg:
        return redirect(f'/proxy_group/{cseg}')
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
"logformat \"- +_L%t.%.  %N.%p %E %U %C:%c %R:%r %O %I %h %T\"",
"rotate 30",
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

# --------- backup.py（自动备份脚本） ---------
cat > $WORKDIR/backup.py << 'EOF'
import os, shutil, gzip, datetime

BACKUP_DIR = '/usr/local/etc/3proxy/backups'
DB_PATH = '/opt/3proxy-web/3proxy.db'
CONFIG_PATH = '/usr/local/etc/3proxy/3proxy.cfg'

def backup():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    # 备份时间戳
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 备份数据库
    db_backup = os.path.join(BACKUP_DIR, f'3proxy_db_{timestamp}.gz')
    with open(DB_PATH, 'rb') as f_in:
        with gzip.open(db_backup, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    # 备份配置文件
    cfg_backup = os.path.join(BACKUP_DIR, f'3proxy_cfg_{timestamp}.gz')
    with open(CONFIG_PATH, 'rb') as f_in:
        with gzip.open(cfg_backup, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    # 清理3天前的备份
    cutoff = datetime.datetime.now() - datetime.timedelta(days=3)
    for filename in os.listdir(BACKUP_DIR):
        filepath = os.path.join(BACKUP_DIR, filename)
        if os.path.getctime(filepath) < cutoff.timestamp():
            os.remove(filepath)
    
    print(f"Backup completed: {timestamp}")

if __name__ == '__main__':
    backup()
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
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
            padding: 40px;
            width: 400px;
        }
        .login-title {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: bold;
            margin-bottom: 30px;
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 10px;
            padding: 12px;
            font-weight: 500;
            transition: transform 0.2s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .form-control {
            border-radius: 10px;
            border: 2px solid #e0e0e0;
            padding: 12px;
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h2 class="text-center login-title">3Proxy 管理系统</h2>
        <form method="post">
            <div class="mb-4">
                <label class="form-label fw-bold">用户名</label>
                <input type="text" class="form-control" name="username" autofocus required>
            </div>
            <div class="mb-4">
                <label class="form-label fw-bold">密码</label>
                <input type="password" class="form-control" name="password" required>
            </div>
            <button class="btn btn-primary btn-login w-100" type="submit">登录系统</button>
        </form>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="alert alert-danger mt-3 rounded-3">{{ messages[0] }}</div>
          {% endif %}
        {% endwith %}
    </div>
</body>
</html>
EOF

# --------- index.html（主页面 - 卡片式设计） ---------
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>3Proxy 管理系统</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
            --hover-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }
        
        body {
            background-color: #f8f9fa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        /* 导航栏样式 */
        .navbar {
            background: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 1rem 0;
        }
        
        .navbar-brand {
            font-weight: bold;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        /* 系统状态卡片 */
        .stats-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
            margin-bottom: 20px;
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--hover-shadow);
        }
        
        .stats-icon {
            width: 60px;
            height: 60px;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            margin-bottom: 15px;
        }
        
        .stats-cpu { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
        .stats-memory { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
        .stats-proxy { background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }
        
        /* 主要内容卡片 */
        .main-card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: var(--card-shadow);
            margin-bottom: 25px;
        }
        
        .section-title {
            font-size: 1.5rem;
            font-weight: bold;
            margin-bottom: 20px;
            position: relative;
            padding-left: 15px;
        }
        
        .section-title::before {
            content: '';
            position: absolute;
            left: 0;
            top: 50%;
            transform: translateY(-50%);
            width: 4px;
            height: 24px;
            background: var(--primary-gradient);
            border-radius: 2px;
        }
        
        /* 代理组卡片 */
        .proxy-group-card {
            background: white;
            border: 2px solid #f0f0f0;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .proxy-group-card:hover {
            border-color: #667eea;
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.2);
        }
        
        .proxy-group-icon {
            width: 50px;
            height: 50px;
            background: var(--primary-gradient);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 20px;
            margin-right: 20px;
        }
        
        .proxy-count-badge {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        /* 按钮样式 */
        .btn-gradient {
            background: var(--primary-gradient);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 10px 25px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn-gradient:hover {
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        /* Tab样式 */
        .nav-tabs {
            border: none;
            background: #f5f7fa;
            border-radius: 15px;
            padding: 5px;
            margin-bottom: 30px;
        }
        
        .nav-tabs .nav-link {
            border: none;
            border-radius: 10px;
            padding: 12px 30px;
            color: #666;
            font-weight: 500;
            transition: all 0.3s ease;
            margin: 0 5px;
        }
        
        .nav-tabs .nav-link.active {
            background: white;
            color: #667eea;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1);
        }
        
        /* 表单样式 */
        .form-control, .form-select {
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            padding: 12px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        /* 响应式 */
        @media (max-width: 768px) {
            .proxy-group-card {
                padding: 15px;
            }
            .stats-card {
                margin-bottom: 15px;
            }
        }

        /* 深色模式 */
        .dark-mode {
            background: #1a1a1a;
            color: #e0e0e0;
        }
        
        .dark-mode .navbar,
        .dark-mode .main-card,
        .dark-mode .stats-card,
        .dark-mode .proxy-group-card {
            background: #2a2a2a;
            border-color: #404040;
        }
        
        .dark-mode .form-control,
        .dark-mode .form-select {
            background: #333;
            border-color: #404040;
            color: #e0e0e0;
        }
        
        .mode-toggle {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--primary-gradient);
            color: white;
            border: none;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            font-size: 20px;
            transition: all 0.3s ease;
            z-index: 1000;
        }
        
        .mode-toggle:hover {
            transform: scale(1.1);
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg">
        <div class="container-fluid">
            <span class="navbar-brand fs-3">
                <i class="bi bi-shield-lock-fill"></i> 3Proxy 管理系统
            </span>
            <div class="ms-auto d-flex align-items-center">
                <span class="me-3">
                    <i class="bi bi-person-circle"></i> 欢迎您
                </span>
                <a href="/logout" class="btn btn-outline-danger btn-sm">
                    <i class="bi bi-box-arrow-right"></i> 退出
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid p-4">
        <!-- 系统状态监控 -->
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="stats-card">
                    <div class="stats-icon stats-cpu">
                        <i class="bi bi-cpu text-white"></i>
                    </div>
                    <h6 class="text-muted">CPU 使用率</h6>
                    <h3 class="mb-0"><span id="cpu-usage">0</span>%</h3>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stats-card">
                    <div class="stats-icon stats-memory">
                        <i class="bi bi-memory text-white"></i>
                    </div>
                    <h6 class="text-muted">内存使用率</h6>
                    <h3 class="mb-0"><span id="memory-usage">0</span>%</h3>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stats-card">
                    <div class="stats-icon stats-proxy">
                        <i class="bi bi-hdd-network text-white"></i>
                    </div>
                    <h6 class="text-muted">代理状态</h6>
                    <h3 class="mb-0"><span id="active-proxies">0</span> / <span id="total-proxies">0</span></h3>
                </div>
            </div>
        </div>

        <!-- 主要Tab导航 -->
        <ul class="nav nav-tabs" id="mainTabs" role="tablist">
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
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="log-tab" data-bs-toggle="tab" data-bs-target="#log-pane" type="button">
                    <i class="bi bi-journal-text"></i> 系统日志
                </button>
            </li>
        </ul>

        <div class="tab-content">
            <!-- 代理管理Tab -->
            <div class="tab-pane fade show active" id="proxy-pane" role="tabpanel">
                <div class="row">
                    <!-- 批量添加 -->
                    <div class="col-lg-6">
                        <div class="main-card">
                            <h5 class="section-title">批量添加代理</h5>
                            <form method="post" action="/batchaddproxy">
                                <div class="row g-3 mb-3">
                                    <div class="col-12">
                                        <label class="form-label">IP范围</label>
                                        <input type="text" class="form-control" name="iprange" placeholder="192.168.1.2-254">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">端口范围</label>
                                        <input type="text" class="form-control" name="portrange" placeholder="20000-30000">
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">用户名前缀</label>
                                        <input type="text" class="form-control" name="userprefix" placeholder="user">
                                    </div>
                                </div>
                                <button type="submit" class="btn btn-gradient w-100">
                                    <i class="bi bi-plus-circle"></i> 批量添加
                                </button>
                            </form>
                            
                            <div class="mt-4">
                                <label class="form-label">手动批量添加</label>
                                <form method="post" action="/batchaddproxy">
                                    <textarea name="batchproxy" class="form-control mb-3" rows="5" 
                                        placeholder="每行一个：ip,端口 或 ip:端口"></textarea>
                                    <button type="submit" class="btn btn-outline-primary w-100">
                                        <i class="bi bi-upload"></i> 导入添加
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 单个添加 -->
                    <div class="col-lg-6">
                        <div class="main-card">
                            <h5 class="section-title">新增单个代理</h5>
                            <form method="post" action="/addproxy">
                                <div class="row g-3">
                                    <div class="col-md-6">
                                        <label class="form-label">IP地址</label>
                                        <input name="ip" class="form-control" required>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">端口</label>
                                        <input name="port" class="form-control" type="number" required>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">用户名</label>
                                        <input name="username" class="form-control" required>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">密码</label>
                                        <input name="password" class="form-control" placeholder="留空自动生成">
                                    </div>
                                    <div class="col-12">
                                        <label class="form-label">用户前缀（可选）</label>
                                        <input name="userprefix" class="form-control">
                                    </div>
                                </div>
                                <button class="btn btn-gradient w-100 mt-3" type="submit">
                                    <i class="bi bi-plus"></i> 添加代理
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- 代理组列表 -->
                <div class="main-card mt-4">
                    <h5 class="section-title">代理组列表</h5>
                    <div class="mb-3">
                        <input type="text" id="searchInput" class="form-control" 
                            placeholder="搜索IP段、端口范围或用户前缀...">
                    </div>
                    <div id="proxy-groups">
                        {% for group in proxy_groups %}
                        <div class="proxy-group-card" onclick="window.location.href='/proxy_group/{{ group[0] }}'">
                            <div class="d-flex align-items-center justify-content-between">
                                <div class="d-flex align-items-center">
                                    <div class="proxy-group-icon">
                                        <i class="bi bi-diagram-3"></i>
                                    </div>
                                    <div>
                                        <h6 class="mb-1">{{ group[0] }}.0/24</h6>
                                        <p class="text-muted mb-0">
                                            端口范围: {{ group[2] }}-{{ group[3] }}
                                            {% if group[4] %} | 用户前缀: {{ group[4] }}{% endif %}
                                        </p>
                                    </div>
                                </div>
                                <div class="text-end">
                                    <div class="proxy-count-badge mb-2">
                                        共 {{ group[1] }} 个代理
                                    </div>
                                    <small class="text-muted">
                                        启用: {{ group[5] }} / {{ group[1] }}
                                    </small>
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            
            <!-- 用户管理Tab -->
            <div class="tab-pane fade" id="user-pane" role="tabpanel">
                <div class="main-card">
                    <h5 class="section-title">Web用户管理</h5>
                    <form class="row g-3 mb-4" method="post" action="/adduser">
                        <div class="col-md-5">
                            <input name="username" class="form-control" placeholder="用户名" required>
                        </div>
                        <div class="col-md-5">
                            <input name="password" type="password" class="form-control" placeholder="密码" required>
                        </div>
                        <div class="col-md-2">
                            <button class="btn btn-gradient w-100" type="submit">添加用户</button>
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
                                        <a href="/deluser/{{ u[0] }}" class="btn btn-sm btn-danger" 
                                           onclick="return confirm('确认删除?')">删除</a>
                                        {% endif %}
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- IP批量管理Tab -->
            <div class="tab-pane fade" id="ip-pane" role="tabpanel">
                <div class="main-card">
                    <h5 class="section-title">IP批量管理</h5>
                    <form class="row g-3 mb-4" method="post" action="/add_ip_config">
                        <div class="col-md-2">
                            <label class="form-label">网卡</label>
                            <input name="iface" class="form-control" value="{{ default_iface }}" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">IP区间/单IP</label>
                            <input name="ip_input" class="form-control" placeholder="192.168.1.2-254" required>
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">模式</label>
                            <select name="mode" class="form-select">
                                <option value="perm">永久</option>
                                <option value="temp">临时</option>
                            </select>
                        </div>
                        <div class="col-md-2 d-flex align-items-end">
                            <button class="btn btn-gradient w-100" type="submit">添加</button>
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
            
            <!-- 系统日志Tab -->
            <div class="tab-pane fade" id="log-pane" role="tabpanel">
                <div class="main-card">
                    <h5 class="section-title">系统日志</h5>
                    <div class="text-center p-5">
                        <a href="/logs" class="btn btn-gradient">
                            <i class="bi bi-journal-text"></i> 查看系统日志
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="position-fixed bottom-0 end-0 p-3" style="z-index: 11">
            <div class="toast show" role="alert">
                <div class="toast-header">
                    <strong class="me-auto">系统消息</strong>
                    <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body">
                    {{ messages[0] }}
                </div>
            </div>
        </div>
      {% endif %}
    {% endwith %}
    
    <!-- 深色模式切换 -->
    <button class="mode-toggle" onclick="toggleDarkMode()">
        <i class="bi bi-moon-fill" id="mode-icon"></i>
    </button>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 系统监控更新
        function updateStats() {
            fetch('/system_stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('cpu-usage').textContent = data.cpu.toFixed(1);
                    document.getElementById('memory-usage').textContent = data.memory.toFixed(1);
                    document.getElementById('active-proxies').textContent = data.active_proxies;
                    document.getElementById('total-proxies').textContent = data.total_proxies;
                });
        }
        
        // 每5秒更新一次
        setInterval(updateStats, 5000);
        updateStats();
        
        // 搜索功能
        document.getElementById('searchInput').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const cards = document.querySelectorAll('.proxy-group-card');
            
            cards.forEach(card => {
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(searchTerm) ? 'block' : 'none';
            });
        });
        
        // 深色模式
        function toggleDarkMode() {
            document.body.classList.toggle('dark-mode');
            const icon = document.getElementById('mode-icon');
            if (document.body.classList.contains('dark-mode')) {
                icon.className = 'bi bi-sun-fill';
            } else {
                icon.className = 'bi bi-moon-fill';
            }
        }
    </script>
</body>
</html>
EOF

# --------- proxy_list.html（代理列表二级页面） ---------
cat > $WORKDIR/templates/proxy_list.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>代理列表 - {{ cseg }}.0/24</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
        }
        
        body {
            background-color: #f8f9fa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        .navbar {
            background: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 1rem 0;
        }
        
        .navbar-brand {
            font-weight: bold;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .main-card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: var(--card-shadow);
            margin: 20px 0;
        }
        
        .page-header {
            background: var(--primary-gradient);
            color: white;
            padding: 30px 0;
            margin-bottom: 30px;
            border-radius: 0 0 30px 30px;
        }
        
        .btn-gradient {
            background: var(--primary-gradient);
            color: white;
            border: none;
            border-radius: 10px;
            padding: 10px 25px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn-gradient:hover {
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .table {
            border-radius: 15px;
            overflow: hidden;
        }
        
        .table thead {
            background: #f8f9fa;
        }
        
        .status-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        
        .status-active {
            background: #d4edda;
            color: #155724;
        }
        
        .status-inactive {
            background: #f8d7da;
            color: #721c24;
        }
        
        .search-box {
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            padding: 12px 20px;
            font-size: 16px;
            transition: all 0.3s ease;
        }
        
        .search-box:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar">
        <div class="container-fluid">
            <a href="/" class="navbar-brand fs-4">
                <i class="bi bi-arrow-left"></i> 返回主页
            </a>
            <span class="text-muted">
                代理组管理 - {{ cseg }}.0/24
            </span>
        </div>
    </nav>
    
    <!-- 页面头部 -->
    <div class="page-header">
        <div class="container">
            <h1 class="mb-2">{{ cseg }}.0/24 代理列表</h1>
            <p class="mb-0">共 {{ proxies|length }} 个代理</p>
        </div>
    </div>
    
    <div class="container">
        <div class="main-card">
            <!-- 操作栏 -->
            <div class="row mb-4">
                <div class="col-md-6">
                    <input type="text" class="form-control search-box" id="searchBox" 
                           placeholder="搜索 IP、端口、用户名...">
                </div>
                <div class="col-md-6 text-end">
                    <button class="btn btn-gradient" onclick="exportSelected()">
                        <i class="bi bi-download"></i> 导出选中
                    </button>
                    <button class="btn btn-warning" onclick="batchEnable()">
                        <i class="bi bi-check-circle"></i> 批量启用
                    </button>
                    <button class="btn btn-secondary" onclick="batchDisable()">
                        <i class="bi bi-x-circle"></i> 批量禁用
                    </button>
                    <button class="btn btn-danger" onclick="batchDelete()">
                        <i class="bi bi-trash"></i> 批量删除
                    </button>
                </div>
            </div>
            
            <!-- 代理列表表格 -->
            <div class="table-responsive">
                <form id="proxyForm" method="post" action="/batchdelproxy">
                    <input type="hidden" name="cseg" value="{{ cseg }}">
                    <table class="table table-hover" id="proxyTable">
                        <thead>
                            <tr>
                                <th width="40">
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
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for p in proxies %}
                            <tr>
                                <td>
                                    <input type="checkbox" class="form-check-input" name="ids" value="{{ p[0] }}">
                                </td>
                                <td>{{ p[0] }}</td>
                                <td>{{ p[1] }}</td>
                                <td>{{ p[2] }}</td>
                                <td>{{ p[3] }}</td>
                                <td>
                                    <span class="text-muted" style="font-family: monospace;">{{ p[4] }}</span>
                                </td>
                                <td>
                                    {% if p[5] %}
                                        <span class="status-badge status-active">启用</span>
                                    {% else %}
                                        <span class="status-badge status-inactive">禁用</span>
                                    {% endif %}
                                </td>
                                <td>{{ p[6] or '-' }}</td>
                                <td>{{ p[7] or '-' }}</td>
                                <td>{{ p[8] or '-' }}</td>
                                <td>
                                    {% if p[5] %}
                                        <a href="/disableproxy/{{ p[0] }}?cseg={{ cseg }}" 
                                           class="btn btn-sm btn-warning">禁用</a>
                                    {% else %}
                                        <a href="/enableproxy/{{ p[0] }}?cseg={{ cseg }}" 
                                           class="btn btn-sm btn-success">启用</a>
                                    {% endif %}
                                    <a href="/delproxy/{{ p[0] }}?cseg={{ cseg }}" 
                                       class="btn btn-sm btn-danger" 
                                       onclick="return confirm('确认删除?')">删除</a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </form>
            </div>
        </div>
    </div>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="position-fixed bottom-0 end-0 p-3" style="z-index: 11">
            <div class="toast show" role="alert">
                <div class="toast-header">
                    <strong class="me-auto">系统消息</strong>
                    <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body">
                    {{ messages[0] }}
                </div>
            </div>
        </div>
      {% endif %}
    {% endwith %}
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 全选功能
        document.getElementById('selectAll').addEventListener('change', function() {
            const checkboxes = document.querySelectorAll('tbody input[type="checkbox"]');
            checkboxes.forEach(cb => cb.checked = this.checked);
        });
        
        // 搜索功能
        document.getElementById('searchBox').addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const rows = document.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });
        
        // 获取选中的ID
        function getSelectedIds() {
            const checkboxes = document.querySelectorAll('tbody input[type="checkbox"]:checked');
            return Array.from(checkboxes).map(cb => cb.value);
        }
        
        // 导出选中
        function exportSelected() {
            const ids = getSelectedIds();
            if (ids.length === 0) {
                alert('请先选择要导出的代理');
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
                a.download = 'proxy_export_{{ cseg }}.txt';
                a.click();
            });
        }
        
        // 批量启用
        function batchEnable() {
            const ids = getSelectedIds();
            if (ids.length === 0) {
                alert('请先选择要启用的代理');
                return;
            }
            
            const form = new FormData();
            ids.forEach(id => form.append('ids[]', id));
            
            fetch('/batch_enable', {
                method: 'POST',
                body: form
            }).then(() => location.reload());
        }
        
        // 批量禁用
        function batchDisable() {
            const ids = getSelectedIds();
            if (ids.length === 0) {
                alert('请先选择要禁用的代理');
                return;
            }
            
            const form = new FormData();
            ids.forEach(id => form.append('ids[]', id));
            
            fetch('/batch_disable', {
                method: 'POST',
                body: form
            }).then(() => location.reload());
        }
        
        // 批量删除
        function batchDelete() {
            const ids = getSelectedIds();
            if (ids.length === 0) {
                alert('请先选择要删除的代理');
                return;
            }
            
            if (confirm(`确定要删除选中的 ${ids.length} 个代理吗？`)) {
                document.getElementById('proxyForm').submit();
            }
        }
    </script>
</body>
</html>
EOF

# --------- logs.html（日志查看页面） ---------
cat > $WORKDIR/templates/logs.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>系统日志 - 3Proxy</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
        }
        
        body {
            background-color: #f8f9fa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        .navbar {
            background: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 1rem 0;
        }
        
        .navbar-brand {
            font-weight: bold;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .main-card {
            background: white;
            border-radius: 20px;
            padding: 30px;
            box-shadow: var(--card-shadow);
            margin: 20px 0;
        }
        
        .log-container {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 13px;
            line-height: 1.6;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .log-line {
            padding: 2px 0;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .log-line:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        .pagination {
            margin-top: 20px;
        }
        
        .page-link {
            color: #667eea;
            border-radius: 10px;
            margin: 0 5px;
        }
        
        .page-link:hover {
            background: #667eea;
            color: white;
        }
        
        .page-item.active .page-link {
            background: var(--primary-gradient);
            border: none;
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar">
        <div class="container-fluid">
            <a href="/" class="navbar-brand fs-4">
                <i class="bi bi-arrow-left"></i> 返回主页
            </a>
            <span class="text-muted">
                系统日志查看
            </span>
        </div>
    </nav>
    
    <div class="container">
        <div class="main-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h5 class="mb-0">
                    <i class="bi bi-journal-text"></i> 3Proxy 系统日志
                </h5>
                <span class="text-muted">
                    每3天自动清理一次
                </span>
            </div>
            
            <div class="log-container">
                {% if logs %}
                    {% for line in logs %}
                        <div class="log-line">{{ line.strip() }}</div>
                    {% endfor %}
                {% else %}
                    <div class="text-center text-muted p-5">
                        暂无日志记录
                    </div>
                {% endif %}
            </div>
            
            {% if total_pages > 1 %}
            <nav aria-label="日志分页">
                <ul class="pagination justify-content-center">
                    {% if current_page > 1 %}
                    <li class="page-item">
                        <a class="page-link" href="/logs?page={{ current_page - 1 }}">
                            <i class="bi bi-chevron-left"></i>
                        </a>
                    </li>
                    {% endif %}
                    
                    {% for page in range(1, total_pages + 1) %}
                        {% if page == current_page %}
                        <li class="page-item active">
                            <span class="page-link">{{ page }}</span>
                        </li>
                        {% else %}
                        <li class="page-item">
                            <a class="page-link" href="/logs?page={{ page }}">{{ page }}</a>
                        </li>
                        {% endif %}
                    {% endfor %}
                    
                    {% if current_page < total_pages %}
                    <li class="page-item">
                        <a class="page-link" href="/logs?page={{ current_page + 1 }}">
                            <i class="bi bi-chevron-right"></i>
                        </a>
                    </li>
                    {% endif %}
                </ul>
            </nav>
            {% endif %}
        </div>
    </div>
</body>
</html>
EOF

# --------- Systemd服务文件 ---------
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

# 自动备份服务
cat > /etc/systemd/system/3proxy-backup.service <<EOF
[Unit]
Description=3proxy自动备份服务
After=network.target

[Service]
Type=oneshot
WorkingDirectory=$WORKDIR
ExecStart=$WORKDIR/venv/bin/python3 $WORKDIR/backup.py
User=root
EOF

cat > /etc/systemd/system/3proxy-backup.timer <<EOF
[Unit]
Description=每3天运行一次3proxy备份
Requires=3proxy-backup.service

[Timer]
OnCalendar=*-*-*/3 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

cd $WORKDIR
export ADMINUSER
export ADMINPASS
$WORKDIR/venv/bin/python3 init_db.py

systemctl daemon-reload
systemctl enable 3proxy-web
systemctl enable 3proxy-autostart
systemctl enable 3proxy-backup.timer
systemctl restart 3proxy-web
systemctl restart 3proxy-autostart
systemctl start 3proxy-backup.timer

echo -e "\n========= 部署完成！========="
MYIP=$(get_local_ip)
echo -e "浏览器访问：\n  \033[36mhttp://$MYIP:${PORT}\033[0m"
echo "Web管理用户名: $ADMINUSER"
echo "Web管理密码:  $ADMINPASS"
echo -e "\n功能特性："
echo "✓ 美化的Web界面，卡片式设计"
echo "✓ C段代理分组展示，点击进入二级页面"
echo "✓ 系统监控（CPU、内存、代理数量）"
echo "✓ 自动备份（每3天备份数据库和配置）"
echo "✓ 日志轮换（每3天清理日志防止过大）"
echo "✓ 深色模式支持"
echo -e "\n如需卸载：bash $0 uninstall"
echo -e "如需重装：bash $0 reinstall"
