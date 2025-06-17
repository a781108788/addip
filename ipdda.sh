#!/bin/bash
set -e

WORKDIR=/opt/3proxy-web
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_PATH=/usr/local/etc/3proxy/3proxy.cfg
LOGFILE=/usr/local/etc/3proxy/3proxy.log

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
EOF
fi

cat > /etc/cron.d/3proxy-logrotate <<EOF
0 3 */3 * * root [ -f "$LOGFILE" ] && > "$LOGFILE"
EOF

echo -e "\n========= 2. 部署 Python Web 管理环境 =========\n"
mkdir -p $WORKDIR/templates $WORKDIR/static
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate
pip install flask flask_login flask_wtf wtforms Werkzeug --break-system-packages

# ------------------- manage.py (主后端) -------------------
cat > $WORKDIR/manage.py << 'EOF'
import os, sqlite3, random, string, re, collections
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
    proxies = db.execute('SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix FROM proxy ORDER BY id').fetchall()
    users = db.execute('SELECT id,username FROM users').fetchall()
    ip_configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC').fetchall()
    db.close()
    return render_template('index.html', proxies=proxies, users=users, ip_configs=ip_configs, default_iface=detect_nic())

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
    # 文件名用代理该C段第一个的 user_prefix
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
    # 允许如 192.168.1.2-254 或 2-254 或 192.168.1.2,192.168.1.3
    pattern_full = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", ip_input)
    pattern_short = re.match(r"^(\d+)-(\d+)$", ip_input)
    if pattern_full:
        base = pattern_full.group(1)
        start = int(pattern_full.group(2))
        end = int(pattern_full.group(3))
        ip_range = f"{base}{{{start}..{end}}}"
        ip_list = [f"{base}{i}" for i in range(start, end+1)]
    elif pattern_short:
        base = "192.168.1."  # 默认本地示例，也可换成检测逻辑
        start = int(pattern_short.group(1))
        end = int(pattern_short.group(2))
        ip_range = f"{base}{{{start}..{end}}}"
        ip_list = [f"{base}{i}" for i in range(start, end+1)]
    elif '{' in ip_input and '..' in ip_input:
        ip_range = ip_input
        # 192.168.1.{2..254}
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
    # 存到DB
    db = get_db()
    db.execute('INSERT INTO ip_config (ip_str, type, iface, created) VALUES (?,?,?,datetime("now"))', (ip_range, 'range', iface))
    db.commit()
    db.close()
    # 临时添加（始终都会做）
    for ip in ip_list:
        os.system(f"ip addr add {ip}/24 dev {iface}")
    # 永久添加
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

# --------- login.html (美化版登录页) ---------
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

# --------- index.html（美化版主界面） ---------
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>3proxy 管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
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

        /* IP组头部样式 */
        .ip-group-header {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
            font-weight: 600;
            cursor: pointer;
            position: relative;
        }

        .ip-group-header:hover {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.2), rgba(118, 75, 162, 0.2));
        }

        .ip-group-header td {
            padding: 1.25rem !important;
        }

        .c-collapsed .ip-group-body {
            display: none;
        }

        .c-expanded .ip-group-body {
            display: table-row;
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
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
        }

        .c-expanded .arrow-icon {
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
                    </div>
                </div>
                <div class="col-12">
                    <div class="card p-4">
                        <div class="d-flex mb-3 align-items-center flex-wrap gap-2">
                            <h5 class="fw-bold flex-grow-1 mb-0">代理列表（按C段分组）</h5>
                            <select id="exportCseg" class="form-select" multiple size="5" style="width:240px;max-height:120px;"></select>
                            <button id="exportSelected" class="btn btn-outline-info btn-sm">导出所选C段</button>
                            <button type="button" id="exportSelectedProxy" class="btn btn-outline-success btn-sm">导出选中代理</button>
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
                                    <th>ID</th><th>IP</th><th>端口</th><th>用户名</th><th>密码</th><th>状态</th><th>IP范围</th><th>端口范围</th><th>前缀</th><th style="width:180px;">操作</th>
                                </tr>
                            </thead>
                            <tbody id="proxyTableBody"></tbody>
                        </table>
                        </div>
                        <div class="mt-3 d-flex gap-2 flex-wrap">
                            <button type="submit" class="btn btn-danger" onclick="return confirm('确定批量删除选中项?')">批量删除</button>
                            <button type="button" class="btn btn-warning" id="batchEnable">批量启用</button>
                            <button type="button" class="btn btn-secondary" id="batchDisable">批量禁用</button>
                        </div>
                        </form>
                    </div>
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
<script>
const proxyData = [
{% for p in proxies %}
    {id:{{p[0]}},ip:"{{p[1]}}",port:"{{p[2]}}",user:"{{p[3]}}",pw:"{{p[4]}}",enabled:{{'true' if p[5] else 'false'}},ip_range:"{{p[6]}}",port_range:"{{p[7]}}",user_prefix:"{{p[8]}}"},
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
        th.className = "ip-group-header c-collapsed";
        th.setAttribute("data-cgroup",gid);
        let first = groups[cseg][0];
        let groupInfo = "";
        if(first.ip_range && first.port_range && first.user_prefix){
            groupInfo = `<span class="badge bg-secondary ms-3">范围: ${first.ip_range} | 端口: ${first.port_range} | 前缀: ${first.user_prefix}</span>`;
        }
        th.innerHTML = `<td colspan="11" class="pointer">
            <div class="d-flex align-items-center">
                <span class="arrow-icon me-2">▶</span>
                <strong>${cseg}.x 段</strong> 
                <span class="badge bg-primary ms-2">共 ${groups[cseg].length} 条</span>
                ${groupInfo}
                <span class="badge bg-info ms-3 cnet-traffic" data-cseg="${cseg}">
                    <span class="loading"></span> 统计中...
                </span>
                <input type="checkbox" class="group-select ms-auto me-3" data-gid="${gid}" title="全选本组" onclick="event.stopPropagation()">
            </div>
        </td>`;
        tbody.appendChild(th);
        
        let frag = document.createDocumentFragment();
        groups[cseg].forEach(p=>{
            let tr = document.createElement('tr');
            tr.className = "ip-group-body "+gid;
            tr.style.display = "none";
            tr.innerHTML = `<td><input type="checkbox" name="ids" value="${p.id}"></td>
            <td>${p.id}</td>
            <td><strong>${p.ip}</strong></td>
            <td>${p.port}</td>
            <td>${p.user}</td>
            <td><code style="font-size:0.85rem;">${p.pw}</code></td>
            <td>${p.enabled ? '<span class="badge text-bg-success">启用</span>' : '<span class="badge text-bg-secondary">禁用</span>'}</td>
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
            frag.appendChild(tr);
        });
        tbody.appendChild(frag);
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

// 表格点击事件
document.getElementById('proxyTableBody').onclick = function(e){
    let row = e.target.closest('tr.ip-group-header');
    if(row && !e.target.classList.contains('group-select')) {
        let gid = row.getAttribute('data-cgroup');
        let opened = !row.classList.contains('c-collapsed');
        row.classList.toggle('c-collapsed', opened);
        row.classList.toggle('c-expanded', !opened);
        
        // 旋转箭头
        let arrow = row.querySelector('.arrow-icon');
        arrow.style.transform = opened ? 'rotate(0deg)' : 'rotate(90deg)';
        
        document.querySelectorAll('.ip-group-body.'+gid).forEach(tr=>{
            tr.style.display = opened ? "none" : "";
        });
        return;
    }
    
    if(e.target.classList.contains('group-select')){
        let gid = e.target.getAttribute('data-gid');
        let checked = e.target.checked;
        document.querySelectorAll('.ip-group-body.'+gid+' input[type="checkbox"]').forEach(cb=>cb.checked=checked);
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
    
    // 获取user_prefix
    let user_prefix = '';
    if(selected.length){
        let firstC = selected[0];
        let cProxies = proxyData.filter(p => p.ip.startsWith(firstC + "."));
        if(cProxies.length > 0){
            user_prefix = cProxies[0].user_prefix || '';
        }
    }
    
    fetch('/export_selected', {method:'POST', body:form})
        .then(resp=>resp.blob())
        .then(blob=>{
            let a = document.createElement('a');
            let name = (user_prefix ? user_prefix : 'proxy') + '_' + selected.join('_') + '.txt';
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
    // 确保所有组默认折叠
    document.querySelectorAll('.ip-group-header').forEach(th=>{
        th.classList.add('c-collapsed');
        th.classList.remove('c-expanded');
    });
    
    // 添加平滑滚动
    document.documentElement.style.scrollBehavior = 'smooth';
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
        buildTable(proxyData);
    }
});
</script>
</body>
</html>
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
ExecStart=$WORKDIR/venv/bin/python3 $WORKDIR/config_gen.py && $THREEPROXY_PATH $PROXYCFG_PATH
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
echo "如需自启，已自动设置 systemd 服务"
echo "3proxy日志每3天会自动清空一次"
echo -e "\n如需卸载：bash $0 uninstall"
echo -e "如需重装：bash $0 reinstall"
