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
apt install -y gcc make git wget python3 python3-pip python3-venv sqlite3 cron net-tools

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
mkdir -p $WORKDIR/templates
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate
pip install flask flask_login flask_wtf wtforms Werkzeug --break-system-packages

cat > $WORKDIR/manage.py << 'EOF'
import os, sqlite3, random, string, re, collections, ipaddress, json
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, make_response
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

def detect_iface():
    import subprocess
    try:
        for line in subprocess.check_output("ip -o link show | awk -F': ' '{print \$2}'", shell=True).decode().splitlines():
            if line.startswith('e') or line.startswith('en') or line.startswith('eth'):
                return line.strip()
        return "eth0"
    except: return "eth0"

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
    proxies = db.execute('SELECT id,ip,port,username,password,enabled,userprefix,iprange,portrange FROM proxy ORDER BY id').fetchall()
    users = db.execute('SELECT id,username FROM users').fetchall()
    iprecords = []
    if os.path.exists('ipmanage.json'):
        with open('ipmanage.json','r') as f:
            iprecords = json.load(f)
    db.close()
    return render_template('index.html', proxies=proxies, users=users, iprecords=iprecords, iface=detect_iface())

@app.route('/addproxy', methods=['POST'])
@login_required
def addproxy():
    ip = request.form['ip']
    port = int(request.form['port'])
    username = request.form['username']
    password = request.form['password'] or ''.join(random.choices(string.ascii_letters+string.digits, k=12))
    db = get_db()
    db.execute('INSERT INTO proxy (ip, port, username, password, enabled, userprefix, iprange, portrange) VALUES (?,?,?,?,1,?,?,?)', 
               (ip, port, username, password, username[:3], ip, str(port)))
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
    iprecord = []
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
            db.execute('INSERT INTO proxy (ip, port, username, password, enabled, userprefix, iprange, portrange) VALUES (?,?,?,?,1,?,?,?)', 
                       (ip, port, uname, pw, userprefix, f"{ip_base}{start}-{end}", f"{port_start}-{port_end}"))
            count += 1
        db.commit()
        db.close()
        # 记录IP添加历史
        iprecord = []
        if os.path.exists('ipmanage.json'):
            with open('ipmanage.json','r') as f:
                iprecord = json.load(f)
        iprecord.append({'iprange':f"{ip_base}{start}-{end}",'portrange':f"{port_start}-{port_end}",'userprefix':userprefix})
        with open('ipmanage.json','w') as f:
            json.dump(iprecord,f,ensure_ascii=False)
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
        db.execute('INSERT INTO proxy (ip, port, username, password, enabled, userprefix, iprange, portrange) VALUES (?,?,?,?,1,?,?,?)', 
                   (ip, int(port), username, password, username[:3], ip, str(port)))
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
    userprefix = ""
    filename = ""
    for cseg in csegs:
        rows = db.execute("SELECT ip,port,username,password,userprefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port", (cseg+'.%',)).fetchall()
        for ip,port,user,pw,prefix in rows:
            if not userprefix and prefix: userprefix = prefix
            output += f"{ip}:{port}:{user}:{pw}\n"
        if not filename:
            filename = f"{userprefix}_{cseg.replace('.','_')}.txt"
    db.close()
    mem = BytesIO()
    mem.write(output.encode('utf-8'))
    mem.seek(0)
    response = make_response(mem.read())
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    return response

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

# 新增 IP批量管理（临时/永久加IP到网卡）
@app.route('/ipmanage', methods=['POST'])
@login_required
def ipmanage():
    iface = request.form.get('iface')
    iprange = request.form.get('iprange')  # 支持192.168.1.2-254 或 2-254
    mode = request.form.get('mode') # temp/permanent
    netmask = request.form.get('netmask', '255.255.255.0')
    # 兼容只输入2-254
    if re.match(r'^\d+-\d+$', iprange):
        # 取现有iface第一段
        import subprocess
        firstip = subprocess.getoutput(f"ip addr show {iface} | grep 'inet ' | awk '{{print $2}}' | cut -d/ -f1 | head -1")
        if not firstip: firstip = "192.168.1.1"
        base = '.'.join(firstip.split('.')[:3]) + '.'
        full_iprange = base + iprange
    else:
        full_iprange = iprange
    m = re.match(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", full_iprange.strip())
    if not m:
        flash("IP区间格式错误，应如192.168.1.2-254 或 2-254")
        return redirect('/')
    ip_base = m.group(1)
    start = int(m.group(2))
    end = int(m.group(3))
    ips = [f"{ip_base}{i}" for i in range(start, end+1)]
    # 临时添加
    if mode == 'temp':
        for ip in ips:
            os.system(f"ip addr add {ip}/24 dev {iface}")
        flash(f"已临时添加 {len(ips)} 个IP到 {iface}")
    else:
        # 永久添加，写 interfaces
        with open(INTERFACES_FILE,'r') as f:
            lines = f.readlines()
        upstr = f"up bash -c 'for ip in {ip_base}{{{start}..{end}}};do ip addr add \$ip/24 dev {iface}; done'\n"
        downstr = f"down bash -c 'for ip in {ip_base}{{{start}..{end}}};do ip addr del \$ip/24 dev {iface}; done'\n"
        found = False
        newlines = []
        for line in lines:
            newlines.append(line)
            if line.strip().startswith(f"iface {iface} "):
                found = True
                newlines.append(upstr)
                newlines.append(downstr)
        if not found:
            # 如果没有iface段，手动加
            newlines.append(f"\nauto {iface}\niface {iface} inet static\naddress {ip_base}{start}\nnetmask {netmask}\ngateway {ip_base}1\n{upstr}{downstr}")
        with open(INTERFACES_FILE,'w') as f:
            f.writelines(newlines)
        # 同时临时添加一次
        for ip in ips:
            os.system(f"ip addr add {ip}/24 dev {iface}")
        flash(f"已永久添加并生效 {len(ips)} 个IP到 {iface}")
    return redirect('/')

if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv)>1 else 9999
    app.run('0.0.0.0', port, debug=False)
EOF

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

cat > $WORKDIR/init_db.py << 'EOF'
import sqlite3
from werkzeug.security import generate_password_hash
import os
user = os.environ.get('ADMINUSER')
passwd = os.environ.get('ADMINPASS')
db = sqlite3.connect('3proxy.db')
db.execute('''CREATE TABLE IF NOT EXISTS proxy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, port INTEGER, username TEXT, password TEXT,
    enabled INTEGER DEFAULT 1,
    userprefix TEXT, iprange TEXT, portrange TEXT
)''')
db.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, password TEXT
)''')
db.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?,?)', (user, generate_password_hash(passwd)))
db.commit()
print("WebAdmin: "+user)
print("Webpassword:  "+passwd)
EOF

cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>3proxy 登录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container" style="max-width:400px;margin-top:100px;">
    <div class="card shadow">
        <div class="card-body">
            <h3 class="mb-4 text-center">3proxy 管理登录</h3>
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

cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>3proxy 管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        html,body{background:#f7f7fa;}
        .tab-pane{padding-top:1.5rem;}
        .ip-group-header{background:#e5e9f2;font-weight:bold;cursor:pointer;transition:background 0.2s;}
        .ip-group-header:hover{background:#b5c5e3;}
        .c-collapsed .ip-group-body{display:none;}
        .c-expanded .ip-group-body{display:table-row-group;}
        .group-select{margin-left:12px;}
        .dark-mode{background:#222;color:#eee;}
        .dark-mode .card{background:#1a1a1a;color:#eee;}
        .dark-mode .ip-group-header{background:#292f42;}
        .dark-mode .ip-group-header:hover{background:#1f2230;}
        .dark-mode .table th,.dark-mode .table td{background:#222;}
        .dark-mode .form-control{background:#1a1a1a;color:#eee;}
        .switch-mode{position:fixed;top:18px;right:26px;z-index:10;}
        .custom-textarea { font-family:monospace; height:180px !important; resize:vertical; }
        .proxy-table thead th, .proxy-table td { vertical-align: middle !important; text-align: center; }
    </style>
</head>
<body>
<button class="btn btn-outline-dark btn-sm switch-mode">🌙</button>
<div class="container py-3">
    <ul class="nav nav-tabs" id="mainTabs" role="tablist">
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane" type="button" role="tab" aria-controls="proxy-pane" aria-selected="true">代理管理</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane" type="button" role="tab" aria-controls="user-pane" aria-selected="false">用户管理</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="ipmanage-tab" data-bs-toggle="tab" data-bs-target="#ipmanage-pane" type="button" role="tab" aria-controls="ipmanage-pane" aria-selected="false">IP批量管理</button>
      </li>
    </ul>
    <div class="tab-content">
        <!-- 代理管理tab -->
        <div class="tab-pane fade show active" id="proxy-pane" role="tabpanel" aria-labelledby="proxy-tab">
            <div class="row mt-4 gy-4">
                <div class="col-lg-6">
                    <div class="card shadow-sm p-4 mb-2">
                        <h5 class="fw-bold mb-3 text-success">批量添加代理</h5>
                        <form method="post" action="/batchaddproxy" id="rangeAddForm" class="mb-3 row g-2">
                            <div class="col-12 mb-2 row g-2">
                                <div class="col">
                                    <input type="text" class="form-control" name="iprange" placeholder="IP范围, 如 192.168.1.2-254">
                                </div>
                                <div class="col">
                                    <input type="text" class="form-control" name="portrange" placeholder="端口范围, 如 20000-30000">
                                </div>
                                <div class="col">
                                    <input type="text" class="form-control" name="userprefix" placeholder="用户名前缀">
                                </div>
                                <div class="col-auto">
                                    <button type="submit" class="btn btn-success">范围添加</button>
                                </div>
                            </div>
                        </form>
                        <form method="post" action="/batchaddproxy" class="row g-2 align-items-center">
                            <div class="col-12 mb-2">
                                <textarea name="batchproxy" class="form-control custom-textarea" rows="8" style="font-family:monospace;" placeholder="每行一个：ip,端口 或 ip:端口&#10;也支持 ip,端口,用户名,密码"></textarea>
                            </div>
                            <div class="col-12 d-flex">
                                <button type="submit" class="btn btn-success ms-auto">批量添加</button>
                            </div>
                        </form>
                    </div>
                </div>
                <div class="col-lg-6">
                    <div class="card shadow-sm p-4 mb-2">
                        <h5 class="fw-bold mb-3 text-primary">新增单个代理</h5>
                        <form class="row g-2 align-items-center" method="post" action="/addproxy">
                            <div class="col"><input name="ip" class="form-control" placeholder="IP" required></div>
                            <div class="col"><input name="port" class="form-control" placeholder="端口" required></div>
                            <div class="col"><input name="username" class="form-control" placeholder="用户名" required></div>
                            <div class="col"><input name="password" class="form-control" placeholder="密码(留空随机)"></div>
                            <div class="col-auto"><button class="btn btn-primary" type="submit">新增</button></div>
                        </form>
                    </div>
                </div>
                <div class="col-12">
                    <div class="card shadow-sm p-4">
                        <div class="d-flex mb-2 align-items-center">
                            <h5 class="fw-bold flex-grow-1">代理列表（按C段分组）</h5>
                            <select id="exportCseg" class="form-select form-select-sm ms-2" multiple style="width:350px;max-height:100px;overflow:auto;"></select>
                            <button id="exportSelected" class="btn btn-outline-info btn-sm ms-2">导出所选C段</button>
                            <input id="searchBox" class="form-control form-control-sm ms-2" style="width:180px" placeholder="搜索IP/端口/用户">
                        </div>
                        <form method="post" action="/batchdelproxy" id="proxyForm">
                        <div style="max-height:60vh;overflow-y:auto;">
                        <table class="table table-bordered table-hover align-middle mb-0 proxy-table" id="proxyTable">
                            <thead class="table-light sticky-top">
                                <tr>
                                    <th><input type="checkbox" id="selectAll"></th>
                                    <th>ID</th><th>IP</th><th>端口</th><th>用户名</th><th>密码</th><th>状态</th><th>用户前缀</th><th>IP范围</th><th>端口范围</th><th>操作</th>
                                </tr>
                            </thead>
                            <tbody id="proxyTableBody"></tbody>
                        </table>
                        </div>
                        <button type="submit" class="btn btn-danger mt-2" onclick="return confirm('确定批量删除选中项?')">批量删除</button>
                        <button type="button" class="btn btn-warning ms-2" id="batchEnable">批量启用</button>
                        <button type="button" class="btn btn-secondary ms-2" id="batchDisable">批量禁用</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <!-- 用户管理tab -->
        <div class="tab-pane fade" id="user-pane" role="tabpanel" aria-labelledby="user-tab">
            <div class="card shadow-sm p-4 mt-4">
                <h5 class="fw-bold mb-3 text-warning">Web用户管理</h5>
                <form class="row g-2 align-items-center mb-3" method="post" action="/adduser">
                    <div class="col"><input name="username" class="form-control" placeholder="用户名" required></div>
                    <div class="col"><input name="password" class="form-control" placeholder="密码" required></div>
                    <div class="col-auto"><button class="btn btn-outline-primary" type="submit">添加用户</button></div>
                </form>
                <div class="table-responsive">
                <table class="table table-bordered table-sm mb-0">
                    <tr><th>ID</th><th>用户名</th><th>操作</th></tr>
                    {% for u in users %}
                    <tr>
                        <td>{{u[0]}}</td>
                        <td>{{u[1]}}</td>
                        <td>
                            {% if u[1]!='admin' %}
                            <a href="/deluser/{{u[0]}}" class="btn btn-sm btn-danger" onclick="return confirm('确认删除?')">删除</a>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </table>
                </div>
            </div>
        </div>
        <!-- IP批量管理 -->
        <div class="tab-pane fade" id="ipmanage-pane" role="tabpanel" aria-labelledby="ipmanage-tab">
            <div class="card shadow-sm p-4 mt-4">
                <h5 class="fw-bold mb-3 text-info">IP批量管理 (永久/临时添加)</h5>
                <form method="post" action="/ipmanage" class="row g-2 align-items-center">
                    <div class="col-auto">
                        <label class="form-label">网卡名</label>
                        <input type="text" name="iface" value="{{iface}}" class="form-control" style="width:80px;" required>
                    </div>
                    <div class="col-auto">
                        <label class="form-label">IP区间</label>
                        <input type="text" name="iprange" placeholder="192.168.1.2-254 或 2-254" class="form-control" style="width:160px;" required>
                    </div>
                    <div class="col-auto">
                        <label class="form-label">掩码</label>
                        <input type="text" name="netmask" value="255.255.255.0" class="form-control" style="width:120px;">
                    </div>
                    <div class="col-auto">
                        <label class="form-label">&nbsp;</label>
                        <button name="mode" value="permanent" class="btn btn-primary w-100">永久写入</button>
                    </div>
                    <div class="col-auto">
                        <label class="form-label">&nbsp;</label>
                        <button name="mode" value="temp" class="btn btn-success w-100">临时添加</button>
                    </div>
                </form>
                <div class="mt-4">
                    <h6>历史批量记录：</h6>
                    <ul class="list-group">
                        {% for r in iprecords[::-1][:10] %}
                        <li class="list-group-item">
                            IP范围: <span class="fw-bold">{{r.iprange}}</span>，
                            端口范围: <span class="fw-bold">{{r.portrange or ''}}</span>，
                            用户前缀: <span class="fw-bold">{{r.userprefix or ''}}</span>
                        </li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
        </div>
    </div>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="alert alert-success mt-3 fs-5">{{ messages[0] }}</div>
      {% endif %}
    {% endwith %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
const proxyData = [
{% for p in proxies %}
    {id:{{p[0]}},ip:"{{p[1]}}",port:"{{p[2]}}",user:"{{p[3]}}",pw:"{{p[4]}}",enabled:{{'true' if p[5] else 'false'}},prefix:"{{p[6]}}",iprange:"{{p[7]}}",portrange:"{{p[8]}}"},
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
        // 取组里的第一个前缀、ip段、端口段（分组内一致）
        let prefix = groups[cseg][0].prefix||'';
        let iprange = groups[cseg][0].iprange||'';
        let portrange = groups[cseg][0].portrange||'';
        th.innerHTML = `<td colspan="11" class="pointer">
            <span class="me-2">▶</span>${cseg}.x 段
            <span class="badge bg-info ms-3 cnet-traffic" data-cseg="${cseg}">统计中...</span>
            <span class="badge bg-secondary ms-2">用户前缀: ${prefix}</span>
            <span class="badge bg-success ms-2">IP范围: ${iprange}</span>
            <span class="badge bg-primary ms-2">端口范围: ${portrange}</span>
            <input type="checkbox" class="group-select ms-3" data-gid="${gid}" title="全选本组">
        </td>`;
        tbody.appendChild(th);
        let frag = document.createDocumentFragment();
        groups[cseg].forEach(p=>{
            let tr = document.createElement('tr');
            tr.className = "ip-group-body "+gid;
            tr.style.display = "none";
            tr.innerHTML = `<td><input type="checkbox" name="ids" value="${p.id}"></td>
            <td>${p.id}</td>
            <td>${p.ip}</td>
            <td>${p.port}</td>
            <td>${p.user}</td>
            <td>${p.pw}</td>
            <td>${p.enabled ? '<span class="badge text-bg-success">启用</span>' : '<span class="badge text-bg-secondary">禁用</span>'}</td>
            <td>${p.prefix}</td>
            <td>${p.iprange}</td>
            <td>${p.portrange}</td>
            <td>
                ${p.enabled ? `<a href="/disableproxy/${p.id}" class="btn btn-sm btn-warning">禁用</a>` : `<a href="/enableproxy/${p.id}" class="btn btn-sm btn-success">启用</a>`}
                <a href="/delproxy/${p.id}" class="btn btn-sm btn-danger" onclick="return confirm('确认删除?')">删除</a>
            </td>`;
            frag.appendChild(tr);
        });
        tbody.appendChild(frag);
    });
    // 拉取流量统计
    fetch('/cnet_traffic').then(r=>r.json()).then(data=>{
        document.querySelectorAll('.cnet-traffic').forEach(span=>{
            let c = span.getAttribute('data-cseg');
            span.textContent = data[c] ? `流量${data[c]} MB` : '0 MB';
        });
    });
    fillCsegSelect();
}
// 默认全折叠
setTimeout(()=> {
    document.querySelectorAll('.ip-group-header').forEach(row=>{
        row.classList.add('c-collapsed');
        row.classList.remove('c-expanded');
        let gid = row.getAttribute('data-cgroup');
        document.querySelectorAll('.ip-group-body.'+gid).forEach(tr=>tr.style.display="none");
    });
}, 100);

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
buildTable(proxyData);

document.getElementById('selectAll').onclick = function() {
    var cbs = document.querySelectorAll('#proxyTableBody input[type="checkbox"]');
    for(var i=0;i<cbs.length;++i) cbs[i].checked = this.checked;
};
document.getElementById('proxyTableBody').onclick = function(e){
    let row = e.target.closest('tr.ip-group-header');
    if(row && !e.target.classList.contains('group-select')) {
        let gid = row.getAttribute('data-cgroup');
        let opened = row.classList.contains('c-expanded');
        row.classList.toggle('c-expanded', !opened);
        row.classList.toggle('c-collapsed', opened);
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
document.getElementById('searchBox').oninput = function() {
    let val = this.value.trim().toLowerCase();
    buildTable(proxyData, val);
};
// 导出所选C段
document.getElementById('exportSelected').onclick = function(){
    let selected = Array.from(document.getElementById('exportCseg').selectedOptions).map(o=>o.value);
    if(selected.length==0) { alert("请选择C段"); return; }
    let form = new FormData();
    selected.forEach(c=>form.append('csegs[]',c));
    fetch('/export_selected', {method:'POST', body:form})
        .then(resp=> {
            let disposition = resp.headers.get('Content-Disposition');
            let filename = "export.txt";
            if(disposition && disposition.includes("filename=")){
                filename = disposition.split("filename=")[1];
            }
            return resp.blob().then(blob=>({blob, filename}));
        })
        .then(({blob, filename})=>{
            let a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = filename;
            a.click();
        });
};
// 批量启用/禁用
document.getElementById('batchEnable').onclick = function(){
    let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
    if(ids.length === 0) { alert("请选择代理"); return; }
    let form = new FormData();
    ids.forEach(id=>form.append('ids[]',id));
    fetch('/batch_enable', {method:'POST', body:form}).then(()=>location.reload());
};
document.getElementById('batchDisable').onclick = function(){
    let ids = Array.from(document.querySelectorAll('#proxyTableBody input[name="ids"]:checked')).map(cb=>cb.value);
    if(ids.length === 0) { alert("请选择代理"); return; }
    let form = new FormData();
    ids.forEach(id=>form.append('ids[]',id));
    fetch('/batch_disable', {method:'POST', body:form}).then(()=>location.reload());
};
const btn = document.querySelector('.switch-mode');
btn.onclick = ()=>{
    document.body.classList.toggle('dark-mode');
    btn.textContent = document.body.classList.contains('dark-mode') ? '☀️' : '🌙';
};
</script>
</body>
</html>
EOF

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
