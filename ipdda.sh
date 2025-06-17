#!/bin/bash
set -e

WORKDIR=/opt/3proxy-web
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_PATH=/usr/local/etc/3proxy/3proxy.cfg
LOGFILE=/usr/local/etc/3proxy/3proxy.log
BACKUP_DIR=/opt/3proxy-web/backups

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

# 日志轮转
cat > /etc/cron.d/3proxy-logrotate <<EOF
0 3 */3 * * root [ -f "$LOGFILE" ] && > "$LOGFILE"
EOF

# 自动备份
cat > /etc/cron.d/3proxy-backup <<EOF
0 2 * * * root cd $WORKDIR && python3 backup.py
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
BACKUP_DIR = '/opt/3proxy-web/backups'

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
    # 获取C段统计
    proxies = db.execute('SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix FROM proxy ORDER BY id').fetchall()
    c_segments = {}
    for p in proxies:
        c_seg = '.'.join(p[1].split('.')[:3])
        if c_seg not in c_segments:
            c_segments[c_seg] = {
                'count': 0,
                'enabled': 0,
                'disabled': 0,
                'ip_range': p[6] or '',
                'port_range': p[7] or '',
                'user_prefix': p[8] or ''
            }
        c_segments[c_seg]['count'] += 1
        if p[5]:
            c_segments[c_seg]['enabled'] += 1
        else:
            c_segments[c_seg]['disabled'] += 1
    
    users = db.execute('SELECT id,username FROM users').fetchall()
    ip_configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC').fetchall()
    db.close()
    
    # 获取系统状态
    system_stats = get_system_stats()
    
    return render_template('index.html', c_segments=c_segments, users=users, 
                         ip_configs=ip_configs, default_iface=detect_nic(), system_stats=system_stats)

@app.route('/proxy_list/<cseg>')
@login_required
def proxy_list(cseg):
    db = get_db()
    proxies = db.execute('SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port', 
                        (cseg+'.%',)).fetchall()
    db.close()
    return render_template('proxy_list.html', proxies=proxies, cseg=cseg)

@app.route('/api/proxies/<cseg>')
@login_required
def api_proxies(cseg):
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    search = request.args.get('search', '')
    
    db = get_db()
    if search:
        query = '''SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix 
                   FROM proxy WHERE ip LIKE ? AND (ip LIKE ? OR port LIKE ? OR username LIKE ?) 
                   ORDER BY ip,port LIMIT ? OFFSET ?'''
        proxies = db.execute(query, (cseg+'.%', '%'+search+'%', '%'+search+'%', '%'+search+'%', 
                           per_page, (page-1)*per_page)).fetchall()
        total = db.execute('SELECT COUNT(*) FROM proxy WHERE ip LIKE ? AND (ip LIKE ? OR port LIKE ? OR username LIKE ?)', 
                          (cseg+'.%', '%'+search+'%', '%'+search+'%', '%'+search+'%')).fetchone()[0]
    else:
        proxies = db.execute('SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix FROM proxy WHERE ip LIKE ? ORDER BY ip,port LIMIT ? OFFSET ?', 
                           (cseg+'.%', per_page, (page-1)*per_page)).fetchall()
        total = db.execute('SELECT COUNT(*) FROM proxy WHERE ip LIKE ?', (cseg+'.%',)).fetchone()[0]
    db.close()
    
    return jsonify({
        'proxies': [{'id': p[0], 'ip': p[1], 'port': p[2], 'username': p[3], 
                    'password': p[4], 'enabled': p[5], 'ip_range': p[6], 
                    'port_range': p[7], 'user_prefix': p[8]} for p in proxies],
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })

@app.route('/system_stats')
@login_required
def system_stats():
    return jsonify(get_system_stats())

def get_system_stats():
    # CPU使用率
    cpu_percent = psutil.cpu_percent(interval=1)
    
    # 内存使用
    mem = psutil.virtual_memory()
    
    # 磁盘使用
    disk = psutil.disk_usage('/')
    
    # 网络流量
    net = psutil.net_io_counters()
    
    # 3proxy进程状态
    proxy_status = 'running'
    proxy_count = 0
    try:
        result = subprocess.run(['pgrep', '-c', '3proxy'], capture_output=True, text=True)
        proxy_count = int(result.stdout.strip())
        if proxy_count == 0:
            proxy_status = 'stopped'
    except:
        proxy_status = 'error'
    
    # 获取代理统计
    db = get_db()
    total_proxies = db.execute('SELECT COUNT(*) FROM proxy').fetchone()[0]
    enabled_proxies = db.execute('SELECT COUNT(*) FROM proxy WHERE enabled=1').fetchone()[0]
    db.close()
    
    return {
        'cpu_percent': cpu_percent,
        'memory_percent': mem.percent,
        'memory_used': round(mem.used / 1024 / 1024 / 1024, 2),
        'memory_total': round(mem.total / 1024 / 1024 / 1024, 2),
        'disk_percent': disk.percent,
        'disk_used': round(disk.used / 1024 / 1024 / 1024, 2),
        'disk_total': round(disk.total / 1024 / 1024 / 1024, 2),
        'network_sent': round(net.bytes_sent / 1024 / 1024 / 1024, 2),
        'network_recv': round(net.bytes_recv / 1024 / 1024 / 1024, 2),
        'proxy_status': proxy_status,
        'proxy_processes': proxy_count,
        'total_proxies': total_proxies,
        'enabled_proxies': enabled_proxies
    }

@app.route('/backup_list')
@login_required
def backup_list():
    backups = []
    if os.path.exists(BACKUP_DIR):
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if f.endswith('.tar.gz'):
                fpath = os.path.join(BACKUP_DIR, f)
                size = os.path.getsize(fpath) / 1024 / 1024  # MB
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
                backups.append({
                    'filename': f,
                    'size': round(size, 2),
                    'time': mtime.strftime('%Y-%m-%d %H:%M:%S')
                })
    return jsonify(backups)

@app.route('/manual_backup')
@login_required
def manual_backup():
    try:
        subprocess.run(['python3', os.path.join(WORKDIR, 'backup.py')], check=True)
        flash('手动备份成功')
    except:
        flash('备份失败', 'error')
    return redirect('/')

@app.route('/restore_backup/<filename>')
@login_required
def restore_backup(filename):
    try:
        backup_path = os.path.join(BACKUP_DIR, filename)
        if os.path.exists(backup_path):
            # 解压备份
            subprocess.run(['tar', '-xzf', backup_path, '-C', WORKDIR], check=True)
            reload_3proxy()
            flash('恢复备份成功')
        else:
            flash('备份文件不存在', 'error')
    except:
        flash('恢复失败', 'error')
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

@app.route('/optimize_proxy', methods=['POST'])
@login_required
def optimize_proxy():
    try:
        # 优化3proxy配置
        with open(PROXYCFG_PATH, 'r') as f:
            config = f.read()
        
        # 更新优化配置
        optimized_config = [
            "daemon",
            "maxconn 5000",  # 增加最大连接数
            "nserver 8.8.8.8",
            "nserver 1.1.1.1",  # 添加备用DNS
            "nscache 65536",
            "nsrecord 86400",  # DNS缓存时间
            "timeouts 1 5 30 60 180 1800 15 60",
            "stacksize 262144",  # 增加栈大小
            "flush",  # 启用缓冲区刷新
            "auth strong"
        ]
        
        # 保留用户配置部分
        lines = config.split('\n')
        user_config_start = False
        for line in lines:
            if line.startswith('users'):
                user_config_start = True
            if user_config_start:
                optimized_config.append(line)
        
        with open(PROXYCFG_PATH, 'w') as f:
            f.write('\n'.join(optimized_config))
        
        reload_3proxy()
        flash('代理性能优化成功')
    except Exception as e:
        flash(f'优化失败: {str(e)}', 'error')
    
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
"maxconn 5000",
"nserver 8.8.8.8",
"nserver 1.1.1.1",
"nscache 65536",
"nsrecord 86400",
"timeouts 1 5 30 60 180 1800 15 60",
"stacksize 262144",
"flush",
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

# --------- backup.py（自动备份脚本） ---------
cat > $WORKDIR/backup.py << 'EOF'
import os, shutil, subprocess
from datetime import datetime

WORKDIR = '/opt/3proxy-web'
BACKUP_DIR = '/opt/3proxy-web/backups'
MAX_BACKUPS = 10

def backup():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    # 创建备份文件名
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f'3proxy_backup_{timestamp}.tar.gz'
    backup_path = os.path.join(BACKUP_DIR, backup_name)
    
    # 创建备份
    files_to_backup = ['3proxy.db', 'config_gen.py']
    subprocess.run(['tar', '-czf', backup_path, '-C', WORKDIR] + files_to_backup)
    
    # 清理旧备份
    backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith('.tar.gz')])
    if len(backups) > MAX_BACKUPS:
        for old_backup in backups[:-MAX_BACKUPS]:
            os.remove(os.path.join(BACKUP_DIR, old_backup))
    
    print(f"备份完成: {backup_name}")

if __name__ == '__main__':
    backup()
EOF

# --------- monitor.py（系统监控脚本） ---------
cat > $WORKDIR/monitor.py << 'EOF'
import psutil, subprocess, time, sqlite3

THREEPROXY_PATH = '/usr/local/bin/3proxy'
PROXYCFG_PATH = '/usr/local/etc/3proxy/3proxy.cfg'

def check_and_restart():
    # 检查3proxy进程
    try:
        result = subprocess.run(['pgrep', '-c', '3proxy'], capture_output=True, text=True)
        count = int(result.stdout.strip())
        if count == 0:
            print("3proxy进程未运行，正在重启...")
            subprocess.run(['python3', '/opt/3proxy-web/config_gen.py'])
            subprocess.run([THREEPROXY_PATH, PROXYCFG_PATH], start_new_session=True)
            print("3proxy已重启")
    except:
        pass

if __name__ == '__main__':
    while True:
        check_and_restart()
        time.sleep(60)  # 每分钟检查一次
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
    <meta name="viewport" content="width=device-width,initial-scale=1">
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
            backdrop-filter: blur(16px);
            background: rgba(255, 255, 255, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.3);
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            animation: fadeIn 0.5s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            transition: all 0.3s ease;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
    </style>
</head>
<body>
<div class="container" style="max-width:400px;">
    <div class="card login-card">
        <div class="card-body p-5">
            <h3 class="mb-4 text-center fw-bold">🔐 3proxy 管理登录</h3>
            <form method="post">
                <div class="mb-4">
                    <label class="form-label small text-muted">用户名</label>
                    <input type="text" class="form-control form-control-lg" name="username" autofocus required>
                </div>
                <div class="mb-4">
                    <label class="form-label small text-muted">密码</label>
                    <input type="password" class="form-control form-control-lg" name="password" required>
                </div>
                <button class="btn btn-primary btn-login w-100 btn-lg" type="submit">登录</button>
            </form>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-danger mt-3 animate__animated animate__shakeX">{{ messages[0] }}</div>
              {% endif %}
            {% endwith %}
        </div>
    </div>
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
    <title>3proxy 管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-gradient: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);
            --warning-gradient: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
            --info-gradient: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        }
        
        body {
            background: #f5f7fa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        .navbar {
            background: var(--primary-gradient);
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
            animation: fadeInUp 0.5s ease-out;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
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
            background: var(--primary-gradient);
            opacity: 0.05;
            transform: rotate(45deg);
        }
        
        .stat-icon {
            width: 60px;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 15px;
            font-size: 24px;
            color: white;
            margin-bottom: 15px;
        }
        
        .proxy-card {
            cursor: pointer;
            transition: all 0.3s ease;
            background: white;
            border-radius: 15px;
            padding: 25px;
            position: relative;
            overflow: hidden;
        }
        
        .proxy-card:hover {
            transform: scale(1.02);
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
        }
        
        .proxy-card::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: var(--primary-gradient);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }
        
        .proxy-card:hover::after {
            transform: scaleX(1);
        }
        
        .badge-gradient {
            background: var(--primary-gradient);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
        }
        
        .tab-content {
            animation: fadeIn 0.5s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .form-control, .form-select {
            border-radius: 10px;
            border: 1px solid #e0e6ed;
            padding: 12px 16px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .btn {
            border-radius: 10px;
            padding: 10px 24px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: var(--primary-gradient);
            border: none;
        }
        
        .btn-success {
            background: var(--success-gradient);
            border: none;
        }
        
        .btn-warning {
            background: var(--warning-gradient);
            border: none;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .loading-spinner {
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
        
        .progress {
            height: 8px;
            border-radius: 4px;
            background: #e9ecef;
        }
        
        .progress-bar {
            background: var(--primary-gradient);
            transition: width 0.6s ease;
        }
        
        .tooltip-inner {
            background: var(--primary-gradient);
            border-radius: 8px;
            padding: 8px 12px;
        }
        
        .modal-content {
            border-radius: 20px;
            border: none;
        }
        
        .modal-header {
            border-bottom: none;
            padding: 30px 30px 0;
        }
        
        .modal-body {
            padding: 30px;
        }
        
        .alert {
            border-radius: 10px;
            border: none;
            padding: 16px 20px;
            animation: slideIn 0.5s ease;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(-100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .nav-tabs {
            border-bottom: none;
            background: white;
            padding: 10px;
            border-radius: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .nav-tabs .nav-link {
            border: none;
            border-radius: 10px;
            padding: 12px 24px;
            color: #6c757d;
            font-weight: 600;
            transition: all 0.3s ease;
            margin: 0 5px;
        }
        
        .nav-tabs .nav-link:hover {
            background: #f8f9fa;
        }
        
        .nav-tabs .nav-link.active {
            background: var(--primary-gradient);
            color: white;
        }
        
        /* 暗黑模式 */
        .dark-mode {
            background: #1a1d21;
            color: #e4e6eb;
        }
        
        .dark-mode .card,
        .dark-mode .stat-card,
        .dark-mode .proxy-card,
        .dark-mode .nav-tabs,
        .dark-mode .modal-content {
            background: #242526;
            color: #e4e6eb;
        }
        
        .dark-mode .form-control,
        .dark-mode .form-select {
            background: #3a3b3c;
            border-color: #3a3b3c;
            color: #e4e6eb;
        }
        
        .theme-switch {
            position: fixed;
            bottom: 30px;
            right: 30px;
            z-index: 1000;
        }
        
        .theme-switch button {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            border: none;
            background: var(--primary-gradient);
            color: white;
            font-size: 24px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: all 0.3s ease;
        }
        
        .theme-switch button:hover {
            transform: scale(1.1);
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="bi bi-shield-lock-fill me-2"></i>3proxy 管理面板
            </span>
            <div class="d-flex align-items-center">
                <span class="text-white me-3">
                    <i class="bi bi-person-circle me-1"></i>管理员
                </span>
                <a href="/logout" class="btn btn-light btn-sm">
                    <i class="bi bi-box-arrow-right me-1"></i>退出
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <!-- 系统状态卡片 -->
        <div class="row g-4 mb-4">
            <div class="col-lg-3 col-md-6">
                <div class="stat-card">
                    <div class="stat-icon" style="background: var(--primary-gradient);">
                        <i class="bi bi-cpu"></i>
                    </div>
                    <h6 class="text-muted mb-2">CPU使用率</h6>
                    <h3 class="mb-2"><span id="cpu-percent">-</span>%</h3>
                    <div class="progress">
                        <div class="progress-bar" id="cpu-progress" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6">
                <div class="stat-card">
                    <div class="stat-icon" style="background: var(--success-gradient);">
                        <i class="bi bi-memory"></i>
                    </div>
                    <h6 class="text-muted mb-2">内存使用</h6>
                    <h3 class="mb-2"><span id="mem-used">-</span>GB / <span id="mem-total">-</span>GB</h3>
                    <div class="progress">
                        <div class="progress-bar bg-success" id="mem-progress" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6">
                <div class="stat-card">
                    <div class="stat-icon" style="background: var(--warning-gradient);">
                        <i class="bi bi-hdd"></i>
                    </div>
                    <h6 class="text-muted mb-2">磁盘使用</h6>
                    <h3 class="mb-2"><span id="disk-used">-</span>GB / <span id="disk-total">-</span>GB</h3>
                    <div class="progress">
                        <div class="progress-bar bg-warning" id="disk-progress" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            <div class="col-lg-3 col-md-6">
                <div class="stat-card">
                    <div class="stat-icon" style="background: var(--info-gradient);">
                        <i class="bi bi-server"></i>
                    </div>
                    <h6 class="text-muted mb-2">代理状态</h6>
                    <h3 class="mb-2">
                        <span id="proxy-status" class="badge bg-success">运行中</span>
                    </h3>
                    <small class="text-muted">
                        总数: <span id="total-proxies">{{ system_stats.total_proxies }}</span> | 
                        启用: <span id="enabled-proxies">{{ system_stats.enabled_proxies }}</span>
                    </small>
                </div>
            </div>
        </div>

        <!-- 主选项卡 -->
        <ul class="nav nav-tabs mb-4" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane">
                    <i class="bi bi-diagram-3 me-2"></i>代理管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane">
                    <i class="bi bi-people me-2"></i>用户管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-pane">
                    <i class="bi bi-hdd-network me-2"></i>IP管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="system-tab" data-bs-toggle="tab" data-bs-target="#system-pane">
                    <i class="bi bi-gear me-2"></i>系统设置
                </button>
            </li>
        </ul>

        <div class="tab-content">
            <!-- 代理管理 -->
            <div class="tab-pane fade show active" id="proxy-pane" role="tabpanel">
                <div class="row g-4">
                    <!-- 添加代理 -->
                    <div class="col-lg-6">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title fw-bold mb-4">
                                    <i class="bi bi-plus-circle-fill text-success me-2"></i>批量添加代理
                                </h5>
                                <form method="post" action="/batchaddproxy" class="mb-4">
                                    <div class="row g-3">
                                        <div class="col-md-4">
                                            <label class="form-label small">IP范围</label>
                                            <input type="text" class="form-control" name="iprange" placeholder="192.168.1.2-254">
                                        </div>
                                        <div class="col-md-4">
                                            <label class="form-label small">端口范围</label>
                                            <input type="text" class="form-control" name="portrange" placeholder="20000-30000">
                                        </div>
                                        <div class="col-md-4">
                                            <label class="form-label small">用户名前缀</label>
                                            <input type="text" class="form-control" name="userprefix" placeholder="user">
                                        </div>
                                    </div>
                                    <button type="submit" class="btn btn-success w-100 mt-3">
                                        <i class="bi bi-plus-lg me-2"></i>范围添加
                                    </button>
                                </form>
                                <form method="post" action="/batchaddproxy">
                                    <label class="form-label small">手动批量添加</label>
                                    <textarea name="batchproxy" class="form-control mb-3" rows="6" 
                                        placeholder="每行一个：ip,端口 或 ip:端口"></textarea>
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="bi bi-upload me-2"></i>批量导入
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 单个添加 -->
                    <div class="col-lg-6">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title fw-bold mb-4">
                                    <i class="bi bi-plus-square-fill text-primary me-2"></i>新增单个代理
                                </h5>
                                <form method="post" action="/addproxy">
                                    <div class="mb-3">
                                        <label class="form-label small">IP地址</label>
                                        <input name="ip" class="form-control" placeholder="192.168.1.100" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label small">端口</label>
                                        <input name="port" class="form-control" placeholder="3128" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label small">用户名</label>
                                        <input name="username" class="form-control" placeholder="user001" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label small">密码</label>
                                        <input name="password" class="form-control" placeholder="留空随机生成">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label small">用户前缀</label>
                                        <input name="userprefix" class="form-control" placeholder="可选">
                                    </div>
                                    <button class="btn btn-primary w-100" type="submit">
                                        <i class="bi bi-check-lg me-2"></i>添加代理
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                    
                    <!-- C段列表 -->
                    <div class="col-12">
                        <div class="card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-center mb-4">
                                    <h5 class="card-title fw-bold mb-0">
                                        <i class="bi bi-diagram-3-fill text-primary me-2"></i>代理C段列表
                                    </h5>
                                    <div class="d-flex gap-2">
                                        <select id="exportCseg" class="form-select form-select-sm" multiple style="width: 200px; height: 80px;">
                                            {% for cseg, info in c_segments.items() %}
                                            <option value="{{ cseg }}">{{ cseg }}.x</option>
                                            {% endfor %}
                                        </select>
                                        <button id="exportSelected" class="btn btn-outline-primary btn-sm">
                                            <i class="bi bi-download"></i> 导出选中
                                        </button>
                                    </div>
                                </div>
                                
                                <div class="row g-3" id="proxy-cards">
                                    {% for cseg, info in c_segments.items() %}
                                    <div class="col-lg-4 col-md-6">
                                        <div class="proxy-card" onclick="window.location.href='/proxy_list/{{ cseg }}'">
                                            <div class="d-flex justify-content-between align-items-start mb-3">
                                                <h5 class="mb-0">{{ cseg }}.x</h5>
                                                <span class="badge badge-gradient">{{ info.count }} 个代理</span>
                                            </div>
                                            <div class="mb-3">
                                                <div class="d-flex justify-content-between mb-2">
                                                    <span class="text-muted">启用/禁用</span>
                                                    <span>
                                                        <span class="text-success fw-bold">{{ info.enabled }}</span> / 
                                                        <span class="text-danger fw-bold">{{ info.disabled }}</span>
                                                    </span>
                                                </div>
                                                <div class="progress mb-3">
                                                    <div class="progress-bar bg-success" style="width: {{ (info.enabled / info.count * 100) if info.count > 0 else 0 }}%"></div>
                                                </div>
                                            </div>
                                            {% if info.ip_range %}
                                            <div class="small text-muted">
                                                <i class="bi bi-info-circle me-1"></i>
                                                范围: {{ info.ip_range }} | 端口: {{ info.port_range }} | 前缀: {{ info.user_prefix }}
                                            </div>
                                            {% endif %}
                                            <div class="mt-3">
                                                <span class="badge bg-info cnet-traffic" data-cseg="{{ cseg }}">
                                                    <i class="bi bi-arrow-down-up me-1"></i>加载中...</span>
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
            
            <!-- 用户管理 -->
            <div class="tab-pane fade" id="user-pane" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title fw-bold mb-4">
                            <i class="bi bi-person-badge-fill text-warning me-2"></i>Web用户管理
                        </h5>
                        <form class="row g-3 mb-4" method="post" action="/adduser">
                            <div class="col-md-4">
                                <input name="username" class="form-control" placeholder="用户名" required>
                            </div>
                            <div class="col-md-4">
                                <input type="password" name="password" class="form-control" placeholder="密码" required>
                            </div>
                            <div class="col-md-4">
                                <button class="btn btn-primary w-100" type="submit">
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
                                               onclick="return confirm('确认删除该用户?')">
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
            </div>
            
            <!-- IP管理 -->
            <div class="tab-pane fade" id="ip-pane" role="tabpanel">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title fw-bold mb-4">
                            <i class="bi bi-ethernet text-info me-2"></i>IP批量管理
                        </h5>
                        <form class="row g-3 mb-4" method="post" action="/add_ip_config">
                            <div class="col-md-2">
                                <label class="form-label small">网卡名</label>
                                <input name="iface" class="form-control" value="{{ default_iface }}" required>
                            </div>
                            <div class="col-md-5">
                                <label class="form-label small">IP区间/单IP</label>
                                <input name="ip_input" class="form-control" placeholder="192.168.1.2-254" required>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label small">模式</label>
                                <select name="mode" class="form-select">
                                    <option value="perm">永久</option>
                                    <option value="temp">临时</option>
                                </select>
                            </div>
                            <div class="col-md-2 d-flex align-items-end">
                                <button class="btn btn-success w-100" type="submit">
                                    <i class="bi bi-plus-lg me-2"></i>添加
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
            
            <!-- 系统设置 -->
            <div class="tab-pane fade" id="system-pane" role="tabpanel">
                <div class="row g-4">
                    <!-- 备份管理 -->
                    <div class="col-lg-6">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title fw-bold mb-4">
                                    <i class="bi bi-archive-fill text-primary me-2"></i>备份管理
                                </h5>
                                <button class="btn btn-primary mb-3" onclick="manualBackup()">
                                    <i class="bi bi-cloud-arrow-up me-2"></i>立即备份
                                </button>
                                <div id="backup-list" class="list-group">
                                    <div class="text-center p-3">
                                        <div class="loading-spinner"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 性能优化 -->
                    <div class="col-lg-6">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title fw-bold mb-4">
                                    <i class="bi bi-speedometer2 text-success me-2"></i>性能优化
                                </h5>
                                <p class="text-muted">优化3proxy配置以提高性能和稳定性</p>
                                <ul class="list-unstyled">
                                    <li><i class="bi bi-check-circle text-success me-2"></i>增加最大连接数至5000</li>
                                    <li><i class="bi bi-check-circle text-success me-2"></i>添加备用DNS服务器</li>
                                    <li><i class="bi bi-check-circle text-success me-2"></i>优化缓存和超时设置</li>
                                    <li><i class="bi bi-check-circle text-success me-2"></i>增加栈大小提高并发性能</li>
                                </ul>
                                <form method="post" action="/optimize_proxy">
                                    <button type="submit" class="btn btn-success w-100">
                                        <i class="bi bi-lightning-charge me-2"></i>执行优化
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show mt-3" role="alert">
                    <i class="bi bi-{{ 'exclamation-triangle' if category == 'error' else 'check-circle' }} me-2"></i>
                    {{ message }}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>

    <!-- 主题切换按钮 -->
    <div class="theme-switch">
        <button onclick="toggleTheme()">
            <i class="bi bi-moon-stars-fill" id="theme-icon"></i>
        </button>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 初始化所有工具提示
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl)
        });

        // 主题切换
        function toggleTheme() {
            document.body.classList.toggle('dark-mode');
            const icon = document.getElementById('theme-icon');
            if (document.body.classList.contains('dark-mode')) {
                icon.className = 'bi bi-sun-fill';
                localStorage.setItem('theme', 'dark');
            } else {
                icon.className = 'bi bi-moon-stars-fill';
                localStorage.setItem('theme', 'light');
            }
        }

        // 加载保存的主题
        if (localStorage.getItem('theme') === 'dark') {
            document.body.classList.add('dark-mode');
            document.getElementById('theme-icon').className = 'bi bi-sun-fill';
        }

        // 更新系统状态
        function updateSystemStats() {
            fetch('/system_stats')
                .then(res => res.json())
                .then(data => {
                    // CPU
                    document.getElementById('cpu-percent').textContent = data.cpu_percent.toFixed(1);
                    document.getElementById('cpu-progress').style.width = data.cpu_percent + '%';
                    
                    // 内存
                    document.getElementById('mem-used').textContent = data.memory_used;
                    document.getElementById('mem-total').textContent = data.memory_total;
                    document.getElementById('mem-progress').style.width = data.memory_percent + '%';
                    
                    // 磁盘
                    document.getElementById('disk-used').textContent = data.disk_used;
                    document.getElementById('disk-total').textContent = data.disk_total;
                    document.getElementById('disk-progress').style.width = data.disk_percent + '%';
                    
                    // 代理状态
                    const statusBadge = document.getElementById('proxy-status');
                    if (data.proxy_status === 'running') {
                        statusBadge.className = 'badge bg-success';
                        statusBadge.textContent = '运行中';
                    } else {
                        statusBadge.className = 'badge bg-danger';
                        statusBadge.textContent = '已停止';
                    }
                    
                    document.getElementById('total-proxies').textContent = data.total_proxies;
                    document.getElementById('enabled-proxies').textContent = data.enabled_proxies;
                });
        }

        // 更新流量统计
        function updateTraffic() {
            fetch('/cnet_traffic')
                .then(res => res.json())
                .then(data => {
                    document.querySelectorAll('.cnet-traffic').forEach(span => {
                        const cseg = span.getAttribute('data-cseg');
                        const traffic = data[cseg] || 0;
                        span.innerHTML = `<i class="bi bi-arrow-down-up me-1"></i>${traffic} MB`;
                    });
                });
        }

        // 加载备份列表
        function loadBackups() {
            fetch('/backup_list')
                .then(res => res.json())
                .then(backups => {
                    const list = document.getElementById('backup-list');
                    if (backups.length === 0) {
                        list.innerHTML = '<div class="text-center text-muted p-3">暂无备份</div>';
                        return;
                    }
                    
                    list.innerHTML = backups.map(backup => `
                        <div class="list-group-item d-flex justify-content-between align-items-center">
                            <div>
                                <strong>${backup.filename}</strong>
                                <small class="text-muted d-block">${backup.time} - ${backup.size} MB</small>
                            </div>
                            <button class="btn btn-sm btn-outline-primary" onclick="restoreBackup('${backup.filename}')">
                                <i class="bi bi-arrow-clockwise"></i> 恢复
                            </button>
                        </div>
                    `).join('');
                });
        }

        // 手动备份
        function manualBackup() {
            if (!confirm('确定要立即创建备份吗？')) return;
            window.location.href = '/manual_backup';
        }

        // 恢复备份
        function restoreBackup(filename) {
            if (!confirm(`确定要恢复备份 ${filename} 吗？这将覆盖当前配置。`)) return;
            window.location.href = `/restore_backup/${filename}`;
        }

        // 导出选中的C段
        document.getElementById('exportSelected').onclick = function() {
            const select = document.getElementById('exportCseg');
            const selected = Array.from(select.selectedOptions).map(o => o.value);
            if (selected.length === 0) {
                alert("请选择要导出的C段");
                return;
            }
            
            const form = new FormData();
            selected.forEach(c => form.append('csegs[]', c));
            
            fetch('/export_selected', {method: 'POST', body: form})
                .then(resp => resp.blob())
                .then(blob => {
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'proxy_export.txt';
                    a.click();
                });
        };

        // 定时更新
        updateSystemStats();
        updateTraffic();
        loadBackups();
        
        setInterval(updateSystemStats, 5000);
        setInterval(updateTraffic, 10000);
        setInterval(loadBackups, 30000);
    </script>
</body>
</html>
EOF

# --------- proxy_list.html（二级页面 - 代理列表） ---------
cat > $WORKDIR/templates/proxy_list.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>{{ cseg }}.x 代理列表</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        body {
            background: #f5f7fa;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        .navbar {
            background: var(--primary-gradient);
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            animation: fadeInUp 0.5s ease-out;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .btn {
            border-radius: 10px;
            padding: 8px 16px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .table {
            animation: fadeIn 0.5s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .pagination {
            margin-top: 20px;
        }
        
        .search-box {
            border-radius: 10px;
            border: 1px solid #e0e6ed;
            padding: 10px 16px;
            transition: all 0.3s ease;
        }
        
        .search-box:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 40px;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 40px;
            height: 40px;
            border: 4px solid rgba(102, 126, 234, 0.3);
            border-radius: 50%;
            border-top-color: #667eea;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .dark-mode {
            background: #1a1d21;
            color: #e4e6eb;
        }
        
        .dark-mode .card {
            background: #242526;
            color: #e4e6eb;
        }
        
        .dark-mode .table {
            color: #e4e6eb;
        }
        
        .dark-mode .search-box {
            background: #3a3b3c;
            border-color: #3a3b3c;
            color: #e4e6eb;
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-dark mb-4">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <a href="/" class="text-white text-decoration-none">
                    <i class="bi bi-arrow-left-circle me-2"></i>
                </a>
                {{ cseg }}.x 代理列表
            </span>
            <a href="/logout" class="btn btn-light btn-sm">
                <i class="bi bi-box-arrow-right me-1"></i>退出
            </a>
        </div>
    </nav>

    <div class="container-fluid">
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h5 class="card-title fw-bold mb-0">
                        <i class="bi bi-list-ul me-2"></i>代理详情
                    </h5>
                    <div class="d-flex gap-2">
                        <input type="text" class="search-box form-control" id="searchBox" 
                               placeholder="搜索IP/端口/用户名...">
                        <button class="btn btn-outline-success" id="exportSelectedProxy">
                            <i class="bi bi-download"></i> 导出选中
                        </button>
                        <button class="btn btn-outline-danger" id="deleteSelected">
                            <i class="bi bi-trash"></i> 删除选中
                        </button>
                    </div>
                </div>
                
                <div class="loading" id="loading">
                    <div class="loading-spinner"></div>
                    <p class="mt-3 text-muted">加载中...</p>
                </div>
                
                <div class="table-responsive" id="tableContainer">
                    <table class="table table-hover align-middle">
                        <thead class="table-light">
                            <tr>
                                <th><input type="checkbox" id="selectAll"></th>
                                <th>ID</th>
                                <th>IP</th>
                                <th>端口</th>
                                <th>用户名</th>
                                <th>密码</th>
                                <th>状态</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody id="proxyTableBody">
                            {% for p in proxies %}
                            <tr>
                                <td><input type="checkbox" name="ids" value="{{ p[0] }}"></td>
                                <td>{{ p[0] }}</td>
                                <td>{{ p[1] }}</td>
                                <td>{{ p[2] }}</td>
                                <td>{{ p[3] }}</td>
                                <td>
                                    <code class="user-select-all">{{ p[4] }}</code>
                                    <i class="bi bi-clipboard ms-2 text-primary" style="cursor: pointer;"
                                       onclick="copyToClipboard('{{ p[4] }}')"></i>
                                </td>
                                <td>
                                    {% if p[5] %}
                                        <span class="badge bg-success">启用</span>
                                    {% else %}
                                        <span class="badge bg-secondary">禁用</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if p[5] %}
                                        <a href="/disableproxy/{{ p[0] }}" class="btn btn-sm btn-warning">
                                            <i class="bi bi-pause"></i> 禁用
                                        </a>
                                    {% else %}
                                        <a href="/enableproxy/{{ p[0] }}" class="btn btn-sm btn-success">
                                            <i class="bi bi-play"></i> 启用
                                        </a>
                                    {% endif %}
                                    <a href="/delproxy/{{ p[0] }}" class="btn btn-sm btn-danger" 
                                       onclick="return confirm('确认删除?')">
                                        <i class="bi bi-trash"></i> 删除
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                
                <nav id="pagination"></nav>
                
                <form method="post" action="/batchdelproxy" id="batchForm" style="display: none;">
                    <!-- 用于批量操作的隐藏表单 -->
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const cseg = '{{ cseg }}';
        let currentPage = 1;
        let totalPages = 1;
        let perPage = 50;
        let searchTerm = '';
        
        // 复制到剪贴板
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                const toast = document.createElement('div');
                toast.className = 'position-fixed bottom-0 end-0 p-3';
                toast.style.zIndex = '11';
                toast.innerHTML = `
                    <div class="toast show" role="alert">
                        <div class="toast-body">
                            <i class="bi bi-check-circle text-success me-2"></i>已复制到剪贴板
                        </div>
                    </div>
                `;
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 2000);
            });
        }
        
        // 加载代理数据
        function loadProxies(page = 1) {
            document.getElementById('loading').style.display = 'block';
            document.getElementById('tableContainer').style.display = 'none';
            
            fetch(`/api/proxies/${cseg}?page=${page}&per_page=${perPage}&search=${searchTerm}`)
                .then(res => res.json())
                .then(data => {
                    currentPage = data.page;
                    totalPages = data.total_pages;
                    renderTable(data.proxies);
                    renderPagination();
                    
                    document.getElementById('loading').style.display = 'none';
                    document.getElementById('tableContainer').style.display = 'block';
                });
        }
        
        // 渲染表格
        function renderTable(proxies) {
            const tbody = document.getElementById('proxyTableBody');
            tbody.innerHTML = proxies.map(p => `
                <tr>
                    <td><input type="checkbox" name="ids" value="${p.id}"></td>
                    <td>${p.id}</td>
                    <td>${p.ip}</td>
                    <td>${p.port}</td>
                    <td>${p.username}</td>
                    <td>
                        <code class="user-select-all">${p.password}</code>
                        <i class="bi bi-clipboard ms-2 text-primary" style="cursor: pointer;"
                           onclick="copyToClipboard('${p.password}')"></i>
                    </td>
                    <td>
                        ${p.enabled ? 
                            '<span class="badge bg-success">启用</span>' : 
                            '<span class="badge bg-secondary">禁用</span>'}
                    </td>
                    <td>
                        ${p.enabled ?
                            `<a href="/disableproxy/${p.id}" class="btn btn-sm btn-warning">
                                <i class="bi bi-pause"></i> 禁用
                            </a>` :
                            `<a href="/enableproxy/${p.id}" class="btn btn-sm btn-success">
                                <i class="bi bi-play"></i> 启用
                            </a>`}
                        <a href="/delproxy/${p.id}" class="btn btn-sm btn-danger" 
                           onclick="return confirm('确认删除?')">
                            <i class="bi bi-trash"></i> 删除
                        </a>
                    </td>
                </tr>
            `).join('');
        }
        
        // 渲染分页
        function renderPagination() {
            const pagination = document.getElementById('pagination');
            if (totalPages <= 1) {
                pagination.innerHTML = '';
                return;
            }
            
            let html = '<ul class="pagination justify-content-center">';
            
            // 上一页
            html += `<li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="loadProxies(${currentPage - 1}); return false;">
                    <i class="bi bi-chevron-left"></i>
                </a>
            </li>`;
            
            // 页码
            let startPage = Math.max(1, currentPage - 2);
            let endPage = Math.min(totalPages, currentPage + 2);
            
            if (startPage > 1) {
                html += `<li class="page-item">
                    <a class="page-link" href="#" onclick="loadProxies(1); return false;">1</a>
                </li>`;
                if (startPage > 2) {
                    html += '<li class="page-item disabled"><span class="page-link">...</span></li>';
                }
            }
            
            for (let i = startPage; i <= endPage; i++) {
                html += `<li class="page-item ${i === currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" onclick="loadProxies(${i}); return false;">${i}</a>
                </li>`;
            }
            
            if (endPage < totalPages) {
                if (endPage < totalPages - 1) {
                    html += '<li class="page-item disabled"><span class="page-link">...</span></li>';
                }
                html += `<li class="page-item">
                    <a class="page-link" href="#" onclick="loadProxies(${totalPages}); return false;">${totalPages}</a>
                </li>`;
            }
            
            // 下一页
            html += `<li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="loadProxies(${currentPage + 1}); return false;">
                    <i class="bi bi-chevron-right"></i>
                </a>
            </li>`;
            
            html += '</ul>';
            pagination.innerHTML = html;
        }
        
        // 全选
        document.getElementById('selectAll').addEventListener('change', function() {
            const checkboxes = document.querySelectorAll('input[name="ids"]');
            checkboxes.forEach(cb => cb.checked = this.checked);
        });
        
        // 搜索
        let searchTimeout;
        document.getElementById('searchBox').addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                searchTerm = this.value.trim();
                loadProxies(1);
            }, 500);
        });
        
        // 导出选中
        document.getElementById('exportSelectedProxy').addEventListener('click', function() {
            const ids = Array.from(document.querySelectorAll('input[name="ids"]:checked'))
                .map(cb => cb.value);
            
            if (ids.length === 0) {
                alert('请选择要导出的代理');
                return;
            }
            
            const form = new FormData();
            ids.forEach(id => form.append('ids[]', id));
            
            fetch('/export_selected_proxy', {method: 'POST', body: form})
                .then(resp => resp.blob())
                .then(blob => {
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = `proxy_${cseg}_export.txt`;
                    a.click();
                });
        });
        
        // 删除选中
        document.getElementById('deleteSelected').addEventListener('click', function() {
            const ids = Array.from(document.querySelectorAll('input[name="ids"]:checked'))
                .map(cb => cb.value);
            
            if (ids.length === 0) {
                alert('请选择要删除的代理');
                return;
            }
            
            if (!confirm(`确定要删除选中的 ${ids.length} 个代理吗？`)) {
                return;
            }
            
            const form = document.getElementById('batchForm');
            form.innerHTML = ids.map(id => `<input type="hidden" name="ids" value="${id}">`).join('');
            form.submit();
        });
        
        // 检查主题
        if (localStorage.getItem('theme') === 'dark') {
            document.body.classList.add('dark-mode');
        }
        
        // 初始加载
        // 如果页面已经有数据，就不需要重新加载
        if (document.querySelectorAll('#proxyTableBody tr').length === 0) {
            loadProxies(1);
        }
    </script>
</body>
</html>
EOF

# --------- Systemd服务 ---------
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

cat > /etc/systemd/system/3proxy-monitor.service <<EOF
[Unit]
Description=3proxy监控服务
After=network.target 3proxy-autostart.service

[Service]
Type=simple
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
echo ""
echo "新增功能："
echo "1. 美化的卡片式UI设计，支持暗黑模式"
echo "2. 代理列表二级页面，防止大量数据卡顿"
echo "3. 系统实时监控（CPU、内存、磁盘、网络）"
echo "4. 自动备份功能（每日2点自动备份）"
echo "5. 性能优化功能（一键优化3proxy配置）"
echo "6. 进程监控服务（自动重启崩溃的3proxy）"
echo ""
echo -e "\n如需卸载：bash $0 uninstall"
echo -e "如需重装：bash $0 reinstall"
