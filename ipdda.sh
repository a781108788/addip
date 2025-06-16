#!/bin/bash
set -e

############################################
# 一键部署 3proxy + Flask Web管理后台（完整无删减）
############################################

WORKDIR=/opt/3proxy-web
BIN_3PROXY=/usr/local/bin/3proxy
CFG_3PROXY=/usr/local/etc/3proxy/3proxy.cfg
LOG_3PROXY=/usr/local/etc/3proxy/3proxy.log

# 获取本机IP
get_local_ip(){
  pub=$(curl -s ifconfig.me||curl -s ip.sb||curl -s icanhazip.com)
  lan=$(hostname -I|awk '{print $1}')
  [[ -n "$pub" && "$pub" != "$lan" ]]&&echo $pub||echo $lan
}

# 完全卸载
uninstall_all(){
  systemctl stop 3proxy-web 2>/dev/null||:
  systemctl disable 3proxy-web 2>/dev/null||:
  systemctl stop 3proxy-autostart 2>/dev/null||:
  systemctl disable 3proxy-autostart 2>/dev/null||:
  rm -rf $WORKDIR
  rm -f /etc/systemd/system/3proxy-web.service
  rm -f /etc/systemd/system/3proxy-autostart.service
  rm -f $BIN_3PROXY
  rm -rf $(dirname $CFG_3PROXY)
  rm -f /etc/cron.d/3proxy-logrotate
  systemctl daemon-reload
  echo -e "\e[31m已卸载 3proxy Web管理后台\e[0m"
}

if [[ "$1" == "uninstall" ]];then uninstall_all;exit;fi
if [[ "$1" == "reinstall" ]];then uninstall_all;echo -e "\e[32m重新安装...\e[0m";fi

PORT=$((RANDOM%55534+10000))
ADMINUSER="admin$RANDOM"
ADMINPASS=$(tr -dc A-Za-z0-9 </dev/urandom|head -c16)

echo -e "\n=== 安装依赖 ==="
apt update
apt install -y gcc make git wget python3 python3-venv python3-pip sqlite3 cron net-tools python3-netifaces

echo -e "\n=== 编译安装 3proxy ==="
if [ ! -f "$BIN_3PROXY" ];then
  cd /tmp
  rm -rf 3proxy
  git clone --depth=1 https://github.com/z3APA3A/3proxy.git
  cd 3proxy
  make -f Makefile.Linux
  mkdir -p $(dirname $BIN_3PROXY) $(dirname $CFG_3PROXY)
  cp bin/3proxy $BIN_3PROXY
  chmod +x $BIN_3PROXY
fi

echo -e "\n=== 配置 3proxy 默认配置 ==="
if [ ! -f "$CFG_3PROXY" ];then
cat > $CFG_3PROXY <<EOF
daemon
maxconn 2000
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
auth none
proxy -p3128
log $LOG_3PROXY D
EOF
fi

echo -e "\n=== 日志轮转（每3天清空一次） ==="
cat > /etc/cron.d/3proxy-logrotate <<EOF
0 3 */3 * * root [ -f "$LOG_3PROXY" ] && > "$LOG_3PROXY"
EOF

echo -e "\n=== 部署 Flask Web 管理后台 ==="
mkdir -p $WORKDIR/templates $WORKDIR/static
cd $WORKDIR
python3 -m venv venv
source venv/bin/activate
pip install flask flask_login flask_wtf wtforms Werkzeug netifaces --break-system-packages

############################################
# manage.py —— 后端所有路由及逻辑
############################################
cat > $WORKDIR/manage.py <<'EOF'
import os, sqlite3, random, string, re, collections, netifaces, io
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, make_response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

DB='3proxy.db'
SECRET='changeme_secret'
import sys
PORT=int(sys.argv[1]) if len(sys.argv)>1 else 9999
BIN3='/usr/local/bin/3proxy'
CFG3='/usr/local/etc/3proxy/3proxy.cfg'
LOG3='/usr/local/etc/3proxy/3proxy.log'
IFACE_CFG='/etc/network/interfaces'

app=Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key=SECRET
lm=LoginManager(app); lm.login_view='login'

def db_conn():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

class User(UserMixin):
    def __init__(self,id,uname,phash):
        self.id=id; self.username=uname; self.password_hash=phash
    def check_password(self,pw): return check_password_hash(self.password_hash,pw)

@lm.user_loader
def load_user(uid):
    db=db_conn(); r=db.execute("SELECT id,username,password FROM users WHERE id=?",(uid,)).fetchone(); db.close()
    return User(r['id'],r['username'],r['password']) if r else None

def reload_3proxy():
    os.system(f'python3 config_gen.py')
    os.system(f'pkill 3proxy; {BIN3} {CFG3} &')

def default_iface():
    try: return netifaces.gateways()['default'][netifaces.AF_INET][1]
    except: return 'eth0'

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        db=db_conn(); r=db.execute("SELECT id,username,password FROM users WHERE username=?",(request.form['username'],)).fetchone(); db.close()
        if r and check_password_hash(r['password'],request.form['password']):
            u=User(r['id'],r['username'],r['password']); login_user(u); return redirect('/')
        flash('登录失败')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); return redirect(url_for('login'))

@app.route('/',methods=['GET','POST'])
@login_required
def index():
    db=db_conn()
    proxies=db.execute("SELECT * FROM proxy ORDER BY id").fetchall()
    users=db.execute("SELECT id,username FROM users").fetchall()
    db.close()
    return render_template('index.html',proxies=proxies,users=users,iface=default_iface())

# ------------- 代理管理 -------------
@app.route('/addproxy',methods=['POST'])
@login_required
def addproxy():
    ip=request.form['ip']; port=int(request.form['port']); uname=request.form['username']
    pw=request.form['password'] or ''.join(random.choices(string.ascii_letters+string.digits,k=12))
    db=db_conn(); db.execute("INSERT INTO proxy(ip,port,username,password,enabled) VALUES(?,?,?,?,1)",(ip,port,uname,pw)); db.commit(); db.close()
    reload_3proxy(); flash('代理已添加'); return redirect('/')

@app.route('/batchaddproxy',methods=['POST'])
@login_required
def batchaddproxy():
    ipr=request.form.get('iprange'); pr=request.form.get('portrange'); prefix=request.form.get('userprefix')
    manual=request.form.get('batchproxy')
    db=db_conn(); cnt=0
    if ipr and pr and prefix:
        m=re.match(r'(\d+\.\d+\.\d+\.)(\d+)-(\d+)',ipr.strip())
        if not m: flash('IP范围格式错误'); return redirect('/')
        base,mn, mx = m.group(1),int(m.group(2)),int(m.group(3))
        ips=[f"{base}{i}" for i in range(mn,mx+1)]
        m2=re.match(r'(\d+)-(\d+)',pr.strip())
        if not m2: flash('端口范围格式错误'); return redirect('/')
        ps,pe=int(m2.group(1)),int(m2.group(2))
        ports=list(range(ps,pe+1))
        if len(ports)<len(ips): flash('端口不足'); return redirect('/')
        random.shuffle(ports)
        for i,ip in enumerate(ips):
            uname=prefix+''.join(random.choices(string.ascii_lowercase+string.digits,k=4))
            pw=''.join(random.choices(string.ascii_letters+string.digits,k=12))
            db.execute("INSERT INTO proxy(ip,port,username,password,enabled) VALUES(?,?,?,?,1)",(ip,ports[i],uname,pw)); cnt+=1
        db.commit(); db.close(); reload_3proxy(); flash(f'范围批量添加{cnt}条'); return redirect('/')
    # 手动模式
    lines=manual.strip().splitlines(); base_id=db.execute("SELECT MAX(id) FROM proxy").fetchone()[0] or 0; idx=1
    for l in lines:
        l=l.strip(); 
        if not l or l.startswith('#'): continue
        parts=re.split(r'[:,\s]+',l)
        if len(parts)==2:
            ip,pt=parts; uname=f"user{base_id+idx:03d}"; pw=''.join(random.choices(string.ascii_letters+string.digits,k=12)); idx+=1
        elif len(parts)==3:
            ip,pt,uname=parts; pw=''.join(random.choices(string.ascii_letters+string.digits,k=12))
        else:
            ip,pt,uname,pw=parts[0],parts[1],parts[2],parts[3]
        db.execute("INSERT INTO proxy(ip,port,username,password,enabled) VALUES(?,?,?,?,1)",(ip,int(pt),uname,pw)); cnt+=1
    db.commit(); db.close()
    if cnt: reload_3proxy(); flash(f'手动批量添加{cnt}条')
    return redirect('/')

@app.route('/delproxy/<int:pid>')
@login_required
def delproxy(pid):
    db=db_conn(); db.execute("DELETE FROM proxy WHERE id=?",(pid,)); db.commit(); db.close()
    reload_3proxy(); flash('已删除'); return redirect('/')

@app.route('/batchdelproxy',methods=['POST'])
@login_required
def batchdelproxy():
    ids=request.form.getlist('ids')
    db=db_conn(); db.executemany("DELETE FROM proxy WHERE id=?",[ (i,) for i in ids ]); db.commit(); db.close()
    reload_3proxy(); flash(f'已批量删除{len(ids)}条'); return redirect('/')

@app.route('/batch_enable',methods=['POST'])
@login_required
def batch_enable():
    ids=request.form.getlist('ids[]')
    db=db_conn(); db.executemany("UPDATE proxy SET enabled=1 WHERE id=?",[ (i,) for i in ids ]); db.commit(); db.close()
    reload_3proxy(); return '',204

@app.route('/batch_disable',methods=['POST'])
@login_required
def batch_disable():
    ids=request.form.getlist('ids[]')
    db=db_conn(); db.executemany("UPDATE proxy SET enabled=0 WHERE id=?",[ (i,) for i in ids ]); db.commit(); db.close()
    reload_3proxy(); return '',204

@app.route('/enableproxy/<int:pid>')
@login_required
def enableproxy(pid):
    db=db_conn(); db.execute("UPDATE proxy SET enabled=1 WHERE id=?",(pid,)); db.commit(); db.close()
    reload_3proxy(); flash('已启用'); return redirect('/')

@app.route('/disableproxy/<int:pid>')
@login_required
def disableproxy(pid):
    db=db_conn(); db.execute("UPDATE proxy SET enabled=0 WHERE id=?",(pid,)); db.commit(); db.close()
    reload_3proxy(); flash('已禁用'); return redirect('/')

# 用户管理
@app.route('/adduser',methods=['POST'])
@login_required
def adduser():
    un=request.form['username']; ph=generate_password_hash(request.form['password'])
    db=db_conn(); db.execute("INSERT INTO users(username,password) VALUES(?,?)",(un,ph)); db.commit(); db.close()
    flash('用户已添加'); return redirect('/')

@app.route('/deluser/<int:uid>')
@login_required
def deluser(uid):
    db=db_conn(); db.execute("DELETE FROM users WHERE id=?",(uid,)); db.commit(); db.close()
    flash('用户已删除'); return redirect('/')

# 导出所选C段
@app.route('/export_selected',methods=['POST'])
@login_required
def export_selected():
    csegs=request.form.getlist('csegs[]'); prefix=request.form.get('userprefix','proxy')
    if not csegs: flash('请选择C段'); return redirect('/')
    db=db_conn(); out=''
    for c in csegs:
        rows=db.execute("SELECT ip,port,username,password FROM proxy WHERE ip LIKE ?",(c+'.%',)).fetchall()
        for r in rows: out+=f"{r['ip']}:{r['port']}:{r['username']}:{r['password']}\n"
    db.close()
    fn=f"{prefix}_{'_'.join(csegs)}.txt"
    resp=make_response(out); resp.headers['Content-Disposition']=f'attachment; filename={fn}'; resp.mimetype='text/plain'
    return resp

# 导出所选代理
@app.route('/export_selected_proxy',methods=['POST'])
@login_required
def export_selected_proxy():
    ids=request.form.getlist('ids[]')
    db=db_conn(); rows=db.execute(f"SELECT ip,port,username,password FROM proxy WHERE id IN ({','.join('?'*len(ids))})",tuple(ids)).fetchall(); db.close()
    out=''; import io
    for r in rows: out+=f"{r['ip']}:{r['port']}:{r['username']}:{r['password']}\n"
    return send_file(io.BytesIO(out.encode()), as_attachment=True, download_name='proxy_export.txt', mimetype='text/plain')

# 流量统计
@app.route('/cnet_traffic')
@login_required
def cnet_traffic():
    stats=collections.defaultdict(int)
    if os.path.exists(LOG3):
        with open(LOG3,'r',errors='ignore') as f:
            for line in f:
                p=line.split()
                if len(p)>7:
                    try:
                        seg='.'.join(p[2].split('.')[:3]); stats[seg]+=int(p[-2])
                    except: pass
    return jsonify({k:round(v/1024/1024,2) for k,v in stats.items()})

# IP 批量写 interfaces
def to_brace(ipr):
    m=re.match(r'(\d+\.\d+\.\d+\.)(\d+)-(\d+)',ipr)
    return f"{m.group(1)}{{{m.group(2)}..{m.group(3)}}}" if m else ipr

@app.route('/batch_add_ip',methods=['POST'])
@login_required
def batch_add_ip():
    iface=request.form['iface']; ipr=request.form['iprange']; nm=request.form['netmask'] or '24'; typ=request.form['type']
    brace=to_brace(ipr)
    up=f"    up bash -c 'for ip in {brace};do ip addr add ${{ip}}/{nm} dev {iface}; done'"
    down=f"    down bash -c 'for ip in {brace};do ip addr del ${{ip}}/{nm} dev {iface}; done'"
    if typ=='permanent':
        cp $IFACE_CFG $IFACE_CFG.bak_$(date +%s)
        grep -v "bash -c 'for ip" $IFACE_CFG > tmp.$$ && mv tmp.$$ $IFACE_CFG
        if grep -q "iface $iface " $IFACE_CFG;then
            awk -v u="$up" -v d="$down" -v pat="iface $iface " '$0~pat{print;print u;print d;next}1' $IFACE_CFG>tmp.$$ && mv tmp.$$ $IFACE_CFG
        else
            cat >> $IFACE_CFG <<EOL

auto $iface
iface $iface inet static
$up
$down
EOL
        fi
        flash(f"已写入 interfaces: {brace}")
    else:
        os.system(f"bash -c \"for ip in {brace};do ip addr add ${{ip}}/{nm} dev {iface}; done\"")
        flash(f"已临时添加: {brace}")
    return redirect('/')

if __name__=='__main__':
    app.run('0.0.0.0',PORT,debug=False)
EOF

############################################
# config_gen.py —— 生成 3proxy.cfg
############################################
cat > $WORKDIR/config_gen.py <<'EOF'
import sqlite3
db=sqlite3.connect('3proxy.db')
cur=db.execute('SELECT ip,port,username,password,enabled FROM proxy')
cfg=["daemon","maxconn 2000","nserver 8.8.8.8","nscache 65536","timeouts 1 5 30 60 180 1800 15 60","log /usr/local/etc/3proxy/3proxy.log D","auth strong"]
users,seen=[],set()
for ip,port,u,pw,en in cur:
    if en and (u,pw) not in seen:
        users.append(f"{u}:CL:{pw}"); seen.add((u,pw))
cfg.append("users "+' '.join(users))
for ip,port,u,pw,en in db.execute('SELECT ip,port,username,password,enabled FROM proxy'):
    if en:
        cfg.append(f"auth strong\nallow {u}\nproxy -n -a -p{port} -i{ip} -e{ip}")
open('/usr/local/etc/3proxy/3proxy.cfg','w').write('\n'.join(cfg))
EOF

############################################
# init_db.py —— 初始化 SQLite
############################################
cat > $WORKDIR/init_db.py <<'EOF'
import sqlite3
from werkzeug.security import generate_password_hash
import os
u=os.environ['ADMINUSER']; p=os.environ['ADMINPASS']
db=sqlite3.connect('3proxy.db')
db.execute('''CREATE TABLE IF NOT EXISTS proxy(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT, port INTEGER, username TEXT, password TEXT, enabled INTEGER DEFAULT 1)''')
db.execute('''CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, password TEXT)''')
db.execute("INSERT OR IGNORE INTO users(username,password) VALUES(?,?)",(u,generate_password_hash(p)))
db.commit()
print("Web 用户名:",u)
print("Web 密码:",p)
EOF

############################################
# login.html —— 登录页面
############################################
cat > $WORKDIR/templates/login.html <<'EOF'
<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>3proxy 登录</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-light"><div class="container" style="max-width:400px;margin-top:100px;">
<div class="card shadow"><div class="card-body">
<h3 class="text-center mb-4">3proxy 管理登录</h3>
<form method="post">
  <div class="mb-3"><label class="form-label">用户名</label><input name="username" class="form-control" required></div>
  <div class="mb-3"><label class="form-label">密码</label><input type="password" name="password" class="form-control" required></div>
  <button class="btn btn-primary w-100">登录</button>
</form>
{% with m=get_flashed_messages() %}{% if m %}<div class="alert alert-danger mt-3">{{m[0]}}</div>{% endif %}{% endwith %}
</div></div></div></body></html>
EOF

############################################
# index.html —— 管理界面
############################################
cat > $WORKDIR/templates/index.html <<'EOF'
<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>3proxy 管理面板</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
html,body{background:#f7f7fa;} .tab-pane{padding:1.5rem;}
.beauty-form .form-label{font-weight:bold;} .beauty-form .form-control,.beauty-form .form-select{margin-bottom:10px;}
.ip-group-header{background:#e5e9f2;cursor:pointer;} .c-collapsed .ip-group-body{display:none;}
</style></head><body>
<button class="btn btn-outline-dark btn-sm" onclick="document.body.classList.toggle('dark-mode')">🌙</button>
<div class="container py-3">
<ul class="nav nav-tabs">
  <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tab-proxy">代理管理</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-ip">IP批量管理</button></li>
  <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-user">用户管理</button></li>
</ul>
<div class="tab-content">
  <!-- 代理管理 -->
  <div class="tab-pane fade show active" id="tab-proxy">
    <!-- 批量添加 & 单个添加 -->
    <div class="row">
      <div class="col-md-6">
        <div class="card beauty-form p-3 mb-3">
          <h5 class="text-success">批量添加代理</h5>
          <form method="post" action="/batchaddproxy">
            <label class="form-label">IP范围</label>
            <input name="iprange" class="form-control" placeholder="192.168.1.2-254">
            <label class="form-label">端口范围</label>
            <input name="portrange" class="form-control" placeholder="20000-30000">
            <label class="form-label">用户名前缀</label>
            <input name="userprefix" class="form-control" placeholder="proxy">
            <button class="btn btn-success w-100 mt-2">范围添加</button>
            <hr>
            <label class="form-label">自定义批量</label>
            <textarea name="batchproxy" class="form-control" rows="6" placeholder="每行 ip,port 或 ip,port,user,pass"></textarea>
            <button class="btn btn-success w-100 mt-2">自定义添加</button>
          </form>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card beauty-form p-3 mb-3">
          <h5 class="text-primary">新增单个代理</h5>
          <form class="row g-2" method="post" action="/addproxy">
            <div class="col"><input name="ip" class="form-control" placeholder="IP" required></div>
            <div class="col"><input name="port" class="form-control" placeholder="端口" required></div>
            <div class="col"><input name="username" class="form-control" placeholder="用户名" required></div>
            <div class="col"><input name="password" class="form-control" placeholder="密码(空随机)"></div>
            <div class="col-auto"><button class="btn btn-primary">新增</button></div>
          </form>
        </div>
      </div>
    </div>
    <!-- 代理列表 -->
    <div class="card p-3">
      <div class="d-flex mb-2">
        <input id="searchBox" class="form-control form-control-sm me-2" placeholder="搜索IP/端口/用户">
        <select id="exportCseg" class="form-select form-select-sm me-2" multiple style="width:200px;height:80px;"></select>
        <input id="userprefix" class="form-control form-control-sm me-2" placeholder="导出前缀">
        <button id="exportSelected" class="btn btn-outline-info btn-sm me-2">导出C段</button>
        <button id="exportSelectedProxy" class="btn btn-outline-success btn-sm me-2">导出选中代理</button>
      </div>
      <form method="post" action="/batchdelproxy">
      <div style="max-height:60vh;overflow:auto;">
        <table class="table table-bordered table-hover">
          <thead class="table-light position-sticky top-0">
            <tr><th><input id="selectAll" type="checkbox"></th>
            <th>ID</th><th>IP</th><th>端口</th><th>用户名</th><th>密码</th><th>状态</th><th>操作</th></tr>
          </thead>
          <tbody id="proxyBody"></tbody>
        </table>
      </div>
      <button class="btn btn-danger mt-2">批量删除</button>
      <button type="button" class="btn btn-warning mt-2 ms-2" id="batchEnable">批量启用</button>
      <button type="button" class="btn btn-secondary mt-2 ms-2" id="batchDisable">批量禁用</button>
      </form>
    </div>
  </div>

  <!-- IP 批量管理 -->
  <div class="tab-pane fade" id="tab-ip">
    <div class="card beauty-form p-3 mt-3">
      <h5 class="text-info mb-3">IP地址批量添加</h5>
      <form method="post" action="/batch_add_ip">
        <label class="form-label">网卡</label>
        <input name="iface" class="form-control" value="{{iface}}" required>
        <label class="form-label">IP区间或多IP</label>
        <input name="iprange" class="form-control" placeholder="192.168.1.4-254 或 1.2.3.4,1.2.3.5">
        <label class="form-label">掩码</label>
        <input name="netmask" class="form-control" value="24">
        <label class="form-label">类型</label>
        <select name="type" class="form-select">
          <option value="permanent">永久写入interfaces</option>
          <option value="temp">临时添加</option>
        </select>
        <button class="btn btn-primary w-100 mt-2">执行</button>
      </form>
    </div>
  </div>

  <!-- 用户管理 -->
  <div class="tab-pane fade" id="tab-user">
    <div class="card beauty-form p-3 mt-3">
      <h5 class="text-warning mb-3">Web 用户管理</h5>
      <form method="post" action="/adduser" class="mb-3">
        <input name="username" class="form-control mb-2" placeholder="用户名" required>
        <input name="password" class="form-control mb-2" placeholder="密码" required>
        <button class="btn btn-outline-primary w-100">添加用户</button>
      </form>
      <table class="table">
        <tr><th>ID</th><th>用户名</th><th>操作</th></tr>
        {% for u in users %}
        <tr>
          <td>{{u['id']}}</td><td>{{u['username']}}</td>
          <td>{% if u['username']!='admin' %}<a class="btn btn-sm btn-danger" href="/deluser/{{u['id']}}">删除</a>{% endif %}</td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>

</div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// 以下 JS 完整实现表格渲染、搜索、折叠、导出、批量启用禁用
const proxyData=[{% for p in proxies %}{id:{{p['id']}},ip:"{{p['ip']}}",port:"{{p['port']}}",user:"{{p['username']}}",pw:"{{p['password']}}",enabled:{{'true' if p['enabled'] else 'false'}}},{% endfor %}];
function getC(ip){let m=ip.match(/^(\d+\.\d+\.\d+)\./);return m?m[1]:ip;}
function buildTable(filter=""){
  const body=document.getElementById('proxyBody'); body.innerHTML='';
  let groups={};
  proxyData.forEach(p=>{let s=(p.ip+p.port+p.user+p.pw).toLowerCase();if(filter&&!s.includes(filter))return; let c=getC(p.ip);groups[c]=groups[c]||[];groups[c].push(p);});
  Object.keys(groups).sort().forEach((c,i)=>{
    const gid='g'+i;
    let th=document.createElement('tr'); th.className='ip-group-header c-collapsed'; th.dataset.gid=gid;
    th.innerHTML=`<td colspan=8><span>▶</span>${c}.x 段 共${groups[c].length}条 <input class="group-select" data-gid="${gid}" type="checkbox"></td>`;
    body.appendChild(th);
    groups[c].forEach(p=>{
      let tr=document.createElement('tr'); tr.className='ip-group-body '+gid; tr.style.display='none';
      tr.innerHTML=`<td><input name="ids" type="checkbox" value="${p.id}"></td><td>${p.id}</td><td>${p.ip}</td><td>${p.port}</td><td>${p.user}</td><td>${p.pw}</td><td>${p.enabled?'<span class="badge bg-success">启用</span>':'<span class="badge bg-secondary">禁用</span>'}</td>
        <td>
          ${p.enabled?`<a class="btn btn-sm btn-warning" href="/disableproxy/${p.id}">禁用</a>`:`<a class="btn btn-sm btn-success" href="/enableproxy/${p.id}">启用</a>`}
          <a class="btn btn-sm btn-danger" href="/delproxy/${p.id}">删除</a>
        </td>`;
      body.appendChild(tr);
    });
  });
}
document.getElementById('searchBox').oninput=function(){
  buildTable(this.value.trim().toLowerCase());
};
document.getElementById('proxyBody').onclick=e=>{
  if(e.target.closest('.ip-group-header')&&!e.target.classList.contains('group-select')){
    let row=e.target.closest('tr'),gid=row.dataset.gid,open=row.classList.toggle('c-collapsed');
    document.querySelectorAll('.'+gid).forEach(r=>r.style.display=open?'':'none');
  }
  if(e.target.classList.contains('group-select')){
    document.querySelectorAll(`.ip-group-body.${e.target.dataset.gid} input`).forEach(cb=>cb.checked=e.target.checked);
  }
};
document.getElementById('selectAll').onclick=e=>document.querySelectorAll('#proxyBody input').forEach(cb=>cb.checked=e.target.checked);
document.getElementById('exportSelected').onclick=()=>{
  let sels=Array.from(document.getElementById('exportCseg').selectedOptions).map(o=>o.value);
  let prefix=document.getElementById('userprefix').value.trim()||'proxy';
  if(!sels.length){alert('请选择C段');return;}
  let form=new FormData();sels.forEach(c=>form.append('csegs[]',c));form.append('userprefix',prefix);
  fetch('/export_selected',{method:'POST',body:form})
    .then(r=>r.blob()).then(b=>{let a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=`${prefix}_${sels.join('_')}.txt`;a.click();});
};
document.getElementById('exportSelectedProxy').onclick=()=>{
  let ids=Array.from(document.querySelectorAll('#proxyBody input[name="ids"]:checked')).map(cb=>cb.value);
  if(!ids.length){alert('请选择代理');return;}
  let form=new FormData();ids.forEach(i=>form.append('ids[]',i));
  fetch('/export_selected_proxy',{method:'POST',body:form})
    .then(r=>r.blob()).then(b=>{let a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='proxy_export.txt';a.click();});
};
document.getElementById('batchEnable').onclick=()=>{
  let ids=Array.from(document.querySelectorAll('#proxyBody input[name="ids"]:checked')).map(cb=>cb.value);
  if(!ids.length){alert('请选择代理');return;}
  let form=new FormData();ids.forEach(i=>form.append('ids[]',i));
  fetch('/batch_enable',{method:'POST',body:form}).then(()=>location.reload());
};
document.getElementById('batchDisable').onclick=()=>{
  let ids=Array.from(document.querySelectorAll('#proxyBody input[name="ids"]:checked')).map(cb=>cb.value);
  if(!ids.length){alert('请选择代理');return;}
  let form=new FormData();ids.forEach(i=>form.append('ids[]',i));
  fetch('/batch_disable',{method:'POST',body:form}).then(()=>location.reload());
};
buildTable();
</script>
</body></html>
EOF

############################################
# systemd 服务单元
############################################
cat > /etc/systemd/system/3proxy-web.service <<EOF
[Unit]
Description=3proxy Web 管理后台
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
Description=3proxy 自动启动
After=network.target

[Service]
Type=simple
WorkingDirectory=$WORKDIR
ExecStart=$WORKDIR/venv/bin/python3 $WORKDIR/config_gen.py && $BIN_3PROXY $CFG_3PROXY
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# 初始化SQLite，创建admin用户
export ADMINUSER ADMINPASS
$WORKDIR/venv/bin/python3 $WORKDIR/init_db.py

# 启用并启动服务
systemctl daemon-reload
systemctl enable 3proxy-web
systemctl enable 3proxy-autostart
systemctl restart 3proxy-web
systemctl restart 3proxy-autostart

echo -e "\n\e[32m部署完成！\e[0m"
echo "访问地址: http://$(get_local_ip):$PORT"
echo "Web用户名: $ADMINUSER"
echo "Web密码: $ADMINPASS"
echo -e "卸载: bash $0 uninstall\n重装: bash $0 reinstall"
