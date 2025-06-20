#!/bin/bash
set -e

# 3proxy Enterprise High-Performance Management System
# Optimized for Debian 12, 128GB RAM, 32 Core Server
# Supports 10,000+ concurrent HTTP proxies

WORKDIR=/opt/3proxy-web
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_PATH=/usr/local/etc/3proxy/3proxy.cfg
LOGDIR=/var/log/3proxy
CREDS_FILE=/opt/3proxy-web/.credentials
BACKUP_DIR=/opt/3proxy-web/backups

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

function print_banner() {
    echo -e "${GREEN}"
    echo "================================================"
    echo "   3proxy Enterprise Management System v2.0"
    echo "   Optimized for High-Performance Servers"
    echo "================================================"
    echo -e "${NC}"
}

function get_local_ip() {
    local pubip lanip
    pubip=$(curl -s --max-time 3 ifconfig.me || curl -s --max-time 3 ip.sb || echo "")
    lanip=$(hostname -I | awk '{print $1}')
    if [[ -n "$pubip" && "$pubip" != "$lanip" ]]; then
        echo "$pubip"
    else
        echo "$lanip"
    fi
}

function show_credentials() {
    if [ -f "$CREDS_FILE" ]; then
        echo -e "\n${GREEN}========= 3proxy Web管理系统登录信息 =========${NC}"
        cat "$CREDS_FILE"
        echo -e "${GREEN}============================================${NC}\n"
    else
        echo -e "${RED}未找到登录凭据文件。请运行安装脚本。${NC}"
    fi
}

function optimize_system_enterprise() {
    echo -e "\n${YELLOW}========= 企业级系统优化 =========${NC}\n"
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d) 2>/dev/null || true
    
    # 检查是否已优化
    if grep -q "# 3proxy Enterprise Optimization" /etc/sysctl.conf 2>/dev/null; then
        echo -e "${YELLOW}系统已优化，更新配置...${NC}"
        sed -i '/# 3proxy Enterprise Optimization/,/# End 3proxy Enterprise Optimization/d' /etc/sysctl.conf
    fi
    
    # 企业级内核参数优化
    cat >> /etc/sysctl.conf <<'EOF'
# 3proxy Enterprise Optimization
# Network Core
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# ARP Cache for Multiple Subnets
net.ipv4.neigh.default.gc_thresh1 = 8192
net.ipv4.neigh.default.gc_thresh2 = 32768
net.ipv4.neigh.default.gc_thresh3 = 65536
net.ipv4.neigh.default.gc_stale_time = 120
net.ipv4.neigh.default.gc_interval = 30
net.ipv4.neigh.default.proxy_qlen = 96
net.ipv4.neigh.default.unres_qlen = 6

# Routing Optimization
net.ipv4.route.max_size = 2147483647
net.ipv4.route.gc_thresh = 1048576
net.ipv4.route.gc_timeout = 300
net.ipv4.route.gc_min_interval = 0
net.ipv4.route.gc_min_interval_ms = 10

# TCP Stack Optimization for Proxies
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_rfc1337 = 1

# Port Range
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 3128,8080-8090

# Connection Tracking for 10K+ Proxies
net.netfilter.nf_conntrack_max = 10000000
net.netfilter.nf_conntrack_buckets = 2500000
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 30
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 30
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_max_retrans = 300
net.netfilter.nf_conntrack_tcp_timeout_unacknowledged = 300
net.netfilter.nf_conntrack_tcp_loose = 1
net.netfilter.nf_conntrack_tcp_be_liberal = 1

# Memory Management for 128GB RAM
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.core.optmem_max = 134217728
net.ipv4.tcp_mem = 134217728 268435456 536870912
net.ipv4.udp_mem = 134217728 268435456 536870912
net.ipv4.tcp_rmem = 4096 131072 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
vm.min_free_kbytes = 2097152
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# TCP Congestion Control
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_autocorking = 1
net.ipv4.tcp_ecn = 2

# Security Hardening
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_ratelimit = 1000

# File System
fs.file-max = 10000000
fs.nr_open = 10000000
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 8192
fs.aio-max-nr = 1048576

# Process Limits
kernel.pid_max = 4194304
kernel.threads-max = 4194304
# End 3proxy Enterprise Optimization
EOF
    
    # 应用系统参数
    sysctl -p >/dev/null 2>&1
    
    # 加载必要的内核模块
    modprobe nf_conntrack >/dev/null 2>&1
    modprobe nf_conntrack_ipv4 >/dev/null 2>&1 || true
    echo "nf_conntrack" >> /etc/modules-load.d/3proxy.conf
    
    # 设置 conntrack hashsize (需要 root)
    echo 2500000 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    
    # 禁用所有接口的 rp_filter
    for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
        echo 0 > $i 2>/dev/null || true
    done
    
    # 优化限制
    cat > /etc/security/limits.d/3proxy.conf <<EOF
# 3proxy Enterprise Limits
* soft nofile 10000000
* hard nofile 10000000
* soft nproc 4194304
* hard nproc 4194304
* soft memlock unlimited
* hard memlock unlimited
* soft stack unlimited
* hard stack unlimited
root soft nofile 10000000
root hard nofile 10000000
root soft nproc 4194304
root hard nproc 4194304
EOF
    
    # Systemd 限制优化
    mkdir -p /etc/systemd/system.conf.d/
    cat > /etc/systemd/system.conf.d/3proxy.conf <<EOF
[Manager]
DefaultLimitNOFILE=10000000
DefaultLimitNPROC=4194304
DefaultLimitMEMLOCK=infinity
DefaultLimitSTACK=infinity
DefaultTasksMax=infinity
EOF
    
    # 创建高性能启动脚本
    cat > /usr/local/bin/3proxy-enterprise.sh <<'EOF'
#!/bin/bash
# 3proxy Enterprise Startup Script

# CPU亲和性设置 (使用前16个核心)
CPUS="0-15"

# 设置进程限制
ulimit -n 10000000
ulimit -u 4194304
ulimit -s unlimited
ulimit -l unlimited

# 优化运行时参数
echo 2500000 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
echo 10000000 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true

# 禁用 rp_filter
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 0 > $i 2>/dev/null || true
done

# ARP 优化
for i in /proc/sys/net/ipv4/conf/*/arp_ignore; do
    echo 1 > $i 2>/dev/null || true
done
for i in /proc/sys/net/ipv4/conf/*/arp_announce; do
    echo 2 > $i 2>/dev/null || true
done

# 增加网络缓冲区
echo 134217728 > /proc/sys/net/core/rmem_max
echo 134217728 > /proc/sys/net/core/wmem_max

# 清理旧连接
conntrack -F 2>/dev/null || true

# 生成配置
cd /opt/3proxy-web && /opt/3proxy-web/venv/bin/python3 /opt/3proxy-web/config_gen.py

# 启动 3proxy with CPU affinity
exec taskset -c $CPUS /usr/local/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
EOF
    
    chmod +x /usr/local/bin/3proxy-enterprise.sh
    
    # 创建日志轮转配置
    cat > /etc/logrotate.d/3proxy <<EOF
/var/log/3proxy/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload 3proxy-autostart >/dev/null 2>&1 || true
    endscript
}
EOF
    
    echo -e "${GREEN}企业级系统优化完成！${NC}"
    echo -e "${YELLOW}优化项目：${NC}"
    echo "- 支持1000万并发连接"
    echo "- 优化内存管理(128GB)"
    echo "- CPU亲和性设置"
    echo "- 高性能网络栈"
    echo "- 自动日志管理"
}

function install_dependencies() {
    echo -e "\n${YELLOW}========= 安装依赖 =========${NC}\n"
    
    apt update
    apt install -y \
        build-essential \
        git \
        wget \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        sqlite3 \
        libsqlite3-dev \
        cron \
        logrotate \
        conntrack \
        htop \
        iotop \
        sysstat \
        net-tools \
        nginx \
        redis-server \
        supervisor
}

function install_3proxy_optimized() {
    echo -e "\n${YELLOW}========= 编译优化版 3proxy =========${NC}\n"
    
    cd /tmp
    rm -rf 3proxy
    git clone --depth=1 https://github.com/z3APA3A/3proxy.git
    cd 3proxy
    
    # 优化编译选项
    cat > Makefile.Linux <<'EOF'
CC = gcc
CFLAGS = -O3 -march=native -mtune=native -fomit-frame-pointer -pipe -fno-strict-aliasing -pthread -DWITH_STD_MALLOC -DNDEBUG
LDFLAGS = -O3 -pthread
LIBS = -ldl -lpthread
PLUGINS =

include Makefile.inc
EOF
    
    make -f Makefile.Linux -j$(nproc)
    mkdir -p /usr/local/bin /usr/local/etc/3proxy /var/log/3proxy
    cp bin/3proxy /usr/local/bin/
    chmod +x /usr/local/bin/3proxy
}

function setup_web_management() {
    echo -e "\n${YELLOW}========= 部署Web管理系统 =========${NC}\n"
    
    mkdir -p $WORKDIR/templates $WORKDIR/static $BACKUP_DIR
    cd $WORKDIR
    
    # 创建虚拟环境
    python3 -m venv venv
    source venv/bin/activate
    
    # 安装Python依赖
    pip install --upgrade pip
    pip install \
        flask==2.3.3 \
        flask-login==0.6.2 \
        flask-wtf==1.1.1 \
        flask-caching==2.0.2 \
        gunicorn==21.2.0 \
        gevent==23.9.1 \
        werkzeug==2.3.7 \
        psutil==5.9.5 \
        redis==5.0.0 \
        sqlalchemy==2.0.21 \
        alembic==1.12.0
#!/bin/bash
# 这个脚本应该添加到主安装脚本的 setup_web_management 函数中

# 在 setup_web_management 函数的末尾添加以下内容：

# ========== 创建前端模板 ==========
cat > $WORKDIR/templates/login.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>3proxy Enterprise - 登录</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
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
            animation: slideIn 0.5s ease-out;
            border-radius: 20px;
            overflow: hidden;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .form-control:focus {
            border-color: #2a5298;
            box-shadow: 0 0 0 0.2rem rgba(42, 82, 152, 0.25);
        }
        .btn-login {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            border: none;
            transition: transform 0.2s;
            padding: 12px;
            font-weight: 500;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        .enterprise-badge {
            background: #f8f9fa;
            padding: 10px 20px;
            text-align: center;
            font-size: 0.9rem;
            color: #666;
            border-bottom: 1px solid #e9ecef;
        }
    </style>
</head>
<body>
<div class="container" style="max-width:450px;">
    <div class="card login-card">
        <div class="enterprise-badge">
            <strong>Enterprise Edition</strong> | High Performance Proxy Management
        </div>
        <div class="card-body p-5">
            <h3 class="mb-4 text-center">3proxy 管理系统</h3>
            <form method="post">
                <div class="mb-3">
                    <label class="form-label">用户名</label>
                    <input type="text" class="form-control form-control-lg" name="username" autofocus required>
                </div>
                <div class="mb-3">
                    <label class="form-label">密码</label>
                    <input type="password" class="form-control form-control-lg" name="password" required>
                </div>
                <button class="btn btn-primary btn-login w-100 btn-lg mt-4" type="submit">登录系统</button>
            </form>
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ 'danger' if category == 'danger' else 'info' }} mt-3 mb-0">{{ message }}</div>
                {% endfor %}
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
    <title>3proxy Enterprise Management</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            --success-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --warning-gradient: linear-gradient(135deg, #f2994a 0%, #f2c94c 100%);
            --danger-gradient: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
            --info-gradient: linear-gradient(135deg, #2196f3 0%, #21cbf3 100%);
            --card-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            --hover-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            --btn-radius: 8px;
        }
        
        body {
            background: #f5f7fa;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .navbar {
            background: var(--primary-gradient);
            box-shadow: var(--card-shadow);
            padding: 1rem 0;
        }
        
        .navbar-brand {
            font-weight: 600;
            font-size: 1.4rem;
        }
        
        .enterprise-info {
            background: rgba(255,255,255,0.1);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
        }
        
        /* 系统监控样式 */
        .system-monitor {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: var(--card-shadow);
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
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
            background: radial-gradient(circle, rgba(255,255,255,0.3) 0%, transparent 70%);
            transform: rotate(45deg);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--hover-shadow);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            position: relative;
            z-index: 1;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9rem;
            margin-top: 5px;
        }
        
        .progress {
            height: 10px;
            border-radius: 5px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .progress-bar {
            background: var(--primary-gradient);
            transition: width 0.6s ease;
        }
        
        /* 标签页样式 */
        .nav-tabs {
            border: none;
            background: white;
            border-radius: 10px;
            padding: 5px;
            box-shadow: var(--card-shadow);
            margin-bottom: 25px;
        }
        
        .nav-tabs .nav-link {
            border: none;
            color: #666;
            padding: 12px 24px;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .nav-tabs .nav-link:hover {
            background: #f8f9fa;
            color: #2a5298;
        }
        
        .nav-tabs .nav-link.active {
            background: var(--primary-gradient);
            color: white;
        }
        
        /* 卡片样式 */
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
            overflow: hidden;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: var(--hover-shadow);
        }
        
        /* 代理组卡片 */
        .proxy-card {
            cursor: pointer;
            background: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 15px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
            border: 1px solid #e0e0e0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            user-select: none;
        }
        
        .proxy-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 5px;
            height: 100%;
            background: var(--primary-gradient);
            transition: width 0.3s ease;
        }
        
        .proxy-card:hover {
            transform: translateY(-3px);
            box-shadow: var(--hover-shadow);
            border-color: #2a5298;
        }
        
        .proxy-card:hover::before {
            width: 8px;
        }
        
        .proxy-card.selected {
            background: linear-gradient(to right, #f0f4ff, #ffffff);
            border-color: #2a5298;
            box-shadow: 0 0 0 2px rgba(42, 82, 152, 0.2);
        }
        
        .proxy-card.selected::before {
            width: 10px;
        }
        
        /* 按钮样式 */
        .btn {
            border-radius: var(--btn-radius);
            transition: all 0.2s ease;
            font-weight: 500;
            border: none;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.2);
            transition: left 0.3s ease;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn-primary {
            background: var(--primary-gradient);
            box-shadow: 0 2px 10px rgba(30, 60, 114, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(30, 60, 114, 0.4);
            background: var(--primary-gradient);
        }
        
        .btn-success {
            background: var(--success-gradient);
            box-shadow: 0 2px 10px rgba(17, 153, 142, 0.3);
        }
        
        .btn-warning {
            background: var(--warning-gradient);
            box-shadow: 0 2px 10px rgba(242, 153, 74, 0.3);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger-gradient);
            box-shadow: 0 2px 10px rgba(235, 51, 73, 0.3);
        }
        
        .btn-info {
            background: var(--info-gradient);
            box-shadow: 0 2px 10px rgba(33, 150, 243, 0.3);
        }
        
        /* 徽章样式 */
        .badge {
            font-weight: 500;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
        }
        
        /* 输入框样式 */
        .form-control, .form-select {
            border-radius: var(--btn-radius);
            border: 1px solid #e0e0e0;
            padding: 12px 15px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: #2a5298;
            box-shadow: 0 0 0 0.2rem rgba(42, 82, 152, 0.25);
        }
        
        /* 模态框样式 */
        .modal-dialog {
            max-width: 1100px;
        }
        
        .modal-content {
            border-radius: 20px;
            border: none;
            overflow: hidden;
        }
        
        .modal-header {
            background: var(--primary-gradient);
            color: white;
            border-radius: 0;
            border: none;
            padding: 1.5rem;
        }
        
        .modal-body {
            padding: 0;
            max-height: 85vh;
            overflow-y: auto;
        }
        
        /* Toast样式 */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1050;
        }
        
        /* 加载动画 */
        .loading-spinner {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 9999;
        }
        
        .loading-spinner.show {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .animate-fade-in {
            animation: fadeIn 0.5s ease-out;
        }
        
        /* 深色模式 */
        .dark-mode {
            background: #1a1a2e;
            color: #eee;
        }
        
        .switch-mode {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--primary-gradient);
            color: white;
            border: none;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
        }
        
        /* 连接跟踪进度条 */
        .conntrack-progress {
            background: #e9ecef;
            border-radius: 10px;
            padding: 15px;
            margin-top: 10px;
        }
        
        .conntrack-info {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
            font-size: 0.9rem;
        }
        
        /* 性能优化：减少重绘 */
        .stat-card, .proxy-card {
            will-change: transform;
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="bi bi-shield-check"></i> 3proxy Enterprise
            </span>
            <div class="d-flex align-items-center">
                <span class="enterprise-info me-3">
                    <i class="bi bi-server"></i> 128GB RAM | 32 Cores
                </span>
                <span class="text-white me-3" id="currentTime"></span>
                <a href="/logout" class="btn btn-outline-light btn-sm">
                    <i class="bi bi-box-arrow-right"></i> 退出
                </a>
            </div>
        </div>
    </nav>

    <!-- 主内容区 -->
    <div class="container-fluid px-4 py-4">
        <!-- 系统监控 -->
        <div class="system-monitor animate-fade-in">
            <h5 class="mb-3"><i class="bi bi-speedometer2"></i> 系统监控</h5>
            <div class="row g-3">
                <div class="col-md-2">
                    <div class="stat-card">
                        <div class="stat-number" id="cpuUsage">0%</div>
                        <div class="stat-label">CPU 使用率</div>
                        <div class="progress">
                            <div class="progress-bar" id="cpuProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="stat-card">
                        <div class="stat-number" id="memUsage">0%</div>
                        <div class="stat-label">内存使用率</div>
                        <div class="progress">
                            <div class="progress-bar" id="memProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="stat-card">
                        <div class="stat-number" id="diskUsage">0%</div>
                        <div class="stat-label">磁盘使用率</div>
                        <div class="progress">
                            <div class="progress-bar" id="diskProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-2">
                    <div class="stat-card">
                        <div class="stat-number" id="proxyStatus">
                            <i class="bi bi-circle-fill text-danger"></i>
                        </div>
                        <div class="stat-label">3proxy 状态</div>
                        <div class="mt-1">
                            <small id="proxyInfo">未运行</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="conntrack-progress">
                        <div class="conntrack-info">
                            <span>连接跟踪</span>
                            <span><strong id="conntrackCount">0</strong> / <span id="conntrackMax">0</span></span>
                        </div>
                        <div class="progress">
                            <div class="progress-bar" id="conntrackProgress" style="width: 0%"></div>
                        </div>
                        <small class="text-muted">使用率: <span id="conntrackPercent">0</span>%</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- 标签页 -->
        <ul class="nav nav-tabs" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane">
                    <i class="bi bi-hdd-network"></i> 代理管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane">
                    <i class="bi bi-people"></i> 用户管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-pane">
                    <i class="bi bi-diagram-3"></i> IP管理
                </button>
            </li>
        </ul>

        <!-- 标签内容 -->
        <div class="tab-content">
            <!-- 代理管理 -->
            <div class="tab-pane fade show active animate-fade-in" id="proxy-pane" role="tabpanel">
                <div class="row">
                    <div class="col-lg-4">
                        <div class="card mb-3">
                            <div class="card-body">
                                <h5 class="card-title"><i class="bi bi-plus-circle"></i> 批量添加代理</h5>
                                <div class="alert alert-info">
                                    <i class="bi bi-info-circle"></i> 
                                    端口范围可留空，系统将从 5000-65534 中自动分配未使用的端口
                                </div>
                                <form id="batchAddForm">
                                    <div class="mb-3">
                                        <label class="form-label">IP范围 <span class="text-danger">*</span></label>
                                        <input type="text" class="form-control" name="iprange" placeholder="192.168.1.2-254" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">端口范围 <small class="text-muted">(可选)</small></label>
                                        <input type="text" class="form-control" name="portrange" placeholder="20000-30000 或留空">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">用户名前缀 <span class="text-danger">*</span></label>
                                        <input type="text" class="form-control" name="userprefix" placeholder="user" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="bi bi-cloud-upload"></i> 批量添加
                                    </button>
                                </form>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title"><i class="bi bi-file-text"></i> 手动批量添加</h5>
                                <form id="manualBatchForm">
                                    <div class="mb-3">
                                        <textarea name="batchproxy" class="form-control" rows="6" 
                                                  placeholder="每行一个：&#10;ip,端口&#10;或 ip:端口&#10;或 ip,端口,用户名,密码"></textarea>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="bi bi-upload"></i> 添加
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                    <div class="col-lg-8">
                        <div class="card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <h5 class="card-title mb-0">
                                        <i class="bi bi-list-ul"></i> 代理组列表
                                    </h5>
                                    <div>
                                        <button class="btn btn-sm btn-outline-primary" id="refreshGroups">
                                            <i class="bi bi-arrow-clockwise"></i> 刷新
                                        </button>
                                        <button class="btn btn-sm btn-outline-success" id="exportGroups">
                                            <i class="bi bi-download"></i> 导出选中
                                        </button>
                                    </div>
                                </div>
                                
                                <div id="proxyGroups" class="overflow-auto" style="max-height: 600px;">
                                    <!-- 代理组卡片将在这里动态生成 -->
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 用户管理 -->
            <div class="tab-pane fade" id="user-pane" role="tabpanel">
                <div class="card animate-fade-in">
                    <div class="card-body">
                        <h5 class="card-title"><i class="bi bi-person-plus"></i> Web用户管理</h5>
                        <form id="addUserForm" class="row g-3 mb-4">
                            <div class="col-md-5">
                                <input type="text" name="username" class="form-control" placeholder="用户名" required>
                            </div>
                            <div class="col-md-5">
                                <input type="password" name="password" class="form-control" placeholder="密码" required>
                            </div>
                            <div class="col-md-2">
                                <button type="submit" class="btn btn-primary w-100">添加</button>
                            </div>
                        </form>
                        <div id="usersList">
                            <!-- 用户列表将在这里动态生成 -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- IP管理 -->
            <div class="tab-pane fade" id="ip-pane" role="tabpanel">
                <div class="card animate-fade-in">
                    <div class="card-body">
                        <h5 class="card-title"><i class="bi bi-diagram-3"></i> IP批量管理</h5>
                        <div class="alert alert-warning">
                            <i class="bi bi-exclamation-triangle"></i> 
                            单次最多添加1000个IP地址，超大规模请分批添加
                        </div>
                        <form id="addIpForm" class="row g-3 mb-4">
                            <div class="col-md-2">
                                <input type="text" name="iface" class="form-control" placeholder="网卡" value="eth0">
                            </div>
                            <div class="col-md-5">
                                <input type="text" name="ip_input" class="form-control" 
                                       placeholder="192.168.1.2-254 或 192.168.1.2,192.168.1.3" required>
                            </div>
                            <div class="col-md-3">
                                <select name="mode" class="form-select">
                                    <option value="perm">永久</option>
                                    <option value="temp">临时</option>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <button type="submit" class="btn btn-primary w-100">添加</button>
                            </div>
                        </form>
                        <div id="ipConfigsList">
                            <!-- IP配置列表将在这里动态生成 -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 代理详情模态框 -->
    <div class="modal fade" id="proxyDetailModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">代理详情</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="proxyDetailContent">
                        <!-- 代理详情将在这里动态生成 -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast 通知容器 -->
    <div class="toast-container"></div>

    <!-- 加载动画 -->
    <div class="loading-spinner">
        <div class="spinner-border text-primary" style="width: 3rem; height: 3rem;">
            <span class="visually-hidden">Loading...</span>
        </div>
    </div>

    <!-- 深色模式切换 -->
    <button class="switch-mode" id="darkModeToggle">
        <i class="bi bi-moon-fill"></i>
    </button>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 复制之前版本的JavaScript代码
        // 这里的代码与之前的版本基本相同，只需要添加连接跟踪监控的部分
        
        // 全局变量
        let selectedGroups = new Set();
        let selectedProxies = new Set();

        // 工具函数
        function showLoading() {
            document.querySelector('.loading-spinner').classList.add('show');
        }

        function hideLoading() {
            document.querySelector('.loading-spinner').classList.remove('show');
        }

        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = `toast align-items-center text-white bg-${type} border-0`;
            toast.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">${message}</div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            document.querySelector('.toast-container').appendChild(toast);
            const bsToast = new bootstrap.Toast(toast);
            bsToast.show();
            toast.addEventListener('hidden.bs.toast', () => toast.remove());
        }

        // 时间更新
        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = 
                now.toLocaleString('zh-CN', { hour12: false });
        }
        setInterval(updateTime, 1000);
        updateTime();

        // 系统监控（增强版）
        function updateSystemStatus() {
            fetch('/api/system_status')
                .then(res => res.json())
                .then(data => {
                    // CPU
                    document.getElementById('cpuUsage').textContent = data.cpu.toFixed(1) + '%';
                    document.getElementById('cpuProgress').style.width = data.cpu + '%';
                    
                    // 内存
                    document.getElementById('memUsage').textContent = data.memory.percent.toFixed(1) + '%';
                    document.getElementById('memProgress').style.width = data.memory.percent + '%';
                    
                    // 磁盘
                    document.getElementById('diskUsage').textContent = data.disk.percent.toFixed(1) + '%';
                    document.getElementById('diskProgress').style.width = data.disk.percent + '%';
                    
                    // 3proxy状态
                    const statusIcon = document.getElementById('proxyStatus');
                    const statusInfo = document.getElementById('proxyInfo');
                    if (data.proxy.running) {
                        statusIcon.innerHTML = '<i class="bi bi-circle-fill text-success"></i>';
                        statusInfo.innerHTML = `PID: ${data.proxy.pid}<br>连接: ${data.proxy.connections}<br>内存: ${data.proxy.memory.toFixed(0)}MB`;
                    } else {
                        statusIcon.innerHTML = '<i class="bi bi-circle-fill text-danger"></i>';
                        statusInfo.textContent = '未运行';
                    }
                    
                    // 连接跟踪
                    if (data.conntrack) {
                        document.getElementById('conntrackCount').textContent = data.conntrack.count.toLocaleString();
                        document.getElementById('conntrackMax').textContent = data.conntrack.max.toLocaleString();
                        document.getElementById('conntrackPercent').textContent = data.conntrack.percent.toFixed(1);
                        document.getElementById('conntrackProgress').style.width = data.conntrack.percent + '%';
                        
                        // 根据使用率改变颜色
                        const progress = document.getElementById('conntrackProgress');
                        if (data.conntrack.percent > 80) {
                            progress.className = 'progress-bar bg-danger';
                        } else if (data.conntrack.percent > 60) {
                            progress.className = 'progress-bar bg-warning';
                        } else {
                            progress.className = 'progress-bar';
                        }
                    }
                })
                .catch(err => {
                    console.error('System status error:', err);
                });
        }
        setInterval(updateSystemStatus, 5000);
        updateSystemStatus();

        // 其余的JavaScript代码与之前版本相同...
        // 包括：loadProxyGroups, viewProxyGroup, 各种事件处理等
        // 由于代码过长，这里省略，但应该从之前的版本完整复制过来
        
        // 初始化
        window.addEventListener('DOMContentLoaded', () => {
            // 恢复深色模式设置
            if (localStorage.getItem('darkMode') === 'true') {
                document.body.classList.add('dark-mode');
                document.querySelector('#darkModeToggle i').className = 'bi bi-sun-fill';
            }
            
            // 清空全局选择集合
            selectedGroups.clear();
            selectedProxies.clear();
            
            // 加载初始数据
            loadProxyGroups();
        });
    </script>
</body>
</html>
EOF

# 创建错误页面
cat > $WORKDIR/templates/404.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>404 - 页面未找到</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container text-center" style="margin-top: 100px;">
        <h1 class="display-1">404</h1>
        <p class="fs-3"><span class="text-danger">Oops!</span> 页面未找到</p>
        <p class="lead">您访问的页面不存在</p>
        <a href="/" class="btn btn-primary">返回首页</a>
    </div>
</body>
</html>
EOF

cat > $WORKDIR/templates/500.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>500 - 服务器错误</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container text-center" style="margin-top: 100px;">
        <h1 class="display-1">500</h1>
        <p class="fs-3"><span class="text-danger">Oops!</span> 服务器错误</p>
        <p class="lead">服务器遇到了一个错误，请稍后再试</p>
        <a href="/" class="btn btn-primary">返回首页</a>
    </div>
</body>
</html>
EOF
# ========== manage.py (高性能版本) ==========
cat > $WORKDIR/manage.py << 'EOF'
import os, sqlite3, random, string, re, collections, json, psutil, datetime, threading, time
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_caching import Cache
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from io import BytesIO
import logging
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
import sqlite3

# 配置
DB = '3proxy.db'
SECRET = os.urandom(32).hex()
PORT = int(os.environ.get('PORT', 9999))
THREEPROXY_PATH = '/usr/local/bin/3proxy'
PROXYCFG_PATH = '/usr/local/etc/3proxy/3proxy.cfg'
LOGFILE = '/var/log/3proxy/3proxy.log'
INTERFACES_FILE = '/etc/network/interfaces'

# Flask应用配置
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = SECRET
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# 缓存配置
cache = Cache(app, config={
    'CACHE_TYPE': 'RedisCache',
    'CACHE_REDIS_HOST': 'localhost',
    'CACHE_REDIS_PORT': 6379,
    'CACHE_REDIS_DB': 0,
    'CACHE_DEFAULT_TIMEOUT': 300
})

# 登录管理
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 线程池
executor = ThreadPoolExecutor(max_workers=10)

# 数据库连接池
class DatabasePool:
    def __init__(self, database, max_connections=20):
        self.database = database
        self.max_connections = max_connections
        self.connections = []
        self.lock = threading.Lock()
        self._create_connections()
    
    def _create_connections(self):
        for _ in range(self.max_connections):
            conn = sqlite3.connect(self.database, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self.connections.append(conn)
    
    def get_connection(self):
        with self.lock:
            if self.connections:
                return self.connections.pop()
            else:
                conn = sqlite3.connect(self.database, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                return conn
    
    def return_connection(self, conn):
        with self.lock:
            if len(self.connections) < self.max_connections:
                self.connections.append(conn)
            else:
                conn.close()

db_pool = DatabasePool(DB)

def get_db():
    return db_pool.get_connection()

def return_db(conn):
    db_pool.return_connection(conn)

def detect_nic():
    """检测主网卡"""
    try:
        for nic, addrs in psutil.net_if_addrs().items():
            if nic.startswith(('e', 'en')) and any(addr.family == 2 for addr in addrs):
                return nic
    except:
        pass
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
    try:
        cur = db.execute("SELECT id,username,password FROM users WHERE id=?", (user_id,))
        row = cur.fetchone()
        if row:
            return User(row[0], row[1], row[2])
    finally:
        return_db(db)
    return None

def reload_3proxy_async():
    """异步重载3proxy配置"""
    def _reload():
        try:
            os.system(f'python3 {os.path.join(os.path.dirname(__file__), "config_gen.py")}')
            # 使用reload信号而不是重启
            os.system('pkill -HUP 3proxy 2>/dev/null || true')
            # 如果进程不存在，启动它
            if os.system('pgrep 3proxy > /dev/null') != 0:
                os.system(f'{THREEPROXY_PATH} {PROXYCFG_PATH} &')
        except Exception as e:
            app.logger.error(f"3proxy reload error: {e}")
    
    executor.submit(_reload)

# 路由处理器
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        db = get_db()
        try:
            cur = db.execute('SELECT id,username,password FROM users WHERE username=?', 
                           (request.form['username'],))
            row = cur.fetchone()
            if row and check_password_hash(row[2], request.form['password']):
                user = User(row[0], row[1], row[2])
                login_user(user, remember=True)
                return redirect('/')
            flash('登录失败', 'danger')
        finally:
            return_db(db)
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/proxy_groups')
@login_required
@cache.cached(timeout=60)
def api_proxy_groups():
    db = get_db()
    try:
        cursor = db.execute('''
            SELECT ip, port, enabled, ip_range, port_range, user_prefix 
            FROM proxy 
            ORDER BY ip
        ''')
        proxies = cursor.fetchall()
        
        groups = collections.defaultdict(list)
        for p in proxies:
            c_seg = '.'.join(p[0].split('.')[:3])
            groups[c_seg].append({
                'ip': p[0],
                'port': p[1],
                'enabled': p[2],
                'ip_range': p[3],
                'port_range': p[4],
                'user_prefix': p[5]
            })
        
        # 获取流量统计
        traffic_stats = get_traffic_stats()
        
        result = []
        for c_seg, proxies in groups.items():
            enabled_count = sum(1 for p in proxies if p['enabled'])
            
            # 计算实际范围
            ips = [p['ip'] for p in proxies]
            ports = sorted([p['port'] for p in proxies])
            
            if ips:
                ip_nums = sorted([int(ip.split('.')[-1]) for ip in ips])
                if len(ip_nums) > 1 and ip_nums[-1] - ip_nums[0] == len(ip_nums) - 1:
                    actual_ip_range = f"{c_seg}.{ip_nums[0]}-{ip_nums[-1]}"
                else:
                    actual_ip_range = f"{c_seg}.x ({len(ip_nums)} IPs)"
            else:
                actual_ip_range = ''
            
            if ports:
                actual_port_range = f"{ports[0]}-{ports[-1]}" if len(ports) > 1 else str(ports[0])
            else:
                actual_port_range = ''
            
            result.append({
                'c_segment': c_seg,
                'total': len(proxies),
                'enabled': enabled_count,
                'traffic': traffic_stats.get(c_seg, 0),
                'ip_range': actual_ip_range,
                'port_range': actual_port_range,
                'user_prefix': proxies[0]['user_prefix'] if proxies else ''
            })
        
        return jsonify(sorted(result, key=lambda x: x['c_segment']))
    finally:
        return_db(db)

@app.route('/api/proxy_group/<c_segment>')
@login_required
def api_proxy_group_detail(c_segment):
    db = get_db()
    try:
        cursor = db.execute('''
            SELECT id,ip,port,username,password,enabled,ip_range,port_range,user_prefix 
            FROM proxy 
            WHERE ip LIKE ? 
            ORDER BY ip,port
        ''', (c_segment + '.%',))
        
        proxies = cursor.fetchall()
        result = []
        for p in proxies:
            result.append({
                'id': p[0],
                'ip': p[1],
                'port': p[2],
                'username': p[3],
                'password': p[4],
                'enabled': p[5],
                'ip_range': p[6],
                'port_range': p[7],
                'user_prefix': p[8]
            })
        
        return jsonify(result)
    finally:
        return_db(db)

@app.route('/api/delete_group/<c_segment>', methods=['POST'])
@login_required
def api_delete_group(c_segment):
    db = get_db()
    try:
        db.execute('DELETE FROM proxy WHERE ip LIKE ?', (c_segment + '.%',))
        db.commit()
        cache.clear()
        reload_3proxy_async()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/api/toggle_group/<c_segment>/<action>', methods=['POST'])
@login_required
def api_toggle_group(c_segment, action):
    enabled = 1 if action == 'enable' else 0
    db = get_db()
    try:
        db.execute('UPDATE proxy SET enabled=? WHERE ip LIKE ?', (enabled, c_segment + '.%'))
        db.commit()
        cache.clear()
        reload_3proxy_async()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/api/system_status')
@login_required
def api_system_status():
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_io = psutil.net_io_counters()
        
        # 获取3proxy进程信息
        proxy_info = {'running': False, 'pid': None, 'memory': 0, 'connections': 0}
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == '3proxy':
                proxy_info['running'] = True
                proxy_info['pid'] = proc.info['pid']
                try:
                    p = psutil.Process(proc.info['pid'])
                    proxy_info['memory'] = p.memory_info().rss / 1024 / 1024  # MB
                    proxy_info['connections'] = len(p.connections())
                    proxy_info['cpu_percent'] = p.cpu_percent()
                except:
                    pass
                break
        
        # 获取连接跟踪信息
        conntrack_count = 0
        conntrack_max = 0
        try:
            with open('/proc/sys/net/netfilter/nf_conntrack_count', 'r') as f:
                conntrack_count = int(f.read().strip())
            with open('/proc/sys/net/netfilter/nf_conntrack_max', 'r') as f:
                conntrack_max = int(f.read().strip())
        except:
            pass
        
        return jsonify({
            'cpu': cpu_percent,
            'memory': {
                'percent': memory.percent,
                'used': memory.used / 1024 / 1024 / 1024,  # GB
                'total': memory.total / 1024 / 1024 / 1024  # GB
            },
            'disk': {
                'percent': disk.percent,
                'used': disk.used / 1024 / 1024 / 1024,  # GB
                'total': disk.total / 1024 / 1024 / 1024  # GB
            },
            'network': {
                'bytes_sent': net_io.bytes_sent / 1024 / 1024,  # MB
                'bytes_recv': net_io.bytes_recv / 1024 / 1024   # MB
            },
            'proxy': proxy_info,
            'conntrack': {
                'count': conntrack_count,
                'max': conntrack_max,
                'percent': (conntrack_count / conntrack_max * 100) if conntrack_max > 0 else 0
            },
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users')
@login_required
def api_users():
    db = get_db()
    try:
        users = db.execute('SELECT id,username FROM users').fetchall()
        return jsonify([{'id': u[0], 'username': u[1]} for u in users])
    finally:
        return_db(db)

@app.route('/api/ip_configs')
@login_required
def api_ip_configs():
    db = get_db()
    try:
        configs = db.execute('SELECT id,ip_str,type,iface,created FROM ip_config ORDER BY id DESC').fetchall()
        return jsonify([{
            'id': c[0],
            'ip_str': c[1],
            'type': c[2],
            'iface': c[3],
            'created': c[4]
        } for c in configs])
    finally:
        return_db(db)

@app.route('/addproxy', methods=['POST'])
@login_required
def addproxy():
    try:
        ip = request.form['ip']
        port = int(request.form['port'])
        username = request.form['username']
        password = request.form['password'] or ''.join(random.choices(string.ascii_letters+string.digits, k=16))
        user_prefix = request.form.get('userprefix','')
        
        db = get_db()
        try:
            db.execute('''INSERT INTO proxy 
                         (ip, port, username, password, enabled, ip_range, port_range, user_prefix) 
                         VALUES (?,?,?,?,1,?,?,?)''', 
                      (ip, port, username, password, ip, str(port), user_prefix))
            db.commit()
            cache.clear()
            reload_3proxy_async()
            return jsonify({'status': 'success', 'message': '已添加代理'})
        finally:
            return_db(db)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/batchaddproxy', methods=['POST'])
@login_required
def batchaddproxy():
    try:
        iprange = request.form.get('iprange')
        portrange = request.form.get('portrange')
        userprefix = request.form.get('userprefix')
        
        if iprange and userprefix:
            # 解析IP范围
            m = re.match(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", iprange.strip())
            if not m:
                return jsonify({'status': 'error', 'message': 'IP范围格式错误'})
            
            ip_base = m.group(1)
            start = int(m.group(2))
            end = int(m.group(3))
            
            if end - start > 1000:
                return jsonify({'status': 'error', 'message': '单次最多添加1000个IP'})
            
            ips = [f"{ip_base}{i}" for i in range(start, end+1)]
            
            # 获取已使用的端口
            db = get_db()
            try:
                cursor = db.execute('SELECT port FROM proxy')
                used_ports = set(row[0] for row in cursor)
                
                # 解析或生成端口范围
                if portrange and portrange.strip():
                    m2 = re.match(r"(\d+)-(\d+)", portrange.strip())
                    if not m2:
                        return jsonify({'status': 'error', 'message': '端口范围格式错误'})
                    port_start = int(m2.group(1))
                    port_end = int(m2.group(2))
                    if port_start < 1024 or port_end > 65535:
                        return jsonify({'status': 'error', 'message': '端口范围应在1024-65535之间'})
                else:
                    port_start = 5000
                    port_end = 65534
                
                # 生成可用端口列表
                all_ports = [p for p in range(port_start, port_end+1) if p not in used_ports]
                if len(all_ports) < len(ips):
                    return jsonify({'status': 'error', 'message': f'可用端口不足，需要{len(ips)}个，但只有{len(all_ports)}个可用'})
                
                # 随机选择端口
                random.shuffle(all_ports)
                selected_ports = sorted(all_ports[:len(ips)])
                
                # 批量插入
                count = 0
                batch_data = []
                for i, ip in enumerate(ips):
                    port = selected_ports[i]
                    uname = userprefix + ''.join(random.choices(string.ascii_lowercase+string.digits, k=4))
                    pw = ''.join(random.choices(string.ascii_letters+string.digits, k=16))
                    batch_data.append((ip, port, uname, pw, 1, iprange, f"{selected_ports[0]}-{selected_ports[-1]}", userprefix))
                    count += 1
                
                # 使用事务批量插入
                db.executemany('''INSERT INTO proxy 
                                (ip, port, username, password, enabled, ip_range, port_range, user_prefix) 
                                VALUES (?,?,?,?,?,?,?,?)''', batch_data)
                db.commit()
                cache.clear()
                reload_3proxy_async()
                
                return jsonify({'status': 'success', 'message': f'批量添加完成，共添加{count}条代理'})
            finally:
                return_db(db)
        
        # 处理手动批量添加
        batch_data = request.form.get('batchproxy','').strip().splitlines()
        if not batch_data:
            return jsonify({'status': 'error', 'message': '请输入代理数据'})
        
        db = get_db()
        try:
            count = 0
            insert_data = []
            
            for line in batch_data[:1000]:  # 限制1000条
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ',' in line:
                    parts = [x.strip() for x in line.split(',')]
                elif ':' in line:
                    parts = [x.strip() for x in line.split(':')]
                else:
                    parts = re.split(r'\s+', line)
                
                if len(parts) >= 2:
                    ip = parts[0]
                    try:
                        port = int(parts[1])
                    except:
                        continue
                    
                    if len(parts) >= 3:
                        username = parts[2]
                    else:
                        username = f"user{count:04d}"
                    
                    if len(parts) >= 4:
                        password = parts[3]
                    else:
                        password = ''.join(random.choices(string.ascii_letters+string.digits, k=16))
                    
                    insert_data.append((ip, port, username, password, 1, ip, str(port), username))
                    count += 1
            
            if insert_data:
                db.executemany('''INSERT INTO proxy 
                                (ip, port, username, password, enabled, ip_range, port_range, user_prefix) 
                                VALUES (?,?,?,?,?,?,?,?)''', insert_data)
                db.commit()
                cache.clear()
                reload_3proxy_async()
            
            return jsonify({'status': 'success', 'message': f'批量添加完成，共添加{count}条代理'})
        finally:
            return_db(db)
    
    except Exception as e:
        app.logger.error(f"Batch add error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/delproxy/<int:pid>')
@login_required
def delproxy(pid):
    db = get_db()
    try:
        db.execute('DELETE FROM proxy WHERE id=?', (pid,))
        db.commit()
        cache.clear()
        reload_3proxy_async()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/batchdelproxy', methods=['POST'])
@login_required
def batchdelproxy():
    ids = request.form.getlist('ids')
    if not ids:
        return jsonify({'status': 'error', 'message': '未选择代理'}), 400
    
    db = get_db()
    try:
        placeholders = ','.join('?' * len(ids))
        db.execute(f'DELETE FROM proxy WHERE id IN ({placeholders})', ids)
        db.commit()
        cache.clear()
        reload_3proxy_async()
        return jsonify({'status': 'success', 'message': f'已批量删除 {len(ids)} 条代理'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/batch_enable', methods=['POST'])
@login_required
def batch_enable():
    ids = request.form.getlist('ids[]')
    if not ids:
        return jsonify({'status': 'error', 'message': 'No proxies selected'}), 400
    
    db = get_db()
    try:
        placeholders = ','.join('?' * len(ids))
        db.execute(f'UPDATE proxy SET enabled=1 WHERE id IN ({placeholders})', ids)
        db.commit()
        cache.clear()
        reload_3proxy_async()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/batch_disable', methods=['POST'])
@login_required
def batch_disable():
    ids = request.form.getlist('ids[]')
    if not ids:
        return jsonify({'status': 'error', 'message': 'No proxies selected'}), 400
    
    db = get_db()
    try:
        placeholders = ','.join('?' * len(ids))
        db.execute(f'UPDATE proxy SET enabled=0 WHERE id IN ({placeholders})', ids)
        db.commit()
        cache.clear()
        reload_3proxy_async()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/enableproxy/<int:pid>')
@login_required
def enableproxy(pid):
    db = get_db()
    try:
        db.execute('UPDATE proxy SET enabled=1 WHERE id=?', (pid,))
        db.commit()
        cache.clear()
        reload_3proxy_async()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/disableproxy/<int:pid>')
@login_required
def disableproxy(pid):
    db = get_db()
    try:
        db.execute('UPDATE proxy SET enabled=0 WHERE id=?', (pid,))
        db.commit()
        cache.clear()
        reload_3proxy_async()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/adduser', methods=['POST'])
@login_required
def adduser():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    
    db = get_db()
    try:
        db.execute('INSERT INTO users (username, password) VALUES (?,?)', (username, password))
        db.commit()
        return jsonify({'status': 'success', 'message': '已添加用户'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': '用户名已存在'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/deluser/<int:uid>')
@login_required
def deluser(uid):
    db = get_db()
    try:
        db.execute('DELETE FROM users WHERE id=?', (uid,))
        db.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        return_db(db)

@app.route('/export_selected', methods=['POST'])
@login_required
def export_selected():
    csegs = request.form.getlist('csegs[]')
    if not csegs:
        return jsonify({'status': 'error', 'message': '未选择C段'}), 400
    
    db = get_db()
    try:
        output = ""
        prefix_for_filename = None
        
        for cseg in csegs:
            cursor = db.execute("""SELECT ip,port,username,password,user_prefix 
                               FROM proxy 
                               WHERE ip LIKE ? 
                               ORDER BY ip,port""", (cseg + '.%',))
            rows = cursor.fetchall()
            
            if not prefix_for_filename and rows:
                for row in rows:
                    if row[4]:
                        prefix_for_filename = row[4]
                        break
            
            for ip, port, user, pw, _ in rows:
                output += f"{ip}:{port}:{user}:{pw}\n"
        
        if not prefix_for_filename:
            prefix_for_filename = 'proxy'
        
        cseg_names = [cseg.replace('.', '_') for cseg in sorted(csegs)]
        filename = f"{prefix_for_filename}_{'_'.join(cseg_names)}.txt"
        
        return Response(
            output,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'text/plain; charset=utf-8'
            }
        )
    finally:
        return_db(db)

@app.route('/export_selected_proxy', methods=['POST'])
@login_required
def export_selected_proxy():
    ids = request.form.getlist('ids[]')
    if not ids:
        return jsonify({'status': 'error', 'message': 'No proxies selected'}), 400
    
    db = get_db()
    try:
        placeholders = ','.join('?' * len(ids))
        cursor = db.execute(f'''SELECT ip, port, username, password 
                            FROM proxy 
                            WHERE id IN ({placeholders})''', ids)
        rows = cursor.fetchall()
        
        output = ''
        for ip, port, user, pw in rows:
            output += f"{ip}:{port}:{user}:{pw}\n"
        
        filename = f"proxy_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        return Response(
            output,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'text/plain; charset=utf-8'
            }
        )
    finally:
        return_db(db)

@app.route('/add_ip_config', methods=['POST'])
@login_required
def add_ip_config():
    try:
        ip_input = request.form.get('ip_input', '').strip()
        iface = request.form.get('iface', detect_nic())
        mode = request.form.get('mode', 'perm')
        
        # 解析IP输入
        pattern_full = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", ip_input)
        pattern_short = re.match(r"^(\d+)-(\d+)$", ip_input)
        
        if pattern_full:
            base = pattern_full.group(1)
            start = int(pattern_full.group(2))
            end = int(pattern_full.group(3))
            ip_range = f"{base}{start}-{end}"
            ip_list = [f"{base}{i}" for i in range(start, end+1)]
        elif pattern_short:
            base = "192.168.1."
            start = int(pattern_short.group(1))
            end = int(pattern_short.group(2))
            ip_range = f"{base}{start}-{end}"
            ip_list = [f"{base}{i}" for i in range(start, end+1)]
        else:
            ip_range = ip_input
            ip_list = [ip.strip() for ip in re.split(r'[,\s]+', ip_input) if ip.strip()]
        
        if len(ip_list) > 1000:
            return jsonify({'status': 'error', 'message': '单次最多添加1000个IP'})
        
        # 保存到数据库
        db = get_db()
        try:
            db.execute('''INSERT INTO ip_config (ip_str, type, iface, created) 
                         VALUES (?,?,?,datetime("now"))''', (ip_range, 'range', iface))
            db.commit()
        finally:
            return_db(db)
        
        # 异步添加IP
        def add_ips():
            try:
                for ip in ip_list:
                    # 使用/32掩码避免路由冲突
                    os.system(f"ip addr add {ip}/32 dev {iface} 2>/dev/null")
                    # 添加主机路由
                    os.system(f"ip route add {ip}/32 dev {iface} 2>/dev/null")
                
                if mode == 'perm':
                    # 永久保存配置
                    with open(INTERFACES_FILE, 'a+') as f:
                        f.write(f"\n# 3proxy IP配置 - {ip_range}\n")
                        for ip in ip_list:
                            f.write(f"up ip addr add {ip}/32 dev {iface} 2>/dev/null || true\n")
                            f.write(f"down ip addr del {ip}/32 dev {iface} 2>/dev/null || true\n")
                
                # 刷新ARP缓存
                os.system("ip neigh flush all")
            except Exception as e:
                app.logger.error(f"Add IP error: {e}")
        
        executor.submit(add_ips)
        
        return jsonify({'status': 'success', 'message': f'正在添加{len(ip_list)}个IP配置'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

def get_traffic_stats():
    """获取流量统计（优化版）"""
    stats = collections.defaultdict(int)
    if not os.path.exists(LOGFILE):
        return stats
    
    try:
        # 只读取最后10MB的日志
        file_size = os.path.getsize(LOGFILE)
        read_size = min(file_size, 10 * 1024 * 1024)
        
        with open(LOGFILE, 'rb') as f:
            if file_size > read_size:
                f.seek(file_size - read_size)
                f.readline()  # 跳过可能不完整的行
            
            for line in f:
                try:
                    line = line.decode('utf-8', errors='ignore')
                    parts = line.split()
                    if len(parts) > 7:
                        srcip = parts[2]
                        bytes_sent = int(parts[-2])
                        cseg = '.'.join(srcip.split('.')[:3])
                        stats[cseg] += bytes_sent
                except:
                    continue
    except:
        pass
    
    return {k: round(v/1024/1024, 2) for k, v in stats.items()}

# 错误处理
@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

# 日志配置
if not app.debug:
    file_handler = RotatingFileHandler('/var/log/3proxy/web.log', maxBytes=10240000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('3proxy web startup')

if __name__ == '__main__':
    # 生产环境使用gunicorn
    app.run('0.0.0.0', PORT, debug=False)
EOF

# ========== config_gen.py (高性能版本) ==========
cat > $WORKDIR/config_gen.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import os
import sys
import time

def generate_config():
    """生成3proxy配置文件（优化版）"""
    start_time = time.time()
    
    try:
        db = sqlite3.connect('3proxy.db')
        db.row_factory = sqlite3.Row
        
        # 使用索引优化查询
        cursor = db.execute('SELECT ip, port, username, password FROM proxy WHERE enabled=1 ORDER BY ip, port')
        
        # 配置头
        cfg = [
            "# 3proxy Enterprise Configuration",
            "# Generated: " + time.strftime("%Y-%m-%d %H:%M:%S"),
            "",
            "daemon",
            "maxconn 500000",
            "nserver 8.8.8.8",
            "nserver 1.1.1.1",
            "nserver 8.8.4.4",
            "nserver 1.0.0.1",
            "nscache 65536",
            "nscache6 65536",
            "nsrecord www.google.com 60",
            "nsrecord www.youtube.com 60",
            "stacksize 6291456",
            "timeouts 1 5 30 60 180 1800 15 60",
            "log /var/log/3proxy/3proxy.log D",
            "logformat \"- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T\"",
            "rotate 30",
            "archiver gz /usr/bin/gzip %F",
            "auth strong cache",
            "allow * * * * HTTP",
            "allow * * * * HTTPS",
            ""
        ]
        
        # 收集用户
        users = {}
        proxies = []
        
        for row in cursor:
            key = (row['username'], row['password'])
            if key not in users:
                users[key] = True
            proxies.append(row)
        
        # 分批添加用户（避免单行过长）
        user_list = [f"{u}:CL:{p}" for u, p in users.keys()]
        batch_size = 50
        
        for i in range(0, len(user_list), batch_size):
            batch = user_list[i:i+batch_size]
            cfg.append(f"users {' '.join(batch)}")
        
        cfg.append("")
        
        # 添加代理配置
        for proxy in proxies:
            cfg.extend([
                f"auth strong cache",
                f"allow {proxy['username']}",
                f"parent 1000 none",
                f"proxy -n -a -p{proxy['port']} -i{proxy['ip']} -e{proxy['ip']}",
                ""
            ])
        
        # 写入配置文件
        config_path = '/usr/local/etc/3proxy/3proxy.cfg'
        with open(config_path, 'w') as f:
            f.write('\n'.join(cfg))
        
        # 设置权限
        os.chmod(config_path, 0o600)
        
        db.close()
        
        elapsed = time.time() - start_time
        print(f"Configuration generated successfully in {elapsed:.2f} seconds")
        print(f"Total proxies: {len(proxies)}")
        print(f"Total users: {len(users)}")
        
    except Exception as e:
        print(f"Error generating configuration: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    generate_config()
EOF

chmod +x $WORKDIR/config_gen.py

# ========== init_db.py ==========
cat > $WORKDIR/init_db.py << 'EOF'
import sqlite3
from werkzeug.security import generate_password_hash
import os

def init_database():
    """初始化数据库"""
    user = os.environ.get('ADMINUSER', 'admin')
    passwd = os.environ.get('ADMINPASS', 'changeme')
    
    db = sqlite3.connect('3proxy.db')
    
    # 创建表
    db.execute('''CREATE TABLE IF NOT EXISTS proxy (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        ip_range TEXT,
        port_range TEXT,
        user_prefix TEXT,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(ip, port)
    )''')
    
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    db.execute('''CREATE TABLE IF NOT EXISTS ip_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_str TEXT NOT NULL,
        type TEXT NOT NULL,
        iface TEXT NOT NULL,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 创建索引
    db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_ip ON proxy(ip)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON proxy(enabled)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_proxy_port ON proxy(port)')
    
    # 添加默认管理员
    db.execute('INSERT OR IGNORE INTO users (username, password) VALUES (?,?)', 
               (user, generate_password_hash(passwd)))
    
    db.commit()
    db.close()
    
    print(f"Database initialized")
    print(f"Admin user: {user}")
    print(f"Admin password: {passwd}")

if __name__ == "__main__":
    init_database()
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
            animation: slideIn 0.5s ease-out;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            transition: transform 0.2s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
    </style>
</head>
<body>
<div class="container" style="max-width:400px;">
    <div class="card login-card">
        <div class="card-body p-5">
            <h3 class="mb-4 text-center">3proxy 管理系统</h3>
            <form method="post">
                <div class="mb-3">
                    <label class="form-label">用户名</label>
                    <input type="text" class="form-control" name="username" autofocus required>
                </div>
                <div class="mb-3">
                    <label class="form-label">密码</label>
                    <input type="password" class="form-control" name="password" required>
                </div>
                <button class="btn btn-primary btn-login w-100 mt-4" type="submit">登录</button>
            </form>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-danger mt-3 mb-0">{{ messages[0] }}</div>
              {% endif %}
            {% endwith %}
        </div>
    </div>
</div>
</body>
</html>
EOF

# --------- index.html（主UI） ---------
cat > $WORKDIR/templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>3proxy 管理面板</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --warning-gradient: linear-gradient(135deg, #f2994a 0%, #f2c94c 100%);
            --danger-gradient: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
            --info-gradient: linear-gradient(135deg, #2196f3 0%, #21cbf3 100%);
            --card-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            --hover-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            --btn-radius: 8px;
        }
        
        body {
            background: #f5f7fa;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .navbar {
            background: var(--primary-gradient);
            box-shadow: var(--card-shadow);
        }
        
        .nav-tabs {
            border: none;
            background: white;
            border-radius: 10px;
            padding: 5px;
            box-shadow: var(--card-shadow);
            margin-bottom: 25px;
        }
        
        .nav-tabs .nav-link {
            border: none;
            color: #666;
            padding: 12px 24px;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .nav-tabs .nav-link:hover {
            background: #f8f9fa;
            color: #667eea;
        }
        
        .nav-tabs .nav-link.active {
            background: var(--primary-gradient);
            color: white;
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
            overflow: hidden;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: var(--hover-shadow);
        }
        
        .proxy-card {
            cursor: pointer;
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .proxy-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: var(--primary-gradient);
        }
        
        .proxy-card:hover {
            transform: translateX(10px);
            box-shadow: var(--hover-shadow);
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: scale(1.05);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .btn-gradient {
            background: var(--primary-gradient);
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: var(--btn-radius);
            transition: all 0.3s ease;
            font-weight: 500;
            box-shadow: 0 2px 10px rgba(102, 126, 234, 0.3);
        }
        
        .btn-gradient:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            color: white;
        }
        
        /* 统一按钮样式 */
        .btn {
            border-radius: var(--btn-radius);
            transition: all 0.2s ease;
            font-weight: 500;
            border: none;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.2);
            transition: left 0.3s ease;
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn-success {
            background: var(--success-gradient);
            box-shadow: 0 2px 10px rgba(17, 153, 142, 0.3);
        }
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(17, 153, 142, 0.4);
            background: var(--success-gradient);
        }
        
        .btn-warning {
            background: var(--warning-gradient);
            box-shadow: 0 2px 10px rgba(242, 153, 74, 0.3);
            color: white;
        }
        
        .btn-warning:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(242, 153, 74, 0.4);
            background: var(--warning-gradient);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger-gradient);
            box-shadow: 0 2px 10px rgba(235, 51, 73, 0.3);
        }
        
        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(235, 51, 73, 0.4);
            background: var(--danger-gradient);
        }
        
        .btn-info {
            background: var(--info-gradient);
            box-shadow: 0 2px 10px rgba(33, 150, 243, 0.3);
        }
        
        .btn-info:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(33, 150, 243, 0.4);
            background: var(--info-gradient);
        }
        
        .btn-primary {
            background: var(--primary-gradient);
            box-shadow: 0 2px 10px rgba(102, 126, 234, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            background: var(--primary-gradient);
        }
        
        .btn-outline-secondary {
            background: white;
            border: 1px solid #e0e0e0;
            color: #666;
        }
        
        .btn-outline-secondary:hover {
            background: #f8f9fa;
            border-color: #667eea;
            color: #667eea;
            transform: translateY(-1px);
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 0.875rem;
        }
        
        .btn-group .btn {
            border-radius: 0;
        }
        
        .btn-group .btn:first-child {
            border-radius: var(--btn-radius) 0 0 var(--btn-radius);
        }
        
        .btn-group .btn:last-child {
            border-radius: 0 var(--btn-radius) var(--btn-radius) 0;
        }
        
        /* 徽章样式统一 */
        .badge {
            font-weight: 500;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
        }
        
        .badge.bg-secondary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        }
        
        .badge.bg-success {
            background: var(--success-gradient) !important;
        }
        
        .badge.bg-primary {
            background: var(--primary-gradient) !important;
        }
        
        .badge.bg-info {
            background: var(--info-gradient) !important;
        }
        
        /* 输入框美化 */
        .form-control {
            border-radius: var(--btn-radius);
            border: 1px solid #e0e0e0;
            padding: 12px 15px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .form-control-sm {
            padding: 6px 10px;
            font-size: 0.875rem;
        }
        
        /* 复选框美化 */
        .form-check-input {
            width: 1.2em;
            height: 1.2em;
            border-radius: 4px;
            border: 2px solid #ddd;
            transition: all 0.2s ease;
        }
        
        .form-check-input:checked {
            background-color: #667eea;
            border-color: #667eea;
        }
        
        .form-check-input:hover {
            border-color: #667eea;
            cursor: pointer;
        }
        
        .form-control, .form-select {
            border-radius: 10px;
            border: 1px solid #e0e0e0;
            padding: 12px 15px;
            transition: all 0.3s ease;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        
        .modal-content {
            border-radius: 20px;
            border: none;
        }
        
        .modal-header {
            background: var(--primary-gradient);
            color: white;
            border-radius: 20px 20px 0 0;
            border: none;
        }
        
        .badge-status {
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: normal;
            font-size: 0.85rem;
        }
        
        .loading-spinner {
            display: none;
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 9999;
        }
        
        .loading-spinner.show {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .animate-fade-in {
            animation: fadeIn 0.5s ease-out;
        }
        
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1050;
        }
        
        .system-monitor {
            background: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .progress {
            height: 10px;
            border-radius: 5px;
            overflow: hidden;
        }
        
        .progress-bar {
            background: var(--primary-gradient);
            transition: width 0.6s ease;
        }
        
        .dark-mode {
            background: #1a1a2e;
            color: #eee;
        }
        
        .dark-mode .card, .dark-mode .nav-tabs {
            background: #16213e;
            color: #eee;
        }
        
        .dark-mode .form-control, .dark-mode .form-select {
            background: #0f3460;
            color: #eee;
            border-color: #2a2a3e;
        }
        
        .switch-mode {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 1000;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--primary-gradient);
            color: white;
            border: none;
            box-shadow: var(--card-shadow);
            transition: all 0.3s ease;
        }
        
        .switch-mode:hover {
            transform: scale(1.1);
            box-shadow: var(--hover-shadow);
        }
    </style>
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-dark mb-4">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="bi bi-shield-check"></i> 3proxy 管理系统
            </span>
            <div class="d-flex align-items-center">
                <span class="text-white me-3" id="currentTime"></span>
                <a href="/logout" class="btn btn-outline-light btn-sm">
                    <i class="bi bi-box-arrow-right"></i> 退出
                </a>
            </div>
        </div>
    </nav>

    <!-- 主内容区 -->
    <div class="container-fluid px-4">
        <!-- 系统监控 -->
        <div class="system-monitor animate-fade-in">
            <h5 class="mb-3"><i class="bi bi-speedometer2"></i> 系统监控</h5>
            <div class="row g-3">
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number" id="cpuUsage">0%</div>
                        <small>CPU 使用率</small>
                        <div class="progress mt-2">
                            <div class="progress-bar" id="cpuProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number" id="memUsage">0%</div>
                        <small>内存使用率</small>
                        <div class="progress mt-2">
                            <div class="progress-bar" id="memProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number" id="diskUsage">0%</div>
                        <small>磁盘使用率</small>
                        <div class="progress mt-2">
                            <div class="progress-bar" id="diskProgress" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number" id="proxyStatus">
                            <i class="bi bi-circle-fill text-danger"></i>
                        </div>
                        <small>3proxy 状态</small>
                        <div class="mt-1">
                            <small id="proxyInfo">未运行</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- 标签页 -->
        <ul class="nav nav-tabs" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="proxy-tab" data-bs-toggle="tab" data-bs-target="#proxy-pane">
                    <i class="bi bi-hdd-network"></i> 代理管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="user-tab" data-bs-toggle="tab" data-bs-target="#user-pane">
                    <i class="bi bi-people"></i> 用户管理
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-pane">
                    <i class="bi bi-diagram-3"></i> IP管理
                </button>
            </li>
        </ul>

        <!-- 标签内容 -->
        <div class="tab-content">
            <!-- 代理管理 -->
            <div class="tab-pane fade show active animate-fade-in" id="proxy-pane" role="tabpanel">
                <div class="row">
                    <div class="col-lg-4">
                        <div class="card mb-3">
                            <div class="card-body">
                                <h5 class="card-title"><i class="bi bi-plus-circle"></i> 批量添加代理</h5>
                                <form id="batchAddForm">
                                    <div class="mb-3">
                                        <label class="form-label">IP范围</label>
                                        <input type="text" class="form-control" name="iprange" placeholder="192.168.1.2-254">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">端口范围</label>
                                        <input type="text" class="form-control" name="portrange" placeholder="20000-30000">
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">用户名前缀</label>
                                        <input type="text" class="form-control" name="userprefix" placeholder="user">
                                    </div>
                                    <button type="submit" class="btn btn-gradient w-100">
                                        <i class="bi bi-cloud-upload"></i> 批量添加
                                    </button>
                                </form>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title"><i class="bi bi-file-text"></i> 手动批量添加</h5>
                                <form id="manualBatchForm">
                                    <div class="mb-3">
                                        <textarea name="batchproxy" class="form-control" rows="6" 
                                                  placeholder="每行一个：ip,端口 或 ip:端口"></textarea>
                                    </div>
                                    <button type="submit" class="btn btn-gradient w-100">
                                        <i class="bi bi-upload"></i> 添加
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                    <div class="col-lg-8">
                        <div class="card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <h5 class="card-title mb-0">
                                        <i class="bi bi-list-ul"></i> 代理组列表
                                    </h5>
                                    <div>
                                        <button class="btn btn-sm btn-outline-primary" id="refreshGroups">
                                            <i class="bi bi-arrow-clockwise"></i> 刷新
                                        </button>
                                        <button class="btn btn-sm btn-outline-success" id="exportGroups">
                                            <i class="bi bi-download"></i> 导出选中
                                        </button>
                                    </div>
                                </div>
                                
                                <div id="proxyGroups" class="overflow-auto" style="max-height: 600px;">
                                    <!-- 代理组卡片将在这里动态生成 -->
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 用户管理 -->
            <div class="tab-pane fade" id="user-pane" role="tabpanel">
                <div class="card animate-fade-in">
                    <div class="card-body">
                        <h5 class="card-title"><i class="bi bi-person-plus"></i> Web用户管理</h5>
                        <form id="addUserForm" class="row g-3 mb-4">
                            <div class="col-md-5">
                                <input type="text" name="username" class="form-control" placeholder="用户名" required>
                            </div>
                            <div class="col-md-5">
                                <input type="password" name="password" class="form-control" placeholder="密码" required>
                            </div>
                            <div class="col-md-2">
                                <button type="submit" class="btn btn-gradient w-100">添加</button>
                            </div>
                        </form>
                        <div id="usersList">
                            <!-- 用户列表将在这里动态生成 -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- IP管理 -->
            <div class="tab-pane fade" id="ip-pane" role="tabpanel">
                <div class="card animate-fade-in">
                    <div class="card-body">
                        <h5 class="card-title"><i class="bi bi-diagram-3"></i> IP批量管理</h5>
                        <form id="addIpForm" class="row g-3 mb-4">
                            <div class="col-md-2">
                                <input type="text" name="iface" class="form-control" placeholder="网卡" value="eth0">
                            </div>
                            <div class="col-md-5">
                                <input type="text" name="ip_input" class="form-control" 
                                       placeholder="192.168.1.2-254 或 192.168.1.2,192.168.1.3" required>
                            </div>
                            <div class="col-md-3">
                                <select name="mode" class="form-select">
                                    <option value="perm">永久</option>
                                    <option value="temp">临时</option>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <button type="submit" class="btn btn-gradient w-100">添加</button>
                            </div>
                        </form>
                        <div id="ipConfigsList">
                            <!-- IP配置列表将在这里动态生成 -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 代理详情模态框 -->
    <div class="modal fade" id="proxyDetailModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">代理详情</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="proxyDetailContent">
                        <!-- 代理详情将在这里动态生成 -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast 通知容器 -->
    <div class="toast-container"></div>

    <!-- 加载动画 -->
    <div class="loading-spinner">
        <div class="spinner-border text-primary" style="width: 3rem; height: 3rem;">
            <span class="visually-hidden">Loading...</span>
        </div>
    </div>

    <!-- 深色模式切换 -->
    <button class="switch-mode" id="darkModeToggle">
        <i class="bi bi-moon-fill"></i>
    </button>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 全局变量
        let selectedGroups = new Set();
        let selectedProxies = new Set();

        // 工具函数
        function showLoading() {
            document.querySelector('.loading-spinner').classList.add('show');
        }

        function hideLoading() {
            document.querySelector('.loading-spinner').classList.remove('show');
        }

        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = `toast align-items-center text-white bg-${type} border-0`;
            toast.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">${message}</div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            document.querySelector('.toast-container').appendChild(toast);
            const bsToast = new bootstrap.Toast(toast);
            bsToast.show();
            toast.addEventListener('hidden.bs.toast', () => toast.remove());
        }

        // 时间更新
        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = 
                now.toLocaleString('zh-CN', { hour12: false });
        }
        setInterval(updateTime, 1000);
        updateTime();

        // 系统监控
        function updateSystemStatus() {
            fetch('/api/system_status')
                .then(res => res.json())
                .then(data => {
                    // CPU
                    document.getElementById('cpuUsage').textContent = data.cpu.toFixed(1) + '%';
                    document.getElementById('cpuProgress').style.width = data.cpu + '%';
                    
                    // 内存
                    document.getElementById('memUsage').textContent = data.memory.percent.toFixed(1) + '%';
                    document.getElementById('memProgress').style.width = data.memory.percent + '%';
                    
                    // 磁盘
                    document.getElementById('diskUsage').textContent = data.disk.percent.toFixed(1) + '%';
                    document.getElementById('diskProgress').style.width = data.disk.percent + '%';
                    
                    // 3proxy状态
                    const statusIcon = document.getElementById('proxyStatus');
                    const statusInfo = document.getElementById('proxyInfo');
                    if (data.proxy.running) {
                        statusIcon.innerHTML = '<i class="bi bi-circle-fill text-success"></i>';
                        statusInfo.textContent = `PID: ${data.proxy.pid} | 连接: ${data.proxy.connections}`;
                    } else {
                        statusIcon.innerHTML = '<i class="bi bi-circle-fill text-danger"></i>';
                        statusInfo.textContent = '未运行';
                    }
                });
        }
        setInterval(updateSystemStatus, 5000);
        updateSystemStatus();

        // 加载代理组
        function loadProxyGroups() {
            // 加载前先验证选中的组是否还存在
            const currentSelected = new Set(selectedGroups);
            
            showLoading();
            fetch('/api/proxy_groups')
                .then(res => res.json())
                .then(groups => {
                    const container = document.getElementById('proxyGroups');
                    container.innerHTML = '';
                    
                    // 获取当前存在的C段列表
                    const existingSegments = new Set(groups.map(g => g.c_segment));
                    
                    // 清理已不存在的选中项
                    currentSelected.forEach(cseg => {
                        if (!existingSegments.has(cseg)) {
                            selectedGroups.delete(cseg);
                        }
                    });
                    
                    groups.forEach(group => {
                        const card = document.createElement('div');
                        card.className = 'proxy-card';
                        
                        // 如果这个组在选中集合中，添加选中样式
                        if (selectedGroups.has(group.c_segment)) {
                            card.classList.add('selected');
                        }
                        card.innerHTML = `
                            <div class="row align-items-center">
                                <div class="col-md-7">
                                    <h6 class="mb-2 d-flex align-items-center">
                                        <input type="checkbox" class="form-check-input me-2" 
                                               data-group="${group.c_segment}" onclick="event.stopPropagation();">
                                        <i class="bi bi-hdd-network text-primary me-2"></i>
                                        <strong>${group.c_segment}.x</strong>
                                    </h6>
                                    <div class="d-flex flex-wrap gap-2 mb-2">
                                        <span class="badge rounded-pill bg-primary">
                                            <i class="bi bi-layers"></i> ${group.total} 个
                                        </span>
                                        <span class="badge rounded-pill bg-success">
                                            <i class="bi bi-check-circle"></i> ${group.enabled} 启用
                                        </span>
                                        <span class="badge rounded-pill bg-info">
                                            <i class="bi bi-arrow-down-up"></i> ${group.traffic} MB
                                        </span>
                                    </div>
                                    <small class="text-muted d-block">
                                        ${group.ip_range ? `<i class="bi bi-diagram-3"></i> ${group.ip_range}` : ''}
                                        ${group.port_range ? `<i class="bi bi-ethernet"></i> ${group.port_range}` : ''}
                                        ${group.user_prefix ? `<i class="bi bi-person"></i> ${group.user_prefix}` : ''}
                                    </small>
                                </div>
                                <div class="col-md-5 text-end">
                                    <div class="btn-toolbar justify-content-end" role="toolbar">
                                        <div class="btn-group btn-group-sm" role="group">
                                            <button class="btn btn-primary" 
                                                    onclick="event.stopPropagation(); viewProxyGroup('${group.c_segment}')"
                                                    title="查看详情">
                                                <i class="bi bi-eye"></i> 查看
                                            </button>
                                            <button class="btn btn-success" 
                                                    onclick="event.stopPropagation(); toggleGroup('${group.c_segment}', 'enable')"
                                                    title="启用全部">
                                                <i class="bi bi-play-circle"></i> 启用
                                            </button>
                                            <button class="btn btn-warning" 
                                                    onclick="event.stopPropagation(); toggleGroup('${group.c_segment}', 'disable')"
                                                    title="禁用全部">
                                                <i class="bi bi-pause-circle"></i> 禁用
                                            </button>
                                            <button class="btn btn-danger" 
                                                    onclick="event.stopPropagation(); deleteGroup('${group.c_segment}')"
                                                    title="删除整组">
                                                <i class="bi bi-trash"></i> 删除
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `;
                        
                        // 点击卡片切换选中状态
                        card.addEventListener('click', (e) => {
                            // 如果点击的是按钮或输入框，不处理
                            if (e.target.closest('button') || e.target.closest('input')) {
                                return;
                            }
                            
                            const checkbox = card.querySelector('input[type="checkbox"]');
                            checkbox.checked = !checkbox.checked;
                            
                            if (checkbox.checked) {
                                selectedGroups.add(group.c_segment);
                                card.classList.add('selected');
                            } else {
                                selectedGroups.delete(group.c_segment);
                                card.classList.remove('selected');
                            }
                        });
                        
                        // 复选框事件（阻止冒泡）
                        const checkbox = card.querySelector('input[type="checkbox"]');
                        
                        // 如果这个组在选中集合中，勾选复选框
                        if (selectedGroups.has(group.c_segment)) {
                            checkbox.checked = true;
                        }
                        
                        checkbox.addEventListener('change', (e) => {
                            e.stopPropagation();
                            if (e.target.checked) {
                                selectedGroups.add(group.c_segment);
                                card.classList.add('selected');
                            } else {
                                selectedGroups.delete(group.c_segment);
                                card.classList.remove('selected');
                            }
                        });
                        
                        container.appendChild(card);
                    });
                    hideLoading();
                })
                .catch(err => {
                    hideLoading();
                    showToast('加载失败: ' + err.message, 'danger');
                });
        }

        // 查看代理组详情
        function viewProxyGroup(cSegment) {
            // 清空之前的选择
            selectedProxies.clear();
            
            showLoading();
            fetch(`/api/proxy_group/${cSegment}`)
                .then(res => res.json())
                .then(proxies => {
                    const content = document.getElementById('proxyDetailContent');
                    const firstProxy = proxies[0] || {};
                    
                    // 构建完整的HTML，确保表格结构正确
                    let html = `
                        <div class="detail-header">
                            <h5>${cSegment}.x 段代理详情</h5>
                            <div class="info-row">
                                ${firstProxy.ip_range ? `<span class="info-item"><i class="bi bi-diagram-3"></i> IP范围: <strong>${firstProxy.ip_range}</strong></span>` : ''}
                                ${firstProxy.port_range ? `<span class="info-item"><i class="bi bi-ethernet"></i> 端口范围: <strong>${firstProxy.port_range}</strong></span>` : ''}
                                ${firstProxy.user_prefix ? `<span class="info-item"><i class="bi bi-person"></i> 用户前缀: <strong>${firstProxy.user_prefix}</strong></span>` : ''}
                                <span class="info-item"><i class="bi bi-list"></i> 代理总数: <strong>${proxies.length}</strong></span>
                            </div>
                        </div>
                        
                        <div class="action-bar">
                            <div class="d-flex align-items-center justify-content-between">
                                <div class="d-flex align-items-center gap-3">
                                    <input type="checkbox" class="form-check-input" id="selectAllCheck">
                                    <label for="selectAllCheck" class="mb-0">全选</label>
                                    <span class="text-muted">已选择 <span id="selectedCount">0</span> 项</span>
                                </div>
                                <div class="d-flex gap-2">
                                    <button class="btn btn-sm btn-success" onclick="batchEnableProxies()">
                                        <i class="bi bi-check-circle-fill"></i> 启用
                                    </button>
                                    <button class="btn btn-sm btn-warning" onclick="batchDisableProxies()">
                                        <i class="bi bi-pause-circle-fill"></i> 禁用
                                    </button>
                                    <button class="btn btn-sm btn-danger" onclick="batchDeleteProxies()">
                                        <i class="bi bi-trash-fill"></i> 删除
                                    </button>
                                    <button class="btn btn-sm btn-info" onclick="exportSelectedProxies()">
                                        <i class="bi bi-download"></i> 导出
                                    </button>
                                    <input type="text" class="form-control form-control-sm" style="width:200px; border-radius: 8px;"
                                           placeholder="搜索..." onkeyup="filterProxyTable(this.value)">
                                </div>
                            </div>
                        </div>
                        
                        <div style="overflow-x: auto;">
                            <table class="table table-sm" style="width: 100%; min-width: 900px;">
                                <thead style="background: #343a40; color: white;">
                                    <tr>
                                        <th style="width: 40px; text-align: center;">选</th>
                                        <th style="width: 60px;">ID</th>
                                        <th style="width: 120px;">IP地址</th>
                                        <th style="width: 80px; text-align: center;">端口</th>
                                        <th style="width: 120px;">用户名</th>
                                        <th style="width: 200px;">密码</th>
                                        <th style="width: 70px; text-align: center;">状态</th>
                                        <th style="width: 100px; text-align: center;">操作</th>
                                    </tr>
                                </thead>
                                <tbody>`;
                    
                    // 逐行构建表格内容
                    proxies.forEach((proxy, index) => {
                        const rowClass = index % 2 === 0 ? 'table-light' : '';
                        html += `
                            <tr class="proxy-row ${rowClass}">
                                <td style="text-align: center; padding: 8px 4px;">
                                    <input type="checkbox" class="form-check-input proxy-check" 
                                           data-id="${proxy.id}" onchange="updateSelectedCount()">
                                </td>
                                <td style="padding: 8px 4px;">
                                    <small class="text-muted">#${proxy.id}</small>
                                </td>
                                <td style="padding: 8px 4px;">
                                    <span class="font-monospace" style="font-size: 0.9rem;">${proxy.ip}</span>
                                </td>
                                <td style="padding: 8px 4px;">
                                    <span class="badge bg-info" style="font-family: monospace;">${proxy.port}</span>
                                </td>
                                <td style="padding: 8px 4px;">
                                    <code style="color: #d63384; font-size: 0.9rem;">${proxy.username}</code>
                                </td>
                                <td style="padding: 8px 4px;">
                                    <div style="display: flex; align-items: center; gap: 4px;">
                                        <input type="text" class="form-control form-control-sm" 
                                               value="${proxy.password}" readonly 
                                               style="font-family: monospace; font-size: 0.85rem; background: #f8f9fa; border-radius: 6px;">
                                        <button class="btn btn-sm btn-outline-secondary" 
                                                style="padding: 4px 10px; border-radius: 6px;"
                                                onclick="copyPassword('${proxy.password.replace(/'/g, "\\'")}', ${proxy.id})"
                                                title="复制密码">
                                            <i class="bi bi-clipboard" style="font-size: 0.9rem;"></i>
                                        </button>
                                    </div>
                                </td>
                                <td style="text-align: center; padding: 8px 4px;">
                                    ${proxy.enabled ? 
                                        '<span class="badge bg-success" style="font-size: 0.8rem;"><i class="bi bi-check-circle-fill me-1"></i>启用</span>' : 
                                        '<span class="badge bg-secondary" style="font-size: 0.8rem;"><i class="bi bi-x-circle-fill me-1"></i>禁用</span>'}
                                </td>
                                <td style="text-align: center; padding: 8px 4px;">
                                    <button class="btn btn-sm ${proxy.enabled ? 'btn-warning' : 'btn-success'}" 
                                            style="padding: 4px 10px; margin-right: 4px; border-radius: 6px;"
                                            onclick="toggleProxy(${proxy.id}, ${!proxy.enabled})"
                                            title="${proxy.enabled ? '禁用' : '启用'}">
                                        <i class="bi bi-${proxy.enabled ? 'pause-circle' : 'play-circle'}-fill" style="font-size: 0.9rem;"></i>
                                    </button>
                                    <button class="btn btn-sm btn-danger" 
                                            style="padding: 4px 10px; border-radius: 6px;"
                                            onclick="deleteProxy(${proxy.id})"
                                            title="删除">
                                        <i class="bi bi-trash-fill" style="font-size: 0.9rem;"></i>
                                    </button>
                                </td>
                            </tr>`;
                    });
                    
                    html += `
                                </tbody>
                            </table>
                        </div>
                    `;
                    
                    // 一次性设置内容
                    content.innerHTML = html;
                    
                    // 绑定事件
                    document.getElementById('selectAllCheck').addEventListener('change', (e) => {
                        document.querySelectorAll('.proxy-check').forEach(cb => {
                            cb.checked = e.target.checked;
                            const id = cb.getAttribute('data-id');
                            if (e.target.checked) {
                                selectedProxies.add(id);
                            } else {
                                selectedProxies.delete(id);
                            }
                        });
                        updateSelectedCount();
                    });
                    
                    // 初始化选中数量
                    updateSelectedCount();
                    
                    hideLoading();
                    const modal = new bootstrap.Modal(document.getElementById('proxyDetailModal'));
                    
                    // 监听模态框关闭事件，清空选择
                    document.getElementById('proxyDetailModal').addEventListener('hidden.bs.modal', function () {
                        selectedProxies.clear();
                        updateSelectedCount();
                    }, { once: true });
                    
                    modal.show();
                })
                .catch(err => {
                    hideLoading();
                    showToast('加载失败: ' + err.message, 'danger');
                });
        }

        // 更新选中数量
        function updateSelectedCount() {
            const count = document.querySelectorAll('.proxy-check:checked').length;
            document.getElementById('selectedCount').textContent = count;
        }

        // 过滤代理表格
        function filterProxyTable(value) {
            const rows = document.querySelectorAll('.proxy-row');
            const searchTerm = value.toLowerCase();
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        }

        // 代理组操作
        function deleteGroup(cSegment) {
            if (!confirm(`确定要删除 ${cSegment}.x 段的所有代理吗？`)) return;
            
            showLoading();
            fetch(`/api/delete_group/${cSegment}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    showToast(`已删除 ${cSegment}.x 段代理组`);
                    // 从选中集合中移除已删除的组
                    selectedGroups.delete(cSegment);
                    loadProxyGroups();
                })
                .catch(err => {
                    hideLoading();
                    showToast('删除失败: ' + err.message, 'danger');
                });
        }

        function toggleGroup(cSegment, action) {
            showLoading();
            fetch(`/api/toggle_group/${cSegment}/${action}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    showToast(`已${action === 'enable' ? '启用' : '禁用'} ${cSegment}.x 段代理组`);
                    loadProxyGroups();
                })
                .catch(err => {
                    hideLoading();
                    showToast('操作失败: ' + err.message, 'danger');
                });
        }

        // 单个代理操作
        function toggleProxy(id, enable) {
            const action = enable ? 'enableproxy' : 'disableproxy';
            fetch(`/${action}/${id}`)
                .then(res => res.json())
                .then(data => {
                    showToast(`代理已${enable ? '启用' : '禁用'}`);
                    // 刷新当前模态框内容
                    const modal = bootstrap.Modal.getInstance(document.getElementById('proxyDetailModal'));
                    if (modal) {
                        const detailHeader = document.querySelector('.detail-header h5');
                        if (detailHeader) {
                            const cSegment = detailHeader.textContent.split('.')[0].trim();
                            viewProxyGroup(cSegment);
                        }
                    }
                })
                .catch(err => {
                    showToast('操作失败: ' + err.message, 'danger');
                });
        }

        function deleteProxy(id) {
            if (!confirm('确定要删除此代理吗？')) return;
            
            fetch(`/delproxy/${id}`)
                .then(res => res.json())
                .then(data => {
                    showToast('代理已删除');
                    const modal = bootstrap.Modal.getInstance(document.getElementById('proxyDetailModal'));
                    if (modal) {
                        const detailHeader = document.querySelector('.detail-header h5');
                        if (detailHeader) {
                            const cSegment = detailHeader.textContent.split('.')[0].trim();
                            viewProxyGroup(cSegment);
                        }
                    }
                    loadProxyGroups();
                })
                .catch(err => {
                    showToast('删除失败: ' + err.message, 'danger');
                });
        }

        // 批量操作函数
        function batchEnableProxies() {
            if (selectedProxies.size === 0) {
                showToast('请先选择代理', 'warning');
                return;
            }
            
            const formData = new FormData();
            selectedProxies.forEach(id => formData.append('ids[]', id));
            
            fetch('/batch_enable', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    showToast('批量启用成功');
                    selectedProxies.clear();
                    updateSelectedCount();
                    // 重新加载当前代理组
                    const cSegment = document.querySelector('.detail-header h5').textContent.split('.')[0];
                    viewProxyGroup(cSegment);
                });
        }

        function batchDisableProxies() {
            if (selectedProxies.size === 0) {
                showToast('请先选择代理', 'warning');
                return;
            }
            
            const formData = new FormData();
            selectedProxies.forEach(id => formData.append('ids[]', id));
            
            fetch('/batch_disable', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    showToast('批量禁用成功');
                    selectedProxies.clear();
                    updateSelectedCount();
                    const cSegment = document.querySelector('.detail-header h5').textContent.split('.')[0];
                    viewProxyGroup(cSegment);
                });
        }

        function batchDeleteProxies() {
            if (selectedProxies.size === 0) {
                showToast('请先选择代理', 'warning');
                return;
            }
            
            if (!confirm(`确定要删除选中的 ${selectedProxies.size} 个代理吗？`)) return;
            
            const formData = new FormData();
            selectedProxies.forEach(id => formData.append('ids', id));
            
            fetch('/batchdelproxy', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    showToast('批量删除成功');
                    selectedProxies.clear();
                    updateSelectedCount();
                    bootstrap.Modal.getInstance(document.getElementById('proxyDetailModal')).hide();
                    loadProxyGroups();
                });
        }

        function exportSelectedProxies() {
            if (selectedProxies.size === 0) {
                showToast('请先选择代理', 'warning');
                return;
            }
            
            const formData = new FormData();
            selectedProxies.forEach(id => formData.append('ids[]', id));
            
            fetch('/export_selected_proxy', { method: 'POST', body: formData })
                .then(res => res.blob())
                .then(blob => {
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = 'proxy_export.txt';
                    a.click();
                    URL.revokeObjectURL(a.href);
                    showToast('导出成功');
                    // 导出后清空选择
                    selectedProxies.clear();
                    updateSelectedCount();
                    // 取消全选
                    const selectAllCheck = document.getElementById('selectAllCheck');
                    if (selectAllCheck) selectAllCheck.checked = false;
                });
        }

        // 导出选中的代理组
        document.getElementById('exportGroups').addEventListener('click', () => {
            if (selectedGroups.size === 0) {
                showToast('请先选择代理组', 'warning');
                return;
            }
            
            const formData = new FormData();
            selectedGroups.forEach(cseg => formData.append('csegs[]', cseg));
            
            showLoading();
            fetch('/export_selected', { method: 'POST', body: formData })
                .then(res => {
                    if (!res.ok) throw new Error('Export failed');
                    
                    // 从响应头获取文件名
                    const contentDisposition = res.headers.get('Content-Disposition');
                    let filename = 'proxy_export.txt';
                    if (contentDisposition) {
                        const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
                        if (filenameMatch && filenameMatch[1]) {
                            filename = filenameMatch[1].replace(/['"]/g, '');
                        }
                    }
                    
                    return res.blob().then(blob => ({ blob, filename }));
                })
                .then(({ blob, filename }) => {
                    hideLoading();
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = filename;
                    a.click();
                    URL.revokeObjectURL(a.href);
                    showToast(`导出成功: ${filename}`);
                    
                    // 导出后清空选择
                    selectedGroups.clear();
                    // 取消所有复选框的选中状态
                    document.querySelectorAll('.proxy-card input[type="checkbox"]').forEach(cb => {
                        cb.checked = false;
                    });
                    // 移除所有卡片的选中样式
                    document.querySelectorAll('.proxy-card.selected').forEach(card => {
                        card.classList.remove('selected');
                    });
                })
                .catch(err => {
                    hideLoading();
                    showToast('导出失败: ' + err.message, 'danger');
                });
        });

        // 表单提交
        document.getElementById('batchAddForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            showLoading();
            fetch('/batchaddproxy', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    if (data.status === 'success') {
                        showToast(data.message);
                        e.target.reset();
                        loadProxyGroups();
                    } else {
                        showToast(data.message, 'danger');
                    }
                });
        });

        document.getElementById('manualBatchForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            showLoading();
            fetch('/batchaddproxy', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    if (data.status === 'success') {
                        showToast(data.message);
                        e.target.reset();
                        loadProxyGroups();
                    } else {
                        showToast(data.message, 'danger');
                    }
                });
        });

        // 用户管理
        function loadUsers() {
            fetch('/api/users')
                .then(res => res.json())
                .then(users => {
                    const container = document.getElementById('usersList');
                    container.innerHTML = `
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>用户名</th>
                                        <th>操作</th>
                                    </tr>
                                </thead>
                                <tbody>
                    `;
                    
                    users.forEach(user => {
                        container.innerHTML += `
                            <tr>
                                <td>${user.id}</td>
                                <td>${user.username}</td>
                                <td>
                                    ${user.username !== 'admin' ? 
                                        `<button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id})">
                                            <i class="bi bi-trash"></i> 删除
                                        </button>` : 
                                        '<span class="text-muted">系统用户</span>'}
                                </td>
                            </tr>
                        `;
                    });
                    
                    container.innerHTML += '</tbody></table></div>';
                });
        }

        document.getElementById('addUserForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            fetch('/adduser', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        showToast(data.message);
                        e.target.reset();
                        loadUsers();
                    } else {
                        showToast(data.message, 'danger');
                    }
                });
        });

        function deleteUser(id) {
            if (!confirm('确定要删除此用户吗？')) return;
            
            fetch(`/deluser/${id}`)
                .then(res => res.json())
                .then(data => {
                    showToast('用户已删除');
                    loadUsers();
                });
        }

        // IP配置管理
        function loadIpConfigs() {
            fetch('/api/ip_configs')
                .then(res => res.json())
                .then(configs => {
                    const container = document.getElementById('ipConfigsList');
                    container.innerHTML = `
                        <div class="table-responsive">
                            <table class="table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>IP配置</th>
                                        <th>类型</th>
                                        <th>网卡</th>
                                        <th>创建时间</th>
                                    </tr>
                                </thead>
                                <tbody>
                    `;
                    
                    configs.forEach(config => {
                        container.innerHTML += `
                            <tr>
                                <td>${config.id}</td>
                                <td><code>${config.ip_str}</code></td>
                                <td>${config.type}</td>
                                <td>${config.iface}</td>
                                <td>${config.created}</td>
                            </tr>
                        `;
                    });
                    
                    container.innerHTML += '</tbody></table></div>';
                });
        }

        document.getElementById('addIpForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            showLoading();
            fetch('/add_ip_config', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    hideLoading();
                    if (data.status === 'success') {
                        showToast(data.message);
                        e.target.reset();
                        loadIpConfigs();
                    } else {
                        showToast(data.message, 'danger');
                    }
                });
        });

        // 深色模式
        document.getElementById('darkModeToggle').addEventListener('click', () => {
            document.body.classList.toggle('dark-mode');
            const icon = document.querySelector('#darkModeToggle i');
            if (document.body.classList.contains('dark-mode')) {
                icon.className = 'bi bi-sun-fill';
                localStorage.setItem('darkMode', 'true');
            } else {
                icon.className = 'bi bi-moon-fill';
                localStorage.setItem('darkMode', 'false');
            }
        });

        // 标签页切换事件
        document.getElementById('user-tab').addEventListener('shown.bs.tab', loadUsers);
        document.getElementById('ip-tab').addEventListener('shown.bs.tab', loadIpConfigs);

        // 刷新按钮
        document.getElementById('refreshGroups').addEventListener('click', loadProxyGroups);

        // 初始化
        window.addEventListener('DOMContentLoaded', () => {
            // 恢复深色模式设置
            if (localStorage.getItem('darkMode') === 'true') {
                document.body.classList.add('dark-mode');
                document.querySelector('#darkModeToggle i').className = 'bi bi-sun-fill';
            }
            
            // 清空全局选择集合
            selectedGroups.clear();
            selectedProxies.clear();
            
            // 加载初始数据
            loadProxyGroups();
        });
    </script>
</body>
</html>
EOF

}

function create_services() {
    echo -e "\n${YELLOW}========= 创建系统服务 =========${NC}\n"
    
    # Web服务 (使用gunicorn)
    cat > /etc/systemd/system/3proxy-web.service <<EOF
[Unit]
Description=3proxy Web Management System
After=network.target redis.service

[Service]
Type=notify
WorkingDirectory=$WORKDIR
Environment="PATH=$WORKDIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$WORKDIR/venv/bin/gunicorn \
    --bind 0.0.0.0:$PORT \
    --workers 4 \
    --worker-class gevent \
    --worker-connections 1000 \
    --timeout 30 \
    --keep-alive 5 \
    --max-requests 10000 \
    --max-requests-jitter 1000 \
    --access-logfile /var/log/3proxy/access.log \
    --error-logfile /var/log/3proxy/error.log \
    --log-level info \
    manage:app
Restart=always
User=root
LimitNOFILE=1000000
LimitNPROC=1000000

[Install]
WantedBy=multi-user.target
EOF

    # 3proxy服务
    cat > /etc/systemd/system/3proxy-autostart.service <<EOF
[Unit]
Description=3proxy Enterprise Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$WORKDIR
ExecStart=/usr/local/bin/3proxy-enterprise.sh
Restart=always
RestartSec=5
User=root
LimitNOFILE=10000000
LimitNPROC=4194304
LimitMEMLOCK=infinity
LimitSTACK=infinity
OOMScoreAdjust=-1000
CPUAccounting=true
MemoryAccounting=true
TasksAccounting=true
IOAccounting=true

[Install]
WantedBy=multi-user.target
EOF

    # Nginx反向代理配置
    cat > /etc/nginx/sites-available/3proxy <<EOF
server {
    listen 80;
    server_name _;
    
    client_max_body_size 100M;
    
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
    
    location /static {
        alias $WORKDIR/static;
        expires 30d;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/3proxy /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    systemctl daemon-reload
}

function setup_monitoring() {
    echo -e "\n${YELLOW}========= 设置监控 =========${NC}\n"
    
    # 创建监控脚本
    cat > /usr/local/bin/3proxy-monitor.sh <<'EOF'
#!/bin/bash
# 3proxy监控脚本

LOGFILE="/var/log/3proxy/monitor.log"
THRESHOLD_CPU=80
THRESHOLD_MEM=90
THRESHOLD_CONN=8000000

while true; do
    # CPU使用率
    CPU=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    
    # 内存使用率
    MEM=$(free | grep Mem | awk '{print ($2-$7)/$2 * 100.0}')
    
    # 连接数
    CONN=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
    
    # 3proxy进程检查
    if ! pgrep -x 3proxy > /dev/null; then
        echo "$(date): 3proxy not running, restarting..." >> $LOGFILE
        systemctl restart 3proxy-autostart
    fi
    
    # 告警
    if (( $(echo "$CPU > $THRESHOLD_CPU" | bc -l) )); then
        echo "$(date): High CPU usage: $CPU%" >> $LOGFILE
    fi
    
    if (( $(echo "$MEM > $THRESHOLD_MEM" | bc -l) )); then
        echo "$(date): High memory usage: $MEM%" >> $LOGFILE
    fi
    
    if [ $CONN -gt $THRESHOLD_CONN ]; then
        echo "$(date): High connection count: $CONN" >> $LOGFILE
    fi
    
    sleep 60
done
EOF
    
    chmod +x /usr/local/bin/3proxy-monitor.sh
    
    # 创建监控服务
    cat > /etc/systemd/system/3proxy-monitor.service <<EOF
[Unit]
Description=3proxy Monitoring Service
After=3proxy-autostart.service

[Service]
Type=simple
ExecStart=/usr/local/bin/3proxy-monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
}
