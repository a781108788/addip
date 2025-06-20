else:
            # 导出所有
            cursor = conn.execute("SELECT ip, port, username, password FROM proxy ORDER BY ip, port")
        
        # 生成导出内容
        if format_type == 'json':
            proxies = []
            for row in cursor:
                proxies.append({
                    'ip': row[0],
                    'port': row[1],
                    'username': row[2],
                    'password': row[3]
                })
            
            content = json.dumps(proxies, indent=2)
            mimetype = 'application/json'
            filename = 'proxies.json'
        else:
            # 默认txt格式
            lines = []
            for row in cursor:
                lines.append(f"{row[0]}:{row[1]}:{row[2]}:{row[3]}")
            
            content = '\n'.join(lines)
            mimetype = 'text/plain'
            filename = 'proxies.txt'
    
    return Response(
        content,
        mimetype=mimetype,
        headers={
            'Content-Disposition': f'attachment; filename={filename}',
            'Content-Type': f'{mimetype}; charset=utf-8'
        }
    )

@app.route('/api/proxy/import', methods=['POST'])
@login_required
def api_proxy_import():
    """导入代理"""
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '未选择文件'}), 400
    
    # 读取文件内容
    content = file.read().decode('utf-8', errors='ignore')
    lines = content.strip().split('\n')
    
    # 解析代理数据
    proxies = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 支持多种格式
        parts = re.split(r'[:|,\s]+', line)
        if len(parts) >= 2:
            ip = parts[0]
            port = int(parts[1]) if parts[1].isdigit() else 0
            username = parts[2] if len(parts) > 2 else f"user{random.randint(1000, 9999)}"
            password = parts[3] if len(parts) > 3 else ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            
            if port > 0:
                proxies.append((ip, port, username, password))
    
    if not proxies:
        return jsonify({'error': '未找到有效的代理数据'}), 400
    
    # 创建批量操作
    op_id = batch_manager.create_operation('import_proxy', len(proxies))
    
    # 异步执行导入
    def import_worker():
        with db_pool.get_connection() as conn:
            # 分批插入
            for i in range(0, len(proxies), BATCH_SIZE):
                batch = proxies[i:i+BATCH_SIZE]
                
                # 检查重复
                for proxy in batch:
                    existing = conn.execute(
                        "SELECT id FROM proxy WHERE ip = ? AND port = ?",
                        (proxy[0], proxy[1])
                    ).fetchone()
                    
                    if not existing:
                        conn.execute(
                            "INSERT INTO proxy (ip, port, username, password, enabled) VALUES (?, ?, ?, ?, 1)",
                            proxy
                        )
                        batch_manager.update_progress(op_id, True)
                    else:
                        batch_manager.update_progress(op_id, False, f"代理已存在: {proxy[0]}:{proxy[1]}")
                
                conn.commit()
        
        # 重新生成配置
        config_generator.generate_configs()
    
    # 提交到线程池执行
    executor.submit(import_worker)
    
    return jsonify({'operation_id': op_id, 'message': f'正在导入{len(proxies)}个代理'})

@app.route('/api/users')
@login_required
def api_users():
    """获取用户列表"""
    with db_pool.get_connection() as conn:
        cursor = conn.execute("SELECT id, username FROM users ORDER BY id")
        users = []
        for row in cursor:
            users.append({
                'id': row['id'],
                'username': row['username']
            })
    
    return jsonify({'users': users})

@app.route('/api/users/add', methods=['POST'])
@login_required
def api_add_user():
    """添加用户"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400
    
    # 检查用户名是否存在
    with db_pool.get_connection() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            return jsonify({'error': '用户名已存在'}), 400
        
        # 添加用户
        password_hash = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    
    return jsonify({'message': '用户添加成功'})

@app.route('/api/users/delete/<int:user_id>', methods=['DELETE'])
@login_required
def api_delete_user(user_id):
    """删除用户"""
    if user_id == current_user.id:
        return jsonify({'error': '不能删除当前登录用户'}), 400
    
    with db_pool.get_connection() as conn:
        # 检查是否是最后一个管理员
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count <= 1:
            return jsonify({'error': '不能删除最后一个用户'}), 400
        
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    
    return jsonify({'message': '用户删除成功'})

@app.route('/api/network/interfaces')
@login_required
def api_network_interfaces():
    """获取网络接口列表"""
    interfaces = get_network_interfaces()
    return jsonify({'interfaces': interfaces})

@app.route('/api/network/ip/add', methods=['POST'])
@login_required
def api_add_ip():
    """添加IP地址"""
    data = request.get_json()
    interface = data.get('interface')
    ip_range = data.get('ip_range')
    
    if not interface or not ip_range:
        return jsonify({'error': '参数不完整'}), 400
    
    # 验证IP范围
    if not validate_ip_range(ip_range):
        return jsonify({'error': 'IP范围格式错误'}), 400
    
    # 展开IP范围
    ips = expand_ip_range(ip_range)
    if not ips:
        return jsonify({'error': '无效的IP范围'}), 400
    
    if len(ips) > 1000:
        return jsonify({'error': 'IP数量超过限制(1000)'}), 400
    
    # 添加IP地址
    success = 0
    failed = 0
    
    for ip in ips:
        try:
            # 使用/32掩码避免路由冲突
            subprocess.run(['ip', 'addr', 'add', f'{ip}/32', 'dev', interface], 
                         check=True, capture_output=True, text=True)
            success += 1
        except subprocess.CalledProcessError:
            failed += 1
    
    # 保存到数据库
    with db_pool.get_connection() as conn:
        conn.execute(
            "INSERT INTO ip_config (ip_str, type, iface, created) VALUES (?, ?, ?, datetime('now'))",
            (ip_range, 'range', interface)
        )
        conn.commit()
    
    return jsonify({
        'message': f'IP添加完成',
        'success': success,
        'failed': failed,
        'total': len(ips)
    })

@app.route('/api/config/reload', methods=['POST'])
@login_required
def api_reload_config():
    """重新加载配置"""
    try:
        config_generator.generate_configs()
        return jsonify({'message': '配置重载成功'})
    except Exception as e:
        app.logger.error(f"配置重载失败: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/view')
@login_required
def api_view_logs():
    """查看日志"""
    log_type = request.args.get('type', 'proxy')
    lines = request.args.get('lines', 100, type=int)
    
    log_files = {
        'proxy': '/var/log/3proxy/3proxy.log',
        'webapp': '/var/log/3proxy/webapp.log',
        'monitor': '/var/log/3proxy/monitor.log'
    }
    
    log_file = log_files.get(log_type)
    if not log_file or not os.path.exists(log_file):
        return jsonify({'error': '日志文件不存在'}), 404
    
    try:
        # 读取最后N行
        result = subprocess.run(['tail', '-n', str(lines), log_file], 
                              capture_output=True, text=True, check=True)
        
        return jsonify({
            'log_type': log_type,
            'content': result.stdout,
            'lines': lines
        })
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'读取日志失败: {e}'}), 500

# 清理函数
def cleanup():
    """清理资源"""
    executor.shutdown(wait=True)
    app.logger.info('3proxy Enterprise shutdown')

# 信号处理
def signal_handler(signum, frame):
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# 初始化数据库
def init_database():
    """初始化数据库"""
    with db_pool.get_connection() as conn:
        # 创建表
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS proxy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                ip_range TEXT,
                port_range TEXT,
                user_prefix TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, port)
            );
            
            CREATE INDEX IF NOT EXISTS idx_proxy_ip ON proxy(ip);
            CREATE INDEX IF NOT EXISTS idx_proxy_port ON proxy(port);
            CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON proxy(enabled);
            CREATE INDEX IF NOT EXISTS idx_proxy_c_segment ON proxy(
                substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.'))
            );
            
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS ip_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_str TEXT NOT NULL,
                type TEXT NOT NULL,
                iface TEXT NOT NULL,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS operation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                operation TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ''')
        
        # 创建默认管理员用户
        admin_exists = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if not admin_exists:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123456')
            password_hash = generate_password_hash(admin_password)
            conn.execute("INSERT INTO users (username, password) VALUES ('admin', ?)", (password_hash,))
            conn.commit()
            app.logger.info(f"Created default admin user")

# 主函数
if __name__ == '__main__':
    # 初始化数据库
    init_database()
    
    # 获取端口
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    
    # 开发模式
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(host='0.0.0.0', port=port, debug=True)
    else:
        # 生产模式使用gunicorn
        from gunicorn.app.base import BaseApplication
        
        class GunicornApp(BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()
            
            def load_config(self):
                for key, value in self.options.items():
                    self.cfg.set(key.lower(), value)
            
            def load(self):
                return self.application
        
        options = {
            'bind': f'0.0.0.0:{port}',
            'workers': min(MAX_WORKERS, (psutil.cpu_count() or 1) * 2 + 1),
            'worker_class': 'gevent',
            'worker_connections': 1000,
            'timeout': 120,
            'keepalive': 5,
            'max_requests': 10000,
            'max_requests_jitter': 1000,
            'preload_app': True,
            'accesslog': '/var/log/3proxy/access.log',
            'errorlog': '/var/log/3proxy/error.log',
            'loglevel': 'info'
        }
        
        GunicornApp(app, options).run()
EOAPP3
}

function create_app_part4() {
    # 创建静态目录
    mkdir -p $WORKDIR/static
    
    # 创建一个简单的favicon
    cat > $WORKDIR/static/favicon.ico << 'EOF'
EOF
}

function create_templates() {
    # 创建login.html
    cat > $WORKDIR/templates/login.html << 'EOHTML'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3proxy Enterprise - 登录</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 450px;
            width: 100%;
            backdrop-filter: blur(10px);
            animation: fadeIn 0.5s ease-out;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h1 {
            font-size: 2rem;
            font-weight: 700;
            color: #2a5298;
            margin-bottom: 10px;
        }
        
        .login-header p {
            color: #6c757d;
            font-size: 1.1rem;
        }
        
        .form-control {
            border-radius: 10px;
            padding: 12px 20px;
            font-size: 1rem;
            border: 2px solid #e0e0e0;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: #2a5298;
            box-shadow: 0 0 0 0.2rem rgba(42, 82, 152, 0.25);
        }
        
        .btn-login {
            background: linear-gradient(135deg, #2a5298 0%, #1e3c72 100%);
            border: none;
            border-radius: 10px;
            padding: 12px 30px;
            font-size: 1.1rem;
            font-weight: 600;
            color: white;
            width: 100%;
            transition: all 0.3s ease;
            margin-top: 20px;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(42, 82, 152, 0.3);
        }
        
        .enterprise-badge {
            display: inline-block;
            background: #28a745;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-top: 10px;
        }
        
        .form-floating label {
            color: #6c757d;
        }
        
        .alert {
            border-radius: 10px;
            border: none;
        }
        
        .system-info {
            text-align: center;
            margin-top: 30px;
            color: #6c757d;
            font-size: 0.9rem;
        }
        
        .logo-icon {
            font-size: 4rem;
            color: #2a5298;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <i class="bi bi-shield-lock logo-icon"></i>
            <h1>3proxy Enterprise</h1>
            <p>企业级代理管理系统</p>
            <span class="enterprise-badge">支持百万级并发</span>
        </div>
        
        <form method="POST" action="{{ url_for('login') }}">
            <div class="form-floating mb-3">
                <input type="text" class="form-control" id="username" name="username" 
                       placeholder="用户名" required autofocus>
                <label for="username">用户名</label>
            </div>
            
            <div class="form-floating mb-3">
                <input type="password" class="form-control" id="password" name="password" 
                       placeholder="密码" required>
                <label for="password">密码</label>
            </div>
            
            <button type="submit" class="btn btn-login">
                <i class="bi bi-box-arrow-in-right me-2"></i>登录系统
            </button>
        </form>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'danger' else category }} mt-3" role="alert">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="system-info">
            <p class="mb-0">Version 2.0 Enterprise Edition</p>
            <small>© 2024 3proxy Enterprise Management</small>
        </div>
    </div>
</body>
</html>
EOHTML

    # 创建index.html (将内容分成多个部分以避免过长)
    create_index_part1
    create_index_part2
    create_index_part3
}

function create_index_part1() {
    cat > $WORKDIR/templates/index.html << 'EOHTML1'
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>3proxy Enterprise - 管理面板</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/datatables.net-bs5@1.13.8/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #2a5298;
            --primary-dark: #1e3c72;
            --success: #28a745;
            --info: #17a2b8;
            --warning: #ffc107;
            --danger: #dc3545;
            --dark: #343a40;
            --light: #f8f9fa;
            --sidebar-width: 280px;
        }
        
        * {
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f5f7fa;
            overflow-x: hidden;
        }
        
        /* 顶部导航栏 */
        .navbar {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            box-shadow: 0 2px 4px rgba(0,0,0,.1);
            padding: 0.5rem 1rem;
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.4rem;
            color: white !important;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .navbar-brand i {
            font-size: 1.6rem;
        }
        
        /* 侧边栏 */
        .sidebar {
            position: fixed;
            top: 56px;
            left: 0;
            bottom: 0;
            width: var(--sidebar-width);
            background: white;
            box-shadow: 2px 0 5px rgba(0,0,0,.05);
            z-index: 100;
            overflow-y: auto;
            transition: transform 0.3s ease-in-out;
        }
        
        .sidebar-header {
            padding: 1.5rem;
            border-bottom: 1px solid #e9ecef;
        }
        
        .sidebar-menu {
            padding: 1rem 0;
        }
        
        .sidebar-item {
            padding: 0.75rem 1.5rem;
            color: #495057;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.3s ease;
            border-left: 3px solid transparent;
        }
        
        .sidebar-item:hover {
            background-color: #f8f9fa;
            color: var(--primary);
            text-decoration: none;
        }
        
        .sidebar-item.active {
            background-color: rgba(42, 82, 152, 0.1);
            color: var(--primary);
            border-left-color: var(--primary);
            font-weight: 600;
        }
        
        .sidebar-item i {
            font-size: 1.2rem;
            width: 24px;
            text-align: center;
        }
        
        /* 主内容区 */
        .main-content {
            margin-left: var(--sidebar-width);
            padding: 2rem;
            min-height: calc(100vh - 56px);
            transition: margin-left 0.3s ease-in-out;
        }
        
        /* 统计卡片 */
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 2px 10px rgba(0,0,0,.08);
            transition: all 0.3s ease;
            border: 1px solid transparent;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,.1);
        }
        
        .stat-card .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.8rem;
            color: white;
            margin-bottom: 1rem;
        }
        
        .stat-card.primary .stat-icon { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .stat-card.success .stat-icon { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .stat-card.info .stat-icon { background: linear-gradient(135deg, #2196f3 0%, #21cbf3 100%); }
        .stat-card.warning .stat-icon { background: linear-gradient(135deg, #f2994a 0%, #f2c94c 100%); }
        
        .stat-card h3 {
            font-size: 2rem;
            font-weight: 700;
            margin: 0;
            color: #2d3436;
        }
        
        .stat-card p {
            margin: 0;
            color: #636e72;
            font-size: 0.9rem;
        }
        
        /* 内容卡片 */
        .content-card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,.08);
            margin-bottom: 2rem;
            overflow: hidden;
        }
        
        .content-card-header {
            padding: 1.5rem;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: between;
            align-items: center;
        }
        
        .content-card-body {
            padding: 1.5rem;
        }
        
        /* 系统监控 */
        .system-monitor {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .monitor-item {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 2px 10px rgba(0,0,0,.08);
        }
        
        .monitor-item h6 {
            color: #636e72;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }
        
        .monitor-value {
            font-size: 1.8rem;
            font-weight: 700;
            color: #2d3436;
        }
        
        .progress {
            height: 8px;
            border-radius: 4px;
            margin-top: 0.5rem;
        }
        
        /* 按钮样式 */
        .btn {
            border-radius: 8px;
            padding: 0.5rem 1.2rem;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            border: none;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(42, 82, 152, 0.3);
        }
        
        /* 表格样式 */
        .table {
            font-size: 0.95rem;
        }
        
        .table thead th {
            border-bottom: 2px solid #dee2e6;
            color: #495057;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }
        
        /* 响应式 */
        .sidebar-toggle {
            display: none;
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--primary);
            color: white;
            border: none;
            box-shadow: 0 2px 10px rgba(0,0,0,.2);
            z-index: 1000;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .sidebar.show {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .sidebar-toggle {
                display: flex;
                align-items: center;
                justify-content: center;
            }
        }
        
        /* 加载动画 */
        .spinner-wrapper {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(255, 255, 255, 0.9);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
        }
        
        .spinner-border {
            width: 3rem;
            height: 3rem;
            border-width: 0.3rem;
        }
        
        /* 工具提示 */
        .tooltip-inner {
            max-width: 300px;
            padding: 0.5rem 1rem;
            border-radius: 8px;
        }
        
        /* 批量操作进度 */
        .operation-progress {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 300px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 5px 20px rgba(0,0,0,.15);
            padding: 1rem;
            z-index: 1000;
        }
        
        /* 代理组卡片 */
        .proxy-group-card {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 10px rgba(0,0,0,.08);
            transition: all 0.3s ease;
            cursor: pointer;
            border: 2px solid transparent;
        }
        
        .proxy-group-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 20px rgba(0,0,0,.1);
            border-color: var(--primary);
        }
        
        .proxy-group-card.selected {
            border-color: var(--primary);
            background: rgba(42, 82, 152, 0.05);
        }
        
        /* 标签样式 */
        .badge {
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            font-weight: 500;
            font-size: 0.85rem;
        }
        
        /* 自定义滚动条 */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #f1f1f1;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
    </style>
</head>
<body>
    <!-- 顶部导航 -->
    <nav class="navbar navbar-dark fixed-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="bi bi-shield-check"></i>
                3proxy Enterprise
            </a>
            <div class="d-flex align-items-center">
                <span class="text-white me-3">
                    <i class="bi bi-person-circle"></i> {{ current_user.username }}
                </span>
                <a href="{{ url_for('logout') }}" class="btn btn-outline-light btn-sm">
                    <i class="bi bi-box-arrow-right"></i> 退出
                </a>
            </div>
        </div>
    </nav>
    
    <!-- 侧边栏 -->
    <aside class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <h5 class="mb-0">控制面板</h5>
            <small class="text-muted">Enterprise Edition</small>
        </div>
        <nav class="sidebar-menu">
            <a href="#" class="sidebar-item active" data-page="dashboard">
                <i class="bi bi-speedometer2"></i>
                <span>仪表板</span>
            </a>
            <a href="#" class="sidebar-item" data-page="proxies">
                <i class="bi bi-hdd-network"></i>
                <span>代理管理</span>
            </a>
            <a href="#" class="sidebar-item" data-page="batch">
                <i class="bi bi-layers"></i>
                <span>批量操作</span>
            </a>
            <a href="#" class="sidebar-item" data-page="network">
                <i class="bi bi-diagram-3"></i>
                <span>网络配置</span>
            </a>
            <a href="#" class="sidebar-item" data-page="users">
                <i class="bi bi-people"></i>
                <span>用户管理</span>
            </a>
            <a href="#" class="sidebar-item" data-page="logs">
                <i class="bi bi-file-text"></i>
                <span>日志查看</span>
            </a>
            <a href="#" class="sidebar-item" data-page="settings">
                <i class="bi bi-gear"></i>
                <span>系统设置</span>
            </a>
        </nav>
    </aside>
    
    <!-- 主内容区 -->
    <main class="main-content">
        <div id="content-area">
            <!-- 内容将通过JavaScript动态加载 -->
        </div>
    </main>
    
    <!-- 侧边栏切换按钮（移动端） -->
    <button class="sidebar-toggle" id="sidebarToggle">
        <i class="bi bi-list"></i>
    </button>
    
    <!-- 批量操作进度提示 -->
    <div class="operation-progress" id="operationProgress" style="display: none;">
        <h6 class="mb-2">批量操作进行中</h6>
        <div class="progress mb-2">
            <div class="progress-bar progress-bar-striped progress-bar-animated" 
                 role="progressbar" style="width: 0%"></div>
        </div>
        <small class="text-muted">
            <span id="operationStatus">处理中...</span>
        </small>
    </div>
    
    <!-- 加载动画 -->
    <div class="spinner-wrapper" id="loadingSpinner" style="display: none;">
        <div class="spinner-border text-primary" role="status">
            <span class="visually-hidden">加载中...</span>
        </div>
    </div>
    
    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/datatables.net@1.13.8/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/datatables.net-bs5@1.13.8/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
EOHTML1
}

function create_index_part2() {
    cat >> $WORKDIR/templates/index.html << 'EOHTML2'
    
    <script>
        // 全局变量
        let currentPage = 'dashboard';
        let refreshInterval = null;
        let selectedProxies = new Set();
        let selectedGroups = new Set();
        
        // 工具函数
        function showLoading() {
            $('#loadingSpinner').show();
        }
        
        function hideLoading() {
            $('#loadingSpinner').hide();
        }
        
        function showToast(message, type = 'success') {
            const toastHtml = `
                <div class="toast align-items-center text-white bg-${type} border-0" role="alert">
                    <div class="d-flex">
                        <div class="toast-body">${message}</div>
                        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                    </div>
                </div>
            `;
            
            const toastContainer = document.querySelector('.toast-container') || createToastContainer();
            const toastElement = $(toastHtml).appendTo(toastContainer);
            const toast = new bootstrap.Toast(toastElement[0]);
            toast.show();
            
            toastElement.on('hidden.bs.toast', function() {
                $(this).remove();
            });
        }
        
        function createToastContainer() {
            const container = document.createElement('div');
            container.className = 'toast-container position-fixed top-0 end-0 p-3';
            document.body.appendChild(container);
            return container;
        }
        
        // API请求封装
        async function api(url, options = {}) {
            try {
                const response = await fetch(url, {
                    ...options,
                    headers: {
                        'Content-Type': 'application/json',
                        ...options.headers
                    }
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || '请求失败');
                }
                
                return await response.json();
            } catch (error) {
                showToast(error.message, 'danger');
                throw error;
            }
        }
        
        // 页面加载函数
        async function loadDashboard() {
            const html = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>仪表板</h2>
                    <button class="btn btn-primary btn-sm" onclick="refreshDashboard()">
                        <i class="bi bi-arrow-clockwise"></i> 刷新
                    </button>
                </div>
                
                <!-- 统计卡片 -->
                <div class="row mb-4" id="statsCards">
                    <div class="col-md-3">
                        <div class="stat-card primary">
                            <div class="stat-icon">
                                <i class="bi bi-hdd-stack"></i>
                            </div>
                            <h3 id="totalProxies">-</h3>
                            <p>总代理数</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card success">
                            <div class="stat-icon">
                                <i class="bi bi-check-circle"></i>
                            </div>
                            <h3 id="enabledProxies">-</h3>
                            <p>启用代理</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card info">
                            <div class="stat-icon">
                                <i class="bi bi-diagram-3"></i>
                            </div>
                            <h3 id="cSegments">-</h3>
                            <p>C段数量</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card warning">
                            <div class="stat-icon">
                                <i class="bi bi-percent"></i>
                            </div>
                            <h3 id="utilization">-</h3>
                            <p>使用率</p>
                        </div>
                    </div>
                </div>
                
                <!-- 系统监控 -->
                <div class="content-card">
                    <div class="content-card-header">
                        <h5 class="mb-0">系统监控</h5>
                    </div>
                    <div class="content-card-body">
                        <div class="system-monitor" id="systemMonitor">
                            <!-- 动态加载 -->
                        </div>
                    </div>
                </div>
            `;
            
            $('#content-area').html(html);
            await refreshDashboard();
            
            // 设置自动刷新
            if (refreshInterval) clearInterval(refreshInterval);
            refreshInterval = setInterval(refreshDashboard, 5000);
        }
        
        async function refreshDashboard() {
            try {
                // 获取统计数据
                const stats = await api('/api/dashboard/stats');
                $('#totalProxies').text(stats.total_proxies.toLocaleString());
                $('#enabledProxies').text(stats.enabled_proxies.toLocaleString());
                $('#cSegments').text(stats.c_segments);
                $('#utilization').text(stats.utilization + '%');
                
                // 获取系统状态
                const systemStatus = await api('/api/system/status');
                
                const monitorHtml = `
                    <div class="monitor-item">
                        <h6>CPU使用率</h6>
                        <div class="monitor-value">${systemStatus.cpu.percent}%</div>
                        <div class="progress">
                            <div class="progress-bar bg-primary" style="width: ${systemStatus.cpu.percent}%"></div>
                        </div>
                    </div>
                    <div class="monitor-item">
                        <h6>内存使用</h6>
                        <div class="monitor-value">${systemStatus.memory.percent}%</div>
                        <div class="progress">
                            <div class="progress-bar bg-success" style="width: ${systemStatus.memory.percent}%"></div>
                        </div>
                        <small class="text-muted">${systemStatus.memory.used}GB / ${systemStatus.memory.total}GB</small>
                    </div>
                    <div class="monitor-item">
                        <h6>磁盘使用</h6>
                        <div class="monitor-value">${systemStatus.disk.percent}%</div>
                        <div class="progress">
                            <div class="progress-bar bg-info" style="width: ${systemStatus.disk.percent}%"></div>
                        </div>
                        <small class="text-muted">${systemStatus.disk.used}GB / ${systemStatus.disk.total}GB</small>
                    </div>
                    <div class="monitor-item">
                        <h6>3proxy状态</h6>
                        <div class="monitor-value">
                            ${systemStatus.proxy.running ? 
                                '<span class="text-success"><i class="bi bi-check-circle-fill"></i> 运行中</span>' : 
                                '<span class="text-danger"><i class="bi bi-x-circle-fill"></i> 已停止</span>'}
                        </div>
                        ${systemStatus.proxy.running ? 
                            `<small class="text-muted">PID: ${systemStatus.proxy.pid} | 连接: ${systemStatus.proxy.connections}</small>` : ''}
                    </div>
                `;
                
                $('#systemMonitor').html(monitorHtml);
                
            } catch (error) {
                console.error('Dashboard refresh error:', error);
            }
        }
        
        async function loadProxies() {
            const html = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>代理管理</h2>
                    <div>
                        <button class="btn btn-success btn-sm" onclick="showBatchAddModal()">
                            <i class="bi bi-plus-circle"></i> 批量添加
                        </button>
                        <button class="btn btn-primary btn-sm" onclick="loadProxyGroups()">
                            <i class="bi bi-arrow-clockwise"></i> 刷新
                        </button>
                    </div>
                </div>
                
                <!-- 搜索栏 -->
                <div class="content-card mb-3">
                    <div class="content-card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <input type="text" class="form-control" id="searchInput" 
                                       placeholder="搜索IP地址或C段...">
                            </div>
                            <div class="col-md-6">
                                <div class="btn-group" role="group">
                                    <button class="btn btn-outline-primary" onclick="exportSelected()">
                                        <i class="bi bi-download"></i> 导出选中
                                    </button>
                                    <button class="btn btn-outline-success" onclick="enableSelected()">
                                        <i class="bi bi-check-circle"></i> 启用选中
                                    </button>
                                    <button class="btn btn-outline-warning" onclick="disableSelected()">
                                        <i class="bi bi-pause-circle"></i> 禁用选中
                                    </button>
                                    <button class="btn btn-outline-danger" onclick="deleteSelected()">
                                        <i class="bi bi-trash"></i> 删除选中
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- 代理组列表 -->
                <div id="proxyGroupsList">
                    <!-- 动态加载 -->
                </div>
                
                <!-- 分页 -->
                <nav id="pagination">
                    <!-- 动态加载 -->
                </nav>
            `;
            
            $('#content-area').html(html);
            
            // 清除自动刷新
            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
            }
            
            // 加载代理组
            await loadProxyGroups();
            
            // 搜索功能
            $('#searchInput').on('input', debounce(function() {
                loadProxyGroups(1, $(this).val());
            }, 500));
        }
        
        async function loadProxyGroups(page = 1, search = '') {
            showLoading();
            try {
                const data = await api(`/api/proxy/groups?page=${page}&per_page=20&search=${encodeURIComponent(search)}`);
                
                let html = '';
                data.groups.forEach(group => {
                    html += `
                        <div class="proxy-group-card ${selectedGroups.has(group.c_segment) ? 'selected' : ''}" 
                             data-segment="${group.c_segment}">
                            <div class="row align-items-center">
                                <div class="col-md-1">
                                    <div class="form-check">
                                        <input class="form-check-input group-checkbox" type="checkbox" 
                                               value="${group.c_segment}" 
                                               ${selectedGroups.has(group.c_segment) ? 'checked' : ''}>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <h5 class="mb-1">${group.c_segment}</h5>
                                    <small class="text-muted">端口: ${group.port_range}</small>
                                </div>
                                <div class="col-md-4">
                                    <span class="badge bg-primary me-2">总数: ${group.total}</span>
                                    <span class="badge bg-success me-2">启用: ${group.enabled}</span>
                                    <span class="badge bg-secondary">禁用: ${group.disabled}</span>
                                </div>
                                <div class="col-md-4 text-end">
                                    <button class="btn btn-sm btn-primary" onclick="viewGroupDetail('${group.c_segment}')">
                                        <i class="bi bi-eye"></i> 查看
                                    </button>
                                    <button class="btn btn-sm btn-success" onclick="toggleGroup('${group.c_segment}', true)">
                                        <i class="bi bi-check-circle"></i> 全部启用
                                    </button>
                                    <button class="btn btn-sm btn-warning" onclick="toggleGroup('${group.c_segment}', false)">
                                        <i class="bi bi-pause-circle"></i> 全部禁用
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                $('#proxyGroupsList').html(html || '<p class="text-center text-muted">暂无数据</p>');
                
                // 渲染分页
                renderPagination(data.page, data.pages, (p) => loadProxyGroups(p, search));
                
                // 绑定复选框事件
                $('.group-checkbox').on('change', function() {
                    const segment = $(this).val();
                    if ($(this).is(':checked')) {
                        selectedGroups.add(segment);
                        $(this).closest('.proxy-group-card').addClass('selected');
                    } else {
                        selectedGroups.delete(segment);
                        $(this).closest('.proxy-group-card').removeClass('selected');
                    }
                });
                
            } catch (error) {
                console.error('Load proxy groups error:', error);
            } finally {
                hideLoading();
            }
        }
        
        async function viewGroupDetail(cSegment) {
            // 创建模态框显示代理详情
            const modalHtml = `
                <div class="modal fade" id="proxyDetailModal" tabindex="-1">
                    <div class="modal-dialog modal-xl">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">代理组详情 - ${cSegment}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <div id="proxyDetailContent">
                                    <div class="text-center">
                                        <div class="spinner-border" role="status">
                                            <span class="visually-hidden">加载中...</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            // 移除旧的模态框
            $('#proxyDetailModal').remove();
            $('body').append(modalHtml);
            
            const modal = new bootstrap.Modal(document.getElementById('proxyDetailModal'));
            modal.show();
            
            // 加载数据
            try {
                const data = await api(`/api/proxy/group/${cSegment}?per_page=1000`);
                
                let tableHtml = `
                    <div class="mb-3">
                        <button class="btn btn-sm btn-outline-primary" onclick="selectAllInGroup()">
                            <i class="bi bi-check-square"></i> 全选
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="unselectAllInGroup()">
                            <i class="bi bi-square"></i> 取消全选
                        </button>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-sm" id="proxyDetailTable">
                            <thead>
                                <tr>
                                    <th width="40">
                                        <input type="checkbox" class="form-check-input" id="selectAllProxies">
                                    </th>
                                    <th>ID</th>
                                    <th>IP地址</th>
                                    <th>端口</th>
                                    <th>用户名</th>
                                    <th>密码</th>
                                    <th>状态</th>
                                    <th>操作</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                
                data.proxies.forEach(proxy => {
                    tableHtml += `
                        <tr>
                            <td>
                                <input type="checkbox" class="form-check-input proxy-checkbox" 
                                       value="${proxy.id}">
                            </td>
                            <td>${proxy.id}</td>
                            <td>${proxy.ip}</td>
                            <td>${proxy.port}</td>
                            <td><code>${proxy.username}</code></td>
                            <td>
                                <div class="input-group input-group-sm">
                                    <input type="text" class="form-control" value="${proxy.password}" readonly>
                                    <button class="btn btn-outline-secondary" onclick="copyToClipboard('${proxy.password}')">
                                        <i class="bi bi-clipboard"></i>
                                    </button>
                                </div>
                            </td>
                            <td>
                                ${proxy.enabled ? 
                                    '<span class="badge bg-success">启用</span>' : 
                                    '<span class="badge bg-secondary">禁用</span>'}
                            </td>
                            <td>
                                <button class="btn btn-sm ${proxy.enabled ? 'btn-warning' : 'btn-success'}" 
                                        onclick="toggleProxy(${proxy.id}, ${!proxy.enabled})">
                                    ${proxy.enabled ? '禁用' : '启用'}
                                </button>
                            </td>
                        </tr>
                    `;
                });
                
                tableHtml += '</tbody></table></div>';
                
                $('#proxyDetailContent').html(tableHtml);
                
                // 初始化DataTable
                $('#proxyDetailTable').DataTable({
                    pageLength: 50,
                    order: [[2, 'asc'], [3, 'asc']],
                    language: {
                        url: '//cdn.datatables.net/plug-ins/1.13.8/i18n/zh.json'
                    }
                });
                
                // 绑定全选
                $('#selectAllProxies').on('change', function() {
                    $('.proxy-checkbox').prop('checked', $(this).is(':checked'));
                });
                
            } catch (error) {
                $('#proxyDetailContent').html(`
                    <div class="alert alert-danger">
                        加载失败: ${error.message}
                    </div>
                `);
            }
        }
EOHTML2
}

function create_index_part3() {
    cat >> $WORKDIR/templates/index.html << 'EOHTML3'
        
        async function loadBatchOperations() {
            const html = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>批量操作</h2>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="content-card">
                            <div class="content-card-header">
                                <h5 class="mb-0">批量添加代理</h5>
                            </div>
                            <div class="content-card-body">
                                <form id="importForm">
                                    <div class="mb-3">
                                        <label class="form-label">选择文件</label>
                                        <input type="file" class="form-control" name="file" 
                                               accept=".txt,.csv" required>
                                        <small class="text-muted">
                                            支持格式: IP:端口:用户名:密码 (每行一个)
                                        </small>
                                    </div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="bi bi-upload"></i> 导入
                                    </button>
                                </form>
                                
                                <hr class="my-4">
                                
                                <h6>快速导出</h6>
                                <div class="btn-group" role="group">
                                    <button class="btn btn-outline-primary" onclick="exportAll('txt')">
                                        <i class="bi bi-file-text"></i> 导出TXT
                                    </button>
                                    <button class="btn btn-outline-primary" onclick="exportAll('json')">
                                        <i class="bi bi-file-code"></i> 导出JSON
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            $('#content-area').html(html);
            
            // 绑定表单提交
            $('#batchAddForm').on('submit', async function(e) {
                e.preventDefault();
                const formData = new FormData(this);
                const data = Object.fromEntries(formData);
                
                showLoading();
                try {
                    const result = await api('/api/proxy/batch/add', {
                        method: 'POST',
                        body: JSON.stringify(data)
                    });
                    
                    showToast(result.message, 'success');
                    trackOperation(result.operation_id);
                    this.reset();
                } catch (error) {
                    console.error('Batch add error:', error);
                } finally {
                    hideLoading();
                }
            });
            
            $('#importForm').on('submit', async function(e) {
                e.preventDefault();
                const formData = new FormData(this);
                
                showLoading();
                try {
                    const response = await fetch('/api/proxy/import', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    if (response.ok) {
                        showToast(result.message, 'success');
                        trackOperation(result.operation_id);
                        this.reset();
                    } else {
                        throw new Error(result.error);
                    }
                } catch (error) {
                    showToast(error.message, 'danger');
                } finally {
                    hideLoading();
                }
            });
        }
        
        async function loadNetworkConfig() {
            const html = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>网络配置</h2>
                </div>
                
                <div class="content-card">
                    <div class="content-card-header">
                        <h5 class="mb-0">IP地址管理</h5>
                    </div>
                    <div class="content-card-body">
                        <form id="addIpForm" class="row g-3 mb-4">
                            <div class="col-md-3">
                                <label class="form-label">网络接口</label>
                                <select class="form-select" name="interface" id="interfaceSelect" required>
                                    <!-- 动态加载 -->
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">IP范围</label>
                                <input type="text" class="form-control" name="ip_range" 
                                       placeholder="例: 192.168.1.1-254" required>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">&nbsp;</label>
                                <button type="submit" class="btn btn-primary d-block w-100">
                                    <i class="bi bi-plus-circle"></i> 添加IP
                                </button>
                            </div>
                        </form>
                        
                        <div id="interfacesList">
                            <!-- 动态加载 -->
                        </div>
                    </div>
                </div>
            `;
            
            $('#content-area').html(html);
            
            // 加载网络接口
            const interfaces = await api('/api/network/interfaces');
            let options = '';
            interfaces.interfaces.forEach(iface => {
                options += `<option value="${iface.name}">${iface.name} (${iface.ip})</option>`;
            });
            $('#interfaceSelect').html(options);
            
            // 显示接口信息
            let ifaceHtml = '<h6>当前网络接口</h6><div class="table-responsive"><table class="table"><thead><tr><th>接口</th><th>IP地址</th><th>子网掩码</th></tr></thead><tbody>';
            interfaces.interfaces.forEach(iface => {
                ifaceHtml += `<tr><td>${iface.name}</td><td>${iface.ip}</td><td>${iface.netmask}</td></tr>`;
            });
            ifaceHtml += '</tbody></table></div>';
            $('#interfacesList').html(ifaceHtml);
            
            // 绑定表单
            $('#addIpForm').on('submit', async function(e) {
                e.preventDefault();
                const formData = new FormData(this);
                const data = Object.fromEntries(formData);
                
                showLoading();
                try {
                    const result = await api('/api/network/ip/add', {
                        method: 'POST',
                        body: JSON.stringify(data)
                    });
                    
                    showToast(`${result.message} (成功: ${result.success}, 失败: ${result.failed})`, 'success');
                    this.reset();
                } catch (error) {
                    console.error('Add IP error:', error);
                } finally {
                    hideLoading();
                }
            });
        }
        
        async function loadUsers() {
            const html = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>用户管理</h2>
                </div>
                
                <div class="content-card">
                    <div class="content-card-header">
                        <h5 class="mb-0">系统用户</h5>
                    </div>
                    <div class="content-card-body">
                        <form id="addUserForm" class="row g-3 mb-4">
                            <div class="col-md-5">
                                <label class="form-label">用户名</label>
                                <input type="text" class="form-control" name="username" required>
                            </div>
                            <div class="col-md-5">
                                <label class="form-label">密码</label>
                                <input type="password" class="form-control" name="password" required>
                            </div>
                            <div class="col-md-2">
                                <label class="form-label">&nbsp;</label>
                                <button type="submit" class="btn btn-primary d-block w-100">
                                    <i class="bi bi-person-plus"></i> 添加
                                </button>
                            </div>
                        </form>
                        
                        <div id="usersList">
                            <!-- 动态加载 -->
                        </div>
                    </div>
                </div>
            `;
            
            $('#content-area').html(html);
            
            // 加载用户列表
            await refreshUsersList();
            
            // 绑定表单
            $('#addUserForm').on('submit', async function(e) {
                e.preventDefault();
                const formData = new FormData(this);
                const data = Object.fromEntries(formData);
                
                showLoading();
                try {
                    const result = await api('/api/users/add', {
                        method: 'POST',
                        body: JSON.stringify(data)
                    });
                    
                    showToast(result.message, 'success');
                    this.reset();
                    await refreshUsersList();
                } catch (error) {
                    console.error('Add user error:', error);
                } finally {
                    hideLoading();
                }
            });
        }
        
        async function refreshUsersList() {
            const data = await api('/api/users');
            let html = '<div class="table-responsive"><table class="table"><thead><tr><th>ID</th><th>用户名</th><th>操作</th></tr></thead><tbody>';
            
            data.users.forEach(user => {
                html += `
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
            
            html += '</tbody></table></div>';
            $('#usersList').html(html);
        }
        
        async function deleteUser(userId) {
            if (!confirm('确定要删除此用户吗？')) return;
            
            try {
                const result = await api(`/api/users/delete/${userId}`, { method: 'DELETE' });
                showToast(result.message, 'success');
                await refreshUsersList();
            } catch (error) {
                console.error('Delete user error:', error);
            }
        }
        
        async function loadLogs() {
            const html = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>日志查看</h2>
                </div>
                
                <div class="content-card">
                    <div class="content-card-header">
                        <h5 class="mb-0">系统日志</h5>
                    </div>
                    <div class="content-card-body">
                        <div class="row mb-3">
                            <div class="col-md-4">
                                <select class="form-select" id="logTypeSelect">
                                    <option value="proxy">3proxy日志</option>
                                    <option value="webapp">Web应用日志</option>
                                    <option value="monitor">监控日志</option>
                                </select>
                            </div>
                            <div class="col-md-4">
                                <input type="number" class="form-control" id="logLines" 
                                       value="100" min="10" max="1000" placeholder="显示行数">
                            </div>
                            <div class="col-md-4">
                                <button class="btn btn-primary" onclick="loadLogContent()">
                                    <i class="bi bi-arrow-clockwise"></i> 刷新日志
                                </button>
                            </div>
                        </div>
                        
                        <div id="logContent" style="height: 500px; overflow-y: auto; background: #f8f9fa; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.9rem;">
                            <!-- 日志内容 -->
                        </div>
                    </div>
                </div>
            `;
            
            $('#content-area').html(html);
            await loadLogContent();
        }
        
        async function loadLogContent() {
            const logType = $('#logTypeSelect').val();
            const lines = $('#logLines').val();
            
            showLoading();
            try {
                const data = await api(`/api/logs/view?type=${logType}&lines=${lines}`);
                $('#logContent').html(`<pre>${escapeHtml(data.content)}</pre>`);
                
                // 滚动到底部
                const logDiv = document.getElementById('logContent');
                logDiv.scrollTop = logDiv.scrollHeight;
            } catch (error) {
                $('#logContent').html(`<div class="alert alert-danger">加载日志失败: ${error.message}</div>`);
            } finally {
                hideLoading();
            }
        }
        
        async function loadSettings() {
            const html = `
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>系统设置</h2>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="content-card">
                            <div class="content-card-header">
                                <h5 class="mb-0">配置管理</h5>
                            </div>
                            <div class="content-card-body">
                                <button class="btn btn-primary mb-3" onclick="reloadConfig()">
                                    <i class="bi bi-arrow-clockwise"></i> 重新加载配置
                                </button>
                                <p class="text-muted">
                                    重新生成并加载3proxy配置文件，应用所有更改。
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="content-card">
                            <div class="content-card-header">
                                <h5 class="mb-0">系统信息</h5>
                            </div>
                            <div class="content-card-body">
                                <table class="table table-sm">
                                    <tr>
                                        <td>版本</td>
                                        <td>3proxy Enterprise 2.0</td>
                                    </tr>
                                    <tr>
                                        <td>安装路径</td>
                                        <td>/opt/3proxy-enterprise</td>
                                    </tr>
                                    <tr>
                                        <td>配置目录</td>
                                        <td>/usr/local/etc/3proxy</td>
                                    </tr>
                                    <tr>
                                        <td>日志目录</td>
                                        <td>/var/log/3proxy</td>
                                    </tr>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            $('#content-area').html(html);
        }
        
        // 批量操作跟踪
        function trackOperation(operationId) {
            const checkStatus = async () => {
                try {
                    const status = await api(`/api/proxy/batch/operation/${operationId}`);
                    
                    if (status.status === 'running') {
                        // 显示进度
                        const progress = Math.round((status.processed / status.total) * 100);
                        $('#operationProgress').show();
                        $('#operationProgress .progress-bar').css('width', progress + '%');
                        $('#operationStatus').text(`已处理 ${status.processed}/${status.total}`);
                        
                        // 继续检查
                        setTimeout(() => checkStatus(), 1000);
                    } else {
                        // 操作完成
                        $('#operationProgress').fadeOut(3000);
                        showToast(`操作完成: 成功 ${status.success}, 失败 ${status.failed}`, 
                                 status.failed > 0 ? 'warning' : 'success');
                        
                        // 刷新当前页面
                        if (currentPage === 'proxies') {
                            loadProxyGroups();
                        }
                    }
                } catch (error) {
                    console.error('Track operation error:', error);
                    $('#operationProgress').hide();
                }
            };
            
            checkStatus();
        }
        
        // 工具函数
        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
        
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, m => map[m]);
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('已复制到剪贴板', 'success');
            }).catch(() => {
                showToast('复制失败', 'danger');
            });
        }
        
        function renderPagination(currentPage, totalPages, callback) {
            if (totalPages <= 1) {
                $('#pagination').empty();
                return;
            }
            
            let html = '<ul class="pagination justify-content-center">';
            
            // 上一页
            html += `<li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
                        <a class="page-link" href="#" data-page="${currentPage - 1}">上一页</a>
                     </li>`;
            
            // 页码
            const range = 2;
            for (let i = Math.max(1, currentPage - range); i <= Math.min(totalPages, currentPage + range); i++) {
                html += `<li class="page-item ${i === currentPage ? 'active' : ''}">
                            <a class="page-link" href="#" data-page="${i}">${i}</a>
                         </li>`;
            }
            
            // 下一页
            html += `<li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
                        <a class="page-link" href="#" data-page="${currentPage + 1}">下一页</a>
                     </li>`;
            
            html += '</ul>';
            
            $('#pagination').html(html);
            
            // 绑定点击事件
            $('#pagination .page-link').on('click', function(e) {
                e.preventDefault();
                const page = parseInt($(this).data('page'));
                if (page && !$(this).parent().hasClass('disabled')) {
                    callback(page);
                }
            });
        }
        
        // 代理操作函数
        async function toggleProxy(proxyId, enable) {
            try {
                await api('/api/proxy/batch/toggle', {
                    method: 'POST',
                    body: JSON.stringify({
                        ids: [proxyId],
                        enabled: enable
                    })
                });
                
                showToast(`代理已${enable ? '启用' : '禁用'}`, 'success');
                
                // 刷新模态框内容
                const modal = bootstrap.Modal.getInstance(document.getElementById('proxyDetailModal'));
                if (modal) {
                    const modalTitle = $('#proxyDetailModal .modal-title').text();
                    const cSegment = modalTitle.split(' - ')[1];
                    if (cSegment) {
                        viewGroupDetail(cSegment);
                    }
                }
            } catch (error) {
                console.error('Toggle proxy error:', error);
            }
        }
        
        async function toggleGroup(cSegment, enable) {
            if (!confirm(`确定要${enable ? '启用' : '禁用'}整个C段的代理吗？`)) return;
            
            showLoading();
            try {
                // 先获取该组所有代理ID
                const data = await api(`/api/proxy/group/${cSegment}?per_page=10000`);
                const ids = data.proxies.map(p => p.id);
                
                if (ids.length > 0) {
                    const result = await api('/api/proxy/batch/toggle', {
                        method: 'POST',
                        body: JSON.stringify({
                            ids: ids,
                            enabled: enable
                        })
                    });
                    
                    showToast(result.message, 'success');
                    trackOperation(result.operation_id);
                }
            } catch (error) {
                console.error('Toggle group error:', error);
            } finally {
                hideLoading();
            }
        }
        
        async function exportSelected() {
            if (selectedGroups.size === 0) {
                showToast('请先选择要导出的代理组', 'warning');
                return;
            }
            
            try {
                const response = await fetch('/api/proxy/export', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        format: 'txt',
                        c_segments: Array.from(selectedGroups)
                    })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'proxies_export.txt';
                    a.click();
                    window.URL.revokeObjectURL(url);
                    
                    showToast('导出成功', 'success');
                } else {
                    throw new Error('导出失败');
                }
            } catch (error) {
                showToast(error.message, 'danger');
            }
        }
        
        async function exportAll(format) {
            try {
                const response = await fetch('/api/proxy/export', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ format: format })
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `proxies_all.${format}`;
                    a.click();
                    window.URL.revokeObjectURL(url);
                    
                    showToast('导出成功', 'success');
                } else {
                    throw new Error('导出失败');
                }
            } catch (error) {
                showToast(error.message, 'danger');
            }
        }
        
        async function enableSelected() {
            await batchToggleSelected(true);
        }
        
        async function disableSelected() {
            await batchToggleSelected(false);
        }
        
        async function batchToggleSelected(enable) {
            if (selectedGroups.size === 0) {
                showToast('请先选择代理组', 'warning');
                return;
            }
            
            if (!confirm(`确定要${enable ? '启用' : '禁用'}选中的代理组吗？`)) return;
            
            showLoading();
            try {
                // 获取所有选中组的代理ID
                let allIds = [];
                for (const cSegment of selectedGroups) {
                    const data = await api(`/api/proxy/group/${cSegment}?per_page=10000`);
                    allIds = allIds.concat(data.proxies.map(p => p.id));
                }
                
                if (allIds.length > 0) {
                    const result = await api('/api/proxy/batch/toggle', {
                        method: 'POST',
                        body: JSON.stringify({
                            ids: allIds,
                            enabled: enable
                        })
                    });
                    
                    showToast(result.message, 'success');
                    trackOperation(result.operation_id);
                }
            } catch (error) {
                console.error('Batch toggle error:', error);
            } finally {
                hideLoading();
            }
        }
        
        async function deleteSelected() {
            if (selectedGroups.size === 0) {
                showToast('请先选择代理组', 'warning');
                return;
            }
            
            if (!confirm('确定要删除选中的代理组吗？此操作不可恢复！')) return;
            
            showLoading();
            try {
                // 获取所有选中组的代理ID
                let allIds = [];
                for (const cSegment of selectedGroups) {
                    const data = await api(`/api/proxy/group/${cSegment}?per_page=10000`);
                    allIds = allIds.concat(data.proxies.map(p => p.id));
                }
                
                if (allIds.length > 0) {
                    const result = await api('/api/proxy/batch/delete', {
                        method: 'POST',
                        body: JSON.stringify({ ids: allIds })
                    });
                    
                    showToast(result.message, 'success');
                    trackOperation(result.operation_id);
                    
                    // 清空选择
                    selectedGroups.clear();
                }
            } catch (error) {
                console.error('Batch delete error:', error);
            } finally {
                hideLoading();
            }
        }
        
        async function reloadConfig() {
            if (!confirm('确定要重新加载配置吗？这将重启3proxy服务。')) return;
            
            showLoading();
            try {
                const result = await api('/api/config/reload', { method: 'POST' });
                showToast(result.message, 'success');
            } catch (error) {
                console.error('Reload config error:', error);
            } finally {
                hideLoading();
            }
        }
        
        // 初始化
        $(document).ready(function() {
            // 侧边栏切换
            $('#sidebarToggle').on('click', function() {
                $('#sidebar').toggleClass('show');
            });
            
            // 侧边栏菜单点击
            $('.sidebar-item').on('click', function(e) {
                e.preventDefault();
                
                // 更新活动状态
                $('.sidebar-item').removeClass('active');
                $(this).addClass('active');
                
                // 加载对应页面
                const page = $(this).data('page');
                currentPage = page;
                
                // 清除定时器
                if (refreshInterval) {
                    clearInterval(refreshInterval);
                    refreshInterval = null;
                }
                
                // 清空选择
                selectedGroups.clear();
                selectedProxies.clear();
                
                // 加载页面内容
                switch (page) {
                    case 'dashboard':
                        loadDashboard();
                        break;
                    case 'proxies':
                        loadProxies();
                        break;
                    case 'batch':
                        loadBatchOperations();
                        break;
                    case 'network':
                        loadNetworkConfig();
                        break;
                    case 'users':
                        loadUsers();
                        break;
                    case 'logs':
                        loadLogs();
                        break;
                    case 'settings':
                        loadSettings();
                        break;
                }
                
                // 移动端关闭侧边栏
                if ($(window).width() < 768) {
                    $('#sidebar').removeClass('show');
                }
            });
            
            // 默认加载仪表板
            loadDashboard();
            
            // 响应式处理
            $(window).on('resize', function() {
                if ($(window).width() >= 768) {
                    $('#sidebar').removeClass('show');
                }
            });
        });
    </script>
</body>
</html>
EOHTML3
}

function create_systemd_services() {
    print_info "创建系统服务..."
    
    # 3proxy服务
    cat > /etc/systemd/system/3proxy-enterprise.service << 'EOF'
[Unit]
Description=3proxy Enterprise Proxy Server
After=network.target

[Service]
Type=forking
PIDFile=/run/3proxy/3proxy.pid
ExecStartPre=/bin/mkdir -p /run/3proxy
ExecStart=/usr/local/bin/3proxy-enterprise.sh
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=10000000
LimitNPROC=10000000
LimitSTACK=67108864
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

    # Web管理服务
    cat > /etc/systemd/system/3proxy-web.service << 'EOF'
[Unit]
Description=3proxy Enterprise Web Management
After=network.target redis-server.service

[Service]
Type=simple
WorkingDirectory=/opt/3proxy-enterprise
Environment="FLASK_ENV=production"
Environment="ADMIN_PASSWORD=ADMIN_PASS_PLACEHOLDER"
ExecStart=/opt/3proxy-enterprise/venv/bin/python /opt/3proxy-enterprise/app.py 9999
Restart=always
RestartSec=5
User=root
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
EOF

    # 使用Supervisor管理多个worker进程
    cat > /etc/supervisor/conf.d/3proxy-web.conf << 'EOF'
[program:3proxy-web]
command=/opt/3proxy-enterprise/venv/bin/gunicorn -c /opt/3proxy-enterprise/gunicorn_config.py app:app
directory=/opt/3proxy-enterprise
user=root
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/3proxy/web.log
environment=FLASK_ENV="production"
EOF

    # Gunicorn配置文件
    cat > $WORKDIR/gunicorn_config.py << 'EOF'
import multiprocessing
import os

bind = "0.0.0.0:9999"
workers = min(multiprocessing.cpu_count() * 2 + 1, 16)
worker_class = "gevent"
worker_connections = 1000
timeout = 120
keepalive = 5
max_requests = 10000
max_requests_jitter = 1000
preload_app = True
accesslog = "/var/log/3proxy/access.log"
errorlog = "/var/log/3proxy/error.log"
loglevel = "info"

# 性能优化
backlog = 2048
daemon = False
pidfile = "/run/3proxy/gunicorn.pid"
EOF

    # Nginx反向代理配置
    cat > /etc/nginx/sites-available/3proxy-enterprise << 'EOF'
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:9999;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # 超时设置
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # 缓冲设置
        proxy_buffering off;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
        
        # 上传大小限制
        client_max_body_size 100M;
    }
    
    # 静态文件
    location /static {
        alias /opt/3proxy-enterprise/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

    # 启用Nginx站点
    ln -sf /etc/nginx/sites-available/3proxy-enterprise /etc/nginx/sites-enabled/
    
    # 重载systemd
    systemctl daemon-reload
    
    print_success "系统服务创建完成"
}

function initialize_database() {
    print_info "初始化数据库..."
    
    cd $WORKDIR
    source venv/bin/activate
    
    # 创建初始化脚本
    cat > init_db.py << 'EOF'
#!/usr/bin/env python3
import os
import sqlite3
from werkzeug.security import generate_password_hash

# 创建数据库
db_path = '/opt/3proxy-enterprise/3proxy.db'
conn = sqlite3.connect(db_path)

# 启用WAL模式
conn.execute('PRAGMA journal_mode=WAL')
conn.execute('PRAGMA synchronous=NORMAL')

# 创建表
conn.executescript('''
    CREATE TABLE IF NOT EXISTS proxy (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        ip_range TEXT,
        port_range TEXT,
        user_prefix TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(ip, port)
    );
    
    CREATE INDEX IF NOT EXISTS idx_proxy_ip ON proxy(ip);
    CREATE INDEX IF NOT EXISTS idx_proxy_port ON proxy(port);
    CREATE INDEX IF NOT EXISTS idx_proxy_enabled ON proxy(enabled);
    CREATE INDEX IF NOT EXISTS idx_proxy_c_segment ON proxy(
        substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.'))
    );
    
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS ip_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_str TEXT NOT NULL,
        type TEXT NOT NULL,
        iface TEXT NOT NULL,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS operation_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        operation TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
''')

# 创建管理员用户
admin_user = os.environ.get('ADMINUSER', 'admin')
admin_pass = os.environ.get('ADMINPASS', 'admin123456')
password_hash = generate_password_hash(admin_pass)

conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", 
             (admin_user, password_hash))
conn.commit()
conn.close()

print(f"数据库初始化完成")
print(f"管理员用户: {admin_user}")
print(f"管理员密码: {admin_pass}")
EOF

    # 运行初始化
    export ADMINUSER="admin$RANDOM"
    export ADMINPASS=$(tr -dc 'A-Za-z0-9!@#batchAddForm">
                                    <div class="mb-3">
                                        <label class="form-label">IP范围</label>
                                        <input type="text" class="form-control" name="ip_range" 
                                               placeholder="例: 192.168.1.1-254" required>
                                        <small class="text-muted">支持格式: x.x.x.1-254 或 x.x.x.1-x.x.x.254</small>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">起始端口</label>
                                                <input type="number" class="form-control" name="port_start" 
                                                       value="10000" min="1024" max="65535" required>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">结束端口</label>
                                                <input type="number" class="form-control" name="port_end" 
                                                       value="60000" min="1024" max="65535" required>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">用户名前缀</label>
                                        <input type="text" class="form-control" name="user_prefix" 
                                               value="user" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">密码长度</label>
                                        <input type="number" class="form-control" name="password_length" 
                                               value="12" min="8" max="32" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="bi bi-plus-circle"></i> 批量添加
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="content-card">
                            <div class="content-card-header">
                                <h5 class="mb-0">导入代理</h5>
                            </div>
                            <div class="content-card-body">
                                <form id="#!/bin/bash
set -e

# 3proxy企业级管理系统安装脚本 v2.0 (修复版)
# 支持Debian 11/12，优化为128G内存32核服务器
# 修复引号匹配问题

WORKDIR=/opt/3proxy-enterprise
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_DIR=/usr/local/etc/3proxy
PROXYCFG_PATH=$PROXYCFG_DIR/3proxy.cfg
LOGDIR=/var/log/3proxy
LOGFILE=$LOGDIR/3proxy.log
CREDS_FILE=/opt/3proxy-enterprise/.credentials
CACHE_DIR=/var/cache/3proxy
RUNTIME_DIR=/run/3proxy

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m'

function print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function get_local_ip() {
    local pubip lanip
    pubip=$(curl -s --connect-timeout 5 ifconfig.me || curl -s --connect-timeout 5 ip.sb || curl -s --connect-timeout 5 icanhazip.com || echo "")
    lanip=$(hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 2>/dev/null | awk '{print $NF;exit}' || echo "127.0.0.1")
    if [[ -n "$pubip" && "$pubip" != "$lanip" ]]; then
        echo "$pubip"
    else
        echo "$lanip"
    fi
}

function show_credentials() {
    if [ -f "$CREDS_FILE" ]; then
        echo -e "\n========= 3proxy Enterprise 登录信息 ========="
        cat "$CREDS_FILE"
        echo -e "============================================\n"
    else
        print_error "未找到登录凭据文件。请运行安装脚本。"
    fi
}

function check_system() {
    print_info "检查系统环境..."
    
    # 检查操作系统
    if ! grep -qE "Debian GNU/Linux (11|12)" /etc/os-release 2>/dev/null; then
        print_warning "当前系统可能不是 Debian 11/12，继续安装可能遇到兼容性问题"
    fi
    
    # 检查内存
    total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 16 ]; then
        print_warning "系统内存小于16GB，建议升级硬件以获得最佳性能"
    fi
    
    # 检查CPU核心数
    cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 8 ]; then
        print_warning "CPU核心数小于8，可能影响并发性能"
    fi
    
    print_success "系统检查完成 (内存: ${total_mem}GB, CPU: ${cpu_cores}核)"
}

function optimize_system() {
    print_info "执行系统性能优化..."
    
    # 检查是否已经优化过
    if grep -q "# 3proxy Enterprise Performance Tuning" /etc/sysctl.conf 2>/dev/null; then
        print_warning "系统已经优化过，跳过..."
        return
    fi
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)
    
    # 企业级内核参数优化
    cat >> /etc/sysctl.conf << 'EOF'

# 3proxy Enterprise Performance Tuning
# 针对128G内存32核服务器优化，支持百万级并发连接

# 基础网络设置
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1

# TCP优化 - 支持大规模并发
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_orphan_retries = 1
net.ipv4.tcp_retries2 = 5

# 端口范围 - 最大化可用端口
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 3128,8080,8888,9999

# 连接跟踪 - 支持千万级并发
net.netfilter.nf_conntrack_max = 10000000
net.netfilter.nf_conntrack_buckets = 2500000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_generic_timeout = 120

# 套接字缓冲区 - 针对128G内存优化
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.core.optmem_max = 134217728
net.ipv4.tcp_mem = 786432 1048576 134217728
net.ipv4.udp_mem = 786432 1048576 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 524288
net.core.wmem_default = 524288
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

# ARP表优化
net.ipv4.neigh.default.gc_thresh1 = 8192
net.ipv4.neigh.default.gc_thresh2 = 32768
net.ipv4.neigh.default.gc_thresh3 = 65536
net.ipv6.neigh.default.gc_thresh1 = 8192
net.ipv6.neigh.default.gc_thresh2 = 32768
net.ipv6.neigh.default.gc_thresh3 = 65536

# 路由缓存
net.ipv4.route.max_size = 8388608
net.ipv4.route.gc_timeout = 300

# 文件系统优化
fs.file-max = 10000000
fs.nr_open = 10000000
fs.inotify.max_user_instances = 65536
fs.inotify.max_user_watches = 1048576
fs.aio-max-nr = 1048576

# 内存管理优化
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.max_map_count = 655360
vm.overcommit_memory = 1

# 安全相关
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# CPU调度优化
kernel.sched_migration_cost_ns = 5000000
kernel.sched_autogroup_enabled = 0
EOF
    
    # 立即应用
    sysctl -p >/dev/null 2>&1
    
    # 加载必要的内核模块
    modprobe nf_conntrack >/dev/null 2>&1
    modprobe nf_conntrack_ipv4 >/dev/null 2>&1 || true  # Debian 12可能不需要
    
    # 设置conntrack hashsize
    echo 2500000 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    
    # 优化limits
    if ! grep -q "# 3proxy Enterprise limits" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf << 'EOF'

# 3proxy Enterprise limits
* soft nofile 10000000
* hard nofile 10000000
* soft nproc 10000000
* hard nproc 10000000
* soft stack 65536
* hard stack 65536
root soft nofile 10000000
root hard nofile 10000000
root soft nproc 10000000
root hard nproc 10000000
EOF
    fi
    
    # 优化systemd限制
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/3proxy-limits.conf << 'EOF'
[Manager]
DefaultLimitNOFILE=10000000
DefaultLimitNPROC=10000000
DefaultLimitSTACK=67108864
DefaultTasksMax=infinity
EOF
    
    # 创建优化的启动脚本
    cat > /usr/local/bin/3proxy-enterprise.sh << 'EOF'
#!/bin/bash
# 3proxy Enterprise启动脚本

# 设置运行时限制
ulimit -n 10000000
ulimit -u 10000000
ulimit -s 65536

# CPU亲和性设置 - 将3proxy绑定到特定CPU核心
CORES=$(nproc)
if [ $CORES -ge 32 ]; then
    # 为3proxy预留后16个核心
    taskset -c 16-31 /usr/local/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
else
    # 使用所有可用核心
    /usr/local/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
fi
EOF
    
    chmod +x /usr/local/bin/3proxy-enterprise.sh
    
    # 禁用透明大页
    echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
    echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
    
    print_success "系统优化完成！已配置为支持千万级并发连接"
}

function setup_directories() {
    print_info "创建必要的目录结构..."
    
    # 创建目录
    mkdir -p $WORKDIR/{templates,static,backups,configs,scripts}
    mkdir -p $PROXYCFG_DIR
    mkdir -p $LOGDIR
    mkdir -p $CACHE_DIR
    mkdir -p $RUNTIME_DIR
    
    # 设置权限
    chmod 755 $WORKDIR
    chmod 755 $PROXYCFG_DIR
    chmod 755 $LOGDIR
    chmod 755 $CACHE_DIR
    chmod 755 $RUNTIME_DIR
    
    print_success "目录创建完成"
}

function install_dependencies() {
    print_info "安装依赖包..."
    
    # 更新包列表
    apt update
    
    # 安装编译工具和基础包
    apt install -y gcc make git wget curl \
        python3 python3-pip python3-venv python3-dev \
        sqlite3 libsqlite3-dev \
        redis-server \
        nginx \
        supervisor \
        htop iotop iftop \
        net-tools dnsutils \
        cron logrotate \
        build-essential \
        libssl-dev libffi-dev \
        libevent-dev \
        libmaxminddb0 libmaxminddb-dev mmdb-bin
    
    # 启动Redis（用于缓存）
    systemctl enable redis-server
    systemctl start redis-server
    
    print_success "依赖安装完成"
}

function compile_3proxy() {
    print_info "编译安装3proxy..."
    
    if [ ! -f "$THREEPROXY_PATH" ]; then
        cd /tmp
        rm -rf 3proxy
        git clone --depth=1 https://github.com/3proxy/3proxy.git
        cd 3proxy
        
        # 修改编译配置以支持更多连接
        sed -i 's/MAXUSERS 128/MAXUSERS 100000/g' src/structures.h 2>/dev/null || true
        
        # 编译
        make -f Makefile.Linux
        make -f Makefile.Linux install
        
        # 确保二进制文件存在
        if [ ! -f /usr/local/bin/3proxy ]; then
            cp src/3proxy /usr/local/bin/3proxy
        fi
        
        chmod +x /usr/local/bin/3proxy
        
        print_success "3proxy编译安装完成"
    else
        print_warning "3proxy已安装，跳过编译"
    fi
}

function setup_initial_config() {
    print_info "创建初始配置..."
    
    # 创建基础配置文件
    cat > $PROXYCFG_PATH << 'EOF'
# 3proxy Enterprise Configuration
# 支持百万级并发连接

daemon
pidfile /run/3proxy/3proxy.pid
config /usr/local/etc/3proxy/3proxy.cfg
monitor /usr/local/etc/3proxy/3proxy.cfg

# 性能参数
maxconn 1000000
stacksize 262144

# DNS配置
nserver 8.8.8.8
nserver 8.8.4.4
nserver 1.1.1.1
nserver 1.0.0.1
nscache 262144
nscache6 65536

# 超时设置（优化为快速释放资源）
timeouts 1 3 10 30 60 180 1800 15 60

# 日志配置
log /var/log/3proxy/3proxy.log D
logformat "L%t %N.%p %E %U %C:%c %R:%r %O %I %h %T"
rotate 100M
archiver gz /usr/bin/gzip %F

# 访问控制
auth none

# 认证方式将由Python动态生成
# 代理配置将由Python动态生成
EOF
    
    print_success "初始配置创建完成"
}

function setup_log_rotation() {
    print_info "配置日志轮转..."
    
    cat > /etc/logrotate.d/3proxy << 'EOF'
/var/log/3proxy/*.log {
    daily
    rotate 7
    maxsize 1G
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        /usr/bin/killall -USR1 3proxy 2>/dev/null || true
    endscript
}
EOF
    
    print_success "日志轮转配置完成"
}

function setup_backup() {
    print_info "设置自动备份..."
    
    # 创建备份脚本
    cat > $WORKDIR/scripts/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/3proxy-enterprise/backups"
DB_FILE="/opt/3proxy-enterprise/3proxy.db"
CONFIG_DIR="/usr/local/etc/3proxy"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7

# 确保备份目录存在
mkdir -p "$BACKUP_DIR"

# 清理旧备份
find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true

# 创建新备份
cd /
tar -czf "$BACKUP_DIR/backup_$DATE.tar.gz" \
    "$DB_FILE" \
    "$CONFIG_DIR" \
    --exclude="$CONFIG_DIR/*.log*" \
    2>/dev/null || true

echo "[$(date)] Backup completed: backup_$DATE.tar.gz"

# 如果备份目录超过10GB，删除最旧的备份
BACKUP_SIZE=$(du -sb "$BACKUP_DIR" | awk '{print $1}')
if [ $BACKUP_SIZE -gt 10737418240 ]; then
    ls -t "$BACKUP_DIR"/backup_*.tar.gz | tail -n +10 | xargs rm -f 2>/dev/null || true
fi
EOF
    
    chmod +x $WORKDIR/scripts/backup.sh
    
    # 设置定时备份
    echo "0 2 * * * root $WORKDIR/scripts/backup.sh >> $LOGDIR/backup.log 2>&1" > /etc/cron.d/3proxy-backup
    
    print_success "自动备份已设置（每天凌晨2点）"
}

function setup_monitoring() {
    print_info "设置监控脚本..."
    
    # 创建监控脚本
    cat > $WORKDIR/scripts/monitor.sh << 'EOF'
#!/bin/bash
# 3proxy监控脚本

PIDFILE="/run/3proxy/3proxy.pid"
LOGFILE="/var/log/3proxy/monitor.log"
MAX_MEMORY_MB=65536  # 最大内存使用量(MB)
MAX_CPU_PERCENT=800  # 最大CPU使用率(800% = 8核心满载)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOGFILE
}

# 检查3proxy是否运行
if [ -f "$PIDFILE" ]; then
    PID=$(cat $PIDFILE)
    if ! kill -0 $PID 2>/dev/null; then
        log "ERROR: 3proxy进程不存在，正在重启..."
        systemctl restart 3proxy-enterprise
        exit 1
    fi
    
    # 获取进程信息
    STATS=$(ps -p $PID -o pid,vsz,rss,pcpu,comm --no-headers)
    if [ -n "$STATS" ]; then
        VSZ=$(echo $STATS | awk '{print $2}')
        RSS=$(echo $STATS | awk '{print $3}')
        CPU=$(echo $STATS | awk '{print $4}')
        
        RSS_MB=$((RSS/1024))
        
        # 检查内存使用
        if [ $RSS_MB -gt $MAX_MEMORY_MB ]; then
            log "WARNING: 内存使用过高 (${RSS_MB}MB > ${MAX_MEMORY_MB}MB)"
            # 可以在这里添加告警通知
        fi
        
        # 检查CPU使用
        CPU_INT=$(echo $CPU | cut -d. -f1)
        if [ $CPU_INT -gt $MAX_CPU_PERCENT ]; then
            log "WARNING: CPU使用过高 (${CPU}% > ${MAX_CPU_PERCENT}%)"
        fi
        
        # 记录统计信息
        echo "$(date '+%s')|$RSS_MB|$CPU" >> /var/log/3proxy/stats.log
    fi
else
    log "ERROR: PID文件不存在，正在重启3proxy..."
    systemctl restart 3proxy-enterprise
fi

# 清理旧的统计数据（保留24小时）
tail -n 1440 /var/log/3proxy/stats.log > /var/log/3proxy/stats.log.tmp 2>/dev/null
mv -f /var/log/3proxy/stats.log.tmp /var/log/3proxy/stats.log 2>/dev/null || true
EOF
    
    chmod +x $WORKDIR/scripts/monitor.sh
    
    # 设置定时监控（每分钟）
    echo "* * * * * root $WORKDIR/scripts/monitor.sh" > /etc/cron.d/3proxy-monitor
    
    print_success "监控脚本设置完成"
}

function create_web_application() {
    print_info "创建Web管理应用..."
    
    cd $WORKDIR
    
    # 创建Python虚拟环境
    python3 -m venv venv
    source venv/bin/activate
    
    # 安装Python包
    pip install --upgrade pip
    pip install flask flask_login flask_wtf wtforms \
                werkzeug psutil redis \
                gunicorn gevent \
                sqlalchemy alembic \
                click python-dotenv \
                --no-cache-dir
    
    # 创建主应用文件 (分成多个部分以避免引号问题)
    create_app_part1
    create_app_part2
    create_app_part3
    create_app_part4
    
    # 创建模板文件
    create_templates
    
    print_success "Web应用创建完成"
}

function create_app_part1() {
    cat > $WORKDIR/app.py << 'EOAPP1'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
3proxy Enterprise Management System
支持百万级代理管理的高性能Web管理系统
"""

import os
import sys
import sqlite3
import random
import string
import re
import json
import time
import threading
import queue
import psutil
import redis
import hashlib
import datetime
import subprocess
import signal
from collections import defaultdict, OrderedDict
from functools import wraps, lru_cache
from contextlib import contextmanager

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response, g
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from logging.handlers import RotatingFileHandler

# 配置常量
DB_PATH = '/opt/3proxy-enterprise/3proxy.db'
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
CACHE_TTL = 300  # 缓存5分钟
BATCH_SIZE = 1000  # 批量操作大小
MAX_WORKERS = 16  # 最大工作线程数
CONFIG_CHUNK_SIZE = 10000  # 配置文件分片大小

# 初始化Flask应用
app = Flask(__name__, 
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'enterprise-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# 初始化日志
def setup_logging():
    if not app.debug:
        file_handler = RotatingFileHandler(
            '/var/log/3proxy/webapp.log',
            maxBytes=10485760,
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('3proxy Enterprise startup')

setup_logging()

# 初始化登录管理器
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录'

# 初始化Redis连接池
redis_pool = redis.ConnectionPool(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    max_connections=100,
    decode_responses=True
)

# 线程池
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# 数据库连接池
class DatabasePool:
    def __init__(self, database, max_connections=50):
        self.database = database
        self.max_connections = max_connections
        self.pool = queue.Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        self._initialize_pool()
    
    def _initialize_pool(self):
        for _ in range(self.max_connections):
            conn = sqlite3.connect(self.database, timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            self.pool.put(conn)
    
    @contextmanager
    def get_connection(self):
        conn = self.pool.get()
        try:
            yield conn
        finally:
            self.pool.put(conn)

# 初始化数据库连接池
db_pool = DatabasePool(DB_PATH)

# Redis缓存装饰器
def redis_cache(key_prefix, ttl=CACHE_TTL):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            r = redis.Redis(connection_pool=redis_pool)
            
            # 生成缓存键
            cache_key = f"{key_prefix}:{hashlib.md5(str(args).encode() + str(kwargs).encode()).hexdigest()}"
            
            # 尝试从缓存获取
            cached = r.get(cache_key)
            if cached:
                return json.loads(cached)
            
            # 执行函数
            result = f(*args, **kwargs)
            
            # 存入缓存
            r.setex(cache_key, ttl, json.dumps(result))
            
            return result
        return wrapped
    return decorator

# 用户模型
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def get(user_id):
        with db_pool.get_connection() as conn:
            cur = conn.execute("SELECT id, username, password FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            if row:
                return User(row['id'], row['username'], row['password'])
        return None
    
    @staticmethod
    def get_by_username(username):
        with db_pool.get_connection() as conn:
            cur = conn.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row:
                return User(row['id'], row['username'], row['password'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
EOAPP1
}

function create_app_part2() {
    cat >> $WORKDIR/app.py << 'EOAPP2'

# 代理配置生成器（支持分片）
class ProxyConfigGenerator:
    def __init__(self):
        self.config_dir = '/usr/local/etc/3proxy'
        self.chunk_size = CONFIG_CHUNK_SIZE
    
    def generate_configs(self):
        """生成3proxy配置文件（支持分片）"""
        app.logger.info("开始生成代理配置...")
        
        with db_pool.get_connection() as conn:
            # 获取所有启用的代理
            cursor = conn.execute(
                "SELECT ip, port, username, password FROM proxy WHERE enabled = 1 ORDER BY id"
            )
            
            # 生成主配置文件
            self._generate_main_config()
            
            # 生成用户认证文件
            users_dict = {}
            proxy_configs = []
            
            for row in cursor:
                ip, port, username, password = row
                users_dict[username] = password
                proxy_configs.append((ip, port, username))
            
            # 写入用户文件（分片）
            self._write_users_file(users_dict)
            
            # 写入代理配置（分片）
            self._write_proxy_configs(proxy_configs)
        
        app.logger.info(f"配置生成完成，共{len(proxy_configs)}个代理")
        
        # 重载3proxy
        self._reload_3proxy()
    
    def _generate_main_config(self):
        """生成主配置文件"""
        config = """# 3proxy Enterprise Configuration
# Auto-generated - DO NOT EDIT MANUALLY

daemon
pidfile /run/3proxy/3proxy.pid
monitor /usr/local/etc/3proxy/

# 性能参数
maxconn 1000000
stacksize 262144

# DNS配置
nserver 8.8.8.8
nserver 8.8.4.4
nserver 1.1.1.1
nscache 262144
nscache6 65536

# 超时设置
timeouts 1 3 10 30 60 180 1800 15 60

# 日志配置
log /var/log/3proxy/3proxy.log D
logformat "L%t %N.%p %E %U %C:%c %R:%r %O %I %h %T"
rotate 100M

# 包含其他配置文件
include /usr/local/etc/3proxy/users.cfg
include /usr/local/etc/3proxy/proxies/*.cfg
"""
        
        with open(f"{self.config_dir}/3proxy.cfg", 'w') as f:
            f.write(config)
    
    def _write_users_file(self, users_dict):
        """写入用户认证文件（支持大量用户）"""
        os.makedirs(f"{self.config_dir}/proxies", exist_ok=True)
        
        with open(f"{self.config_dir}/users.cfg", 'w') as f:
            f.write("# Users configuration\n")
            f.write("auth strong\n")
            
            # 分批写入用户
            users_list = [f"{user}:CL:{passwd}" for user, passwd in users_dict.items()]
            for i in range(0, len(users_list), 1000):
                batch = users_list[i:i+1000]
                f.write(f"users {' '.join(batch)}\n")
    
    def _write_proxy_configs(self, proxy_configs):
        """写入代理配置（分片）"""
        # 清理旧配置
        import glob
        for old_file in glob.glob(f"{self.config_dir}/proxies/*.cfg"):
            os.remove(old_file)
        
        # 分片写入
        for i in range(0, len(proxy_configs), self.chunk_size):
            chunk = proxy_configs[i:i+self.chunk_size]
            chunk_id = i // self.chunk_size
            
            with open(f"{self.config_dir}/proxies/proxy_{chunk_id:04d}.cfg", 'w') as f:
                f.write(f"# Proxy chunk {chunk_id}\n")
                
                for ip, port, username in chunk:
                    f.write(f"auth strong\n")
                    f.write(f"allow {username}\n")
                    f.write(f"proxy -n -a -p{port} -i{ip} -e{ip}\n")
                    f.write("\n")
    
    def _reload_3proxy(self):
        """重载3proxy配置"""
        try:
            # 发送SIGHUP信号重载配置
            subprocess.run(['pkill', '-HUP', '3proxy'], check=False)
            app.logger.info("3proxy配置重载成功")
        except Exception as e:
            app.logger.error(f"3proxy重载失败: {e}")
            # 如果重载失败，尝试重启
            try:
                subprocess.run(['systemctl', 'restart', '3proxy-enterprise'], check=True)
                app.logger.info("3proxy重启成功")
            except Exception as e2:
                app.logger.error(f"3proxy重启失败: {e2}")

# 实例化配置生成器
config_generator = ProxyConfigGenerator()

# 批量操作管理器
class BatchOperationManager:
    def __init__(self):
        self.operations = {}
        self.lock = threading.Lock()
    
    def create_operation(self, operation_type, total_items):
        """创建批量操作"""
        op_id = hashlib.md5(f"{operation_type}:{time.time()}".encode()).hexdigest()
        
        with self.lock:
            self.operations[op_id] = {
                'type': operation_type,
                'total': total_items,
                'processed': 0,
                'success': 0,
                'failed': 0,
                'status': 'running',
                'start_time': time.time(),
                'errors': []
            }
        
        return op_id
    
    def update_progress(self, op_id, success=True, error=None):
        """更新操作进度"""
        with self.lock:
            if op_id in self.operations:
                op = self.operations[op_id]
                op['processed'] += 1
                
                if success:
                    op['success'] += 1
                else:
                    op['failed'] += 1
                    if error:
                        op['errors'].append(error)
                
                if op['processed'] >= op['total']:
                    op['status'] = 'completed'
                    op['end_time'] = time.time()
    
    def get_status(self, op_id):
        """获取操作状态"""
        with self.lock:
            return self.operations.get(op_id, {})

# 实例化批量操作管理器
batch_manager = BatchOperationManager()

# 工具函数
def get_network_interfaces():
    """获取网络接口列表"""
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        if name != 'lo':  # 排除回环接口
            for addr in addrs:
                if addr.family == 2:  # IPv4
                    interfaces.append({
                        'name': name,
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
    return interfaces

def validate_ip_range(ip_range):
    """验证IP范围格式"""
    # 支持格式: 192.168.1.1-254 或 192.168.1.1-192.168.1.254
    pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}|(\d{1,3}\.){3}\d{1,3})$'
    return re.match(pattern, ip_range) is not None

def expand_ip_range(ip_range):
    """展开IP范围"""
    ips = []
    
    if '-' in ip_range:
        parts = ip_range.split('-')
        if '.' in parts[1]:
            # 完整IP范围: 192.168.1.1-192.168.1.254
            start_ip = parts[0]
            end_ip = parts[1]
            
            start_parts = [int(x) for x in start_ip.split('.')]
            end_parts = [int(x) for x in end_ip.split('.')]
            
            current = start_parts[:]
            while current <= end_parts:
                ips.append('.'.join(map(str, current)))
                
                current[3] += 1
                for i in range(3, 0, -1):
                    if current[i] > 255:
                        current[i] = 0
                        current[i-1] += 1
                
                if current[0] > 255:
                    break
        else:
            # 简短格式: 192.168.1.1-254
            base = '.'.join(parts[0].split('.')[:-1])
            start = int(parts[0].split('.')[-1])
            end = int(parts[1])
            
            for i in range(start, end + 1):
                if i <= 255:
                    ips.append(f"{base}.{i}")
    
    return ips
EOAPP2
}

function create_app_part3() {
    cat >> $WORKDIR/app.py << 'EOAPP3'

# 路由处理函数
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_by_username(username)
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        
        flash('用户名或密码错误', 'danger')
    
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

# API路由
@app.route('/api/dashboard/stats')
@login_required
@redis_cache('dashboard_stats', ttl=60)
def api_dashboard_stats():
    """获取仪表板统计信息"""
    with db_pool.get_connection() as conn:
        # 总代理数
        total = conn.execute("SELECT COUNT(*) FROM proxy").fetchone()[0]
        
        # 启用的代理数
        enabled = conn.execute("SELECT COUNT(*) FROM proxy WHERE enabled = 1").fetchone()[0]
        
        # C段统计
        c_segments = conn.execute(
            "SELECT COUNT(DISTINCT substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.'))) FROM proxy"
        ).fetchone()[0]
        
        # 端口范围
        port_range = conn.execute(
            "SELECT MIN(port), MAX(port) FROM proxy"
        ).fetchone()
    
    return jsonify({
        'total_proxies': total,
        'enabled_proxies': enabled,
        'disabled_proxies': total - enabled,
        'c_segments': c_segments,
        'port_range': f"{port_range[0]}-{port_range[1]}" if port_range[0] else "N/A",
        'utilization': round(enabled / total * 100, 2) if total > 0 else 0
    })

@app.route('/api/system/status')
@login_required
def api_system_status():
    """获取系统状态"""
    # CPU使用率
    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
    cpu_avg = sum(cpu_percent) / len(cpu_percent)
    
    # 内存信息
    memory = psutil.virtual_memory()
    
    # 磁盘信息
    disk = psutil.disk_usage('/')
    
    # 网络IO
    net_io = psutil.net_io_counters()
    
    # 3proxy进程信息
    proxy_info = {'running': False, 'pid': None, 'cpu': 0, 'memory': 0, 'connections': 0}
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'connections']):
        try:
            if proc.info['name'] == '3proxy':
                proxy_info['running'] = True
                proxy_info['pid'] = proc.info['pid']
                proxy_info['cpu'] = proc.cpu_percent(interval=0.1)
                proxy_info['memory'] = proc.memory_info().rss / 1024 / 1024  # MB
                proxy_info['connections'] = len(proc.connections())
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    return jsonify({
        'cpu': {
            'percent': round(cpu_avg, 2),
            'cores': len(cpu_percent),
            'per_core': [round(p, 2) for p in cpu_percent]
        },
        'memory': {
            'total': round(memory.total / 1024 / 1024 / 1024, 2),  # GB
            'used': round(memory.used / 1024 / 1024 / 1024, 2),
            'available': round(memory.available / 1024 / 1024 / 1024, 2),
            'percent': round(memory.percent, 2)
        },
        'disk': {
            'total': round(disk.total / 1024 / 1024 / 1024, 2),  # GB
            'used': round(disk.used / 1024 / 1024 / 1024, 2),
            'free': round(disk.free / 1024 / 1024 / 1024, 2),
            'percent': round(disk.percent, 2)
        },
        'network': {
            'bytes_sent': round(net_io.bytes_sent / 1024 / 1024, 2),  # MB
            'bytes_recv': round(net_io.bytes_recv / 1024 / 1024, 2),
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        },
        'proxy': proxy_info,
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/api/proxy/groups')
@login_required
def api_proxy_groups():
    """获取代理组列表（C段分组）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    with db_pool.get_connection() as conn:
        # 构建查询
        query = """
            SELECT 
                substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.')) as c_segment,
                COUNT(*) as total,
                SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled,
                MIN(port) as min_port,
                MAX(port) as max_port,
                GROUP_CONCAT(DISTINCT user_prefix) as prefixes
            FROM proxy
        """
        
        if search:
            query += " WHERE ip LIKE ?"
            params = (f"%{search}%",)
        else:
            params = ()
        
        query += " GROUP BY c_segment ORDER BY c_segment"
        
        # 获取总数
        count_query = f"SELECT COUNT(DISTINCT substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.'))) FROM proxy"
        if search:
            count_query += " WHERE ip LIKE ?"
        
        total = conn.execute(count_query, params).fetchone()[0]
        
        # 分页查询
        query += f" LIMIT {per_page} OFFSET {(page - 1) * per_page}"
        
        cursor = conn.execute(query, params)
        groups = []
        
        for row in cursor:
            groups.append({
                'c_segment': row['c_segment'],
                'total': row['total'],
                'enabled': row['enabled'],
                'disabled': row['total'] - row['enabled'],
                'port_range': f"{row['min_port']}-{row['max_port']}",
                'prefixes': row['prefixes'].split(',') if row['prefixes'] else []
            })
    
    return jsonify({
        'groups': groups,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/api/proxy/group/<c_segment>')
@login_required
def api_proxy_group_detail(c_segment):
    """获取代理组详情"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)
    
    with db_pool.get_connection() as conn:
        # 获取总数
        total = conn.execute(
            "SELECT COUNT(*) FROM proxy WHERE ip LIKE ?",
            (f"{c_segment}%",)
        ).fetchone()[0]
        
        # 获取代理列表
        cursor = conn.execute(
            """
            SELECT id, ip, port, username, password, enabled
            FROM proxy
            WHERE ip LIKE ?
            ORDER BY ip, port
            LIMIT ? OFFSET ?
            """,
            (f"{c_segment}%", per_page, (page - 1) * per_page)
        )
        
        proxies = []
        for row in cursor:
            proxies.append({
                'id': row['id'],
                'ip': row['ip'],
                'port': row['port'],
                'username': row['username'],
                'password': row['password'],
                'enabled': bool(row['enabled'])
            })
    
    return jsonify({
        'proxies': proxies,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/api/proxy/batch/add', methods=['POST'])
@login_required
def api_proxy_batch_add():
    """批量添加代理"""
    data = request.get_json()
    
    ip_range = data.get('ip_range')
    port_start = data.get('port_start', 10000)
    port_end = data.get('port_end', 60000)
    user_prefix = data.get('user_prefix', 'user')
    password_length = data.get('password_length', 12)
    
    # 验证IP范围
    if not validate_ip_range(ip_range):
        return jsonify({'error': 'IP范围格式错误'}), 400
    
    # 展开IP范围
    ips = expand_ip_range(ip_range)
    if not ips:
        return jsonify({'error': '无效的IP范围'}), 400
    
    if len(ips) > 10000:
        return jsonify({'error': 'IP数量超过限制(10000)'}), 400
    
    # 创建批量操作
    op_id = batch_manager.create_operation('batch_add_proxy', len(ips))
    
    # 异步执行批量添加
    def batch_add_worker():
        with db_pool.get_connection() as conn:
            # 获取已使用的端口
            used_ports = set()
            cursor = conn.execute("SELECT port FROM proxy")
            for row in cursor:
                used_ports.add(row[0])
            
            # 生成可用端口池
            available_ports = [p for p in range(port_start, port_end + 1) if p not in used_ports]
            if len(available_ports) < len(ips):
                batch_manager.update_progress(op_id, False, "可用端口不足")
                return
            
            # 随机选择端口
            random.shuffle(available_ports)
            selected_ports = available_ports[:len(ips)]
            
            # 批量插入
            batch_data = []
            for i, ip in enumerate(ips):
                username = f"{user_prefix}{random.randint(1000, 9999)}"
                password = ''.join(random.choices(string.ascii_letters + string.digits, k=password_length))
                port = selected_ports[i]
                
                batch_data.append((ip, port, username, password, 1, ip_range, f"{port_start}-{port_end}", user_prefix))
                
                if len(batch_data) >= BATCH_SIZE:
                    conn.executemany(
                        "INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        batch_data
                    )
                    conn.commit()
                    
                    for _ in batch_data:
                        batch_manager.update_progress(op_id, True)
                    
                    batch_data = []
            
            # 插入剩余数据
            if batch_data:
                conn.executemany(
                    "INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    batch_data
                )
                conn.commit()
                
                for _ in batch_data:
                    batch_manager.update_progress(op_id, True)
        
        # 重新生成配置
        config_generator.generate_configs()
    
    # 提交到线程池执行
    executor.submit(batch_add_worker)
    
    return jsonify({'operation_id': op_id, 'message': '批量添加任务已创建'})

@app.route('/api/proxy/batch/operation/<op_id>')
@login_required
def api_batch_operation_status(op_id):
    """获取批量操作状态"""
    status = batch_manager.get_status(op_id)
    if not status:
        return jsonify({'error': '操作不存在'}), 404
    
    return jsonify(status)

@app.route('/api/proxy/batch/delete', methods=['POST'])
@login_required
def api_proxy_batch_delete():
    """批量删除代理"""
    data = request.get_json()
    proxy_ids = data.get('ids', [])
    
    if not proxy_ids:
        return jsonify({'error': '未选择代理'}), 400
    
    # 创建批量操作
    op_id = batch_manager.create_operation('batch_delete_proxy', len(proxy_ids))
    
    # 异步执行批量删除
    def batch_delete_worker():
        with db_pool.get_connection() as conn:
            # 分批删除
            for i in range(0, len(proxy_ids), BATCH_SIZE):
                batch = proxy_ids[i:i+BATCH_SIZE]
                placeholders = ','.join('?' * len(batch))
                
                conn.execute(f"DELETE FROM proxy WHERE id IN ({placeholders})", batch)
                conn.commit()
                
                for _ in batch:
                    batch_manager.update_progress(op_id, True)
        
        # 重新生成配置
        config_generator.generate_configs()
    
    # 提交到线程池执行
    executor.submit(batch_delete_worker)
    
    return jsonify({'operation_id': op_id, 'message': '批量删除任务已创建'})

@app.route('/api/proxy/batch/toggle', methods=['POST'])
@login_required
def api_proxy_batch_toggle():
    """批量启用/禁用代理"""
    data = request.get_json()
    proxy_ids = data.get('ids', [])
    enabled = data.get('enabled', True)
    
    if not proxy_ids:
        return jsonify({'error': '未选择代理'}), 400
    
    # 创建批量操作
    op_id = batch_manager.create_operation('batch_toggle_proxy', len(proxy_ids))
    
    # 异步执行批量更新
    def batch_toggle_worker():
        with db_pool.get_connection() as conn:
            # 分批更新
            for i in range(0, len(proxy_ids), BATCH_SIZE):
                batch = proxy_ids[i:i+BATCH_SIZE]
                placeholders = ','.join('?' * len(batch))
                
                conn.execute(
                    f"UPDATE proxy SET enabled = ? WHERE id IN ({placeholders})",
                    [1 if enabled else 0] + batch
                )
                conn.commit()
                
                for _ in batch:
                    batch_manager.update_progress(op_id, True)
        
        # 重新生成配置
        config_generator.generate_configs()
    
    # 提交到线程池执行
    executor.submit(batch_toggle_worker)
    
    return jsonify({'operation_id': op_id, 'message': f'批量{"启用" if enabled else "禁用"}任务已创建'})

@app.route('/api/proxy/export', methods=['POST'])
@login_required
def api_proxy_export():
    """导出代理"""
    data = request.get_json()
    format_type = data.get('format', 'txt')
    c_segments = data.get('c_segments', [])
    
    with db_pool.get_connection() as conn:
        if c_segments:
            # 导出指定C段
            placeholders = ','.join('?' * len(c_segments))
            cursor = conn.execute(
                f"SELECT ip, port, username, password FROM proxy WHERE substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.')) IN ({placeholders}) ORDER BY ip, port",
                c_segments
            ) </dev/urandom | head -c 16)
    
    python init_db.py
    
    # 保存凭据
    cat > $CREDS_FILE << EOF
========================================
3proxy Enterprise 管理系统
========================================
访问地址: http://$(get_local_ip)
管理员用户: $ADMINUSER
管理员密码: $ADMINPASS
安装时间: $(date)

系统信息:
- 安装目录: $WORKDIR
- 配置目录: $PROXYCFG_DIR
- 日志目录: $LOGDIR
- 数据库: $WORKDIR/3proxy.db

注意事项:
- 首次登录后请及时修改密码
- 定期备份数据库文件
- 查看日志: tail -f $LOGDIR/*.log
========================================
EOF

    chmod 600 $CREDS_FILE
    
    # 更新服务文件中的密码
    sed -i "s/ADMIN_PASS_PLACEHOLDER/$ADMINPASS/g" /etc/systemd/system/3proxy-web.service
    
    print_success "数据库初始化完成"
}

function start_services() {
    print_info "启动服务..."
    
    # 启动Redis
    systemctl start redis-server
    
    # 启动Nginx
    systemctl restart nginx
    
    # 启动3proxy
    systemctl enable 3proxy-enterprise
    systemctl start 3proxy-enterprise
    
    # 启动Web管理
    systemctl enable 3proxy-web
    systemctl start 3proxy-web
    
    # 启动Supervisor
    systemctl restart supervisor
    
    print_success "所有服务已启动"
}

function uninstall_system() {
    print_warning "开始卸载3proxy Enterprise系统..."
    
    # 停止服务
    systemctl stop 3proxy-enterprise 2>/dev/null || true
    systemctl stop 3proxy-web 2>/dev/null || true
    systemctl disable 3proxy-enterprise 2>/dev/null || true
    systemctl disable 3proxy-web 2>/dev/null || true
    
    # 删除文件
    rm -rf $WORKDIR
    rm -rf $PROXYCFG_DIR
    rm -rf $LOGDIR
    rm -rf $CACHE_DIR
    rm -rf $RUNTIME_DIR
    rm -f /usr/local/bin/3proxy
    rm -f /usr/local/bin/3proxy-enterprise.sh
    rm -f /etc/systemd/system/3proxy-enterprise.service
    rm -f /etc/systemd/system/3proxy-web.service
    rm -f /etc/supervisor/conf.d/3proxy-web.conf
    rm -f /etc/nginx/sites-enabled/3proxy-enterprise
    rm -f /etc/nginx/sites-available/3proxy-enterprise
    rm -f /etc/logrotate.d/3proxy
    rm -f /etc/cron.d/3proxy-*
    
    # 重载systemd
    systemctl daemon-reload
    
    print_success "3proxy Enterprise系统已完全卸载"
}

# 主程序
case "$1" in
    "uninstall")
        uninstall_system
        exit 0
        ;;
    "reinstall")
        uninstall_system
        print_info "准备重新安装..."
        ;;
    "show")
        show_credentials
        exit 0
        ;;
esac

# 安装流程
print_info "========== 3proxy Enterprise 安装程序 =========="
print_info "版本: 2.0 Enterprise Edition"
print_info "支持: 百万级代理并发管理"
print_info "=============================================="

# 检查系统
check_system

# 系统优化
optimize_system

# 创建目录
setup_directories

# 安装依赖
install_dependencies

# 编译3proxy
compile_3proxy

# 设置初始配置
setup_initial_config

# 设置日志轮转
setup_log_rotation

# 设置备份
setup_backup

# 设置监控
setup_monitoring

# 创建Web应用
create_web_application

# 创建系统服务
create_systemd_services

# 初始化数据库
initialize_database

# 启动服务
start_services

# 显示安装信息
print_success "\n========== 安装完成 =========="
cat $CREDS_FILE
print_info "\n常用命令:"
print_info "查看登录信息: bash $0 show"
print_info "卸载系统: bash $0 uninstall" 
print_info "重新安装: bash $0 reinstall"
print_info "查看日志: tail -f /var/log/3proxy/*.log"
print_info "重启服务: systemctl restart 3proxy-enterprise 3proxy-web"

print_warning "\n重要提示:"
print_warning "1. 请妥善保管管理员账号密码"
print_warning "2. 建议配置防火墙规则保护管理端口"
print_warning "3. 定期备份 $WORKDIR/3proxy.db 数据库文件"
print_warning "4. 系统已优化支持千万级并发连接"batchAddForm">
                                    <div class="mb-3">
                                        <label class="form-label">IP范围</label>
                                        <input type="text" class="form-control" name="ip_range" 
                                               placeholder="例: 192.168.1.1-254" required>
                                        <small class="text-muted">支持格式: x.x.x.1-254 或 x.x.x.1-x.x.x.254</small>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">起始端口</label>
                                                <input type="number" class="form-control" name="port_start" 
                                                       value="10000" min="1024" max="65535" required>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">结束端口</label>
                                                <input type="number" class="form-control" name="port_end" 
                                                       value="60000" min="1024" max="65535" required>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">用户名前缀</label>
                                        <input type="text" class="form-control" name="user_prefix" 
                                               value="user" required>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">密码长度</label>
                                        <input type="number" class="form-control" name="password_length" 
                                               value="12" min="8" max="32" required>
                                    </div>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="bi bi-plus-circle"></i> 批量添加
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="content-card">
                            <div class="content-card-header">
                                <h5 class="mb-0">导入代理</h5>
                            </div>
                            <div class="content-card-body">
                                <form id="#!/bin/bash
set -e

# 3proxy企业级管理系统安装脚本 v2.0 (修复版)
# 支持Debian 11/12，优化为128G内存32核服务器
# 修复引号匹配问题

WORKDIR=/opt/3proxy-enterprise
THREEPROXY_PATH=/usr/local/bin/3proxy
PROXYCFG_DIR=/usr/local/etc/3proxy
PROXYCFG_PATH=$PROXYCFG_DIR/3proxy.cfg
LOGDIR=/var/log/3proxy
LOGFILE=$LOGDIR/3proxy.log
CREDS_FILE=/opt/3proxy-enterprise/.credentials
CACHE_DIR=/var/cache/3proxy
RUNTIME_DIR=/run/3proxy

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
NC='\033[0m'

function print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function get_local_ip() {
    local pubip lanip
    pubip=$(curl -s --connect-timeout 5 ifconfig.me || curl -s --connect-timeout 5 ip.sb || curl -s --connect-timeout 5 icanhazip.com || echo "")
    lanip=$(hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 2>/dev/null | awk '{print $NF;exit}' || echo "127.0.0.1")
    if [[ -n "$pubip" && "$pubip" != "$lanip" ]]; then
        echo "$pubip"
    else
        echo "$lanip"
    fi
}

function show_credentials() {
    if [ -f "$CREDS_FILE" ]; then
        echo -e "\n========= 3proxy Enterprise 登录信息 ========="
        cat "$CREDS_FILE"
        echo -e "============================================\n"
    else
        print_error "未找到登录凭据文件。请运行安装脚本。"
    fi
}

function check_system() {
    print_info "检查系统环境..."
    
    # 检查操作系统
    if ! grep -qE "Debian GNU/Linux (11|12)" /etc/os-release 2>/dev/null; then
        print_warning "当前系统可能不是 Debian 11/12，继续安装可能遇到兼容性问题"
    fi
    
    # 检查内存
    total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 16 ]; then
        print_warning "系统内存小于16GB，建议升级硬件以获得最佳性能"
    fi
    
    # 检查CPU核心数
    cpu_cores=$(nproc)
    if [ "$cpu_cores" -lt 8 ]; then
        print_warning "CPU核心数小于8，可能影响并发性能"
    fi
    
    print_success "系统检查完成 (内存: ${total_mem}GB, CPU: ${cpu_cores}核)"
}

function optimize_system() {
    print_info "执行系统性能优化..."
    
    # 检查是否已经优化过
    if grep -q "# 3proxy Enterprise Performance Tuning" /etc/sysctl.conf 2>/dev/null; then
        print_warning "系统已经优化过，跳过..."
        return
    fi
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)
    
    # 企业级内核参数优化
    cat >> /etc/sysctl.conf << 'EOF'

# 3proxy Enterprise Performance Tuning
# 针对128G内存32核服务器优化，支持百万级并发连接

# 基础网络设置
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1

# TCP优化 - 支持大规模并发
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_orphan_retries = 1
net.ipv4.tcp_retries2 = 5

# 端口范围 - 最大化可用端口
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 3128,8080,8888,9999

# 连接跟踪 - 支持千万级并发
net.netfilter.nf_conntrack_max = 10000000
net.netfilter.nf_conntrack_buckets = 2500000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_generic_timeout = 120

# 套接字缓冲区 - 针对128G内存优化
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.core.optmem_max = 134217728
net.ipv4.tcp_mem = 786432 1048576 134217728
net.ipv4.udp_mem = 786432 1048576 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 524288
net.core.wmem_default = 524288
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

# ARP表优化
net.ipv4.neigh.default.gc_thresh1 = 8192
net.ipv4.neigh.default.gc_thresh2 = 32768
net.ipv4.neigh.default.gc_thresh3 = 65536
net.ipv6.neigh.default.gc_thresh1 = 8192
net.ipv6.neigh.default.gc_thresh2 = 32768
net.ipv6.neigh.default.gc_thresh3 = 65536

# 路由缓存
net.ipv4.route.max_size = 8388608
net.ipv4.route.gc_timeout = 300

# 文件系统优化
fs.file-max = 10000000
fs.nr_open = 10000000
fs.inotify.max_user_instances = 65536
fs.inotify.max_user_watches = 1048576
fs.aio-max-nr = 1048576

# 内存管理优化
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.max_map_count = 655360
vm.overcommit_memory = 1

# 安全相关
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# CPU调度优化
kernel.sched_migration_cost_ns = 5000000
kernel.sched_autogroup_enabled = 0
EOF
    
    # 立即应用
    sysctl -p >/dev/null 2>&1
    
    # 加载必要的内核模块
    modprobe nf_conntrack >/dev/null 2>&1
    modprobe nf_conntrack_ipv4 >/dev/null 2>&1 || true  # Debian 12可能不需要
    
    # 设置conntrack hashsize
    echo 2500000 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    
    # 优化limits
    if ! grep -q "# 3proxy Enterprise limits" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf << 'EOF'

# 3proxy Enterprise limits
* soft nofile 10000000
* hard nofile 10000000
* soft nproc 10000000
* hard nproc 10000000
* soft stack 65536
* hard stack 65536
root soft nofile 10000000
root hard nofile 10000000
root soft nproc 10000000
root hard nproc 10000000
EOF
    fi
    
    # 优化systemd限制
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/3proxy-limits.conf << 'EOF'
[Manager]
DefaultLimitNOFILE=10000000
DefaultLimitNPROC=10000000
DefaultLimitSTACK=67108864
DefaultTasksMax=infinity
EOF
    
    # 创建优化的启动脚本
    cat > /usr/local/bin/3proxy-enterprise.sh << 'EOF'
#!/bin/bash
# 3proxy Enterprise启动脚本

# 设置运行时限制
ulimit -n 10000000
ulimit -u 10000000
ulimit -s 65536

# CPU亲和性设置 - 将3proxy绑定到特定CPU核心
CORES=$(nproc)
if [ $CORES -ge 32 ]; then
    # 为3proxy预留后16个核心
    taskset -c 16-31 /usr/local/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
else
    # 使用所有可用核心
    /usr/local/bin/3proxy /usr/local/etc/3proxy/3proxy.cfg
fi
EOF
    
    chmod +x /usr/local/bin/3proxy-enterprise.sh
    
    # 禁用透明大页
    echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
    echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
    
    print_success "系统优化完成！已配置为支持千万级并发连接"
}

function setup_directories() {
    print_info "创建必要的目录结构..."
    
    # 创建目录
    mkdir -p $WORKDIR/{templates,static,backups,configs,scripts}
    mkdir -p $PROXYCFG_DIR
    mkdir -p $LOGDIR
    mkdir -p $CACHE_DIR
    mkdir -p $RUNTIME_DIR
    
    # 设置权限
    chmod 755 $WORKDIR
    chmod 755 $PROXYCFG_DIR
    chmod 755 $LOGDIR
    chmod 755 $CACHE_DIR
    chmod 755 $RUNTIME_DIR
    
    print_success "目录创建完成"
}

function install_dependencies() {
    print_info "安装依赖包..."
    
    # 更新包列表
    apt update
    
    # 安装编译工具和基础包
    apt install -y gcc make git wget curl \
        python3 python3-pip python3-venv python3-dev \
        sqlite3 libsqlite3-dev \
        redis-server \
        nginx \
        supervisor \
        htop iotop iftop \
        net-tools dnsutils \
        cron logrotate \
        build-essential \
        libssl-dev libffi-dev \
        libevent-dev \
        libmaxminddb0 libmaxminddb-dev mmdb-bin
    
    # 启动Redis（用于缓存）
    systemctl enable redis-server
    systemctl start redis-server
    
    print_success "依赖安装完成"
}

function compile_3proxy() {
    print_info "编译安装3proxy..."
    
    if [ ! -f "$THREEPROXY_PATH" ]; then
        cd /tmp
        rm -rf 3proxy
        git clone --depth=1 https://github.com/3proxy/3proxy.git
        cd 3proxy
        
        # 修改编译配置以支持更多连接
        sed -i 's/MAXUSERS 128/MAXUSERS 100000/g' src/structures.h 2>/dev/null || true
        
        # 编译
        make -f Makefile.Linux
        make -f Makefile.Linux install
        
        # 确保二进制文件存在
        if [ ! -f /usr/local/bin/3proxy ]; then
            cp src/3proxy /usr/local/bin/3proxy
        fi
        
        chmod +x /usr/local/bin/3proxy
        
        print_success "3proxy编译安装完成"
    else
        print_warning "3proxy已安装，跳过编译"
    fi
}

function setup_initial_config() {
    print_info "创建初始配置..."
    
    # 创建基础配置文件
    cat > $PROXYCFG_PATH << 'EOF'
# 3proxy Enterprise Configuration
# 支持百万级并发连接

daemon
pidfile /run/3proxy/3proxy.pid
config /usr/local/etc/3proxy/3proxy.cfg
monitor /usr/local/etc/3proxy/3proxy.cfg

# 性能参数
maxconn 1000000
stacksize 262144

# DNS配置
nserver 8.8.8.8
nserver 8.8.4.4
nserver 1.1.1.1
nserver 1.0.0.1
nscache 262144
nscache6 65536

# 超时设置（优化为快速释放资源）
timeouts 1 3 10 30 60 180 1800 15 60

# 日志配置
log /var/log/3proxy/3proxy.log D
logformat "L%t %N.%p %E %U %C:%c %R:%r %O %I %h %T"
rotate 100M
archiver gz /usr/bin/gzip %F

# 访问控制
auth none

# 认证方式将由Python动态生成
# 代理配置将由Python动态生成
EOF
    
    print_success "初始配置创建完成"
}

function setup_log_rotation() {
    print_info "配置日志轮转..."
    
    cat > /etc/logrotate.d/3proxy << 'EOF'
/var/log/3proxy/*.log {
    daily
    rotate 7
    maxsize 1G
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        /usr/bin/killall -USR1 3proxy 2>/dev/null || true
    endscript
}
EOF
    
    print_success "日志轮转配置完成"
}

function setup_backup() {
    print_info "设置自动备份..."
    
    # 创建备份脚本
    cat > $WORKDIR/scripts/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/3proxy-enterprise/backups"
DB_FILE="/opt/3proxy-enterprise/3proxy.db"
CONFIG_DIR="/usr/local/etc/3proxy"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7

# 确保备份目录存在
mkdir -p "$BACKUP_DIR"

# 清理旧备份
find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true

# 创建新备份
cd /
tar -czf "$BACKUP_DIR/backup_$DATE.tar.gz" \
    "$DB_FILE" \
    "$CONFIG_DIR" \
    --exclude="$CONFIG_DIR/*.log*" \
    2>/dev/null || true

echo "[$(date)] Backup completed: backup_$DATE.tar.gz"

# 如果备份目录超过10GB，删除最旧的备份
BACKUP_SIZE=$(du -sb "$BACKUP_DIR" | awk '{print $1}')
if [ $BACKUP_SIZE -gt 10737418240 ]; then
    ls -t "$BACKUP_DIR"/backup_*.tar.gz | tail -n +10 | xargs rm -f 2>/dev/null || true
fi
EOF
    
    chmod +x $WORKDIR/scripts/backup.sh
    
    # 设置定时备份
    echo "0 2 * * * root $WORKDIR/scripts/backup.sh >> $LOGDIR/backup.log 2>&1" > /etc/cron.d/3proxy-backup
    
    print_success "自动备份已设置（每天凌晨2点）"
}

function setup_monitoring() {
    print_info "设置监控脚本..."
    
    # 创建监控脚本
    cat > $WORKDIR/scripts/monitor.sh << 'EOF'
#!/bin/bash
# 3proxy监控脚本

PIDFILE="/run/3proxy/3proxy.pid"
LOGFILE="/var/log/3proxy/monitor.log"
MAX_MEMORY_MB=65536  # 最大内存使用量(MB)
MAX_CPU_PERCENT=800  # 最大CPU使用率(800% = 8核心满载)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOGFILE
}

# 检查3proxy是否运行
if [ -f "$PIDFILE" ]; then
    PID=$(cat $PIDFILE)
    if ! kill -0 $PID 2>/dev/null; then
        log "ERROR: 3proxy进程不存在，正在重启..."
        systemctl restart 3proxy-enterprise
        exit 1
    fi
    
    # 获取进程信息
    STATS=$(ps -p $PID -o pid,vsz,rss,pcpu,comm --no-headers)
    if [ -n "$STATS" ]; then
        VSZ=$(echo $STATS | awk '{print $2}')
        RSS=$(echo $STATS | awk '{print $3}')
        CPU=$(echo $STATS | awk '{print $4}')
        
        RSS_MB=$((RSS/1024))
        
        # 检查内存使用
        if [ $RSS_MB -gt $MAX_MEMORY_MB ]; then
            log "WARNING: 内存使用过高 (${RSS_MB}MB > ${MAX_MEMORY_MB}MB)"
            # 可以在这里添加告警通知
        fi
        
        # 检查CPU使用
        CPU_INT=$(echo $CPU | cut -d. -f1)
        if [ $CPU_INT -gt $MAX_CPU_PERCENT ]; then
            log "WARNING: CPU使用过高 (${CPU}% > ${MAX_CPU_PERCENT}%)"
        fi
        
        # 记录统计信息
        echo "$(date '+%s')|$RSS_MB|$CPU" >> /var/log/3proxy/stats.log
    fi
else
    log "ERROR: PID文件不存在，正在重启3proxy..."
    systemctl restart 3proxy-enterprise
fi

# 清理旧的统计数据（保留24小时）
tail -n 1440 /var/log/3proxy/stats.log > /var/log/3proxy/stats.log.tmp 2>/dev/null
mv -f /var/log/3proxy/stats.log.tmp /var/log/3proxy/stats.log 2>/dev/null || true
EOF
    
    chmod +x $WORKDIR/scripts/monitor.sh
    
    # 设置定时监控（每分钟）
    echo "* * * * * root $WORKDIR/scripts/monitor.sh" > /etc/cron.d/3proxy-monitor
    
    print_success "监控脚本设置完成"
}

function create_web_application() {
    print_info "创建Web管理应用..."
    
    cd $WORKDIR
    
    # 创建Python虚拟环境
    python3 -m venv venv
    source venv/bin/activate
    
    # 安装Python包
    pip install --upgrade pip
    pip install flask flask_login flask_wtf wtforms \
                werkzeug psutil redis \
                gunicorn gevent \
                sqlalchemy alembic \
                click python-dotenv \
                --no-cache-dir
    
    # 创建主应用文件 (分成多个部分以避免引号问题)
    create_app_part1
    create_app_part2
    create_app_part3
    create_app_part4
    
    # 创建模板文件
    create_templates
    
    print_success "Web应用创建完成"
}

function create_app_part1() {
    cat > $WORKDIR/app.py << 'EOAPP1'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
3proxy Enterprise Management System
支持百万级代理管理的高性能Web管理系统
"""

import os
import sys
import sqlite3
import random
import string
import re
import json
import time
import threading
import queue
import psutil
import redis
import hashlib
import datetime
import subprocess
import signal
from collections import defaultdict, OrderedDict
from functools import wraps, lru_cache
from contextlib import contextmanager

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, Response, g
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from logging.handlers import RotatingFileHandler

# 配置常量
DB_PATH = '/opt/3proxy-enterprise/3proxy.db'
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
CACHE_TTL = 300  # 缓存5分钟
BATCH_SIZE = 1000  # 批量操作大小
MAX_WORKERS = 16  # 最大工作线程数
CONFIG_CHUNK_SIZE = 10000  # 配置文件分片大小

# 初始化Flask应用
app = Flask(__name__, 
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'enterprise-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# 初始化日志
def setup_logging():
    if not app.debug:
        file_handler = RotatingFileHandler(
            '/var/log/3proxy/webapp.log',
            maxBytes=10485760,
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('3proxy Enterprise startup')

setup_logging()

# 初始化登录管理器
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录'

# 初始化Redis连接池
redis_pool = redis.ConnectionPool(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    max_connections=100,
    decode_responses=True
)

# 线程池
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# 数据库连接池
class DatabasePool:
    def __init__(self, database, max_connections=50):
        self.database = database
        self.max_connections = max_connections
        self.pool = queue.Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        self._initialize_pool()
    
    def _initialize_pool(self):
        for _ in range(self.max_connections):
            conn = sqlite3.connect(self.database, timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            self.pool.put(conn)
    
    @contextmanager
    def get_connection(self):
        conn = self.pool.get()
        try:
            yield conn
        finally:
            self.pool.put(conn)

# 初始化数据库连接池
db_pool = DatabasePool(DB_PATH)

# Redis缓存装饰器
def redis_cache(key_prefix, ttl=CACHE_TTL):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            r = redis.Redis(connection_pool=redis_pool)
            
            # 生成缓存键
            cache_key = f"{key_prefix}:{hashlib.md5(str(args).encode() + str(kwargs).encode()).hexdigest()}"
            
            # 尝试从缓存获取
            cached = r.get(cache_key)
            if cached:
                return json.loads(cached)
            
            # 执行函数
            result = f(*args, **kwargs)
            
            # 存入缓存
            r.setex(cache_key, ttl, json.dumps(result))
            
            return result
        return wrapped
    return decorator

# 用户模型
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @staticmethod
    def get(user_id):
        with db_pool.get_connection() as conn:
            cur = conn.execute("SELECT id, username, password FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            if row:
                return User(row['id'], row['username'], row['password'])
        return None
    
    @staticmethod
    def get_by_username(username):
        with db_pool.get_connection() as conn:
            cur = conn.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row:
                return User(row['id'], row['username'], row['password'])
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
EOAPP1
}

function create_app_part2() {
    cat >> $WORKDIR/app.py << 'EOAPP2'

# 代理配置生成器（支持分片）
class ProxyConfigGenerator:
    def __init__(self):
        self.config_dir = '/usr/local/etc/3proxy'
        self.chunk_size = CONFIG_CHUNK_SIZE
    
    def generate_configs(self):
        """生成3proxy配置文件（支持分片）"""
        app.logger.info("开始生成代理配置...")
        
        with db_pool.get_connection() as conn:
            # 获取所有启用的代理
            cursor = conn.execute(
                "SELECT ip, port, username, password FROM proxy WHERE enabled = 1 ORDER BY id"
            )
            
            # 生成主配置文件
            self._generate_main_config()
            
            # 生成用户认证文件
            users_dict = {}
            proxy_configs = []
            
            for row in cursor:
                ip, port, username, password = row
                users_dict[username] = password
                proxy_configs.append((ip, port, username))
            
            # 写入用户文件（分片）
            self._write_users_file(users_dict)
            
            # 写入代理配置（分片）
            self._write_proxy_configs(proxy_configs)
        
        app.logger.info(f"配置生成完成，共{len(proxy_configs)}个代理")
        
        # 重载3proxy
        self._reload_3proxy()
    
    def _generate_main_config(self):
        """生成主配置文件"""
        config = """# 3proxy Enterprise Configuration
# Auto-generated - DO NOT EDIT MANUALLY

daemon
pidfile /run/3proxy/3proxy.pid
monitor /usr/local/etc/3proxy/

# 性能参数
maxconn 1000000
stacksize 262144

# DNS配置
nserver 8.8.8.8
nserver 8.8.4.4
nserver 1.1.1.1
nscache 262144
nscache6 65536

# 超时设置
timeouts 1 3 10 30 60 180 1800 15 60

# 日志配置
log /var/log/3proxy/3proxy.log D
logformat "L%t %N.%p %E %U %C:%c %R:%r %O %I %h %T"
rotate 100M

# 包含其他配置文件
include /usr/local/etc/3proxy/users.cfg
include /usr/local/etc/3proxy/proxies/*.cfg
"""
        
        with open(f"{self.config_dir}/3proxy.cfg", 'w') as f:
            f.write(config)
    
    def _write_users_file(self, users_dict):
        """写入用户认证文件（支持大量用户）"""
        os.makedirs(f"{self.config_dir}/proxies", exist_ok=True)
        
        with open(f"{self.config_dir}/users.cfg", 'w') as f:
            f.write("# Users configuration\n")
            f.write("auth strong\n")
            
            # 分批写入用户
            users_list = [f"{user}:CL:{passwd}" for user, passwd in users_dict.items()]
            for i in range(0, len(users_list), 1000):
                batch = users_list[i:i+1000]
                f.write(f"users {' '.join(batch)}\n")
    
    def _write_proxy_configs(self, proxy_configs):
        """写入代理配置（分片）"""
        # 清理旧配置
        import glob
        for old_file in glob.glob(f"{self.config_dir}/proxies/*.cfg"):
            os.remove(old_file)
        
        # 分片写入
        for i in range(0, len(proxy_configs), self.chunk_size):
            chunk = proxy_configs[i:i+self.chunk_size]
            chunk_id = i // self.chunk_size
            
            with open(f"{self.config_dir}/proxies/proxy_{chunk_id:04d}.cfg", 'w') as f:
                f.write(f"# Proxy chunk {chunk_id}\n")
                
                for ip, port, username in chunk:
                    f.write(f"auth strong\n")
                    f.write(f"allow {username}\n")
                    f.write(f"proxy -n -a -p{port} -i{ip} -e{ip}\n")
                    f.write("\n")
    
    def _reload_3proxy(self):
        """重载3proxy配置"""
        try:
            # 发送SIGHUP信号重载配置
            subprocess.run(['pkill', '-HUP', '3proxy'], check=False)
            app.logger.info("3proxy配置重载成功")
        except Exception as e:
            app.logger.error(f"3proxy重载失败: {e}")
            # 如果重载失败，尝试重启
            try:
                subprocess.run(['systemctl', 'restart', '3proxy-enterprise'], check=True)
                app.logger.info("3proxy重启成功")
            except Exception as e2:
                app.logger.error(f"3proxy重启失败: {e2}")

# 实例化配置生成器
config_generator = ProxyConfigGenerator()

# 批量操作管理器
class BatchOperationManager:
    def __init__(self):
        self.operations = {}
        self.lock = threading.Lock()
    
    def create_operation(self, operation_type, total_items):
        """创建批量操作"""
        op_id = hashlib.md5(f"{operation_type}:{time.time()}".encode()).hexdigest()
        
        with self.lock:
            self.operations[op_id] = {
                'type': operation_type,
                'total': total_items,
                'processed': 0,
                'success': 0,
                'failed': 0,
                'status': 'running',
                'start_time': time.time(),
                'errors': []
            }
        
        return op_id
    
    def update_progress(self, op_id, success=True, error=None):
        """更新操作进度"""
        with self.lock:
            if op_id in self.operations:
                op = self.operations[op_id]
                op['processed'] += 1
                
                if success:
                    op['success'] += 1
                else:
                    op['failed'] += 1
                    if error:
                        op['errors'].append(error)
                
                if op['processed'] >= op['total']:
                    op['status'] = 'completed'
                    op['end_time'] = time.time()
    
    def get_status(self, op_id):
        """获取操作状态"""
        with self.lock:
            return self.operations.get(op_id, {})

# 实例化批量操作管理器
batch_manager = BatchOperationManager()

# 工具函数
def get_network_interfaces():
    """获取网络接口列表"""
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        if name != 'lo':  # 排除回环接口
            for addr in addrs:
                if addr.family == 2:  # IPv4
                    interfaces.append({
                        'name': name,
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
    return interfaces

def validate_ip_range(ip_range):
    """验证IP范围格式"""
    # 支持格式: 192.168.1.1-254 或 192.168.1.1-192.168.1.254
    pattern = r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}|(\d{1,3}\.){3}\d{1,3})$'
    return re.match(pattern, ip_range) is not None

def expand_ip_range(ip_range):
    """展开IP范围"""
    ips = []
    
    if '-' in ip_range:
        parts = ip_range.split('-')
        if '.' in parts[1]:
            # 完整IP范围: 192.168.1.1-192.168.1.254
            start_ip = parts[0]
            end_ip = parts[1]
            
            start_parts = [int(x) for x in start_ip.split('.')]
            end_parts = [int(x) for x in end_ip.split('.')]
            
            current = start_parts[:]
            while current <= end_parts:
                ips.append('.'.join(map(str, current)))
                
                current[3] += 1
                for i in range(3, 0, -1):
                    if current[i] > 255:
                        current[i] = 0
                        current[i-1] += 1
                
                if current[0] > 255:
                    break
        else:
            # 简短格式: 192.168.1.1-254
            base = '.'.join(parts[0].split('.')[:-1])
            start = int(parts[0].split('.')[-1])
            end = int(parts[1])
            
            for i in range(start, end + 1):
                if i <= 255:
                    ips.append(f"{base}.{i}")
    
    return ips
EOAPP2
}

function create_app_part3() {
    cat >> $WORKDIR/app.py << 'EOAPP3'

# 路由处理函数
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.get_by_username(username)
        if user and user.check_password(password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        
        flash('用户名或密码错误', 'danger')
    
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

# API路由
@app.route('/api/dashboard/stats')
@login_required
@redis_cache('dashboard_stats', ttl=60)
def api_dashboard_stats():
    """获取仪表板统计信息"""
    with db_pool.get_connection() as conn:
        # 总代理数
        total = conn.execute("SELECT COUNT(*) FROM proxy").fetchone()[0]
        
        # 启用的代理数
        enabled = conn.execute("SELECT COUNT(*) FROM proxy WHERE enabled = 1").fetchone()[0]
        
        # C段统计
        c_segments = conn.execute(
            "SELECT COUNT(DISTINCT substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.'))) FROM proxy"
        ).fetchone()[0]
        
        # 端口范围
        port_range = conn.execute(
            "SELECT MIN(port), MAX(port) FROM proxy"
        ).fetchone()
    
    return jsonify({
        'total_proxies': total,
        'enabled_proxies': enabled,
        'disabled_proxies': total - enabled,
        'c_segments': c_segments,
        'port_range': f"{port_range[0]}-{port_range[1]}" if port_range[0] else "N/A",
        'utilization': round(enabled / total * 100, 2) if total > 0 else 0
    })

@app.route('/api/system/status')
@login_required
def api_system_status():
    """获取系统状态"""
    # CPU使用率
    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
    cpu_avg = sum(cpu_percent) / len(cpu_percent)
    
    # 内存信息
    memory = psutil.virtual_memory()
    
    # 磁盘信息
    disk = psutil.disk_usage('/')
    
    # 网络IO
    net_io = psutil.net_io_counters()
    
    # 3proxy进程信息
    proxy_info = {'running': False, 'pid': None, 'cpu': 0, 'memory': 0, 'connections': 0}
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'connections']):
        try:
            if proc.info['name'] == '3proxy':
                proxy_info['running'] = True
                proxy_info['pid'] = proc.info['pid']
                proxy_info['cpu'] = proc.cpu_percent(interval=0.1)
                proxy_info['memory'] = proc.memory_info().rss / 1024 / 1024  # MB
                proxy_info['connections'] = len(proc.connections())
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    return jsonify({
        'cpu': {
            'percent': round(cpu_avg, 2),
            'cores': len(cpu_percent),
            'per_core': [round(p, 2) for p in cpu_percent]
        },
        'memory': {
            'total': round(memory.total / 1024 / 1024 / 1024, 2),  # GB
            'used': round(memory.used / 1024 / 1024 / 1024, 2),
            'available': round(memory.available / 1024 / 1024 / 1024, 2),
            'percent': round(memory.percent, 2)
        },
        'disk': {
            'total': round(disk.total / 1024 / 1024 / 1024, 2),  # GB
            'used': round(disk.used / 1024 / 1024 / 1024, 2),
            'free': round(disk.free / 1024 / 1024 / 1024, 2),
            'percent': round(disk.percent, 2)
        },
        'network': {
            'bytes_sent': round(net_io.bytes_sent / 1024 / 1024, 2),  # MB
            'bytes_recv': round(net_io.bytes_recv / 1024 / 1024, 2),
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        },
        'proxy': proxy_info,
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/api/proxy/groups')
@login_required
def api_proxy_groups():
    """获取代理组列表（C段分组）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    with db_pool.get_connection() as conn:
        # 构建查询
        query = """
            SELECT 
                substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.')) as c_segment,
                COUNT(*) as total,
                SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled,
                MIN(port) as min_port,
                MAX(port) as max_port,
                GROUP_CONCAT(DISTINCT user_prefix) as prefixes
            FROM proxy
        """
        
        if search:
            query += " WHERE ip LIKE ?"
            params = (f"%{search}%",)
        else:
            params = ()
        
        query += " GROUP BY c_segment ORDER BY c_segment"
        
        # 获取总数
        count_query = f"SELECT COUNT(DISTINCT substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.'))) FROM proxy"
        if search:
            count_query += " WHERE ip LIKE ?"
        
        total = conn.execute(count_query, params).fetchone()[0]
        
        # 分页查询
        query += f" LIMIT {per_page} OFFSET {(page - 1) * per_page}"
        
        cursor = conn.execute(query, params)
        groups = []
        
        for row in cursor:
            groups.append({
                'c_segment': row['c_segment'],
                'total': row['total'],
                'enabled': row['enabled'],
                'disabled': row['total'] - row['enabled'],
                'port_range': f"{row['min_port']}-{row['max_port']}",
                'prefixes': row['prefixes'].split(',') if row['prefixes'] else []
            })
    
    return jsonify({
        'groups': groups,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/api/proxy/group/<c_segment>')
@login_required
def api_proxy_group_detail(c_segment):
    """获取代理组详情"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)
    
    with db_pool.get_connection() as conn:
        # 获取总数
        total = conn.execute(
            "SELECT COUNT(*) FROM proxy WHERE ip LIKE ?",
            (f"{c_segment}%",)
        ).fetchone()[0]
        
        # 获取代理列表
        cursor = conn.execute(
            """
            SELECT id, ip, port, username, password, enabled
            FROM proxy
            WHERE ip LIKE ?
            ORDER BY ip, port
            LIMIT ? OFFSET ?
            """,
            (f"{c_segment}%", per_page, (page - 1) * per_page)
        )
        
        proxies = []
        for row in cursor:
            proxies.append({
                'id': row['id'],
                'ip': row['ip'],
                'port': row['port'],
                'username': row['username'],
                'password': row['password'],
                'enabled': bool(row['enabled'])
            })
    
    return jsonify({
        'proxies': proxies,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/api/proxy/batch/add', methods=['POST'])
@login_required
def api_proxy_batch_add():
    """批量添加代理"""
    data = request.get_json()
    
    ip_range = data.get('ip_range')
    port_start = data.get('port_start', 10000)
    port_end = data.get('port_end', 60000)
    user_prefix = data.get('user_prefix', 'user')
    password_length = data.get('password_length', 12)
    
    # 验证IP范围
    if not validate_ip_range(ip_range):
        return jsonify({'error': 'IP范围格式错误'}), 400
    
    # 展开IP范围
    ips = expand_ip_range(ip_range)
    if not ips:
        return jsonify({'error': '无效的IP范围'}), 400
    
    if len(ips) > 10000:
        return jsonify({'error': 'IP数量超过限制(10000)'}), 400
    
    # 创建批量操作
    op_id = batch_manager.create_operation('batch_add_proxy', len(ips))
    
    # 异步执行批量添加
    def batch_add_worker():
        with db_pool.get_connection() as conn:
            # 获取已使用的端口
            used_ports = set()
            cursor = conn.execute("SELECT port FROM proxy")
            for row in cursor:
                used_ports.add(row[0])
            
            # 生成可用端口池
            available_ports = [p for p in range(port_start, port_end + 1) if p not in used_ports]
            if len(available_ports) < len(ips):
                batch_manager.update_progress(op_id, False, "可用端口不足")
                return
            
            # 随机选择端口
            random.shuffle(available_ports)
            selected_ports = available_ports[:len(ips)]
            
            # 批量插入
            batch_data = []
            for i, ip in enumerate(ips):
                username = f"{user_prefix}{random.randint(1000, 9999)}"
                password = ''.join(random.choices(string.ascii_letters + string.digits, k=password_length))
                port = selected_ports[i]
                
                batch_data.append((ip, port, username, password, 1, ip_range, f"{port_start}-{port_end}", user_prefix))
                
                if len(batch_data) >= BATCH_SIZE:
                    conn.executemany(
                        "INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        batch_data
                    )
                    conn.commit()
                    
                    for _ in batch_data:
                        batch_manager.update_progress(op_id, True)
                    
                    batch_data = []
            
            # 插入剩余数据
            if batch_data:
                conn.executemany(
                    "INSERT INTO proxy (ip, port, username, password, enabled, ip_range, port_range, user_prefix) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    batch_data
                )
                conn.commit()
                
                for _ in batch_data:
                    batch_manager.update_progress(op_id, True)
        
        # 重新生成配置
        config_generator.generate_configs()
    
    # 提交到线程池执行
    executor.submit(batch_add_worker)
    
    return jsonify({'operation_id': op_id, 'message': '批量添加任务已创建'})

@app.route('/api/proxy/batch/operation/<op_id>')
@login_required
def api_batch_operation_status(op_id):
    """获取批量操作状态"""
    status = batch_manager.get_status(op_id)
    if not status:
        return jsonify({'error': '操作不存在'}), 404
    
    return jsonify(status)

@app.route('/api/proxy/batch/delete', methods=['POST'])
@login_required
def api_proxy_batch_delete():
    """批量删除代理"""
    data = request.get_json()
    proxy_ids = data.get('ids', [])
    
    if not proxy_ids:
        return jsonify({'error': '未选择代理'}), 400
    
    # 创建批量操作
    op_id = batch_manager.create_operation('batch_delete_proxy', len(proxy_ids))
    
    # 异步执行批量删除
    def batch_delete_worker():
        with db_pool.get_connection() as conn:
            # 分批删除
            for i in range(0, len(proxy_ids), BATCH_SIZE):
                batch = proxy_ids[i:i+BATCH_SIZE]
                placeholders = ','.join('?' * len(batch))
                
                conn.execute(f"DELETE FROM proxy WHERE id IN ({placeholders})", batch)
                conn.commit()
                
                for _ in batch:
                    batch_manager.update_progress(op_id, True)
        
        # 重新生成配置
        config_generator.generate_configs()
    
    # 提交到线程池执行
    executor.submit(batch_delete_worker)
    
    return jsonify({'operation_id': op_id, 'message': '批量删除任务已创建'})

@app.route('/api/proxy/batch/toggle', methods=['POST'])
@login_required
def api_proxy_batch_toggle():
    """批量启用/禁用代理"""
    data = request.get_json()
    proxy_ids = data.get('ids', [])
    enabled = data.get('enabled', True)
    
    if not proxy_ids:
        return jsonify({'error': '未选择代理'}), 400
    
    # 创建批量操作
    op_id = batch_manager.create_operation('batch_toggle_proxy', len(proxy_ids))
    
    # 异步执行批量更新
    def batch_toggle_worker():
        with db_pool.get_connection() as conn:
            # 分批更新
            for i in range(0, len(proxy_ids), BATCH_SIZE):
                batch = proxy_ids[i:i+BATCH_SIZE]
                placeholders = ','.join('?' * len(batch))
                
                conn.execute(
                    f"UPDATE proxy SET enabled = ? WHERE id IN ({placeholders})",
                    [1 if enabled else 0] + batch
                )
                conn.commit()
                
                for _ in batch:
                    batch_manager.update_progress(op_id, True)
        
        # 重新生成配置
        config_generator.generate_configs()
    
    # 提交到线程池执行
    executor.submit(batch_toggle_worker)
    
    return jsonify({'operation_id': op_id, 'message': f'批量{"启用" if enabled else "禁用"}任务已创建'})

@app.route('/api/proxy/export', methods=['POST'])
@login_required
def api_proxy_export():
    """导出代理"""
    data = request.get_json()
    format_type = data.get('format', 'txt')
    c_segments = data.get('c_segments', [])
    
    with db_pool.get_connection() as conn:
        if c_segments:
            # 导出指定C段
            placeholders = ','.join('?' * len(c_segments))
            cursor = conn.execute(
                f"SELECT ip, port, username, password FROM proxy WHERE substr(ip, 1, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + instr(substr(ip, instr(ip, '.') + instr(substr(ip, instr(ip, '.') + 1), '.') + 1), '.')) IN ({placeholders}) ORDER BY ip, port",
                c_segments
            )
