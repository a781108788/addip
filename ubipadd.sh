#!/bin/bash

CONFIG_FILE="/root/ip_list.conf"
SCRIPT_FILE="/usr/local/bin/setup_multi_ips.sh"
SERVICE_FILE="/etc/systemd/system/setup-ips.service"
UNINSTALL_SCRIPT="/usr/local/bin/uninstall_multi_ips.sh"

# 自动识别默认出网网卡
DEFAULT_DEV=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
if [[ -z "$DEFAULT_DEV" ]]; then
    echo "❌ 无法识别默认网卡，请确认联网状态。"
    exit 1
fi

echo "=== 多段 IP 策略路由配置工具 ==="
echo "已识别默认网卡: $DEFAULT_DEV"
read -p "是否开始添加多个 IP 段？[y/n]: " confirm
[[ "$confirm" != "y" ]] && echo "已取消。" && exit 0

echo "# IP列表: 本地IP 掩码 网关 网卡 路由表编号" > "$CONFIG_FILE"

while true; do
    echo ""
    read -p "请输入本地 IP (如 143.14.193.3): " ip
    read -p "请输入子网掩码位数 (如 24): " mask
    read -p "请输入网关地址 (如 143.14.193.1): " gw
    read -p "请输入路由表编号（100 以上，不能重复）: " table
    echo "$ip $mask $gw $DEFAULT_DEV $table" >> "$CONFIG_FILE"

    read -p "是否继续添加另一个 IP 段？[y/n]: " again
    [[ "$again" != "y" ]] && break
done

# 写 setup 脚本
cat > "$SCRIPT_FILE" << 'EOF'
#!/bin/bash
CONF="/root/ip_list.conf"
[[ ! -f "$CONF" ]] && echo "配置文件不存在: $CONF" && exit 1

while read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    IP=$(echo "$line" | awk '{print $1}')
    MASK=$(echo "$line" | awk '{print $2}')
    GW=$(echo "$line" | awk '{print $3}')
    DEV=$(echo "$line" | awk '{print $4}')
    TABLE=$(echo "$line" | awk '{print $5}')

    echo "[+] 添加 $IP/$MASK via $GW dev $DEV 表 $TABLE"
    ip addr add "$IP/$MASK" dev "$DEV" 2>/dev/null
    ip route add default via "$GW" dev "$DEV" table "$TABLE" 2>/dev/null
    ip rule add from "$IP/32" table "$TABLE" 2>/dev/null
done < "$CONF"
EOF

chmod +x "$SCRIPT_FILE"

# 写 systemd 服务
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=多段 IP 策略路由服务
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_FILE
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

# 写卸载脚本
cat > "$UNINSTALL_SCRIPT" << 'EOF'
#!/bin/bash
CONF="/root/ip_list.conf"
while read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    IP=$(echo "$line" | awk '{print $1}')
    MASK=$(echo "$line" | awk '{print $2}')
    GW=$(echo "$line" | awk '{print $3}')
    DEV=$(echo "$line" | awk '{print $4}')
    TABLE=$(echo "$line" | awk '{print $5}')

    echo "[-] 删除 $IP/$MASK 表 $TABLE"
    ip rule del from "$IP/32" table "$TABLE" 2>/dev/null
    ip route flush table "$TABLE" 2>/dev/null
    ip addr del "$IP/$MASK" dev "$DEV" 2>/dev/null
done < "$CONF"

systemctl disable --now setup-ips.service
rm -f /usr/local/bin/setup_multi_ips.sh
rm -f /usr/local/bin/uninstall_multi_ips.sh
rm -f /etc/systemd/system/setup-ips.service
rm -f /root/ip_list.conf
systemctl daemon-reexec
echo "[✓] 已全部清除。"
EOF

chmod +x "$UNINSTALL_SCRIPT"

# 启动服务
systemctl daemon-reexec
systemctl enable --now setup-ips.service

echo ""
echo "✅ 所有 IP 段已添加并设置为永久开机自启"
echo "🧩 如需卸载，运行: sudo /usr/local/bin/uninstall_multi_ips.sh"
