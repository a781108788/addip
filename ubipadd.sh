#!/bin/bash

CONFIG_FILE="/root/ip_list.conf"
SCRIPT_FILE="/usr/local/bin/setup_multi_ips.sh"
SERVICE_FILE="/etc/systemd/system/setup-ips.service"
UNINSTALL_SCRIPT="/usr/local/bin/uninstall_multi_ips.sh"

# 自动识别默认网卡
DEFAULT_DEV=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')

if [[ -z "$DEFAULT_DEV" ]]; then
    echo "❌ 无法自动识别默认网卡，请检查网络是否可用。"
    exit 1
fi

echo "=== 多网段 IP 策略路由配置工具 ==="
echo "已自动识别默认网卡：$DEFAULT_DEV"

read -p "是否开始配置新的 IP 段？[y/n]: " confirm
[[ "$confirm" != "y" ]] && echo "已取消。" && exit 0

# 初始化配置文件
echo "# IP 子网配置：IP 掩码 网关 网卡 路由表编号" > "$CONFIG_FILE"

while true; do
    echo ""
    read -p "请输入本地 IP (例如 143.14.193.3): " ip
    read -p "请输入子网掩码位数 (例如 24): " mask
    read -p "请输入网关 (例如 143.14.193.1): " gw
    read -p "请输入路由表编号 (例如 100): " table

    echo "$ip $mask $gw $DEFAULT_DEV $table" >> "$CONFIG_FILE"
    read -p "是否继续添加？[y/n]: " again
    [[ "$again" != "y" ]] && break
done

echo "[+] 配置文件已写入: $CONFIG_FILE"

# 写入 IP 配置脚本
cat > "$SCRIPT_FILE" << 'EOF'
#!/bin/bash
CONF="/root/ip_list.conf"

[[ ! -f "$CONF" ]] && echo "配置文件 $CONF 不存在" && exit 1

while read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    IP=$(echo "$line" | awk '{print $1}')
    MASK=$(echo "$line" | awk '{print $2}')
    GW=$(echo "$line" | awk '{print $3}')
    DEV=$(echo "$line" | awk '{print $4}')
    TABLE=$(echo "$line" | awk '{print $5}')

    echo "[+] 添加 $IP/$MASK via $GW dev $DEV table $TABLE"
    ip addr add "$IP/$MASK" dev "$DEV"
    ip route add default via "$GW" dev "$DEV" table "$TABLE"
    ip rule add from "$IP/32" table "$TABLE"
done < "$CONF"
EOF

chmod +x "$SCRIPT_FILE"

# 写入 systemd 服务文件
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Setup multi-IP with routing policy
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_FILE
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

# 写入卸载脚本
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

    echo "[-] 删除 $IP/$MASK dev $DEV table $TABLE"
    ip rule del from "$IP/32" table "$TABLE"
    ip route flush table "$TABLE"
    ip addr del "$IP/$MASK" dev "$DEV"
done < "$CONF"

systemctl disable --now setup-ips.service
rm -f /usr/local/bin/setup_multi_ips.sh
rm -f /etc/systemd/system/setup-ips.service
rm -f /usr/local/bin/uninstall_multi_ips.sh
rm -f /root/ip_list.conf

systemctl daemon-reexec
echo "[+] 已完全卸载。"
EOF

chmod +x "$UNINSTALL_SCRIPT"

# 启用 systemd 服务
systemctl daemon-reexec
systemctl enable --now setup-ips.service

echo ""
echo "✅ 所有配置已完成，服务已启动并设置为开机自启"
echo "🧩 如需卸载，执行：sudo /usr/local/bin/uninstall_multi_ips.sh"
