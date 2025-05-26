#!/bin/bash
# Debian 12 别名 IP 批量添加脚本 —— 交互 + 固定 post-up/pre-down 块格式
# 依赖: ipcalc
# 用法: sudo bash auto_alias.sh

set -euo pipefail

# 1. 检查 ipcalc
if ! command -v ipcalc &>/dev/null; then
  echo "请先安装 ipcalc：sudo apt-get update && sudo apt-get install -y ipcalc"
  exit 1
fi

# 2. 探测主接口、网关、主IP/CIDR、掩码
route_info=$(ip -4 route show default | head -n1)
IFACE=$(awk '/^default/ {print $5}' <<<"$route_info")
GATEWAY=$(awk '/^default/ {print $3}' <<<"$route_info")
CIDR=$(ip -4 -o addr show dev "$IFACE" scope global \
        | awk '{print $4}' | head -n1)
MAIN_IP=${CIDR%/*}
PREFIX_LEN=${CIDR#*/}
NETMASK=$(ipcalc "$CIDR" | awk '/Netmask:/ {print $2}')

# 3. 计算可用范围 HostMin, HostMax（跳过网关）
HOST_MIN=$(ipcalc "$CIDR" | awk '/HostMin:/ {print $2}')
HOST_MAX=$(ipcalc "$CIDR" | awk '/HostMax:/ {print $2}')
if [ "$HOST_MIN" = "$GATEWAY" ]; then
  HOST_MIN=$(python3 - <<EOF
import ipaddress
print(ipaddress.IPv4Address("$HOST_MIN") + 1)
EOF
)
fi

# 前缀 A.B.C
PREFIX3=${MAIN_IP%.*}

# 4. 交互模式选择
echo "请选择添加范围模式："
echo "  1) 自动 — 添加 $HOST_MIN 到 $HOST_MAX"
echo "  2) 手动 — 自定义起始 IP 和结束 IP"
read -p "输入 1 或 2: " mode
case "$mode" in
  1)
    START_IP=$HOST_MIN
    END_IP=$HOST_MAX
    ;;
  2)
    read -p "请输入起始 IP: " START_IP
    read -p "请输入结束 IP: " END_IP
    ;;
  *)
    echo "无效选择，退出。" >&2
    exit 1
    ;;
esac

START_HOST=${START_IP##*.}
END_HOST=${END_IP##*.}

# 5. 备份原配置
cp /etc/network/interfaces /etc/network/interfaces.bak_$(date +%Y%m%d%H%M%S)

# 6. 追加固定格式的配置块
{
  echo ""
  echo "# --- 添加别名 IP ($(date '+%Y-%m-%d %H:%M:%S')) ---"
  echo "auto $IFACE"
  echo "iface $IFACE inet static"
  echo "    address $MAIN_IP"
  echo "    netmask $NETMASK"
  echo "    gateway $GATEWAY"
  echo "    dns-nameservers 8.8.8.8 1.1.1.1"
  echo ""
  echo "    # 在接口启动后添加 IP"
  echo "    post-up for i in \`seq $START_HOST $END_HOST\`; do ip addr add $PREFIX3.\$i/$PREFIX_LEN dev $IFACE; done"
  echo ""
  echo "    # 在接口关闭前删除 IP（可选）"
  echo "    pre-down for i in \`seq $START_HOST $END_HOST\`; do ip addr del $PREFIX3.\$i/$PREFIX_LEN dev $IFACE; done"
} >> /etc/network/interfaces

echo "已追加接口 $IFACE 的配置到 /etc/network/interfaces。"
echo "IP 范围：$START_HOST 到 $END_HOST (/ $PREFIX_LEN)"
echo "请运行："
echo "  sudo systemctl restart networking"
echo "或"
echo "  sudo ifdown $IFACE && sudo ifup $IFACE"
