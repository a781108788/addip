#!/bin/bash
# Debian 12 网段别名 IP 批量添加脚本 —— 交互式模式 + 单一接口 post-up/pre-down 添加删除
# 依赖：ipcalc
# 用法：sudo bash auto_alias.sh

set -euo pipefail

CONFIG_FILE="/etc/network/interfaces"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# 1. 检查依赖
if ! command -v ipcalc &>/dev/null; then
  echo "错误：请先安装 ipcalc：sudo apt-get update && sudo apt-get install -y ipcalc" >&2
  exit 1
fi

# 2. 探测主网卡、网关和主 IP/CIDR
route_info=$(ip -4 route show default | head -n1)
IFACE=$(awk '/^default/ {print $5}' <<<"$route_info")
GATEWAY=$(awk '/^default/ {print $3}' <<<"$route_info")
CIDR=$(ip -4 -o addr show dev "$IFACE" scope global | awk '{print $4}' | head -n1)
if [ -z "$IFACE" ] || [ -z "$CIDR" ]; then
  echo "错误：无法检测到主网卡或主 IP/CIDR。" >&2
  exit 1
fi

echo "主接口: $IFACE"
echo "主 IP/CIDR: $CIDR"
echo "默认网关: $GATEWAY"

# 3. 提取网络参数
PREFIX_LEN=${CIDR#*/}
NETWORK=$(ipcalc "$CIDR" | awk '/Network:/ {print $2}')
BROADCAST=$(ipcalc "$CIDR" | awk '/Broadcast:/ {print $2}')
NETMASK=$(ipcalc "$CIDR" | awk '/Netmask:/ {print $2}')
HOST_MIN=$(ipcalc "$CIDR" | awk '/HostMin:/ {print $2}')
HOST_MAX=$(ipcalc "$CIDR" | awk '/HostMax:/ {print $2}')
# 跳过网关
if [ "$HOST_MIN" = "$GATEWAY" ]; then
  HOST_MIN=$(python3 - <<EOF
import ipaddress
print(ipaddress.IPv4Address("$HOST_MIN")+1)
EOF
)
fi

# 取前三段前缀
PREFIX3=${NETWORK%.*}

echo "网络地址: $NETWORK"
echo "广播地址: $BROADCAST"
echo "子网掩码: $NETMASK"
echo "可用主机范围: $HOST_MIN — $HOST_MAX"

# 4. 交互模式选择
while true; do
  echo
  echo "请选择添加范围模式："
  echo "  1) 自动 — 添加 $HOST_MIN 到 $HOST_MAX 全部可用IP"
  echo "  2) 手动 — 自定义起始 IP 和结束 IP"
  read -p "输入 1 或 2: " mode
  case "$mode" in
    1)
      START_IP="$HOST_MIN"
      END_IP="$HOST_MAX"
      echo "您选择了自动模式，范围：$START_IP — $END_IP"
      break
      ;;
    2)
      read -p "请输入起始 IP: " START_IP
      read -p "请输入结束 IP: " END_IP
      echo "您选择了手动模式，范围：$START_IP — $END_IP"
      break
      ;;
    *)
      echo "输入无效，请重新输入"
      ;;
  esac
done

# 5. 初始化配置文件（如果不存在）
if [ ! -f "$CONFIG_FILE" ]; then
  cat <<'EOF' > "$CONFIG_FILE"
source /etc/network/interfaces.d/*
auto lo
iface lo inet loopback
EOF
fi

# 6. 追加配置段到 /etc/network/interfaces
cat <<EOF >> "$CONFIG_FILE"

# --- 添加别名 IP ($TIMESTAMP) ---
auto $IFACE
iface $IFACE inet static
    address ${CIDR%/*}
    netmask $NETMASK
    gateway $GATEWAY
    dns-nameservers 8.8.8.8 1.1.1.1

    # 在接口启动后添加指定范围内 IP
    post-up for ip in $(seq ${START_IP##*.} ${END_IP##*.}); do
        ipaddr="$PREFIX3.$ip"
        if ! ip addr show dev $IFACE | grep -qw "$ipaddr"; then
            ip addr add $ipaddr/$PREFIX_LEN dev $IFACE
        fi
    done

    # 在接口关闭前删除这些 IP
    pre-down for ip in $(seq ${START_IP##*.} ${END_IP##*.}); do
        ipaddr="$PREFIX3.$ip"
        ip addr del $ipaddr/$PREFIX_LEN dev $IFACE || true
    done
EOF

# 7. 提示下一步操作
cat <<MSG
已追加接口 $IFACE 的配置到 $CONFIG_FILE。
IP 范围：${START_IP##*.} 到 ${END_IP##*.} (/ $PREFIX_LEN)
请运行：
  sudo systemctl restart networking
或
  sudo ifdown $IFACE && sudo ifup $IFACE
MSG
