#!/bin/bash
# ==============================================================================
# Debian 12 永久化别名 IP 批量添加脚本
#
# 用法: sudo bash auto_alias_perm.sh START_IP END_IP
# 例如: sudo bash auto_alias_perm.sh 192.168.1.100 192.168.1.150
#
# 功能：
#   1. 自动检测系统主网卡（默认路由所用接口）。
#   2. 自动检测主 IP 对应的子网掩码（与主 IP/CIDR 相同）。
#   3. 在 /etc/network/interfaces 中永久添加从 START_IP 到 END_IP 范围内
#      的所有地址（每个别名接口一个 IP），跳过已存在的和主 IP。
#   4. 重启 networking 服务，使配置立即生效且重启后保留。
#
# 依赖：ipcalc（请先 apt-get install -y ipcalc）
# ==============================================================================

set -euo pipefail

# —— 参数校验 ——  
if [ "$#" -ne 2 ]; then
    echo "用法: $0 START_IP END_IP"
    exit 1
fi
START_IP="$1"
END_IP="$2"

CONFIG="/etc/network/interfaces"

# —— 如果不存在，初始化最简模板 ——  
if [ ! -f "$CONFIG" ]; then
    echo "检测到 $CONFIG 不存在，正在创建简易模板…"
    cat <<'EOF' > "$CONFIG"
# /etc/network/interfaces — 基本网络配置
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF
    echo "$CONFIG 已创建。"
fi

# —— 检查 ipcalc ——  
if ! command -v ipcalc &>/dev/null; then
    echo "错误：未安装 ipcalc，请先执行：apt-get update && apt-get install -y ipcalc" >&2
    exit 1
fi

# —— 自动检测主网卡和主 IP/CIDR ——  
route_info=$(ip -4 route show default | head -n1)
IFACE=$(awk '/^default/ {print $5}' <<< "$route_info")
CIDR=$(ip -4 -o addr show dev "$IFACE" scope global \
        | awk '{print $4}' | head -n1)

if [ -z "$IFACE" ] || [ -z "$CIDR" ]; then
    echo "错误：无法检测到主网卡或主 IP/CIDR。" >&2
    exit 1
fi

# —— 提取子网掩码 ——  
NETMASK=$(ipcalc "$CIDR" | awk '/Netmask:/ {print $2}')

echo "主网卡：$IFACE"
echo "主 IP/CIDR：$CIDR"
echo "使用子网掩码：$NETMASK"
echo "准备永久化添加：$START_IP 至 $END_IP"

# —— 备份原配置 ——  
BACKUP="${CONFIG}.bak_$(date +%Y%m%d%H%M%S)"
cp "$CONFIG" "$BACKUP"
echo "已备份 $CONFIG 到 $BACKUP"

# —— IP 转换函数 ——  
ip2int()  { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
int2ip()  { local u=$1; echo "$((u>>24&255)).$((u>>16&255)).$((u>>8&255)).$((u&255))"; }

START_INT=$(ip2int "$START_IP")
END_INT=$(ip2int "$END_IP")
MAIN_IP="${CIDR%/*}"

# —— 收集已存在的 address ——  
mapfile -t EXISTING < <(grep -E '^\s*address\s+([0-9]{1,3}\.){3}' "$CONFIG" | awk '{print $2}')

# —— 找到可用 alias 序号 ——  
mapfile -t USED_IDX < <(grep -oP "^iface ${IFACE}:\K[0-9]+" "$CONFIG")
NEXT_IDX=1
while printf '%s\n' "${USED_IDX[@]}" | grep -qx "$NEXT_IDX"; do
    NEXT_IDX=$((NEXT_IDX+1))
done

# —— 写入永久化配置 ——  
{
  echo ""
  echo "# --- 自动添加别名 IP: $(date '+%Y-%m-%d %H:%M:%S') ---"
} >> "$CONFIG"

ADDED=0
for (( i=START_INT; i<=END_INT; i++ )); do
    IP_ADDR=$(int2ip "$i")
    # 跳过主 IP 和重复
    [ "$IP_ADDR" = "$MAIN_IP" ] && continue
    if printf '%s\n' "${EXISTING[@]}" | grep -qx "$IP_ADDR"; then
        continue
    fi
    cat <<EOF >> "$CONFIG"

auto ${IFACE}:$NEXT_IDX
iface ${IFACE}:$NEXT_IDX inet static
    address $IP_ADDR
    netmask $NETMASK
EOF
    echo "已写入永久化: ${IFACE}:$NEXT_IDX → $IP_ADDR"
    EXISTING+=("$IP_ADDR")
    USED_IDX+=("$NEXT_IDX")
    NEXT_IDX=$((NEXT_IDX+1))
    ADDED=$((ADDED+1))
done

echo "共永久化添加 $ADDED 个别名 IP。"

# —— 重启网络服务 ——  
echo "重启 networking 服务…"
systemctl restart networking

echo "完成：${IFACE} 已永久化添加 $ADDED 个别名 IP。"
