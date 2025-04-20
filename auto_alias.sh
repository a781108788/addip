#!/bin/bash
# Debian 12 永久化别名 IP 批量添加脚本（自动 or 手动 区间）
#
# 用法:
#   自动模式（整段主机可用范围）：
#     sudo bash auto_alias_perm.sh
#   手动模式（指定范围）：
#     sudo bash auto_alias_perm.sh START_IP END_IP
#
# 依赖：ipcalc （请先 apt-get install -y ipcalc）

set -euo pipefail

CONFIG="/etc/network/interfaces"

# ─── 1. 参数和模式处理 ───
if [ "$#" -eq 0 ]; then
  MODE="auto"
elif [ "$#" -eq 2 ]; then
  MODE="manual"
  START_IP="$1"
  END_IP="$2"
else
  echo "用法: $0 [START_IP END_IP]" >&2
  echo "  不带参数：自动检测主 IP/CIDR 整段可用范围" >&2
  echo "  带两个参数：只永久化指定 START_IP — END_IP" >&2
  exit 1
fi

# ─── 2. 初始化或检查 /etc/network/interfaces ───
if [ ! -f "$CONFIG" ]; then
  echo "初始化 $CONFIG…"
  cat <<'EOF' > "$CONFIG"
# /etc/network/interfaces — 基本网络配置
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF
fi

# ─── 3. 检查依赖 ───
if ! command -v ipcalc &>/dev/null; then
  echo "错误：请先安装 ipcalc：apt-get update && apt-get install -y ipcalc" >&2
  exit 1
fi

# ─── 4. 探测主网卡和主 IP/CIDR ───
route_info=$(ip -4 route show default | head -n1)
IFACE=$(awk '/^default/ {print $5}' <<<"$route_info")
CIDR=$(ip -4 -o addr show dev "$IFACE" scope global \
        | awk '{print $4}' | head -n1)

if [ -z "$IFACE" ] || [ -z "$CIDR" ]; then
  echo "错误：无法检测到主网卡或主 IP/CIDR。" >&2
  exit 1
fi

NETMASK=$(ipcalc "$CIDR" | awk '/Netmask:/ {print $2}')
MAIN_IP=${CIDR%/*}

echo "模式：$MODE"
echo "主网卡：$IFACE"
echo "主 IP/CIDR：$CIDR"
echo "子网掩码：$NETMASK"

# ─── 5. 计算范围 ───
if [ "$MODE" = "auto" ]; then
  read _ _ _ HOST_MIN HOST_MAX < <(
    ipcalc "$CIDR" \
      | awk '/HostMin:/  {hmin=$2}
             /HostMax:/  {hmax=$2}
             END{print "", "", "", hmin, hmax}'
  )
  START_IP=$HOST_MIN
  END_IP=$HOST_MAX
  echo "自动模式范围：$START_IP — $END_IP"
else
  echo "手动模式范围：$START_IP — $END_IP"
fi

# ─── 6. 备份原文件 ───
BACKUP="${CONFIG}.bak_$(date +%Y%m%d%H%M%S)"
cp "$CONFIG" "$BACKUP"
echo "已备份 $CONFIG 到 $BACKUP"

# ─── 7. IP 与整数互转函数 ───
ip2int(){ local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
int2ip(){ local u=$1; echo "$((u>>24&255)).$((u>>16&255)).$((u>>8&255)).$((u&255))"; }

START_I=$(ip2int "$START_IP")
END_I=$(ip2int "$END_IP")

# ─── 8. 收集已存在的 address 条目 ───
mapfile -t EXISTING < <(grep -E '^\s*address\s+([0-9]{1,3}\.){3}' "$CONFIG" | awk '{print $2}')

# ─── 9. 分配 alias 序号 ───
mapfile -t USED_IDX < <(grep -oP "^iface ${IFACE}:\K[0-9]+" "$CONFIG")
NEXT_IDX=1
while printf '%s\n' "${USED_IDX[@]}" | grep -qx "$NEXT_IDX"; do
  NEXT_IDX=$((NEXT_IDX+1))
done

# ─── 10. 写永久化配置 ───
{
  echo ""
  echo "# --- 脚本添加别名 IP ($(date '+%F %T')) ---"
} >> "$CONFIG"

COUNT=0
for ((i=START_I; i<=END_I; i++)); do
  IP_ADDR=$(int2ip "$i")
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
  echo "  写入: ${IFACE}:$NEXT_IDX → $IP_ADDR"
  EXISTING+=("$IP_ADDR")
  USED_IDX+=("$NEXT_IDX")
  NEXT_IDX=$((NEXT_IDX+1))
  COUNT=$((COUNT+1))
done

echo "共写入 $COUNT 个永久别名 IP。"

# ─── 11. 重启网络 ───
echo "重启 networking 服务…"
systemctl restart networking

echo "完成：${IFACE} 已永久化添加 $COUNT 个别名 IP。"
