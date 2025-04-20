#!/bin/bash
# Debian 12 别名 IP 批量添加脚本 —— 交互式选择自动/手动模式
# 依赖: ipcalc
# 用法: sudo bash auto_alias.sh

set -euo pipefail

CONFIG_FILE="/etc/network/interfaces"

# ─── 0. 初始化 /etc/network/interfaces ───
if [ ! -f "$CONFIG_FILE" ]; then
  echo "检测到 $CONFIG_FILE 不存在，正在初始化…"
  cat <<'EOF' > "$CONFIG_FILE"
# /etc/network/interfaces — 自动化别名 IP 脚本所需
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF
  echo "$CONFIG_FILE 已创建。"
fi

# ─── 1. 环境 & 依赖检查 ───
if ! command -v ipcalc &>/dev/null; then
  echo "错误：未安装 ipcalc，请先运行 apt-get install -y ipcalc" >&2
  exit 1
fi

# ─── 2. 探测主接口 & 主 IP/CIDR ───
route_info=$(ip -4 route show default | head -n1)
main_iface=$(awk '/^default/ {print $5}' <<< "$route_info")
cidr_info=$(ip -4 -o addr show dev "$main_iface" scope global \
            | awk '{print $4}' | head -n1)

if [ -z "$main_iface" ] || [ -z "$cidr_info" ]; then
  echo "错误：无法检测到主网卡或主 IP/CIDR" >&2
  exit 1
fi

echo "主接口: $main_iface    主IP/CIDR: $cidr_info"

# ─── 3. 选择模式 ───
echo
echo "请选择添加模式："
echo "  1) 自动模式（根据 $cidr_info 自动计算整个可用范围）"
echo "  2) 手动模式（自定义起始 IP 和结束 IP）"
read -p "输入 1 或 2: " mode
echo

case "$mode" in
  1)
    # 自动模式，提取 HostMin/HostMax/Netmask
    read network_address broadcast_address netmask host_min host_max < <(
      ipcalc "$cidr_info" \
        | awk '/HostMin:/ {hmin=$2} /HostMax:/ {hmax=$2} /Netmask:/ {mask=$2} END{print hmin, hmax, mask}'
    )
    echo "自动模式：可用 IP 范围 $host_min — $host_max    掩码 $netmask"
    ;;
  2)
    # 手动模式，提示输入
    read -p "请输入起始 IP: " host_min
    read -p "请输入结束 IP: " host_max
    # 子网掩码仍沿用主IP的 Netmask
    netmask=$(ipcalc "$cidr_info" | awk '/Netmask:/ {print $2}')
    echo "手动模式：添加 IP 范围 $host_min — $host_max    掩码 $netmask"
    ;;
  *)
    echo "无效选择，退出。" >&2
    exit 1
    ;;
esac

main_ip=${cidr_info%/*}

# ─── 4. 临时添加别名 IP ───
ip2int(){ local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
int2ip(){ local u=$1; echo "$((u>>24&255)).$((u>>16&255)).$((u>>8&255)).$((u&255))"; }

start_int=$(ip2int "$host_min")
end_int=$(ip2int "$host_max")

mapfile -t existing < <(grep -E '^\s*address\s+([0-9]{1,3}\.){3}' "$CONFIG_FILE" | awk '{print $2}')

added=0
echo; echo "开始临时添加别名 IP…"
for ((i=start_int; i<=end_int; i++)); do
  ip_addr=$(int2ip "$i")
  [ "$ip_addr" = "$main_ip" ] && continue
  if printf '%s\n' "${existing[@]}" | grep -qx "$ip_addr"; then
    continue
  fi
  ip addr add "$ip_addr"/"$netmask" dev "$main_iface" &>/dev/null \
    && { echo "  添加 $ip_addr"; added=$((added+1)); }
done
echo "共添加 $added 个别名 IP（临时）。"

# ─── 5. 永久化写入 /etc/network/interfaces ───
bak="${CONFIG_FILE}.bak_$(date +%Y%m%d%H%M%S)"
cp "$CONFIG_FILE" "$bak"
echo "已备份原配置到 $bak"

mapfile -t used_idx < <(grep -oP "^iface ${main_iface}:\K[0-9]+" "$CONFIG_FILE")
next_idx=0

{
  echo ""
  echo "# --- 脚本添加的别名 IP （$(date '+%F %T')') ---"
} >> "$CONFIG_FILE"

for ((i=start_int; i<=end_int; i++)); do
  ip_addr=$(int2ip "$i")
  [ "$ip_addr" = "$main_ip" ] && continue
  if printf '%s\n' "${existing[@]}" | grep -qx "$ip_addr"; then
    continue
  fi
  while printf '%s\n' "${used_idx[@]}" | grep -qx "$next_idx"; do
    next_idx=$((next_idx+1))
  done
  alias_if="${main_iface}:$next_idx"
  cat <<EOF >> "$CONFIG_FILE"

auto $alias_if
iface $alias_if inet static
    address $ip_addr
    netmask $netmask
EOF
  used_idx+=("$next_idx")
  next_idx=$((next_idx+1))
done

echo "/etc/network/interfaces 更新完成。"

# ─── 6. 重启网络 ───
echo; echo "重启 networking 服务…"
systemctl restart networking
echo "操作完毕，所有别名 IP 已永久生效。"
