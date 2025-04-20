#!/bin/bash
# Debian 12 动态网段别名 IP 批量添加脚本 —— 自动/手动 + 跳过主IP和网关 + 永久化 + 激活
# 依赖：ipcalc, ifupdown
# 用法：sudo bash auto_alias.sh
#   1) 自动模式：根据当前主IP/CIDR添加所有可用主机
#   2) 手动模式：自定义起始IP和结束IP

set -euo pipefail

CONFIG_FILE="/etc/network/interfaces"

# ─── 0. 初始化 interfaces ───
if [ ! -f "$CONFIG_FILE" ]; then
  echo "初始化 $CONFIG_FILE…"
  cat <<'EOF' > "$CONFIG_FILE"
# /etc/network/interfaces — 基本网络配置
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF
  echo "$CONFIG_FILE 已创建。"
fi

# ─── 1. 检查依赖 ───
for cmd in ipcalc ifup; do
  if ! command -v $cmd &>/dev/null; then
    echo "错误：未安装 $cmd，请运行：sudo apt-get update && sudo apt-get install -y ipcalc ifupdown" >&2
    exit 1
  fi
done

# ─── 2. 探测主网卡, 网关 & 主 IP/CIDR ───
route_info=$(ip -4 route show default | head -n1)
main_iface=$(awk '/^default/ {print $5}' <<<"$route_info")
default_gw=$(awk '/^default/ {print $3}' <<<"$route_info")
cidr_info=$(ip -4 -o addr show dev "$main_iface" scope global \
            | awk '{print $4}' | head -n1)
if [ -z "$main_iface" ] || [ -z "$cidr_info" ]; then
  echo "错误：无法检测到主网卡或主IP/CIDR。" >&2
  exit 1
fi

echo "主接口: $main_iface    默认网关: $default_gw    主IP/CIDR: $cidr_info"

# 提取网络参数
prefix_len=${cidr_info#*/}
read network broadcast netmask hostmin hostmax < <(
  ipcalc "$cidr_info" \
    | awk '/Network:/   {nw=$2}
           /Broadcast:/ {bc=$2}
           /Netmask:/   {nm=$2}
           /HostMin:/   {hmin=$2}
           /HostMax:/   {hmax=$2}
           END{print nw,bc,nm,hmin,hmax}'
)

echo "网络: $network    广播: $broadcast    子网掩码: $netmask    可用范围: $hostmin — $hostmax"

# ─── 3. 选择模式 ───
echo "请选择模式："
echo "  1) 自动 — 添加 $hostmin — $hostmax 全部可用IP"
echo "  2) 手动 — 自定义起始IP和结束IP"
read -p "输入 1 或 2: " mode
case "$mode" in
  1) start_ip=$hostmin; end_ip=$hostmax; echo "自动模式: 范围 $start_ip — $end_ip";;
  2) read -p "请输入起始 IP: " start_ip; read -p "请输入结束 IP: " end_ip; echo "手动模式: 范围 $start_ip — $end_ip";;
  *) echo "无效模式，退出。"; exit 1;;
esac

main_ip=${cidr_info%/*}
echo "跳过 主IP: $main_ip 和 网关IP: $default_gw"

# ─── 4. 临时添加别名 IP ───
ip2int(){ local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
int2ip(){ local u=$1; echo "$((u>>24&255)).$((u>>16&255)).$((u>>8&255)).$((u&255))"; }

start_i=$(ip2int "$start_ip")
end_i=$(ip2int "$end_ip")

# 收集已存在的 address
mapfile -t existing < <(grep -E '^[[:space:]]*address[[:space:]]+'"$network"'\\.(|[0-9]+)' "$CONFIG_FILE" | awk '{print $2}')

echo; echo "开始临时添加别名 IP…"
added_tmp=0
for ((i=start_i; i<=end_i; i++)); do
  ip_addr=$(int2ip "$i")
  # 跳过主IP和网关IP
  [ "$ip_addr" = "$main_ip" ] && continue
  [ "$ip_addr" = "$default_gw" ] && continue
  # 跳过已有
  if printf '%s
' "${existing[@]}" | grep -qx "$ip_addr"; then
    continue
  fi
  if ip addr add "$ip_addr"/"$prefix_len" dev "$main_iface" &>/dev/null; then
    echo "  + $ip_addr/$prefix_len"
    added_tmp=$((added_tmp+1))
  fi
done
echo "共临时添加 $added_tmp 个别名 IP。"

# ─── 5. 永久化写入 ───
bak="${CONFIG_FILE}.bak_$(date +%Y%m%d%H%M%S)"
cp "$CONFIG_FILE" "$bak"
echo "已备份原配置到 $bak"

mapfile -t used_idx < <(grep -oP "^iface ${main_iface}:\\K[0-9]+" "$CONFIG_FILE")
next_idx=0
while printf '%s
' "${used_idx[@]}" | grep -qx "$next_idx"; do
  next_idx=$((next_idx+1))
done

new_aliases=()

{
  echo ""
  echo "# --- 添加别名 IP ($(date '+%F %T')) ---"
} >> "$CONFIG_FILE"

added_perm=0
for ((i=start_i; i<=end_i; i++)); do
  ip_addr=$(int2ip "$i")
  [ "$ip_addr" = "$main_ip" ] && continue
  [ "$ip_addr" = "$default_gw" ] && continue
  if printf '%s
' "${existing[@]}" | grep -qx "$ip_addr"; then
    continue
  fi
  alias_if="${main_iface}:$next_idx"
  cat <<EOF >> "$CONFIG_FILE"

auto $alias_if
iface $alias_if inet static
    address $ip_addr
    netmask $netmask
EOF
  echo "  写入: $alias_if → $ip_addr (掩码 $netmask)"
  new_aliases+=("$alias_if")
  existing+=("$ip_addr")
  used_idx+=("$next_idx")
  next_idx=$((next_idx+1))
  added_perm=$((added_perm+1))
done

echo "共永久化写入 $added_perm 个别名 IP。"

# ─── 6. 激活新别名 ───
echo; echo "激活别名接口…"
for alias_if in "${new_aliases[@]}"; do
  ifup "$alias_if" &>/dev/null && echo "  ifup $alias_if 成功"
done

# ─── 7. 列出所有 IPv4 ───
echo; echo "当前 $main_iface IPv4 列表："
ip -4 addr show dev "$main_iface" | awk '/inet / {print "  "$2}'

echo; echo "完成：所有指定范围 IP 均已临时添加并永久化。"
