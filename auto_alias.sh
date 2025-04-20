#!/bin/bash
# Debian 12 别名 IP 批量添加脚本 —— 交互式选择 + 临时添加 + 永久化写入
# 依赖：ipcalc
# 用法：
#   1) 直接运行：sudo bash auto_alias.sh
#   2) 或者：bash <(curl -sL https://your-download-link/auto_alias.sh)

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
  echo "错误：未安装 ipcalc，请先运行："
  echo "  sudo apt-get update && sudo apt-get install -y ipcalc"
  exit 1
fi

# ─── 2. 检测主网卡 & 主 IP/CIDR ───
route_info=$(ip -4 route show default | head -n1)
main_iface=$(awk '/^default/ {print $5}' <<<"$route_info")
cidr_info=$(ip -4 -o addr show dev "$main_iface" scope global \
            | awk '{print $4}' | head -n1)
if [ -z "$main_iface" ] || [ -z "$cidr_info" ]; then
  echo "错误：无法检测到主网卡或主 IP/CIDR。" >&2
  exit 1
fi
echo "主接口: $main_iface"
echo "主IP/CIDR: $cidr_info"

# ─── 3. 选择自动或手动模式 ───
echo
echo "请选择添加模式："
echo "  1) 自动模式 — 根据 $cidr_info 计算整个可用范围"
echo "  2) 手动模式 — 自定义起始 IP 和结束 IP"
read -p "请输入 1 或 2: " mode
echo

case "$mode" in
  1)
    # 自动模式：获取 HostMin, HostMax, Netmask
    read host_min host_max netmask < <(
      ipcalc "$cidr_info" \
        | awk '/HostMin:/ {hmin=$2}
               /HostMax:/ {hmax=$2}
               /Netmask:/ {mask=$2}
               END{print hmin, hmax, mask}'
    )
    echo "自动模式：范围 $host_min — $host_max，掩码 $netmask"
    ;;
  2)
    # 手动模式：交互输入
    read -p "请输入起始 IP: " host_min
    read -p "请输入结束 IP: " host_max
    netmask=$(ipcalc "$cidr_info" | awk '/Netmask:/ {print $2}')
    echo "手动模式：范围 $host_min — $host_max，掩码 $netmask"
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

# 读取已存在的 address，避免重复
mapfile -t existing < <(grep -E '^\s*address\s+([0-9]{1,3}\.){3}' "$CONFIG_FILE" | awk '{print $2}')

added=0
echo; echo "开始临时添加别名 IP…"
for ((i=start_int; i<=end_int; i++)); do
  ip_addr=$(int2ip "$i")
  # 跳过主 IP 或已存在
  [ "$ip_addr" = "$main_ip" ] && continue
  if printf '%s\n' "${existing[@]}" | grep -qx "$ip_addr"; then
    continue
  fi
  ip addr add "$ip_addr"/"$netmask" dev "$main_iface" &>/dev/null \
    && { echo "  添加 $ip_addr"; added=$((added+1)); }
done
echo "共临时添加 $added 个别名 IP。"

# ─── 5. 永久化写入 /etc/network/interfaces ───
bak="${CONFIG_FILE}.bak_$(date +%Y%m%d%H%M%S)"
cp "$CONFIG_FILE" "$bak"
echo "已备份原配置到 $bak"

# 查找已用 alias 序号
mapfile -t used_idx < <(grep -oP "^iface ${main_iface}:\K[0-9]+" "$CONFIG_FILE")
next_idx=0
while printf '%s\n' "${used_idx[@]}" | grep -qx "$next_idx"; do
  next_idx=$((next_idx+1))
done

{
  echo ""
  echo "# --- 脚本添加的别名 IP （$(date '+%F %T')） ---"
} >> "$CONFIG_FILE"

count=0
for ((i=start_int; i<=end_int; i++)); do
  ip_addr=$(int2ip "$i")
  [ "$ip_addr" = "$main_ip" ] && continue
  if printf '%s\n' "${existing[@]}" | grep -qx "$ip_addr"; then
    continue
  fi
  alias_if="${main_iface}:$next_idx"
  cat <<EOF >> "$CONFIG_FILE"

auto $alias_if
iface $alias_if inet static
    address $ip_addr
    netmask $netmask
EOF
  echo "  永久化写入: $alias_if → $ip_addr"
  existing+=("$ip_addr")
  used_idx+=("$next_idx")
  next_idx=$((next_idx+1))
  count=$((count+1))
done

echo "共永久化写入 $count 个别名 IP。"

# ─── 6. 重启 network 服务 ───
echo; echo "正在重启 networking…"
systemctl restart networking
echo "操作完成，所有别名 IP 均已永久生效。"
