#!/bin/bash
# Debian 12 动态子网别名 IP 自动配置脚本 —— 自动初始化 /etc/network/interfaces
# 支持任意 IPv4 前缀（/8～/30），依赖 ipcalc
# 请以 root 身份运行：sudo bash auto_alias.sh

set -euo pipefail

CONFIG_FILE="/etc/network/interfaces"

# ──────────────── 1. 初始化 /etc/network/interfaces ────────────────
if [ ! -f "$CONFIG_FILE" ]; then
    echo "检测到 $CONFIG_FILE 不存在，正在初始化最简配置…"
    cat <<'EOF' > "$CONFIG_FILE"
# /etc/network/interfaces — 自动化别名 IP 脚本所需
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback
EOF
    echo "$CONFIG_FILE 已创建。"
fi

# ──────────────── 2. 环境检查 ────────────────
if ! command -v ipcalc >/dev/null; then
    echo "错误：未安装 ipcalc，请先运行 apt-get install -y ipcalc" >&2
    exit 1
fi

# ──────────────── 3. 检测主接口、网关及主 IP/CIDR ────────────────
route_info=$(ip -4 route show default | head -n1)
main_iface=$(awk '/^default/ {print $5}' <<< "$route_info")
default_gw=$(awk '/^default/ {print $3}' <<< "$route_info")
cidr_info=$(ip -4 -o addr show dev "$main_iface" scope global | awk '{print $4}' | head -n1)
# 示例 cidr_info="192.168.1.10/26"
if [ -z "$main_iface" ] || [ -z "$cidr_info" ]; then
    echo "错误：无法检测到主网卡或主 IP/CIDR。" >&2
    exit 1
fi

echo "主接口: $main_iface"
echo "默认网关: $default_gw"
echo "主IP/CIDR: $cidr_info"

# ──────────────── 4. 用 ipcalc 提取网络参数 ────────────────
read network_address broadcast_address netmask host_min host_max < <(
  ipcalc "$cidr_info" \
    | awk '/Network:/      {print $2}
           /Broadcast:/    {print $2}
           /Netmask:/      {print $2}
           /HostMin:/      {print $2}
           /HostMax:/      {print $2}'
)
main_ip=${cidr_info%/*}

echo "子网 (Network):       $network_address"
echo "广播地址 (Broadcast): $broadcast_address"
echo "子网掩码 (Netmask):   $netmask"
echo "可用 IP 范围:        $host_min — $host_max"
echo "跳过主 IP:           $main_ip"

# ──────────────── 5. 临时添加别名 IP ────────────────
# IP 与整数互转函数
ip2int()  { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
int2ip()  { local ui32=$1; echo "$(( (ui32>>24)&0xFF )).$(( (ui32>>16)&0xFF )).$(( (ui32>>8)&0xFF )).$(( ui32&0xFF ))"; }

# 读取已有配置文件中已写入的 address
mapfile -t existing_ips < <(grep -E "^\s*address\s+([0-9]{1,3}\.){3}" "$CONFIG_FILE" | awk '{print $2}')

start_int=$(ip2int "$host_min")
end_int=$(ip2int "$host_max")
added=0

echo "开始临时添加别名 IP..."
for (( ip_int=start_int; ip_int<=end_int; ip_int++ )); do
    ip_addr=$(int2ip "$ip_int")
    # 跳过网络、广播以及主 IP
    [ "$ip_addr" = "$network_address" ] && continue
    [ "$ip_addr" = "$broadcast_address" ] && continue
    [ "$ip_addr" = "$main_ip" ] && continue
    # 跳过已在配置文件里声明的 IP
    if printf '%s\n' "${existing_ips[@]}" | grep -qx "$ip_addr"; then
        continue
    fi
    # 添加别名 IP
    if ip addr add "$ip_addr"/"${cidr_info#*/}" dev "$main_iface" 2>/dev/null; then
        echo "  添加: $ip_addr"
        added=$((added+1))
    fi
done
echo "共临时添加 $added 个别名 IP。"

# ──────────────── 6. 更新 /etc/network/interfaces ────────────────
bak="${CONFIG_FILE}.bak_$(date +%Y%m%d%H%M%S)"
cp "$CONFIG_FILE" "$bak"
echo "已备份原配置到: $bak"

# 查找已用别名序号
mapfile -t used_idx < <(grep -oP "^iface ${main_iface}:\K[0-9]+" "$CONFIG_FILE")
next_idx=0

# 在文件末尾追加标记和配置
{
  echo ""
  echo "# --- 脚本自动添加的别名 IP （$(date '+%Y-%m-%d %H:%M:%S')） ---"
} >> "$CONFIG_FILE"

for (( ip_int=start_int; ip_int<=end_int; ip_int++ )); do
    ip_addr=$(int2ip "$ip_int")
    [ "$ip_addr" = "$network_address" ] && continue
    [ "$ip_addr" = "$broadcast_address" ] && continue
    [ "$ip_addr" = "$main_ip" ] && continue
    # 跳过已存在的
    if printf '%s\n' "${existing_ips[@]}" | grep -qx "$ip_addr"; then
        continue
    fi
    # 分配下一个别名序号
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

echo "/etc/network/interfaces 已更新，别名接口配置已写入。"

# ──────────────── 7. 重启网络服务 ────────────────
echo "正在重启 networking 服务…"
systemctl restart networking

echo "完成：所有别名 IP 已在物理接口 $main_iface 上配置并永久生效。"
