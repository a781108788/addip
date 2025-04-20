#!/bin/bash
# Debian 12 动态子网别名 IP 自动配置脚本
# 支持任意 IPv4 前缀（/8~/30），依赖 ipcalc

set -euo pipefail

CONFIG_FILE="/etc/network/interfaces"

# 1. 环境检查
if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误：$CONFIG_FILE 不存在，无法继续。" >&2
    exit 1
fi
if ! command -v ipcalc >/dev/null; then
    echo "错误：未安装 ipcalc，请先运行 apt-get install -y ipcalc" >&2
    exit 1
fi

# 2. 检测主接口、网关及带掩码的主 IP
route_info=$(ip -4 route show default | head -n1)
main_iface=$(awk '/^default/ {print $5}' <<< "$route_info")
default_gw=$(awk '/^default/ {print $3}' <<< "$route_info")
cidr_info=$(ip -4 -o addr show dev "$main_iface" scope global | awk '{print $4}' | head -n1)
# e.g. cidr_info="192.168.1.10/26"

echo "主接口: $main_iface  默认网关: $default_gw  主IP/CIDR: $cidr_info"

# 3. 用 ipcalc 提取网络参数
read network_address broadcast_address netmask host_min host_max < <(
  ipcalc "$cidr_info"     | awk '/Network:/      {print $2} 
           /Broadcast:/    {print $2} 
           /Netmask:/      {print $2} 
           /HostMin:/      {print $2} 
           /HostMax:/      {print $2}'
)
main_ip=${cidr_info%/*}

echo "子网: $network_address  广播: $broadcast_address  子网掩码: $netmask"
echo "可用IP范围: $host_min — $host_max  (跳过主IP $main_ip)"

# 4. 临时添加别名 IP
# 定义 IP 转换函数
ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
int2ip() { local ui32=$1; echo "$(( (ui32>>24)&0xFF )).$(( (ui32>>16)&0xFF )).$(( (ui32>>8)&0xFF )).$(( ui32&0xFF ))"; }

# 记录已有配置中的 IP，避免重复
mapfile -t existing < <(grep -E "^\s*address\s+([0-9]{1,3}\.){3}" "$CONFIG_FILE" | awk '{print $2}')

start_int=$(ip2int "$host_min")
end_int=$(ip2int "$host_max")
added=0

for (( ip_int=start_int; ip_int<=end_int; ip_int++ )); do
    ip_addr=$(int2ip "$ip_int")
    [ "$ip_addr" = "$main_ip" ] && continue
    if printf '%s
' "${existing[@]}" | grep -qx "$ip_addr"; then
        continue
    fi
    ip addr add "$ip_addr"/"${cidr_info#*/}" dev "$main_iface" 2>/dev/null       && { echo "添加 $ip_addr 成功"; added=$((added+1)); }       || echo "跳过或添加失败: $ip_addr"
done

echo "共临时添加 $added 个别名 IP。"

# 5. 更新 /etc/network/interfaces
bak="${CONFIG_FILE}.bak_$(date +%Y%m%d%H%M%S)"
cp "$CONFIG_FILE" "$bak"
echo "已备份原文件到 $bak"

# 已用别名序号
mapfile -t used_idx < <(grep -oP "^iface ${main_iface}:\K[0-9]+" "$CONFIG_FILE")
idx=0

{
  echo ""
  echo "# --- 以下由脚本添加的别名 IP （$(date)）---"
} >> "$CONFIG_FILE"

for (( ip_int=start_int; ip_int<=end_int; ip_int++ )); do
    ip_addr=$(int2ip "$ip_int")
    [ "$ip_addr" = "$main_ip" ] && continue
    if printf '%s
' "${existing[@]}" | grep -qx "$ip_addr"; then
        continue
    fi
    # 找可用的别名序号
    while printf '%s
' "${used_idx[@]}" | grep -qx "$idx"; do
        idx=$((idx+1))
    done
    alias_if="${main_iface}:$idx"
    cat <<EOF >> "$CONFIG_FILE"

auto $alias_if
iface $alias_if inet static
    address $ip_addr
    netmask $netmask
EOF
    used_idx+=("$idx")
    idx=$((idx+1))
done

echo "/etc/network/interfaces 更新完成。"

# 6. 重启网络
echo "正在重启网络服务..."
systemctl restart networking
echo "全部完成，所有别名 IP 已永久生效。"
