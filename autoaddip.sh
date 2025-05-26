#!/bin/bash
# auto_alias.sh — Debian12 别名 IP 批量添加（交互）+ 固定 post-up/pre-down + ip link 重启
# 依赖：ipcalc
# 用法：sudo bash auto_alias.sh

set -euo pipefail

CONFIG_FILE="/etc/network/interfaces"

### 1. 检查依赖 ###
if ! command -v ipcalc &>/dev/null; then
  echo "请先安装 ipcalc："
  echo "  sudo apt-get update && sudo apt-get install -y ipcalc"
  exit 1
fi

### 2. 检测主网卡、网关、主 IP/CIDR ###
route_info=$(ip -4 route show default | head -n1)
IFACE=$(awk '/^default/ {print $5}' <<<"$route_info")
GATEWAY=$(awk '/^default/ {print $3}' <<<"$route_info")
CIDR=$(ip -4 -o addr show dev "$IFACE" scope global \
        | awk '{print $4}' | head -n1)
MAIN_IP=${CIDR%/*}

if [ -z "$IFACE" ] || [ -z "$CIDR" ]; then
  echo "错误：无法检测到主网卡或主 IP/CIDR。" >&2
  exit 1
fi

### 3. 提取网络参数 ###
read NETWORK BCAST NETMASK HOST_MIN HOST_MAX < <(
  ipcalc "$CIDR" \
    | awk '/Network:/   {nw=$2}
           /Broadcast:/ {bc=$2}
           /Netmask:/   {nm=$2}
           /HostMin:/   {hmin=$2}
           /HostMax:/   {hmax=$2}
           END{print nw,bc,nm,hmin,hmax}'
)
# 跳过 .1 如果它是网关
if [ "$HOST_MIN" = "$GATEWAY" ]; then
  HOST_MIN=$(python3 - <<EOF
import ipaddress
print(ipaddress.IPv4Address("$HOST_MIN") + 1)
EOF
)
fi
PREFIX3=${MAIN_IP%.*}
PREFIX_LEN=${CIDR#*/}

### 4. 打印检测信息 ###
echo "================ 检测信息 ================"
echo "主接口:   $IFACE"
echo "主 IP/CIDR:$CIDR"
echo "默认网关: $GATEWAY"
echo "网络地址: $NETWORK"
echo "广播地址: $BCAST"
echo "子网掩码: $NETMASK"
echo "可用范围: $HOST_MIN — $HOST_MAX"
echo "=========================================="
echo

### 5. 交互式选择范围 ###
while true; do
  echo "请选择添加范围："
  echo "  1) 自动 — 添加 $HOST_MIN 到 $HOST_MAX"
  echo "  2) 手动 — 自定义起始 IP 和结束 IP"
  read -rp "输入 1 或 2: " mode
  case "$mode" in
    1)
      START_IP=$HOST_MIN
      END_IP=$HOST_MAX
      break
      ;;
    2)
      read -rp "请输入起始 IP: " START_IP
      read -rp "请输入结束 IP: " END_IP
      break
      ;;
    *)
      echo "无效选择，请重新输入。"
      ;;
  esac
done

START_HOST=${START_IP##*.}
END_HOST=${END_IP##*.}

### 6. 准备 /etc/network/interfaces ###
if [ ! -f "$CONFIG_FILE" ]; then
  cat <<EOF > "$CONFIG_FILE"
source /etc/network/interfaces.d/*
auto lo
iface lo inet loopback
EOF
  echo "已创建基础 $CONFIG_FILE。"
fi

### 7. 备份旧配置 ###
bak="${CONFIG_FILE}.bak_$(date +%Y%m%d%H%M%S)"
cp "$CONFIG_FILE" "$bak"
echo "已备份原配置到：$bak"
echo

### 8. 追加你的固定格式 ###
cat <<EOF >> "$CONFIG_FILE"

# --- 添加别名 IP ($(date '+%Y-%m-%d %H:%M:%S')) ---
auto $IFACE
iface $IFACE inet static
    address $MAIN_IP
    netmask $NETMASK
    gateway $GATEWAY
    dns-nameservers 8.8.8.8 1.1.1.1

    # 在接口启动后添加 IP
    post-up for i in \`seq $START_HOST $END_HOST\`; do ip addr add $PREFIX3.\$i/$PREFIX_LEN dev $IFACE; done

    # 在接口关闭前删除 IP（可选）
    pre-down for i in \`seq $START_HOST $END_HOST\`; do ip addr del $PREFIX3.\$i/$PREFIX_LEN dev $IFACE; done
EOF

echo "新配置块已追加到 $CONFIG_FILE。"
echo "IP 范围：$START_HOST—$END_HOST  (/ $PREFIX_LEN)"
echo

### 9. 用 ip link 方式重启 ###
echo "正在用 ip link 重启接口 $IFACE ..."
ip link set dev "$IFACE" down
sleep 1
ip link set dev "$IFACE" up

echo
echo "重启完成，请用下面命令检查 IP 是否生效："
echo "  ip -4 addr show dev $IFACE"
