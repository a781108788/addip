#!/bin/bash
# Debian 12 网段别名 IP 批量添加 —— 交互式 + 固定 post-up/pre-down 块格式
# 依赖：ipcalc
# 用法：sudo bash auto_alias.sh

set -euo pipefail

# 1. 检查依赖
if ! command -v ipcalc &>/dev/null; then
  echo "请先安装 ipcalc："
  echo "  sudo apt-get update && sudo apt-get install -y ipcalc"
  exit 1
fi

# 2. 探测主接口、网关、主 IP/CIDR
route=$(ip -4 route show default | head -n1)
IFACE=$(awk '/^default/ {print $5}' <<<"$route")
GATEWAY=$(awk '/^default/ {print $3}' <<<"$route")
CIDR=$(ip -4 -o addr show dev "$IFACE" scope global \
        | awk '{print $4}' | head -n1)
MAIN_IP=${CIDR%/*}

# 3. 提取网络参数
read NETWORK BCAST NETMASK HOST_MIN HOST_MAX < <(
  ipcalc "$CIDR" \
    | awk '/Network:/   {nw=$2}
           /Broadcast:/ {bc=$2}
           /Netmask:/   {nm=$2}
           /HostMin:/   {hmin=$2}
           /HostMax:/   {hmax=$2}
           END{print nw,bc,nm,hmin,hmax}'
)
# 如果 HostMin 恰好是网关，则跳过
if [ "$HOST_MIN" = "$GATEWAY" ]; then
  HOST_MIN=$(python3 - <<EOF
import ipaddress
print(ipaddress.IPv4Address("$HOST_MIN") + 1)
EOF
)
fi

PREFIX3=${MAIN_IP%.*}
PREFIX_LEN=${CIDR#*/}

# 4. 打印检测信息
echo "主接口:   $IFACE"
echo "默认网关: $GATEWAY"
echo "主 IP/CIDR:$CIDR"
echo "网络:     $NETWORK"
echo "广播:     $BCAST"
echo "掩码:     $NETMASK"
echo "可用范围: $HOST_MIN — $HOST_MAX"

# 5. 交互式选择范围
while true; do
  echo
  echo "请选择添加范围模式："
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
      echo "输入无效，请重新输入"
      ;;
  esac
done

START_HOST=${START_IP##*.}
END_HOST=${END_IP##*.}

# 6. 备份原配置
cp /etc/network/interfaces /etc/network/interfaces.bak_$(date +%Y%m%d%H%M%S)

# 7. 追加配置块
cat <<EOF >> /etc/network/interfaces

# --- 添加别名 IP ($(date '+%Y-%m-%d %H:%M:%S')) ---
auto $IFACE
iface $IFACE inet static
    address $MAIN_IP
    netmask $NETMASK
    gateway $GATEWAY
    dns-nameservers 8.8.8.8 1.1.1.1

    # 在接口启动后添加 IP
    post-up for i in \`seq $START_HOST $END_HOST\`; do ip addr add $PREFIX3.\$i/$PREFIX_LEN dev $IFACE; done

    # 在接口关闭前删除 IP
    pre-down for i in \`seq $START_HOST $END_HOST\`; do ip addr del $PREFIX3.\$i/$PREFIX_LEN dev $IFACE; done
EOF

# 8. 提示后续操作
echo
echo "已将配置追加到 /etc/network/interfaces。"
echo "IP 范围：$START_HOST—$END_HOST (/$PREFIX_LEN)"
echo "请运行："
echo "  sudo systemctl restart networking"
echo "或"
echo "  sudo ifdown $IFACE && sudo ifup $IFACE"
