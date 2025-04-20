#!/bin/bash

NETPLAN_CONFIG="/etc/netplan/50-cloud-init.yaml"

# 读取用户输入
read -p "请输入起始 IP: " start_ip
read -p "请输入结束 IP: " end_ip

# 提取 IP 的前三段和起始、结束的最后一段
IFS='.' read -r i1 i2 i3 i4 <<< "$start_ip"
IFS='.' read -r e1 e2 e3 e4 <<< "$end_ip"

# 确保前三段一致
if [[ "$i1.$i2.$i3" != "$e1.$e2.$e3" ]]; then
    echo "错误：起始和结束 IP 不在同一网段。"
    exit 1
fi

# 备份 Netplan 配置
cp $NETPLAN_CONFIG "${NETPLAN_CONFIG}.bak"

# 提取 macaddress
MAC_ADDRESS=$(awk '/macaddress:/ {print $2}' $NETPLAN_CONFIG)

# 定义网关 IP
gateway_ip="$i1.$i2.$i3.1"

# 生成新的 Netplan 配置
echo "network:
    version: 2
    ethernets:
        eth0:
            addresses:" > $NETPLAN_CONFIG

# 写入新的 IP 地址
for (( i=$i4; i<=$e4; i++ )); do
    echo "            - $i1.$i2.$i3.$i/22" >> $NETPLAN_CONFIG
    ip addr add "$i1.$i2.$i3.$i/24" dev eth0
    echo "已添加 IP: $i1.$i2.$i3.$i/22"
done

# 继续写入网关、DNS等配置信息，并保留原始 MAC 地址
cat <<EOL >> $NETPLAN_CONFIG
            gateway4: $gateway_ip
            match:
                macaddress: $MAC_ADDRESS
            nameservers:
                addresses:
                - 8.8.8.8
                - 8.8.4.4
                search:
                - example.com
            set-name: eth0
EOL

# 修正权限
chmod 600 $NETPLAN_CONFIG

# 重新应用 Netplan
netplan apply

echo "✅ 所有 IP 已成功添加，并使用 gateway4！"
