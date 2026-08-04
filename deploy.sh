#!/bin/bash
# deploy.sh — 一键部署脚本(需 root)

set -e

# 配置
XDPBAN_SERVER=${XDPBAN_SERVER:-http://localhost:8080}
XDPBAN_API_KEY=${XDPBAN_API_KEY:-changeme}
SAMPLER_DEVICE=${SAMPLER_DEVICE:-eth1}  # 镜像流量网卡
FILTER_DEVICE=${FILTER_DEVICE:-eth0}    # 业务网卡
SAMPLER_N=${SAMPLER_N:-100}             # 采样率 1/N
AGENT_INTERVAL=${AGENT_INTERVAL:-5s}

echo "=========================================="
echo "xdp-ban 部署脚本"
echo "=========================================="
echo ""
echo "配置:"
echo "  XDPBAN_SERVER: $XDPBAN_SERVER"
echo "  SAMPLER_DEVICE: $SAMPLER_DEVICE"
echo "  FILTER_DEVICE: $FILTER_DEVICE"
echo "  SAMPLER_N: 1/$SAMPLER_N"
echo ""

# 检查权限
if [ "$EUID" -ne 0 ]; then
   echo "❌ 此脚本需要 root 权限"
   exit 1
fi

# 检查工具
check_cmd() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ 未找到: $1"
        exit 1
    fi
}

echo "检查依赖..."
check_cmd clang
check_cmd llvm-objcopy
check_cmd nftables
check_cmd ip
echo "✓ 依赖检查通过"
echo ""

# 编译 eBPF
echo "编译 eBPF 程序..."
bash build_xdp.sh
echo ""

# 初始化 nftables
echo "初始化 nftables..."
nft add table ip filter 2>/dev/null || true
nft add chain ip filter input { type filter hook input priority 0\; policy accept\; } 2>/dev/null || true
nft add set ip filter blacklist { type ipv4_addr\; flags dynamic\; } 2>/dev/null || true
nft add rule ip filter input ip daddr @blacklist drop 2>/dev/null || true
echo "✓ nftables 就绪"
echo ""

# 挂载采样 XDP
echo "挂载采样 XDP 到 $SAMPLER_DEVICE..."
ip link set dev $SAMPLER_DEVICE xdp off 2>/dev/null || true
ip link set dev $SAMPLER_DEVICE xdp obj ./cmd/xdp-sampler/obj/xdp_sampler.o
echo "✓ 采样 XDP 已挂载"
echo ""

# 挂载过滤 XDP
echo "挂载过滤 XDP 到 $FILTER_DEVICE..."
ip link set dev $FILTER_DEVICE xdp off 2>/dev/null || true
ip link set dev $FILTER_DEVICE xdp obj ./cmd/xdp-agent/obj/xdp_filter.o
echo "✓ 过滤 XDP 已挂载"
echo ""

# 启动 systemd 服务(可选)
echo "创建 systemd 服务..."

# xdp-agent.service
cat > /etc/systemd/system/xdp-agent.service << EOF
[Unit]
Description=xdp-ban Agent - Dispatch Executor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xdp-agent -server $XDPBAN_SERVER -key $XDPBAN_API_KEY -interval $AGENT_INTERVAL
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# xdp-sampler.service
cat > /etc/systemd/system/xdp-sampler.service << EOF
[Unit]
Description=xdp-ban Sampler - Traffic Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xdp-sampler -d $SAMPLER_DEVICE -prog ./cmd/xdp-sampler/obj/xdp_sampler.o -url $XDPBAN_SERVER/api/v1/samples -n $SAMPLER_N -interval 10s
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
WorkingDirectory=$(pwd)

[Install]
WantedBy=multi-user.target
EOF

echo "✓ systemd 服务已创建"
echo ""

# 拷贝二进制(可选)
if [ -f "./xdp-agent" ]; then
    cp ./xdp-agent /usr/local/bin/
    chmod +x /usr/local/bin/xdp-agent
fi
if [ -f "./xdp-sampler" ]; then
    cp ./xdp-sampler /usr/local/bin/
    chmod +x /usr/local/bin/xdp-sampler
fi

echo "=========================================="
echo "✓ 部署完成!"
echo "=========================================="
echo ""
echo "后续步骤:"
echo "  1. 启动 agent:  systemctl start xdp-agent"
echo "  2. 启动 sampler: systemctl start xdp-sampler"
echo "  3. 查看日志:    journalctl -u xdp-agent -f"
echo "  4. 检查黑名单:  nft list set ip filter blacklist"
echo ""
echo "验证部署:"
echo "  curl http://localhost:8080/api/v1/dispatch/pending"
echo "  bpftool map dump name sampling_rate"
echo ""
