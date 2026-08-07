# ElastiFlow 接入(NetFlow v5)

xdp-sampler 可把采样流量以 **NetFlow v5** 导出到 ElastiFlow,做可视化流量分析。
这一套是可选的旁路:开不开都不影响封禁功能。

## 为什么是 NetFlow v5 而不是 IPFIX

我们的 XDP 采样只产出 IPv4 五元组 + 包数/字节数,这正好是 NetFlow v5 固定
记录字段的全集。v5 无模板、无状态——编码一次调对就永远对。IPFIX/v9 需要
周期性发送模板报文,收方在收到模板前会**静默丢弃**数据流,是一类"看着在跑
其实没数据"的隐性故障。我们用不上 IPFIX 的可扩展字段,却要为它多背一份
稳定性风险,所以选 v5。

v5 的限制(32 位计数器、仅 IPv4)对抽样统计无影响——采样本就是有损的,
不是精确计费。

## 启用导出

给 xdp-sampler 加 `-netflow` 参数指向 collector:

```bash
sudo ./xdp-sampler \
  -d eth1 \
  -url http://<control>:8080/api/v1/samples \
  -n 4096 \
  -key <API_KEY> \
  -netflow 127.0.0.1:2055
```

采样率(`-n`)会写入 NetFlow 报文的 sampling_interval 字段,ElastiFlow
据此把采样计数乘以 N 还原真实流量,不需要在 ElastiFlow 侧再配一遍。

## 一键起 ElastiFlow(Docker 或 Podman)

`deploy/elastiflow/` 下的 compose 文件兼容 Docker Compose v2 与 Podman Compose:

```bash
cd deploy/elastiflow

# Docker
docker compose up -d

# Podman(需安装 podman-compose)
podman-compose up -d

# 首次启动 Elasticsearch 需要一两分钟,就绪后:
#   Kibana:      http://localhost:5601
#   NetFlow 入口: udp/2055
```

然后让 sampler 指向宿主机的 2055 端口即可。Kibana 里导入 ElastiFlow
官方 dashboard(compose 已挂载 setup 容器自动导入)后,就能看到按
源国家 / AS / 端口 的流量视图——这也正好对应本项目"按国家/AS 封禁"的
决策依据:先在 ElastiFlow 看清谁在打,再回 xdp-ban 下封禁。

## 数据流

```
交换机镜像口 ─▶ eth1 ─▶ xdp_sampler.o(1/N 采样)
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
            HTTP /api/v1/samples   NetFlow v5 udp/2055
            (xdp-ban 仪表板)        (ElastiFlow → Kibana)
```

两条上报独立:xdp-ban 只取聚合后的 TopFlows 做即时展示与封禁决策,
ElastiFlow 做长期存储与多维分析。同一份采样,两个消费者。
