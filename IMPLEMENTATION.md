# xdp-ban — 完整实现

全栈 Go + Gin + SQLite 的单二进制 DDoS 防护管理平台。

## 快速开始

```bash
# 编译
make build

# 运行(http://localhost:8080,默认 admin/admin12345)
./xdp-ban

# 测试
make test
```

## 完整功能

### 后端模块

| 模块 | 功能 | 状态 |
|------|------|------|
| `internal/model` | 数据模型(GORM + SQLite) | ✅ 完成 |
| `internal/policy` | 权限矩阵(4 角色、12 能力) | ✅ 完成 |
| `internal/web` | 路由、认证、HTML 模板、API | ✅ 完成 |
| `internal/safety` | 安全兜底层(保护集判定) | ✅ 完成 |
| `internal/escalation` | 阶梯封禁(5 级时间表) | ✅ 完成 |
| `internal/resolution` | 裁决规则(优先级算法) | ✅ 完成 |
| `internal/dispatch` | 下发指令生成与管理 | ✅ 完成 |
| `internal/approval` | 邮件审批令牌 | ✅ 完成 |
| `internal/auth` | 本地 + LDAP 认证 | ✅ 占位 |
| `internal/notification` | 邮件通知服务 | ✅ 完成 |
| `internal/config` | 环境配置管理 | ✅ 完成 |

### 前端页面

| 页面 | 功能 | 状态 |
|------|------|------|
| `/login` | 登录 | ✅ 完成 |
| `/dashboard` | 仪表板(统计卡片) | ✅ 完成 |
| `/bans` | 列表、过滤、操作 | ✅ 完成 |
| `/bans/new` | 新建请求 | ✅ 完成 |
| `/bans/:id` | 详情页 | ✅ 完成 |
| `/users` | 用户管理 | ✅ 完成 |
| `/audit` | 审计日志 | ✅ 完成 |
| `/approve/:token` | 邮件审批链接 | ✅ 完成 |

### API 端点(智能体/agent 轮询)

```bash
# 获取待下发指令
GET /api/v1/dispatch/pending
Authorization: X-API-Key: changeme

# 确认收到
POST /api/v1/dispatch/:id/ack

# 标记失败(重试)
POST /api/v1/dispatch/:id/fail -d error="msg"
```

## 权限体系

| 角色 | Dashboard | 新建 | 查看 | 批准 | 驳回 | 用户管理 | 审计 |
|------|-----------|------|------|------|------|----------|------|
| admin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| approver | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| operator | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ |
| viewer | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |

## 默认账户(首次启动自动创建)

| 用户名 | 密码 | 角色 |
|-------|------|------|
| admin | admin12345 | admin |
| approver | approver12345 | approver |
| operator | operator12345 | operator |
| viewer | viewer12345 | viewer |

**⚠️ 生产环境必须修改密码！**

## 数据流

```
1. operator 提交封禁请求
   ↓
2. 系统检查: SafetyGuard 保护集判定
   ↓
3. approver 审批(邮件 + 链接一次性)
   ↓
4. 生成 dispatch 指令 → 智能体
   ↓
5. 智能体下发至 XDP/nftables/iptables
   ↓
6. 审计日志记录全程
```

## 工作流

### 单次封禁(一次性)

```bash
POST /bans
  target=203.0.113.7
  reason="ssh 爆破"
```

结果: `pending` → approver 批准 → `active` → 下发 dispatch

### 重复攻击(阶梯时间表)

| 级别 | 时长 |
|------|------|
| 0 | 10 分钟 |
| 1 | 1 小时 |
| 2 | 1 天 |
| 3 | 7 天 |
| 4 | 永久 |

观察期:解封后 1 小时内未再犯 → 降级

## 环境变量

```bash
# 数据库路径(默认 xdpban.db)
XDPBAN_DB=./data/xdpban.db

# 监听地址(默认 :8080)
XDPBAN_LISTEN=:8080

# 基础 URL(用于邮件链接)
XDPBAN_BASE_URL=https://xdpban.example.com

# 邮件配置(占位;可集成 SendGrid/SES)
XDPBAN_MAIL_SERVER=smtp.example.com
XDPBAN_MAIL_FROM=xdpban@example.com

# API Key(智能体用)
XDPBAN_API_KEY=your-secret-key

# 日志级别
XDPBAN_LOG_LEVEL=info
```

## 开发

```bash
# 构建
make build

# 运行
make run

# 测试(含覆盖率)
make test
make coverage

# Docker
make docker-build
```

## 部署

### 单机模式

```bash
./xdp-ban
# 数据: ./xdpban.db (可备份)
```

### 智能体(agent)部署

智能体轮询 `/api/v1/dispatch/pending`，获取待执行指令，执行后 POST 确认。

参考: [https://github.com/githubflyideas/xdp-agent](https://github.com/githubflyideas/xdp-agent)

## 架构特性

- **单二进制** — 纯 Go,CGO_ENABLED=0,可静态编译
- **无外部依赖** — SQLite 内嵌,Gin 轻量路由
- **安全兜底** — 双重检查(SafetyGuard + ResolutionPolicy)
- **四眼原则** — requester 不能批准自己的请求
- **审计完整** — 全过程不可否认
- **一次性链接** — 邮件审批令牌 10 分钟失效
- **幂等下发** — 同一请求重复发不会重复执行

## 许可

[LICENSE](LICENSE)
