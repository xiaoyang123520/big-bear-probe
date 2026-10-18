# 🐻 大熊探针

![License](https://img.shields.io/badge/license-MIT-green)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange)
![Turso](https://img.shields.io/badge/Database-Turso-blue)
![No Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)

跑在 Cloudflare Workers + Turso 上的服务器/网站监控站。零依赖后端，前端纯原生 JS，支持 HTTP/TCP/HTTPS/服务器 Agent 四种监控类型，11 种告警渠道。

## ✨ 功能

**监控类型**
- 🌐 HTTP/HTTPS：状态码 + 关键词匹配检测
- 🔌 TCP 端口：host:port 连通性检测（需 Workers 付费版）
- 🔒 HTTPS：HTTPS 连通性检测（注意：不验证证书详情，证书到期检查请用 Agent）
- 🖥️ 服务器 Agent：Python 脚本上报 CPU/内存/磁盘/负载/三网延迟

**Agent 高级能力**
- SSH 爆破检测 + 自动封禁（iptables）
- 可疑进程告警（挖矿特征）
- DDoS/CC 症状检测（连接数/SYN）
- 一键断网/恢复（iptables 隔离）
- 进程存活监控
- **SSL 证书到期检查**：在 Agent 监控里配置域名（逗号分隔，支持多个），Agent 用 openssl 检查每个域名的证书剩余天数，详情页显示列表，7 天内告警

**告警渠道（11 种，可多选）**
- Telegram、邮件（Resend）、Webhook、钉钉、Bark、企业微信
- 自建邮件接口、SMTP 直发、Server酱、WxPusher、飞书

**其他**
- 邮件订阅：访客订阅故障/恢复通知
- 计划维护公告、历史故障时间线、响应时间曲线
- 监控分组、中/英双语、品牌定制
- 访客统计（IP 哈希，不存明文）
- TOTP 双因素认证、自定义后台入口路径、登录限流
- RSS、bot 防护、公开 API 缓存（D1 防爆）

## 🚀 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/xiaoyang123520/big-bear-probe)

在线演示：https://probe.helloxy.xyz

## 🛠️ 手动部署

### 方案 A：Turso（推荐）

1. 在 [Turso](https://turso.tech) 注册并创建数据库
2. 执行 `migrations/` 下的 SQL（按文件名顺序，001-017）
3. 在 Cloudflare Dashboard → Workers → probe → Settings → Variables 添加 Secrets：
   - `TURSO_URL`=https://xxx.turso.io（注意用 https 不是 libsql://）
   - `TURSO_TOKEN`=xxx
4. 构建并部署：
```bash
node build.js
npx wrangler deploy
```
5. 设置 Cron 触发器（每分钟）：`wrangler.toml` 已配好 `* * * * *`
6. 首次访问后台按提示设置管理员密码（≥10 位）

### 方案 B：D1

1. 在 Cloudflare Dashboard 创建 D1 数据库，记下 database_id
2. 执行 `migrations/` 下的 SQL（按文件名顺序，001-017）
3. 修改 `wrangler.toml` 填入你的 `database_id`
4. 构建并部署（同上，不设置 TURSO_URL/TURSO_TOKEN 即自动用 D1）

> 也可直接调 Cloudflare API 上传 `dist/index.js`（详见源码注释）。

## 🖥️ 服务器 Agent 部署

在后台监控列表点"📥 部署"，复制一键安装命令到服务器执行。Agent 为纯 Python 标准库脚本，无第三方依赖。

## 📁 项目结构

```
├── src/
│   ├── worker.js    # 后端（API + 定时检测 + 告警）
│   ├── app.html     # 前端（状态页 + 管理后台，单文件）
│   └── smtp.js      # SMTP 直发模块
├── agent.py         # 服务器监控脚本（纯标准库）
├── migrations/     # 数据库迁移（001-017，Turso/SQLite 兼容）
├── build.js         # 构建脚本（内联打包）
└── wrangler.toml   # Workers 配置模板
```

## 📊 容量规划（Turso 免费版）

Turso 免费版：每月 5 亿行读（约每天 1600 万）、1000 万行写（约每天 33 万）。

| 监控数 | /api/status 每次读 | Cron 每天写 | 结论 |
|--------|-------------------|------------|------|
| 3（当前） | ~75 行 | ~4 千行 | 余量充足 |
| 50 | ~1250 行 | ~7 万行 | 随便加 |
| 100+ | ~2500 行 | ~14 万行 | 写接近上限，把低优监控频率从 1 分钟改 5 分钟 |

> 读优化：7 天统计由 Cron 每小时预计算，`/api/status` 直接读结果；公开接口 300 秒缓存 + bot 防护。

## 🔌 API 概览

| 接口 | 说明 |
|------|------|
| `GET /api/status` | 聚合状态（一屏所需全部数据） |
| `GET /api/monitors` | 监控列表 |
| `GET /api/incidents` | 当前故障 |
| `POST /api/agent/report` | Agent 上报（HMAC 签名） |
| `/agent.py` | Agent 脚本下载 |

管理接口统一在 `/api/admin/*` 下，需 Token 鉴权。

## 💰 成本

Cloudflare 免费额度内完全够用（D1 日读 500 万行/写 10 万行）。公开接口带 60 秒内存缓存 + bot 防护，防爬虫刷爆额度。

## 🔐 安全建议

- 绑定 TOTP 双因素（后台设置页）
- 修改默认后台入口路径（默认 `/admin`）
- 定期更换管理员密码

## 📄 License

MIT
