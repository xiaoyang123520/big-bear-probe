# 更新日志

## 2026-10-20

### 🧪 v1.2 借鉴 Kokoro：主机信息 / 流量 / 历史曲线 / 一键体检
- **主机配置展示**：Agent 上报 CPU 型号/核数、内存/磁盘总量、系统、虚拟化、架构（迁移 018 `monitors.host_info`），状态页卡片与详情页展示
- **流量统计**：Agent 上报实时速率（Mbps）与累计流量计数器；服务端按北京时间算今日/本月流量（计数器差值，重置兜底）；Agent 里原本写好未调用的 `read_bandwidth()` 正式接上
- **历史曲线**：新增 `GET /api/monitors/:id/agent/history`（降采样至约 240 点），详情页画近 24 小时 CPU/内存、三网延迟 SVG 折线
- **一键体检**：后台监控菜单下发任务 → Agent 下次上报时执行 → 回传结果。项目：CPU 跑分（固定工作量计时）、磁盘顺序读/写（128MB）、Cloudflare 测速、流媒体解锁粗测（Netflix/ChatGPT/YouTube/Disney+/TikTok 连通性判定，页面标注仅供参考）
- **价格与到期展示**：监控新增 `price_text` 字段（后台表单可填），详情页显示价格、到期日与剩余天数
- 解锁判定口径诚实标注：仅 HTTP 可达性粗测，非精确解锁结论；三网回程路由检测需 traceroute，本版未做
- 复查修复：agent_stats 保留期 7 天 → 35 天（否则每月 8 号起「本月流量」基线被删、统计失真）；流量统计排除 Docker 虚拟网卡（veth/br-/docker）防重复计数；三网延迟全为 0 时不再画贴底平线

## 2026-10-18

### 🔄 v1.1 Turso 迁移 + 15 项修复
- **数据库从 D1 切换到 Turso**（D1 免费版日读额度超限），Worker 支持 TURSO_URL/TURSO_TOKEN，无则回退 D1
- Turso 兼容层：integer/float 类型转换（修复复选框全勾选 bug）
- **SSL 证书多域名检查**：Agent 上报所有域名的证书剩余天数，详情页列表展示
- 修复：保存监控 500（last_row_id）、ssl_domains 列缺失
- 修复：testAlert 表单 ID 错误、状态码字符串/数字比较误判
- 修复：编辑/详情页 ID 类型匹配（String 比较）
- 修复：/api/status 漏 ssl_days/ssl_domain/ssl_list 字段
- 优化：告警消息带监控类型、故障原因、持续时间；告警列只显示已配置渠道
- 新增：监控保存后端非空校验、SSL 证书测试按钮

### 🎉 v1.0 首个开源版本
- HTTP/TCP/SSL/Agent 四种监控类型
- 11 种告警渠道（Telegram/邮件/Webhook/钉钉/Bark/企业微信/自建邮件/SMTP/Server酱/WxPusher/飞书）
- 服务器 Agent：资源监控、三网延迟、SSH 爆破检测+自动封禁、可疑进程告警、DDoS 检测、一键断网/恢复、进程存活监控、SSL 证书检查
- 邮件订阅、计划维护、历史故障时间线、响应时间曲线
- 监控分组、中/英双语、品牌定制、访客统计
- TOTP 双因素认证、自定义后台入口、登录限流
- 聚合状态接口（`/api/status`）、公开 API 缓存、bot 防护

## 更早

项目内部迭代，未记录。
