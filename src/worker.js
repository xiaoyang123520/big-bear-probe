// 探针站 Worker：定时检测 + 状态 API + 告警
// 部署：node build.js 然后上传 dist/index.js

import { connect } from "cloudflare:sockets";

const APP_HTML = "__APP_HTML__";

//__SMTP_JS__

//__TURSO_JS__

// 获取数据库：优先 Turso（环境变量配置），回退 D1
function getDB(env) {
  if (env.TURSO_URL && env.TURSO_TOKEN) {
    return createTursoDB(env.TURSO_URL, env.TURSO_TOKEN);
  }
  return env.DB;
}

// ---------- 工具 ----------
const now = () => Math.floor(Date.now() / 1000);

async function sha256hex(s) {
const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}

function json(data, status = 200) {
return new Response(JSON.stringify(data), {
status,
headers: { "Content-Type": "application/json"}
});
}

// ---------- 应用层 botguard：爬虫/脚本刷 API 直接 403，不消耗 D1 ----------
// 自家 Agent（ProbeAgent/1.0）放行；搜索引擎放行页面但禁 /api/
function botGuard(req, path) {
const ua = req.headers.get("User-Agent") || "";
// Agent 上报接口已有 token+HMAC 鉴权，免除 UA 检查（防旧版 agent 被误杀）
if (path === "/api/agent/report") return null;
// 自家监控 Agent 放行
if (/^ProbeAgent\//i.test(ua)) return null;
// 空 UA：只拦 API，页面放行
if (!ua.trim() && path.startsWith("/api/")) return new Response("Forbidden", { status: 403 });
// AI 训练 / 商业采集爬虫
if (/gptbot|ccbot|claudebot|anthropic|bytespider|ahrefsbot|semrushbot|mj12bot|dotbot|petalbot|dataforseo|cohere|ai2bot/i.test(ua)) return new Response("Forbidden", { status: 403 });
// 脚本客户端与扫描器
if (/python-requests|python-urllib|go-http-client|scrapy|headlesschrome|phantomjs|sqlmap|nuclei|nikto|masscan|zgrab/i.test(ua)) {
if (path.startsWith("/api/")) return new Response("Forbidden", { status: 403 });
}
// curl：Agent 不用 curl，API 直接拦
if (/^curl\//i.test(ua) && path.startsWith("/api/")) return new Response("Forbidden", { status: 403 });
// 漏洞扫描路径
if (/\/(wp-login|wp-admin|\.env|\.git|phpmyadmin|pma|actuator|server-status|\.svn|\.hg|composer\.json|package\.json)/i.test(path)) return new Response("Forbidden", { status: 403 });
// 搜索引擎：放行页面，但禁 API
if (/googlebot|bingbot|baiduspider|yandexbot|sogou|360spider|duckduckbot/i.test(ua)) {
if (path.startsWith("/api/")) return new Response("Forbidden", { status: 403 });
return null;
}
// 社交预览：放行
if (/twitterbot|telegrambot|discordbot|facebookexternalhit|linkedinbot|slackbot|whatsapp/i.test(ua)) return null;
return null;
}

// ---------- 公开接口缓存：命中则不查 D1，TTL 60 秒 ----------
// 数据每分钟才变一次，缓存不影响实时性
// 用内存 Map（同 isolate 内有效），Cache API 对合成响应不可靠
const CACHEABLE_API = [
/^\/api\/monitors$/,
/^\/api\/monitors\/\d+\/stats$/,
/^\/api\/monitors\/\d+\/checks$/,
/^\/api\/monitors\/\d+\/agent$/,
/^\/api\/incidents$/,
/^\/api\/incidents\/history$/,
/^\/api\/maintenances$/,
/^\/api\/branding$/,
/^\/api\/status$/,
];
const apiCache = new Map(); // key -> { body, headers, expires }
// admin 写操作后清缓存（同 isolate 有效）
function invalidateApiCache() { apiCache.clear(); }
function isCacheableApi(req, path) {
if (req.method !== "GET") return false;
return CACHEABLE_API.some(re => re.test(path));
}
async function cachedApi(req, db, env) {
const key = req.url;
const hit = apiCache.get(key);
if (hit && hit.expires > Date.now()) {
return new Response(hit.body, { status: 200, headers: { ...hit.headers, "X-Probe-Cache": "HIT" } });
}
const resp = await handleApi(req, db, env);
if (resp.ok) {
const body = await resp.arrayBuffer();
const headers = {};
resp.headers.forEach((v, k) => { headers[k] = v; });
apiCache.set(key, { body, headers, expires: Date.now() + 300000 }); // 5 分钟缓存，降 D1 读
// 防止内存无限增长，最多保留 200 条
if (apiCache.size > 200) {
const oldest = apiCache.keys().next().value;
apiCache.delete(oldest);
}
return new Response(body, { status: resp.status, headers: { ...headers, "X-Probe-Cache": "MISS" } });
}
return resp;
}

// ---------- 检测逻辑 ----------
async function checkHttp(m) {
const t0 = Date.now();
try {
const ctrl = new AbortController();
const timer = setTimeout(() => ctrl.abort(), 30000);
const resp = await fetch(m.target, {
signal: ctrl.signal,
redirect: "follow",
headers: { "User-Agent": "ProbeBot/1.0"}
});
clearTimeout(timer);
const ms = Date.now() - t0;
// 状态码检查（转数字再比，避免字符串 "200" !== 数字 200）
const expected = parseInt(m.expected_status, 10) || 0;
if (expected && resp.status !== expected) {
return { status: "down", ms, detail: `状态码 ${resp.status}，期望 ${expected}`};
}
// 关键词检查（只读前 1MB，防止大文件打爆内存）
if (m.keyword) {
const reader = resp.body.getReader();
let text = "";
let received = 0;
while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  received += value.length;
  if (received > 1024 * 1024) break;
  text += new TextDecoder().decode(value, { stream: true });
}
reader.cancel();
if (!text.includes(m.keyword)) {
return { status: "down", ms, detail: `关键词 "${m.keyword}" 未找到`};
}
}
return { status: "up", ms, detail: `${resp.status}`};
} catch (e) {
return { status: "down", ms: Date.now() - t0, detail: e.name === "AbortError"? "超时 30s": String(e.message || e).slice(0, 200)};
}
}

async function checkTcp(m) {
const t0 = Date.now();
try {
// 支持 IPv6：用最后一个冒号分割 host 和 port
const idx = m.target.lastIndexOf(":");
let host, port;
if (idx > 0 && /^\d+$/.test(m.target.slice(idx + 1))) {
  host = m.target.slice(0, idx).replace(/^\[|\]$/g, "");
  port = parseInt(m.target.slice(idx + 1), 10);
} else {
  host = m.target.replace(/^\[|\]$/g, "");
  port = 80;
}
// Workers Socket API（需 Workers 付费版，免费版会抛权限错误）
const socket = await connect({ hostname: host, port});
socket.close();
return { status: "up", ms: Date.now() - t0, detail: `${host}:${port} 连通`};
} catch (e) {
const msg = String(e.message || e);
// 免费版无 Socket 权限时给明确提示，而非普通 down
if (/socket|permit|allow|paid|plan/i.test(msg)) {
return { status: "down", ms: Date.now() - t0, detail: "TCP 检测需 Workers 付费版，当前套餐不支持" };
}
return { status: "down", ms: Date.now() - t0, detail: msg.slice(0, 200)};
}
}

// Agent 心跳检查：如果超过 2 倍间隔没上报，判定离线
async function checkAgent(db, m) {
  const t0 = Date.now();
  try {
    const last = await db.prepare(
      `SELECT reported_at, cpu, mem, disk FROM agent_stats WHERE monitor_id=? ORDER BY reported_at DESC LIMIT 1`
    ).bind(m.id).first();
    if (!last) {
      return { status: "down", ms: 0, detail: "从未收到 Agent 上报" };
    }
    const intervalSec = (m.interval_minutes || 5) * 60;
    const gap = now() - last.reported_at;
    if (gap > intervalSec * 2) {
      return { status: "down", ms: 0, detail: `Agent ${Math.floor(gap / 60)} 分钟未上报` };
    }
    return { status: "up", ms: 0, detail: `CPU ${last.cpu}% · 内存 ${last.mem}% · 磁盘 ${last.disk}%` };
  } catch (e) {
    return { status: "down", ms: Date.now() - t0, detail: String(e.message || e).slice(0, 200) };
  }
}

async function runCheck(db, m, opts = {}) {
const silent = !!opts.silent; // 手动测试时为 true，跳过真实告警和订阅者通知
let result;
// SSL 类型：如果 target 没带协议，自动补 https://
if (m.type === "ssl" && m.target && !/^https?:\/\//i.test(m.target)) {
  m = { ...m, target: "https://" + m.target };
}
if (m.type === "tcp") result = await checkTcp(m);
else if (m.type === "agent") result = await checkAgent(db, m);
else result = await checkHttp(m); // ssl 类型走 https 连通性检测

const ts = now();
const prevStatus = m.last_status;

// 更新 monitor 状态
const failures = result.status === "down"? m.consecutive_failures + 1: 0;
await db.prepare(
`UPDATE monitors SET last_check_at=?, last_status=?, last_ms=?, consecutive_failures=? WHERE id=?`
).bind(ts, result.status, result.ms, failures, m.id).run();

// 写历史
await db.prepare(
`INSERT INTO checks (monitor_id, checked_at, status, ms, detail) VALUES (?,?,?,?,?)`
).bind(m.id, ts, result.status, result.ms, result.detail).run();

// 状态变化处理（unknown 为新建监控首次检测，只写状态不告警，防误报轰炸）
if (prevStatus!== result.status) {
if (prevStatus === "unknown") {
// 新建监控首次检测：静默记录，不发告警
} else if (result.status === "down") {
// 新故障
await db.prepare(
`INSERT INTO incidents (monitor_id, started_at, fail_count) VALUES (?,?,1)`
).bind(m.id, ts).run();
if (!silent) {
await sendAlerts(db, m, "down", result);
// 通知订阅者
const origin = await getSetting(db, "site_origin") || "";
const siteTitle = await getSetting(db, "site_title") || "大熊探针";
const subTarget = m.target ? `（${m.target}）` : "";
await notifySubscribers(db, origin, `🔴 ${m.name} 出现故障 - ${siteTitle}`,
`${m.name}${subTarget}出现故障。\n原因：${result.detail}`);
}
} else if (prevStatus === "down") {
// 恢复
await db.prepare(
`UPDATE incidents SET ended_at=? WHERE monitor_id=? AND ended_at=0`
).bind(ts, m.id).run();
if (!silent) {
await sendAlerts(db, m, "up", result);
// 通知订阅者
const origin2 = await getSetting(db, "site_origin") || "";
const siteTitle2 = await getSetting(db, "site_title") || "大熊探针";
const subTarget2 = m.target ? `（${m.target}）` : "";
await notifySubscribers(db, origin2, `🟢 ${m.name} 已恢复 - ${siteTitle2}`,
`${m.name}${subTarget2}已恢复正常。`);
}
}
} else if (result.status === "down") {
// 持续故障，更新计数
await db.prepare(
`UPDATE incidents SET fail_count=fail_count+1 WHERE monitor_id=? AND ended_at=0`
).bind(m.id).run();
}

return result;
}

// ---------- 告警 ----------
async function getSetting(db, key) {
const r = await db.prepare(`SELECT value FROM settings WHERE key=?`).bind(key).first();
return r? r.value: "";
}

// 获取客户端 IP
function getClientIp(req) {
  return req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() || "unknown";
}

// 记录后台操作日志
async function adminLog(db, action, detail, ip) {
  try {
    await db.prepare(`INSERT INTO admin_logs (action, detail, ip, created_at) VALUES (?,?,?,?)`)
      .bind(action, detail || "", ip || "", now()).run();
    // 只保留 90 天
    await db.prepare(`DELETE FROM admin_logs WHERE created_at < ?`).bind(now() - 90 * 86400).run();
  } catch (e) {}
}

// HMAC-SHA256（用于 Agent 签名验证）
async function hmacSha256(key, msg) {
  const keyBuf = new TextEncoder().encode(key);
  const msgBuf = new TextEncoder().encode(msg);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBuf, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, msgBuf);
  return [...new Uint8Array(sig)].map(x => x.toString(16).padStart(2, "0")).join("");
}

// 通用邮件发送（Resend）
async function sendEmail(db, from, to, subject, text) {
const apiKey = await getSetting(db, "resend_api_key");
if (!apiKey || !from || !to) return false;
try {
const r = await fetch("https://api.resend.com/emails", {
method: "POST",
headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}`},
body: JSON.stringify({ from, to: Array.isArray(to) ? to : [to], subject, text})
});
return r.ok;
} catch (e) { return false; }
}

// 通知所有已验证的订阅者
async function notifySubscribers(db, origin, subject, text) {
try {
const r = await db.prepare(`SELECT email, token FROM subscribers WHERE verified=1`).all();
const subs = r.results || [];
if (!subs.length) return;
const from = await getSetting(db, "alert_email_from");
if (!from) return;
for (const s of subs) {
const body = text + `\n\n---\n不想再收到？点击取消订阅：${origin}/api/subscribe/unsubscribe?token=${s.token}`;
await sendEmail(db, from, s.email, subject, body);
}
} catch (e) {}
}

// 通用告警：标题 + 内容，走监控配置的告警渠道
async function sendAlert(db, m, title, detail) {
const text = `${title}\n监控：${m.name}\n${detail}\n时间：${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai"})}`;

// Telegram
if (m.alert_telegram) {
const token = await getSetting(db, "telegram_bot_token");
const chatId = await getSetting(db, "telegram_chat_id");
if (token && chatId) {
try {
await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
method: "POST",
headers: { "Content-Type": "application/json"},
body: JSON.stringify({ chat_id: chatId, text})
});
} catch (e) {}
}
}

// 邮件 (Resend)
if (m.alert_email) {
const apiKey = await getSetting(db, "resend_api_key");
const from = await getSetting(db, "alert_email_from");
const to = await getSetting(db, "alert_email_to");
if (apiKey && from && to) {
try {
await fetch("https://api.resend.com/emails", {
method: "POST",
headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}`},
body: JSON.stringify({ from, to: [to], subject: title.replace(/^[⚠️✅🔴🟢]\s*/, ""), text})
});
} catch (e) {}
}
}

// Webhook
if (m.alert_webhook && m.webhook_url) {
try {
await fetch(m.webhook_url, {
method: "POST",
headers: { "Content-Type": "application/json"},
body: JSON.stringify({ monitor: m.name, event: title, detail, time: now()})
});
} catch (e) {}
}

// 钉钉
if (m.alert_dingtalk) {
const webhook = await getSetting(db, "dingtalk_webhook");
if (webhook) {
try {
await fetch(webhook, {
method: "POST",
headers: { "Content-Type": "application/json"},
body: JSON.stringify({
msgtype: "markdown",
markdown: { title: title, text: `### ${title}\n\n🖥️ ${m.name}\n\n${detail}\n\n⏰ ${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai"})}` }
})
});
} catch (e) {}
}
}

// Bark
if (m.alert_bark) {
const barkUrl = await getSetting(db, "bark_url");
if (barkUrl) {
try {
const url = barkUrl.replace(/\/$/, "") + "/" + encodeURIComponent(title) + "/" + encodeURIComponent(`${m.name}\n${detail}`.slice(0, 800));
await fetch(url);
} catch (e) {}
}
}

// 企业微信
if (m.alert_wecom) {
const webhook = await getSetting(db, "wecom_webhook");
if (webhook) {
try {
await fetch(webhook, {
method: "POST",
headers: { "Content-Type": "application/json"},
body: JSON.stringify({
msgtype: "markdown",
markdown: { content: `## ${title}\n🖥️ ${m.name}\n${detail}\n⏰ ${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai"})}` }
})
});
} catch (e) {}
}
}

// 自定义邮件接口（用户自建 HTTP 发邮件服务）
if (m.alert_custom_email) {
const url = await getSetting(db, "custom_email_url");
if (url) {
try {
const headersJson = await getSetting(db, "custom_email_headers");
let headers = { "Content-Type": "application/json" };
try { if (headersJson) headers = { ...headers, ...JSON.parse(headersJson) }; } catch (e) {}
const from = await getSetting(db, "custom_email_from") || await getSetting(db, "alert_email_from") || "";
const to = await getSetting(db, "custom_email_to") || await getSetting(db, "alert_email_to") || "";
await fetch(url, {
method: "POST",
headers,
body: JSON.stringify({ from, to, subject: title.replace(/^[⚠️✅🔴🟢🚨]\s*/, ""), text, monitor: m.name })
});
} catch (e) {}
}
}

// SMTP 直发（需 Workers 付费版 sockets）
if (m.alert_smtp) {
const host = await getSetting(db, "smtp_host");
const user = await getSetting(db, "smtp_user");
const pass = await getSetting(db, "smtp_pass");
if (host && user && pass) {
try {
const to = await getSetting(db, "smtp_to") || await getSetting(db, "alert_email_to") || "";
const from = await getSetting(db, "smtp_from") || user;
await sendSmtpMail(
{ host, port: parseInt(await getSetting(db, "smtp_port") || "587", 10), username: user, password: pass, from, to: to.split(",").map(s => s.trim()).filter(Boolean), secure: await getSetting(db, "smtp_secure") || "auto" },
title.replace(/^[⚠️✅🔴🟢🚨]\s*/, ""),
text
);
} catch (e) {}
}
}

// Server酱
if (m.alert_serverchan) {
const sendkey = await getSetting(db, "serverchan_sendkey");
if (sendkey) {
try {
await fetch(`https://sctapi.ftqq.com/${sendkey}.send`, {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ title: title, desp: `**${m.name}**\n\n${detail}\n\n${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" })}` })
});
} catch (e) {}
}
}

// WxPusher
if (m.alert_wxpusher) {
const spt = await getSetting(db, "wxpusher_spt");
if (spt) {
try {
await fetch("https://wxpusher.zjiecode.com/api/send/message", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({
appToken: spt,
content: `<h2>${title}</h2><p><b>${m.name}</b></p><p>${detail.replace(/\n/g, "<br>")}</p>`,
summary: `${title} - ${m.name}`,
contentType: 2
})
});
} catch (e) {}
}
}

// 飞书
if (m.alert_feishu) {
const webhook = await getSetting(db, "feishu_webhook");
if (webhook) {
try {
await fetch(webhook, {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({
msg_type: "text",
content: { text: `${title}\n🖥️ ${m.name}\n${detail}\n⏰ ${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" })}` }
})
});
} catch (e) {}
}
}
}

async function sendAlerts(db, m, kind, result) {
const emoji = kind === "down"? "🔴": "🟢";
const action = kind === "down"? "宕机": "恢复";
// 监控类型中文名
const typeName = m.type === "http" ? "网站监控" : m.type === "ssl" ? "SSL证书" : m.type === "tcp" ? "TCP端口" : m.type === "agent" ? "服务器" : m.type;
// Agent 类型：target 可能为空
const targetLine = m.type === "agent" ? "" : `\n🎯 目标：${m.target}`;
let detailLine = "";
let extraLine = "";
if (kind === "down") {
  detailLine = "\n❌ 原因：" + result.detail;
  // 连续失败次数
  const fails = (m.consecutive_failures || 0) + 1;
  extraLine = `\n🔢 连续失败：第 ${fails} 次`;
  // 检查频率
  extraLine += `\n⏱️ 检测频率：每 ${m.interval_minutes || 5} 分钟`;
} else {
  // 恢复：查故障持续时间
  const inc = await db.prepare(`SELECT started_at, fail_count FROM incidents WHERE monitor_id=? ORDER BY started_at DESC LIMIT 1`).bind(m.id).first();
  if (inc && inc.started_at) {
    const mins = Math.max(1, Math.round((now() - inc.started_at) / 60));
    const durStr = mins >= 60 ? `${Math.floor(mins/60)}小时${mins%60}分钟` : `${mins}分钟`;
    extraLine = `\n⏳ 故障持续：${durStr}`;
    if (inc.fail_count) extraLine += `\n🔢 累计失败：${inc.fail_count} 次`;
  }
  detailLine = m.type === "agent" ? "\n" + result.detail : "\n✅ 耗时：" + result.ms + "ms";
}
const text = `${emoji}${action}【${typeName}】\n📡 监控：${m.name}${targetLine}${detailLine}${extraLine}\n🕐 时间：${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai"})}`;

// Telegram
if (m.alert_telegram) {
const token = await getSetting(db, "telegram_bot_token");
const chatId = await getSetting(db, "telegram_chat_id");
if (token && chatId) {
try {
await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
method: "POST",
headers: { "Content-Type": "application/json"},
body: JSON.stringify({ chat_id: chatId, text})
});
} catch (e) { /* 告警失败不影响主流程 */}
}
}

// 邮件 (Resend)
if (m.alert_email) {
const apiKey = await getSetting(db, "resend_api_key");
const from = await getSetting(db, "alert_email_from");
const to = await getSetting(db, "alert_email_to");
if (apiKey && from && to) {
try {
await fetch("https://api.resend.com/emails", {
method: "POST",
headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}`},
body: JSON.stringify({ from, to: [to], subject: `${m.name}${action}`, text})
});
} catch (e) { /* 忽略 */}
}
}

// Webhook
if (m.alert_webhook && m.webhook_url) {
try {
await fetch(m.webhook_url, {
method: "POST",
headers: { "Content-Type": "application/json"},
body: JSON.stringify({ monitor: m.name, target: m.target, event: action, detail: result.detail, time: now()})
});
} catch (e) { /* 忽略 */}
}
}

// ---------- Cron：每分钟跑，挑到点的检测 ----------
async function handleCron(db) {
const ts = now();
// 选出所有启用的监控，在 JS 里按类型精细判断（agent 的 last_check_at 是上报时间，不能直接用于过滤）
const due = await db.prepare(
`SELECT * FROM monitors WHERE enabled=1 ORDER BY last_check_at ASC`
).all();

let checked = 0;
for (const m of (due.results || [])) {
const intervalSec = (m.interval_minutes || 5) * 60;
if (m.type === "agent") {
// Agent：每次 cron 都检查心跳（只是查 DB，很便宜）；上报正常且状态已是 up 时可跳过省一次写
if (m.last_status === "up" && ts - (m.last_check_at || 0) < 120) continue;
} else {
if (ts - (m.last_check_at || 0) < intervalSec) continue;
}
await runCheck(db, m);
checked++;
if (checked >= 20) break;
}

// 清理 90 天前的历史
await db.prepare(`DELETE FROM checks WHERE checked_at <?`).bind(ts - 90 * 86400).run();
// 清理过期的订阅限流 key（1小时前的）
await db.prepare(`DELETE FROM settings WHERE key LIKE 'sub_ratelimit\_%\_ts' AND CAST(value AS INTEGER) < ?`).bind(ts - 3600).run();
// 清理孤立的限流计数（没有对应时间戳的）
await db.prepare(`DELETE FROM settings WHERE key LIKE 'sub_ratelimit\_%' AND key NOT LIKE '%\_ts' AND NOT EXISTS (SELECT 1 FROM settings s2 WHERE s2.key = settings.key || '_ts')`).run();

// 预计算 7 天统计（每小时一次，避免 /api/status 现场扫全表）
try {
  const statsNeed = await db.prepare(
    `SELECT id FROM monitors WHERE stats_updated_at < ? LIMIT 1`
  ).bind(ts - 3600).first();
  if (statsNeed) {
    const since7d = ts - 7 * 86400;
    const allM = await db.prepare(`SELECT id FROM monitors`).all();
    for (const mm of (allM.results || [])) {
      const st = await db.prepare(
        `SELECT COUNT(*) as total, SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) as up, AVG(ms) as avg_ms FROM checks WHERE monitor_id=? AND checked_at>=?`
      ).bind(mm.id, since7d).first();
      const total = st.total || 0;
      const uptime = total ? ((st.up || 0) / total * 100).toFixed(2) : "100.00";
      const avgMs = Math.round(st.avg_ms || 0);
      await db.prepare(
        `UPDATE monitors SET uptime_7d=?, avg_ms_7d=?, stats_updated_at=? WHERE id=?`
      ).bind(uptime, avgMs, ts, mm.id).run();
    }
  }
} catch (e) { /* 列不存在时跳过（迁移前） */ }

// 到期提醒（每天检查一次，用日期做去重）
try {
  const today = new Date().toISOString().slice(0, 10);
  const expireDays = parseInt(await getSetting(db, "expire_alert_days") || "7", 10);
  const expiring = await db.prepare(
    `SELECT * FROM monitors WHERE enabled=1 AND expire_at > 0 AND expire_at < ?`
  ).bind(ts + expireDays * 86400).all();
  for (const m of (expiring.results || [])) {
    const state = JSON.parse(m.expire_alert_state || "{}");
    if (state.last_alert === today) continue;
    const daysLeft = Math.ceil((m.expire_at - ts) / 86400);
    const dateStr = new Date(m.expire_at * 1000).toLocaleDateString("zh-CN", { timeZone: "Asia/Shanghai" });
    state.last_alert = today;
    await db.prepare(`UPDATE monitors SET expire_alert_state=? WHERE id=?`).bind(JSON.stringify(state), m.id).run();
    await sendAlert(db, m, `⏰ ${m.name} 即将到期`, `到期时间：${dateStr}（还有 ${daysLeft} 天）\n请及时续费，避免服务中断`);
  }
} catch (e) {}

return { checked};
}

// ---------- API ----------
async function handleApi(req, db, env) {
const url = new URL(req.url);
const path = url.pathname;
const method = req.method;

// 公开：监控列表（不含敏感字段）
if (path === "/api/monitors" && method === "GET") {
const r = await db.prepare(
`SELECT id, name, type, target, interval_minutes, group_name, enabled, last_check_at, last_status, last_ms, consecutive_failures, created_at FROM monitors ORDER BY group_name, id`
).all();
return json({ monitors: r.results || []});
}

// 公开：可用率统计
if (path.match(/^\/api\/monitors\/\d+\/stats$/) && method === "GET") {
const id = path.split("/")[3];
const days = Math.min(parseInt(url.searchParams.get("days") || "7", 10), 90);
const since = now() - days * 86400;
const r = await db.prepare(
`SELECT COUNT(*) as total, SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) as up, AVG(ms) as avg_ms FROM checks WHERE monitor_id=? AND checked_at>=?`
).bind(id, since).first();
const total = r.total || 0;
return json({
uptime: total? ((r.up || 0) / total * 100).toFixed(2): "100.00",
total, avg_ms: Math.round(r.avg_ms || 0)
});
}

// 公开：最近检测记录（图表用）
if (path.match(/^\/api\/monitors\/\d+\/checks$/) && method === "GET") {
const id = path.split("/")[3];
const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
const r = await db.prepare(
`SELECT checked_at, status, ms FROM checks WHERE monitor_id=? ORDER BY checked_at DESC LIMIT?`
).bind(id, limit).all();
return json({ checks: (r.results || []).reverse()});
}

// 公开：未恢复的故障
if (path === "/api/incidents" && method === "GET") {
const r = await db.prepare(
`SELECT i.*, m.name FROM incidents i JOIN monitors m ON m.id=i.monitor_id WHERE i.ended_at=0 ORDER BY i.started_at DESC`
).all();
return json({ incidents: r.results || []});
}

// Agent 上报（用 agent_token 鉴权）
if (path === "/api/agent/report" && method === "POST") {
const body = await req.json().catch(() => ({}));
const token = body.token || req.headers.get("X-Agent-Token") || "";
if (!token) return json({ error: "missing token" }, 401);
const m = await db.prepare(`SELECT * FROM monitors WHERE agent_token=? AND type='agent'`).bind(token).first();
if (!m) return json({ error: "invalid token" }, 401);
// HMAC 签名验证（防重放）：新版 agent 会带 ts + sig，老版兼容跳过
if (body.ts && body.sig) {
  const tsDiff = Math.abs(now() - parseInt(body.ts, 10));
  if (tsDiff > 300) return json({ error: "timestamp expired" }, 401);
  const expected = await hmacSha256(token, String(body.ts));
  if (expected !== body.sig) return json({ error: "invalid signature" }, 401);
}
const ts = now();
const cpu = body.cpu || 0, mem = body.mem || 0, disk = body.disk || 0;
await db.prepare(
`INSERT INTO agent_stats (monitor_id, reported_at, cpu, mem, disk, uptime, load1, ping_telecom, ping_unicom, ping_mobile, rx_mbps, tx_mbps, net_rx, net_tx) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
).bind(m.id, ts, cpu, mem, disk, body.uptime || 0, body.load1 || 0, body.ping_telecom || 0, body.ping_unicom || 0, body.ping_mobile || 0, body.rx_mbps || 0, body.tx_mbps || 0, body.net_rx || 0, body.net_tx || 0).run();
// 主机配置（CPU 型号/核数/内存/磁盘/系统等，agent 每次上报都带，覆盖存最新）
if (body.host_info) {
  try {
    const hi = JSON.stringify(body.host_info);
    await db.prepare(`UPDATE monitors SET host_info=? WHERE id=?`).bind(hi, m.id).run();
    m.host_info = hi;
  } catch (e) {}
}
// 更新最后上报时间（复用 last_check_at 字段）
await db.prepare(`UPDATE monitors SET last_check_at=? WHERE id=?`).bind(ts, m.id).run();
// 只保留 35 天的 agent 数据（要覆盖整月，供本月流量统计取月初基线）
await db.prepare(`DELETE FROM agent_stats WHERE reported_at < ?`).bind(ts - 35 * 86400).run();
// ---------- 资源阈值告警 ----------
try {
  const state = JSON.parse(m.agent_alert_state || "{}");
  const checks = [
    ["cpu", cpu, m.cpu_threshold, "CPU"],
    ["mem", mem, m.mem_threshold, "内存"],
    ["disk", disk, m.disk_threshold, "磁盘"],
  ];
  let stateChanged = false;
  for (const [key, val, threshold, label] of checks) {
    if (!threshold || threshold <= 0) continue;
    const alerting = !!state[key];
    if (!alerting && val >= threshold) {
      // 触发告警
      state[key] = 1; stateChanged = true;
      await sendAlert(db, m, `⚠️ ${m.name} ${label}使用率过高`, `${label}使用率 ${val}%，超过阈值 ${threshold}%`);
    } else if (alerting && val < threshold * 0.9) {
      // 回滞 10%，恢复正常
      state[key] = 0; stateChanged = true;
      await sendAlert(db, m, `✅ ${m.name} ${label}已恢复`, `${label}使用率回落到 ${val}%，阈值 ${threshold}%`);
    }
  }
  if (stateChanged) {
    await db.prepare(`UPDATE monitors SET agent_alert_state=? WHERE id=?`).bind(JSON.stringify(state), m.id).run();
  }
} catch (e) { /* 告警失败不影响上报 */ }

// ---------- SSH 爆破检测 ----------
try {
  const sshFail = body.ssh_fail || 0;
  const sshIps = body.ssh_ips || "";
  const sshThreshold = m.ssh_threshold || 0;
  if (sshThreshold > 0) {
    const state = JSON.parse(m.ssh_alert_state || "{}");
    const alerting = !!state.ssh;
    if (!alerting && sshFail >= sshThreshold) {
      state.ssh = 1;
      await db.prepare(`UPDATE monitors SET ssh_alert_state=? WHERE id=?`).bind(JSON.stringify(state), m.id).run();
      const ipList = sshIps ? `\n攻击 IP Top：\n${sshIps}` : "";
      await sendAlert(db, m, `🚨 ${m.name} 疑似 SSH 爆破攻击`, `10 分钟内 SSH 失败登录 ${sshFail} 次，超过阈值 ${sshThreshold} 次${ipList}\n\n建议：检查 /var/log/secure（或 auth.log），考虑封禁 IP 或改 SSH 端口`);
    } else if (alerting && sshFail < sshThreshold) {
      state.ssh = 0;
      await db.prepare(`UPDATE monitors SET ssh_alert_state=? WHERE id=?`).bind(JSON.stringify(state), m.id).run();
      await sendAlert(db, m, `✅ ${m.name} SSH 爆破告警解除`, `10 分钟内 SSH 失败登录回落到 ${sshFail} 次`);
    }
  }
} catch (e) { /* 告警失败不影响上报 */ }

// ---------- 网络异常检测（DDoS/CC 症状） ----------
try {
  const connCount = body.conn_count || 0;
  const synRecv = body.syn_recv || 0;
  const connThreshold = m.conn_threshold || 0;
  const netState = JSON.parse(m.net_alert_state || "{}");
  // TCP 连接数突增
  if (connThreshold > 0) {
    const alerting = !!netState.conn;
    if (!alerting && connCount >= connThreshold) {
      netState.conn = 1;
      await db.prepare(`UPDATE monitors SET net_alert_state=? WHERE id=?`).bind(JSON.stringify(netState), m.id).run();
      await sendAlert(db, m, `🌐 ${m.name} TCP 连接数异常`, `当前 TCP 连接 ${connCount} 个，超过阈值 ${connThreshold} 个\n疑似 CC 攻击或业务突增，请检查`);
    } else if (alerting && connCount < connThreshold * 0.7) {
      netState.conn = 0;
      await db.prepare(`UPDATE monitors SET net_alert_state=? WHERE id=?`).bind(JSON.stringify(netState), m.id).run();
      await sendAlert(db, m, `✅ ${m.name} TCP 连接数恢复`, `当前 ${connCount} 个，回落到阈值 70% 以下`);
    }
  }
  // SYN 洪水特征：SYN_RECV 堆积超过 100
  if (synRecv >= 100) {
    if (!netState.syn) {
      netState.syn = 1;
      await db.prepare(`UPDATE monitors SET net_alert_state=? WHERE id=?`).bind(JSON.stringify(netState), m.id).run();
      await sendAlert(db, m, `🚨 ${m.name} 疑似 SYN 洪水攻击`, `SYN_RECV 状态连接 ${synRecv} 个，大量半连接堆积\n建议：检查防火墙，考虑启用 SYN Cookie`);
    }
  } else if (netState.syn && synRecv < 20) {
    netState.syn = 0;
    await db.prepare(`UPDATE monitors SET net_alert_state=? WHERE id=?`).bind(JSON.stringify(netState), m.id).run();
    await sendAlert(db, m, `✅ ${m.name} SYN 洪水告警解除`, `SYN_RECV 回落到 ${synRecv} 个`);
  }
} catch (e) {}

// ---------- 进程存活 / 可疑进程检测 ----------
try {
  const procState = JSON.parse(m.proc_alert_state || "{}");
  let procChanged = false;
  // 关键进程存活检查
  if (body.proc_status) {
    const ps = JSON.parse(body.proc_status);
    for (const [name, alive] of Object.entries(ps)) {
      const key = "dead_" + name;
      if (!alive && !procState[key]) {
        procState[key] = 1; procChanged = true;
        await sendAlert(db, m, `💀 ${m.name} 进程 ${name} 已停止`, `关键进程 ${name} 未在运行，请检查服务状态`);
      } else if (alive && procState[key]) {
        procState[key] = 0; procChanged = true;
        await sendAlert(db, m, `✅ ${m.name} 进程 ${name} 已恢复`, `关键进程 ${name} 重新运行中`);
      }
    }
  }
  // 可疑进程（挖矿木马特征）
  if (body.suspect_procs) {
    if (!procState.suspect || procState.suspect !== body.suspect_procs) {
      procState.suspect = body.suspect_procs; procChanged = true;
      await sendAlert(db, m, `⛏️ ${m.name} 发现可疑进程`, `疑似挖矿/木马进程：\n${body.suspect_procs}\n\n请立即检查服务器！`);
    }
  } else if (procState.suspect) {
    procState.suspect = ""; procChanged = true;
    await sendAlert(db, m, `✅ ${m.name} 可疑进程已清除`, `之前的可疑进程已消失`);
  }
  if (procChanged) {
    await db.prepare(`UPDATE monitors SET proc_alert_state=? WHERE id=?`).bind(JSON.stringify(procState), m.id).run();
  }
} catch (e) {}

// ---------- SSL 证书到期检查（agent 上报） ----------
try {
  if (body.ssl_days !== undefined && body.ssl_days !== null) {
    const sslDays = parseInt(body.ssl_days, 10);
    // 存下来供前端展示（ssl_list 是全部域名的 JSON）
    const sslListJson = body.ssl_list ? JSON.stringify(body.ssl_list) : "";
    await db.prepare(`UPDATE monitors SET ssl_days=?, ssl_domain=?, ssl_list=? WHERE id=?`).bind(sslDays, body.ssl_domain || "", sslListJson, m.id).run();
    const sslState = JSON.parse(m.ssl_alert_state || "{}");
    if (sslDays < 7) {
      const key = "exp_" + (body.ssl_domain || "cert");
      if (!sslState[key]) {
        sslState[key] = 1;
        await db.prepare(`UPDATE monitors SET ssl_alert_state=? WHERE id=?`).bind(JSON.stringify(sslState), m.id).run();
        await sendAlert(db, m, `🔒 ${m.name} SSL 证书即将到期`, `域名 ${body.ssl_domain || ""} 证书还有 ${sslDays} 天到期\n请及时续期，避免服务中断`);
      }
    } else if (sslState["exp_" + (body.ssl_domain || "cert")]) {
      delete sslState["exp_" + (body.ssl_domain || "cert")];
      await db.prepare(`UPDATE monitors SET ssl_alert_state=? WHERE id=?`).bind(JSON.stringify(sslState), m.id).run();
      await sendAlert(db, m, `✅ ${m.name} SSL 证书已更新`, `域名 ${body.ssl_domain || ""} 证书还有 ${sslDays} 天到期`);
    }
  }
} catch (e) {}

// SSH 自动封禁上报（agent 已执行 iptables，记录日志）
if (body.banned_ips) {
  try {
    await adminLog(db, "ssh_autoban", `${m.name} 自动封禁 IP: ${body.banned_ips}`, "agent");
  } catch (e) {}
}

// 断网状态同步（agent 上报实际状态）
// 防竞态：管理员 3 分钟内的操作优先，agent 旧上报不覆盖
if (typeof body.net_isolated !== "undefined") {
  const isolated = body.net_isolated ? 1 : 0;
  const adminChangedAt = m.net_blocked_at || 0;
  const adminRecent = (now() - adminChangedAt) < 180;
  if (isolated !== (m.net_blocked || 0) && !adminRecent) {
    await db.prepare(`UPDATE monitors SET net_blocked=? WHERE id=?`).bind(isolated, m.id).run();
    m.net_blocked = isolated;
  }
}

// 返回断网指令 + 配置下发（agent 下次上报时执行）+ 体检任务下发
return json({ ok: true, net_blocked: m.net_blocked || 0, process_watch: m.process_watch || "", ssl_domains: m.ssl_domains || "", ssh_threshold: m.ssh_threshold || 0, bench_requested: m.bench_requested || 0 });
}

// Agent 一键体检结果回传（鉴权同 report）
if (path === "/api/agent/bench" && method === "POST") {
const body = await req.json().catch(() => ({}));
const token = body.token || "";
if (!token) return json({ error: "missing token" }, 401);
const m = await db.prepare(`SELECT * FROM monitors WHERE agent_token=? AND type='agent'`).bind(token).first();
if (!m) return json({ error: "invalid token" }, 401);
if (body.ts && body.sig) {
  const tsDiff = Math.abs(now() - parseInt(body.ts, 10));
  if (tsDiff > 300) return json({ error: "timestamp expired" }, 401);
  const expected = await hmacSha256(token, String(body.ts));
  if (expected !== body.sig) return json({ error: "invalid signature" }, 401);
}
await db.prepare(`UPDATE monitors SET bench_result=?, bench_at=?, bench_requested=0 WHERE id=?`).bind(JSON.stringify(body.result || {}), now(), m.id).run();
try { await adminLog(db, "bench_done", `${m.name} 完成一键体检`, "agent"); } catch (e) {}
return json({ ok: true });
}

// 公开：计划维护（进行中 + 未来 7 天，不含已完成/已取消）
if (path === "/api/maintenances" && method === "GET") {
const r = await db.prepare(
`SELECT * FROM maintenances WHERE end_at > ? AND status IN ('scheduled','ongoing') ORDER BY start_at LIMIT 10`
).bind(now()).all();
return json({ maintenances: r.results || []});
}

// 公开：历史故障（已恢复，近 30 天）
if (path === "/api/incidents/history" && method === "GET") {
const r = await db.prepare(
`SELECT i.*, m.name FROM incidents i JOIN monitors m ON m.id=i.monitor_id
WHERE i.ended_at > 0 AND i.started_at > ? ORDER BY i.started_at DESC LIMIT 20`
).bind(now() - 30 * 86400).all();
return json({ incidents: r.results || []});
}

// 公开：订阅状态更新通知
if (path === "/api/subscribe" && method === "POST") {
const body = await req.json().catch(() => ({}));
const email = (body.email || "").trim().toLowerCase();
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "邮箱格式不正确" }, 400);
const origin = new URL(req.url).origin;
// 保存站点地址（用于退订链接）
await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("site_origin", origin).run();
// IP 级限流：同一 IP 1 小时内最多请求 5 次（防刷验证邮件烧 Resend 额度）
const ip = req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For") || "unknown";
const ipKey = "sub_ratelimit_" + ip;
const ipCount = parseInt(await getSetting(db, ipKey) || "0", 10);
const ipReset = parseInt(await getSetting(db, ipKey + "_ts") || "0", 10);
if (now() - ipReset > 3600) {
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind(ipKey, "1").run();
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind(ipKey + "_ts", String(now())).run();
} else if (ipCount >= 5) {
  return json({ error: "请求过于频繁，请 1 小时后再试" }, 429);
} else {
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind(ipKey, String(ipCount + 1)).run();
}
// 频率限制：同一邮箱 1 小时内只能请求一次
const existing = await db.prepare(`SELECT * FROM subscribers WHERE email=?`).bind(email).first();
if (existing && existing.verified) return json({ ok: true, code: "already" });
if (existing && now() - existing.created_at < 3600) return json({ ok: true, code: "sent" });
const token = [...crypto.getRandomValues(new Uint8Array(24))].map(x => x.toString(16).padStart(2, "0")).join("");
await db.prepare(
`INSERT INTO subscribers (email, verified, token, created_at) VALUES (?,?,?,?)
ON CONFLICT(email) DO UPDATE SET token=excluded.token, created_at=excluded.created_at`
).bind(email, 0, token, now()).run();
// 发验证邮件
const siteTitle = await getSetting(db, "site_title") || "大熊探针";
const emailSent = await sendEmail(db,
await getSetting(db, "alert_email_from") || "noreply@example.com",
email,
`确认订阅 ${siteTitle} 状态通知`,
`点击以下链接确认订阅，有服务故障时你会收到邮件通知：\n\n${origin}/api/subscribe/verify?token=${token}\n\n如果不是你操作的请忽略。`
);
if (!emailSent) return json({ error: "邮件服务未配置，订阅失败，请联系管理员" }, 500);
return json({ ok: true, code: "sent" });
}

// 订阅验证（点击邮件链接）
if (path === "/api/subscribe/verify" && method === "GET") {
const token = new URL(req.url).searchParams.get("token") || "";
const sub = await db.prepare(`SELECT * FROM subscribers WHERE token=?`).bind(token).first();
if (!sub) return new Response("链接无效或已过期", { status: 400 });
await db.prepare(`UPDATE subscribers SET verified=1 WHERE id=?`).bind(sub.id).run();
return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>订阅成功</title></head><body style="font-family:sans-serif;text-align:center;padding:60px 20px;background:#0b0e14;color:#e8edf3"><div style="font-size:48px">✅</div><h2>订阅成功</h2><p style="color:#8b95a7">服务出现故障或恢复时，你会收到邮件通知。</p><a href="/" style="color:#3b82f6">返回状态页</a></body></html>`, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// 取消订阅
if (path === "/api/subscribe/unsubscribe" && method === "GET") {
const token = new URL(req.url).searchParams.get("token") || "";
await db.prepare(`DELETE FROM subscribers WHERE token=?`).bind(token).run();
return new Response(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>已取消订阅</title></head><body style="font-family:sans-serif;text-align:center;padding:60px 20px;background:#0b0e14;color:#e8edf3"><div style="font-size:48px">👋</div><h2>已取消订阅</h2><p style="color:#8b95a7">你不会再收到状态通知邮件。</p><a href="/" style="color:#3b82f6">返回状态页</a></body></html>`, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// 公开：站点品牌信息
if (path === "/api/branding" && method === "GET") {
const title = await getSetting(db, "site_title") || "";
const subtitle = await getSetting(db, "site_subtitle") || "";
return json({ title, subtitle });
}

// 公开：聚合状态接口（一次返回状态页所需全部数据，减少请求数）
// 包含：监控列表（含7天可用率+近期检测记录）、故障、维护、品牌
if (path === "/api/status" && method === "GET") {
const ts = now();
const monitorsR = await db.prepare(
`SELECT id, name, type, target, interval_minutes, group_name, enabled, last_check_at, last_status, last_ms, consecutive_failures, created_at, uptime_7d, avg_ms_7d, ssl_days, ssl_domain, ssl_list, host_info, price_text, expire_at, bench_at, bench_result FROM monitors ORDER BY group_name, id`
).all();
const monitors = monitorsR.results || [];
// Agent 流量统计（今日/本月，北京时间零点起；累计计数器差值，计数器重置时取当前值兜底）
for (const m of monitors) {
if (m.type !== "agent") continue;
try {
  const lastRow = await db.prepare(`SELECT net_rx, net_tx, rx_mbps, tx_mbps FROM agent_stats WHERE monitor_id=? ORDER BY reported_at DESC LIMIT 1`).bind(m.id).first();
  if (!lastRow) { m.traffic = null; continue; }
  const dayStart = ts - ((ts + 28800) % 86400);
  const dNow = new Date((ts + 28800) * 1000);
  const monthStart = Math.floor(Date.UTC(dNow.getUTCFullYear(), dNow.getUTCMonth(), 1) / 1000) - 28800;
  const firstOf = async (since) => db.prepare(`SELECT net_rx, net_tx FROM agent_stats WHERE monitor_id=? AND reported_at>=? ORDER BY reported_at ASC LIMIT 1`).bind(m.id, since).first();
  const fd = await firstOf(dayStart);
  const fm = await firstOf(monthStart);
  const delta = (f) => {
    if (!f) return { rx: 0, tx: 0 };
    let rx = (lastRow.net_rx || 0) - (f.net_rx || 0); if (rx < 0) rx = lastRow.net_rx || 0;
    let tx = (lastRow.net_tx || 0) - (f.net_tx || 0); if (tx < 0) tx = lastRow.net_tx || 0;
    return { rx, tx };
  };
  m.traffic = { today: delta(fd), month: delta(fm), rx_mbps: lastRow.rx_mbps || 0, tx_mbps: lastRow.tx_mbps || 0 };
} catch (e) { m.traffic = null; }
}
// 7 天统计已由 cron 预计算，直接读；只查近期检测记录（曲线图用，24 条足够）
for (const m of monitors) {
const ck = await db.prepare(
`SELECT checked_at, status, ms FROM checks WHERE monitor_id=? ORDER BY checked_at DESC LIMIT 24`
).bind(m.id).all();
m.recent_checks = (ck.results || []).reverse();
}
const incR = await db.prepare(
`SELECT i.*, m.name FROM incidents i JOIN monitors m ON m.id=i.monitor_id WHERE i.ended_at=0 ORDER BY i.started_at DESC`
).all();
const maintR = await db.prepare(
`SELECT * FROM maintenances WHERE end_at > ? AND status IN ('scheduled','ongoing') ORDER BY start_at LIMIT 10`
).bind(ts).all();
const histR = await db.prepare(
`SELECT i.*, m.name FROM incidents i JOIN monitors m ON m.id=i.monitor_id WHERE i.ended_at>0 ORDER BY i.started_at DESC LIMIT 30`
).all();
const title = await getSetting(db, "site_title") || "";
const subtitle = await getSetting(db, "site_subtitle") || "";
const adminPath = await getSetting(db, "admin_path") || "/admin";
return json({
monitors,
incidents: incR.results || [],
maintenances: maintR.results || [],
history: histR.results || [],
branding: { title, subtitle },
admin_path: adminPath
});
}

// 公开：Agent 最新状态
const agentStatMatch = path.match(/^\/api\/monitors\/(\d+)\/agent$/);
if (agentStatMatch && method === "GET") {
const r = await db.prepare(
`SELECT reported_at, cpu, mem, disk, uptime, load1, ping_telecom, ping_unicom, ping_mobile FROM agent_stats WHERE monitor_id=? ORDER BY reported_at DESC LIMIT 60`
).bind(agentStatMatch[1]).all();
return json({ stats: (r.results || []).reverse() });
}

// 公开：Agent 历史曲线（CPU/内存/三网延迟/速率，降采样到最多约 240 点）
const agentHistMatch = path.match(/^\/api\/monitors\/(\d+)\/agent\/history$/);
if (agentHistMatch && method === "GET") {
const hours = Math.min(parseInt(url.searchParams.get("hours") || "24", 10) || 24, 168);
const since = now() - hours * 3600;
const cnt = await db.prepare(`SELECT COUNT(*) as c FROM agent_stats WHERE monitor_id=? AND reported_at>=?`).bind(agentHistMatch[1], since).first();
const step = Math.max(1, Math.ceil((cnt.c || 0) / 240));
const r = await db.prepare(
`SELECT reported_at, cpu, mem, disk, ping_telecom, ping_unicom, ping_mobile, rx_mbps, tx_mbps FROM agent_stats WHERE monitor_id=? AND reported_at>=? AND id % ? = 0 ORDER BY reported_at ASC`
).bind(agentHistMatch[1], since, step).all();
return json({ stats: r.results || [] });
}

// 管理员鉴权
const auth = req.headers.get("X-Admin-Token") || "";
const tokenHash = await getSetting(db, "admin_token_hash");
const authed = tokenHash && auth && (await sha256hex(auth)) === tokenHash;

// TOTP 双因素认证
// Base32 解码
function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  str = str.toUpperCase().replace(/=+$/, "");
  let bits = 0, value = 0, output = [];
  for (let i = 0; i < str.length; i++) {
    value = (value << 5) | alphabet.indexOf(str[i]);
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
// 验证 TOTP 码（允许前后 1 个时间窗口的误差）
async function verifyTOTP(secret, code) {
  const keyData = base32Decode(secret);
  const key = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const timeStep = 30;
  const nowSec = Math.floor(Date.now() / 1000);
  for (let offset = -1; offset <= 1; offset++) {
    const counter = Math.floor(nowSec / timeStep) + offset;
    const counterBuf = new ArrayBuffer(8);
    const view = new DataView(counterBuf);
    view.setUint32(4, counter); // 高 4 字节为 0，低 4 字节为 counter
    const sig = await crypto.subtle.sign("HMAC", key, counterBuf);
    const bytes = new Uint8Array(sig);
    const off = bytes[19] & 0x0f;
    const num = ((bytes[off] & 0x7f) << 24 | bytes[off+1] << 16 | bytes[off+2] << 8 | bytes[off+3]) % 1000000;
    if (String(num).padStart(6, "0") === code) return true;
  }
  return false;
}
// 生成 TOTP 密钥（Base32，160 位）
function generateTOTPSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let str = "";
  let bits = 0, value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      str += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) str += alphabet[(value << (5 - bits)) & 31];
  return str;
}

if (path === "/api/admin/login" && method === "POST") {
const body = await req.json().catch(() => ({}));
const ip = getClientIp(req);
// 登录限流：5 次失败锁 15 分钟
const failKey = `login_fail_${ip}`;
const lockKey = `login_lock_${ip}`;
const lockUntil = parseInt(await getSetting(db, lockKey) || "0", 10);
if (lockUntil > now()) {
  const waitMin = Math.ceil((lockUntil - now()) / 60);
  await adminLog(db, "login_blocked", `IP 被锁定，剩余 ${waitMin} 分钟`, ip);
  return json({ error: `尝试次数过多，请 ${waitMin} 分钟后再试` }, 429);
}
const pwHash = await getSetting(db, "admin_password_hash");
if (!pwHash) {
// 首次：设置密码
if (!body.password || body.password.length < 10) return json({ error: "密码至少 10 位"}, 400);
const token = crypto.randomUUID();
await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("admin_password_hash", await sha256hex(body.password)).run();
await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("admin_token_hash", await sha256hex(token)).run();
await adminLog(db, "password_set", "首次设置管理员密码", ip);
return json({ token});
}
if ((await sha256hex(body.password || "")) === pwHash) {
// 如果启用了 TOTP，要求验证动态码
const totpEnabled = await getSetting(db, "totp_enabled");
if (totpEnabled === "1") {
  const totpSecret = await getSetting(db, "totp_secret");
  if (!body.totp_code || !(await verifyTOTP(totpSecret, body.totp_code))) {
    const failCount = parseInt(await getSetting(db, failKey) || "0", 10) + 1;
    await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind(failKey, String(failCount)).run();
    await adminLog(db, "login_fail", `TOTP 验证失败（第 ${failCount} 次）`, ip);
    if (failCount >= 5) {
      await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind(lockKey, String(now() + 900)).run();
    }
    return json({ error: "动态码错误", totp_required: true }, 401);
  }
}
const token = crypto.randomUUID();
await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("admin_token_hash", await sha256hex(token)).run();
// 清除失败计数
await db.prepare(`DELETE FROM settings WHERE key=?`).bind(failKey).run();
await db.prepare(`DELETE FROM settings WHERE key=?`).bind(lockKey).run();
await adminLog(db, "login_ok", "登录成功", ip);
// Telegram 登录提醒
try {
  const tgToken = await getSetting(db, "telegram_bot_token");
  const tgChat = await getSetting(db, "telegram_chat_id");
  if (tgToken && tgChat) {
    await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: tgChat, text: `🔐 探针后台登录提醒\n\nIP：${ip}\n时间：${new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" })}\n\n如非本人操作，请立即修改密码` })
    });
  }
} catch (e) {}
return json({ token});
}
// 密码错误：计数
const failCount = parseInt(await getSetting(db, failKey) || "0", 10) + 1;
await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind(failKey, String(failCount)).run();
await adminLog(db, "login_fail", `密码错误（第 ${failCount} 次）`, ip);
if (failCount >= 5) {
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind(lockKey, String(now() + 900)).run();
  return json({ error: "尝试次数过多，已锁定 15 分钟" }, 429);
}
return json({ error: "密码错误"}, 401);
}

if (!authed) return json({ error: "未授权"}, 401);
const adminIp = getClientIp(req);

// 管理：监控 CRUD
if (path === "/api/admin/monitors" && method === "GET") {
const r = await db.prepare(`SELECT * FROM monitors ORDER BY id`).all();
// 返回各告警渠道是否已全局配置，前端只显示真正可用的
const cfg = {};
cfg.telegram = !!(await getSetting(db, "telegram_bot_token")) && !!(await getSetting(db, "telegram_chat_id"));
cfg.email = !!(await getSetting(db, "resend_api_key")) && !!(await getSetting(db, "alert_email_from"));
cfg.dingtalk = !!(await getSetting(db, "dingtalk_webhook"));
cfg.bark = !!(await getSetting(db, "bark_url"));
cfg.wecom = !!(await getSetting(db, "wecom_webhook"));
cfg.custom_email = !!(await getSetting(db, "custom_email_url"));
cfg.smtp = !!(await getSetting(db, "smtp_host")) && !!(await getSetting(db, "smtp_user"));
cfg.serverchan = !!(await getSetting(db, "serverchan_sendkey"));
cfg.wxpusher = !!(await getSetting(db, "wxpusher_spt"));
cfg.feishu = !!(await getSetting(db, "feishu_webhook"));
// webhook 是每个监控单独配的 URL，有填就算可用（前端按 m.webhook_url 判断）
return json({ monitors: r.results || [], channels: cfg });
}
if (path === "/api/admin/monitors" && method === "POST") {
const b = await req.json();
// 后端非空校验（防绕过前端直接调 API）
if (!b.name || !String(b.name).trim()) return json({ error: "名称不能为空" }, 400);
if (b.type !== "agent" && (!b.target || !String(b.target).trim())) return json({ error: "目标不能为空" }, 400);
// agent 类型自动生成 token
const agentToken = b.type === "agent" ? [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, "0")).join("") : "";
const r = await db.prepare(
`INSERT INTO monitors (name,type,target,interval_minutes,group_name,keyword,expected_status,enabled,alert_telegram,alert_email,alert_webhook,webhook_url,alert_dingtalk,alert_bark,alert_wecom,alert_custom_email,alert_smtp,alert_serverchan,alert_wxpusher,alert_feishu,agent_token,cpu_threshold,mem_threshold,disk_threshold,ssh_threshold,conn_threshold,process_watch,ssl_domains,price_text,expire_at,created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
).bind(b.name, b.type || "http", b.target || "", b.interval_minutes || 5, b.group_name || "", b.keyword || "",
b.expected_status?? 200, b.enabled?? 1, b.alert_telegram? 1: 0, b.alert_email? 1: 0,
b.alert_webhook? 1: 0, b.webhook_url || "",
b.alert_dingtalk? 1: 0, b.alert_bark? 1: 0, b.alert_wecom? 1: 0, b.alert_custom_email? 1: 0,
b.alert_smtp? 1: 0, b.alert_serverchan? 1: 0, b.alert_wxpusher? 1: 0, b.alert_feishu? 1: 0,
agentToken,
b.cpu_threshold || 0, b.mem_threshold || 0, b.disk_threshold || 0, b.ssh_threshold || 0, b.conn_threshold || 0, b.process_watch || "", b.ssl_domains || "", b.price_text || "", b.expire_at || 0, now()).run();
await adminLog(db, "monitor_add", b.name, adminIp);
return json({ id: r.meta.last_row_id, agent_token: agentToken || undefined });
}
const mm = path.match(/^\/api\/admin\/monitors\/(\d+)$/);
if (mm && method === "PUT") {
const b = await req.json();
// 后端非空校验（防绕过前端直接调 API）
if (!b.name || !String(b.name).trim()) return json({ error: "名称不能为空" }, 400);
if (b.type !== "agent" && (!b.target || !String(b.target).trim())) return json({ error: "目标不能为空" }, 400);
await db.prepare(
`UPDATE monitors SET name=?,type=?,target=?,interval_minutes=?,group_name=?,keyword=?,expected_status=?,enabled=?,alert_telegram=?,alert_email=?,alert_webhook=?,webhook_url=?,alert_dingtalk=?,alert_bark=?,alert_wecom=?,alert_custom_email=?,alert_smtp=?,alert_serverchan=?,alert_wxpusher=?,alert_feishu=?,cpu_threshold=?,mem_threshold=?,disk_threshold=?,ssh_threshold=?,conn_threshold=?,process_watch=?,ssl_domains=?,price_text=?,expire_at=? WHERE id=?`
).bind(b.name, b.type, b.target, b.interval_minutes, b.group_name || "", b.keyword || "", b.expected_status?? 200,
b.enabled?? 1, b.alert_telegram? 1: 0, b.alert_email? 1: 0, b.alert_webhook? 1: 0,
b.webhook_url || "", b.alert_dingtalk? 1: 0, b.alert_bark? 1: 0, b.alert_wecom? 1: 0, b.alert_custom_email? 1: 0,
b.alert_smtp? 1: 0, b.alert_serverchan? 1: 0, b.alert_wxpusher? 1: 0, b.alert_feishu? 1: 0,
b.cpu_threshold || 0, b.mem_threshold || 0, b.disk_threshold || 0, b.ssh_threshold || 0, b.conn_threshold || 0, b.process_watch || "", b.ssl_domains || "", b.price_text || "", b.expire_at || 0, mm[1]).run();
await adminLog(db, "monitor_edit", b.name, adminIp);
return json({ ok: true});
}
if (mm && method === "DELETE") {
await db.prepare(`DELETE FROM monitors WHERE id=?`).bind(mm[1]).run();
await adminLog(db, "monitor_del", `id=${mm[1]}`, adminIp);
await db.prepare(`DELETE FROM checks WHERE monitor_id=?`).bind(mm[1]).run();
await db.prepare(`DELETE FROM incidents WHERE monitor_id=?`).bind(mm[1]).run();
await db.prepare(`DELETE FROM agent_stats WHERE monitor_id=?`).bind(mm[1]).run();
return json({ ok: true});
}

// 管理：手动触发检测
const tm = path.match(/^\/api\/admin\/test\/(\d+)$/);
if (tm && method === "POST") {
const m = await db.prepare(`SELECT * FROM monitors WHERE id=?`).bind(tm[1]).first();
if (!m) return json({ error: "不存在"}, 404);
// 手动测试：silent 模式，只返回结果不触发真实告警/订阅邮件
const result = await runCheck(db, m, { silent: true });
return json(result);
}
// 管理：一键断网 / 恢复（Agent 下次上报时执行）
const iso = path.match(/^\/api\/admin\/monitors\/(\d+)\/isolate$/);
if (iso && method === "POST") {
const b = await req.json().catch(() => ({}));
const m = await db.prepare(`SELECT * FROM monitors WHERE id=? AND type='agent'`).bind(iso[1]).first();
if (!m) return json({ error: "仅 Agent 监控支持断网" }, 400);
const blocked = b.action === "isolate" ? 1 : 0;
await db.prepare(`UPDATE monitors SET net_blocked=?, net_blocked_at=? WHERE id=?`).bind(blocked, now(), m.id).run();
await adminLog(db, blocked ? "net_isolate" : "net_restore", `${m.name} ${blocked ? "执行断网" : "恢复网络"}`, adminIp);
if (blocked) {
  await sendAlert(db, m, `🔌 ${m.name} 已执行一键断网`, `管理员手动触发网络隔离，服务器已屏蔽所有入站连接（保留探针心跳）`);
}
return json({ ok: true, net_blocked: blocked });
}

// 管理：一键体检（Agent 下次上报时执行：CPU 跑分/磁盘 IO/测速/解锁检测）
const bm = path.match(/^\/api\/admin\/monitors\/(\d+)\/bench$/);
if (bm && method === "POST") {
const m = await db.prepare(`SELECT * FROM monitors WHERE id=? AND type='agent'`).bind(bm[1]).first();
if (!m) return json({ error: "仅 Agent 监控支持体检" }, 400);
await db.prepare(`UPDATE monitors SET bench_requested=1 WHERE id=?`).bind(m.id).run();
await adminLog(db, "bench_request", `${m.name} 触发一键体检`, adminIp);
invalidateApiCache();
return json({ ok: true });
}

// 管理：设置
if (path === "/api/admin/settings" && method === "GET") {
const keys = ["telegram_bot_token", "telegram_chat_id", "resend_api_key", "alert_email_from", "alert_email_to", "site_title", "site_subtitle", "admin_path", "dingtalk_webhook", "bark_url", "wecom_webhook", "custom_email_url", "custom_email_headers", "custom_email_from", "custom_email_to",
"smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_from", "smtp_to", "smtp_secure",
"serverchan_sendkey", "wxpusher_spt", "feishu_webhook", "expire_alert_days"];
const out = {};
for (const k of keys) out[k] = await getSetting(db, k);
// 脱敏
for (const k of ["telegram_bot_token", "resend_api_key", "smtp_pass"]) {
if (out[k]) out[k] = "***" + out[k].slice(-4);
}
return json({ settings: out});
}
if (path === "/api/admin/settings" && method === "PUT") {
const b = await req.json();
const keys = ["telegram_bot_token", "telegram_chat_id", "resend_api_key", "alert_email_from", "alert_email_to", "site_title", "site_subtitle", "admin_path", "dingtalk_webhook", "bark_url", "wecom_webhook", "custom_email_url", "custom_email_headers", "custom_email_from", "custom_email_to",
"smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_from", "smtp_to", "smtp_secure",
"serverchan_sendkey", "wxpusher_spt", "feishu_webhook", "expire_alert_days"];
for (const k of keys) {
if (b[k]!== undefined &&!b[k].startsWith("***")) {
await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind(k, b[k]).run();
}
}
await adminLog(db, "settings_save", "更新告警设置", adminIp);
return json({ ok: true});
}

// 管理：测试告警渠道（发一条测试消息）
if (path === "/api/admin/test-alert" && method === "POST") {
const b = await req.json().catch(() => ({}));
const channel = b.channel || "";
const validChannels = ["telegram", "email", "webhook", "dingtalk", "bark", "wecom", "custom_email", "smtp", "serverchan", "wxpusher", "feishu"];
if (!validChannels.includes(channel)) return json({ error: "未知渠道" }, 400);
// 构造一个只启用指定渠道的测试监控对象，复用 sendAlert 逻辑
const testMonitor = {
  name: "🧪 测试",
  alert_telegram: channel === "telegram" ? 1 : 0,
  alert_email: channel === "email" ? 1 : 0,
  alert_webhook: channel === "webhook" ? 1 : 0,
  alert_dingtalk: channel === "dingtalk" ? 1 : 0,
  alert_bark: channel === "bark" ? 1 : 0,
  alert_wecom: channel === "wecom" ? 1 : 0,
  alert_custom_email: channel === "custom_email" ? 1 : 0,
  alert_smtp: channel === "smtp" ? 1 : 0,
  alert_serverchan: channel === "serverchan" ? 1 : 0,
  alert_wxpusher: channel === "wxpusher" ? 1 : 0,
  alert_feishu: channel === "feishu" ? 1 : 0,
  webhook_url: b.webhook_url || "",
};
try {
  await sendAlert(db, testMonitor, "🧪 探针站测试消息", "这是一条测试消息，收到说明该渠道配置正常。");
  await adminLog(db, "test_alert", `测试告警渠道: ${channel}`, adminIp);
  return json({ ok: true });
} catch (e) {
  return json({ error: String(e.message || e).slice(0, 200) }, 500);
}
}

// 管理：重新生成 Agent Token
const regenMatch = path.match(/^\/api\/admin\/monitors\/(\d+)\/regen-token$/);
if (regenMatch && method === "POST") {
const m = await db.prepare(`SELECT * FROM monitors WHERE id=?`).bind(regenMatch[1]).first();
if (!m || m.type !== "agent") return json({ error: "不是 Agent 监控" }, 400);
const newToken = [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, "0")).join("");
await db.prepare(`UPDATE monitors SET agent_token=? WHERE id=?`).bind(newToken, m.id).run();
return json({ agent_token: newToken });
}

// 管理：计划维护 CRUD
if (path === "/api/admin/maintenances" && method === "GET") {
const r = await db.prepare(`SELECT * FROM maintenances ORDER BY start_at DESC LIMIT 50`).all();
return json({ maintenances: r.results || []});
}
// 管理：修改管理员密码（需登录）：验旧密码、新密码 ≥10 位、改完轮换 token 踢掉所有旧会话
// 管理：TOTP 设置 - 生成密钥（返回 otpauth URL，前端生成二维码）
if (path === "/api/admin/totp/setup" && method === "POST") {
  const secret = generateTOTPSecret();
  // 暂存未启用的密钥，验证通过后才正式启用
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("totp_pending_secret", secret).run();
  const siteTitle = await getSetting(db, "site_title") || "大熊探针";
  const otpauth = `otpauth://totp/${encodeURIComponent(siteTitle)}:admin?secret=${secret}&issuer=${encodeURIComponent(siteTitle)}`;
  await adminLog(db, "totp_setup", "生成 TOTP 密钥", adminIp);
  return json({ secret, otpauth });
}
// 管理：TOTP 设置 - 验证并启用
if (path === "/api/admin/totp/enable" && method === "POST") {
  const b = await req.json().catch(() => ({}));
  const pending = await getSetting(db, "totp_pending_secret");
  if (!pending) return json({ error: "请先生成密钥" }, 400);
  if (!(await verifyTOTP(pending, b.code || ""))) return json({ error: "验证码错误" }, 400);
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("totp_secret", pending).run();
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("totp_enabled", "1").run();
  await db.prepare(`DELETE FROM settings WHERE key=?`).bind("totp_pending_secret").run();
  await adminLog(db, "totp_enable", "启用 TOTP 双因素", adminIp);
  return json({ ok: true });
}
// 管理：TOTP 设置 - 禁用（需验证密码）
if (path === "/api/admin/totp/disable" && method === "POST") {
  const b = await req.json().catch(() => ({}));
  const pwHash = await getSetting(db, "admin_password_hash");
  if ((await sha256hex(b.password || "")) !== pwHash) return json({ error: "密码错误" }, 401);
  await db.prepare(`DELETE FROM settings WHERE key IN ('totp_secret','totp_enabled','totp_pending_secret')`).run();
  await adminLog(db, "totp_disable", "禁用 TOTP 双因素", adminIp);
  return json({ ok: true });
}
// 管理：TOTP 状态
if (path === "/api/admin/totp/status" && method === "GET") {
  const enabled = await getSetting(db, "totp_enabled");
  return json({ enabled: enabled === "1" });
}

if (path === "/api/admin/change-password" && method === "POST") {
  const b = await req.json().catch(() => ({}));
  const pwHash = await getSetting(db, "admin_password_hash");
  if ((await sha256hex(b.oldPassword || "")) !== pwHash) {
    await adminLog(db, "change_pw_fail", "旧密码错误", adminIp);
    return json({ error: "旧密码错误" }, 400);
  }
  if (!b.newPassword || b.newPassword.length < 10) {
    return json({ error: "新密码至少 10 位" }, 400);
  }
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("admin_password_hash", await sha256hex(b.newPassword)).run();
  // 轮换 token：所有旧会话失效
  const newToken = crypto.randomUUID();
  await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("admin_token_hash", await sha256hex(newToken)).run();
  // 清除所有登录限流
  await db.prepare(`DELETE FROM settings WHERE key LIKE 'login_fail\_%'`).run();
  await db.prepare(`DELETE FROM settings WHERE key LIKE 'login_lock\_%'`).run();
  await adminLog(db, "change_pw_ok", "修改管理员密码成功", adminIp);
  return json({ token: newToken });
}

// 管理：操作日志
if (path === "/api/admin/logs" && method === "GET") {
const r = await db.prepare(`SELECT * FROM admin_logs ORDER BY id DESC LIMIT 100`).all();
return json({ logs: r.results || []});
}
// 管理：访客统计
if (path === "/api/admin/visitors" && method === "GET") {
const days = Math.min(parseInt(url.searchParams.get("days") || "7", 10), 30);
const since = now() - days * 86400;
const enabled = await getSetting(db, "visitor_log_enabled");
// 每日统计
const daily = await db.prepare(
`SELECT date(created_at, 'unixepoch') as d, COUNT(*) as pv, COUNT(DISTINCT ip_hash) as uv FROM visitor_logs WHERE created_at >= ? GROUP BY d ORDER BY d`
).bind(since).all();
// 最近记录
const recent = await db.prepare(
`SELECT ip_hash, country, path, device, datetime(created_at, 'unixepoch') as t FROM visitor_logs ORDER BY id DESC LIMIT 100`
).all();
// 可疑 IP：1 分钟内超过 60 次请求
const sus = await db.prepare(
`SELECT ip_hash, COUNT(*) as c FROM visitor_logs WHERE created_at >= ? GROUP BY ip_hash HAVING c >= 60`
).bind(now() - 60).all();
return json({ daily: daily.results || [], recent: recent.results || [], suspicious: sus.results || [], enabled: enabled !== "0" });
}
// 管理：访客记录开关
if (path === "/api/admin/visitors/toggle" && method === "POST") {
const b = await req.json().catch(() => ({}));
await db.prepare(`INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)`).bind("visitor_log_enabled", b.enabled ? "1" : "0").run();
await adminLog(db, "visitor_toggle", b.enabled ? "开启访客记录" : "关闭访客记录", adminIp);
return json({ ok: true });
}
if (path === "/api/admin/maintenances" && method === "POST") {
const b = await req.json();
const r = await db.prepare(
`INSERT INTO maintenances (title, description, start_at, end_at, status, created_at) VALUES (?,?,?,?,?,?)`
).bind(b.title, b.description || "", b.start_at, b.end_at, b.status || "scheduled", now()).run();
return json({ id: r.meta.last_row_id});
}
const maintMatch = path.match(/^\/api\/admin\/maintenances\/(\d+)$/);
if (maintMatch && method === "PUT") {
const b = await req.json();
await db.prepare(
`UPDATE maintenances SET title=?, description=?, start_at=?, end_at=?, status=? WHERE id=?`
).bind(b.title, b.description || "", b.start_at, b.end_at, b.status || "scheduled", maintMatch[1]).run();
return json({ ok: true});
}
if (maintMatch && method === "DELETE") {
await db.prepare(`DELETE FROM maintenances WHERE id=?`).bind(maintMatch[1]).run();
return json({ ok: true});
}

return json({ error: "not found"}, 404);
}

// ---------- 入口 ----------
export default {
async fetch(req, env, ctx) {
const url = new URL(req.url);
// 应用层 botguard：爬虫/脚本刷接口直接 403，不消耗 D1
const guardBlock = botGuard(req, url.pathname);
if (guardBlock) return guardBlock;
// Agent 上报脚本下载
if (url.pathname === "/agent.py") {
const agentPy = "__AGENT_PY__".replaceAll("your-probe-domain.com", url.host);
return new Response(agentPy, {
headers: { "Content-Type": "text/x-python; charset=utf-8",
"Content-Disposition": 'attachment; filename="probe-agent.py"'}
});
}
if (url.pathname.startsWith("/api/")) {
// 公开读接口走 60 秒缓存，命中不查 D1
if (isCacheableApi(req, url.pathname)) return cachedApi(req, getDB(env), env);
// admin 写操作后清缓存，保证状态页及时更新
const resp = await handleApi(req, getDB(env), env);
if (url.pathname.startsWith("/api/admin/") && req.method !== "GET" && resp.ok) invalidateApiCache();
return resp;
}
// 访客记录（仅记录页面访问，不记录 API）
ctx.waitUntil(logVisitor(req, getDB(env), url.pathname));
return new Response(APP_HTML, { headers: { "Content-Type": "text/html; charset=utf-8"}});
},
async scheduled(event, env, ctx) {
ctx.waitUntil(handleCron(getDB(env)));
}
};

// 访客记录（异步，不阻塞响应）
async function logVisitor(req, db, path) {
try {
  // 检查是否启用访客记录（默认启用）
  const enabled = await getSetting(db, "visitor_log_enabled");
  if (enabled === "0") return;
  const ip = getClientIp(req);
  const ipHash = await sha256hex(ip + "|visitor-salt");
  const country = req.headers.get("CF-IPCountry") || "";
  const ua = req.headers.get("User-Agent") || "";
  const device = /mobile|android|iphone|ipad/i.test(ua) ? "手机" : (/bot|crawler|spider/i.test(ua) ? "爬虫" : "电脑");
  await db.prepare(
    `INSERT INTO visitor_logs (ip_hash, country, path, device, created_at) VALUES (?,?,?,?,?)`
  ).bind(ipHash.substring(0, 16), country, path.substring(0, 100), device, now()).run();
  // 清理 30 天前的日志：按 1% 概率执行，避免每次访问都写放大
  if (Math.random() < 0.01) {
    await db.prepare(`DELETE FROM visitor_logs WHERE created_at < ?`).bind(now() - 30 * 86400).run();
  }
} catch (e) {}
}
