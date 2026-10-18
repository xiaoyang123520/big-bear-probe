-- 探针站 D1 表结构

-- 监控目标
CREATE TABLE IF NOT EXISTS monitors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'http',  -- http | tcp | ssl
  target TEXT NOT NULL,               -- http: 完整 URL；tcp: host:port；ssl: 域名
  interval_minutes INTEGER NOT NULL DEFAULT 5,  -- 1/5/15/30/60
  keyword TEXT DEFAULT '',            -- http 关键词匹配（响应体包含才算正常）
  expected_status INTEGER DEFAULT 200,-- 期望 HTTP 状态码（0 表示不检查）
  enabled INTEGER NOT NULL DEFAULT 1,
  -- 告警开关
  alert_telegram INTEGER DEFAULT 0,
  alert_email INTEGER DEFAULT 0,
  alert_webhook INTEGER DEFAULT 0,
  webhook_url TEXT DEFAULT '',
  -- 运行状态
  last_check_at INTEGER DEFAULT 0,
  last_status TEXT DEFAULT 'unknown', -- up | down | unknown
  last_ms INTEGER DEFAULT 0,
  consecutive_failures INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_monitors_enabled ON monitors(enabled, interval_minutes, last_check_at);

-- 检测历史（用于可用率统计和图表，定期清理只留 90 天）
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id INTEGER NOT NULL,
  checked_at INTEGER NOT NULL,
  status TEXT NOT NULL,  -- up | down
  ms INTEGER DEFAULT 0,
  detail TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_checks_monitor ON checks(monitor_id, checked_at);

-- 故障事件
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id INTEGER NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at INTEGER DEFAULT 0,  -- 0 表示未恢复
  fail_count INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_incidents_monitor ON incidents(monitor_id, started_at);

-- 全局设置
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
-- 预置：admin_password_hash（首次访问后台时设置）, telegram_bot_token, alert_email_from, resend_api_key
