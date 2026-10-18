-- 012: 访客记录 + 网络防护字段
CREATE TABLE IF NOT EXISTS visitor_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash TEXT NOT NULL,
  country TEXT DEFAULT '',
  path TEXT DEFAULT '',
  device TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visitor_time ON visitor_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_visitor_ip ON visitor_logs(ip_hash, created_at);

-- monitors 新增字段
ALTER TABLE monitors ADD COLUMN process_watch TEXT DEFAULT '';
ALTER TABLE monitors ADD COLUMN conn_threshold INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN net_blocked INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN net_alert_state TEXT DEFAULT '{}';
ALTER TABLE monitors ADD COLUMN proc_alert_state TEXT DEFAULT '{}';
ALTER TABLE monitors ADD COLUMN ssl_alert_state TEXT DEFAULT '{}';
