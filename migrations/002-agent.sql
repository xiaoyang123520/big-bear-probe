-- Agent 上报：服务器资源监控
ALTER TABLE monitors ADD COLUMN agent_token TEXT DEFAULT '';

CREATE TABLE IF NOT EXISTS agent_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id INTEGER NOT NULL,
  reported_at INTEGER NOT NULL,
  cpu REAL DEFAULT 0,
  mem REAL DEFAULT 0,
  disk REAL DEFAULT 0,
  uptime INTEGER DEFAULT 0,
  load1 REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_agent_stats_monitor ON agent_stats(monitor_id, reported_at);
