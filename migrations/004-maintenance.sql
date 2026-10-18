-- 计划维护
CREATE TABLE IF NOT EXISTS maintenances (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  start_at INTEGER NOT NULL,
  end_at INTEGER NOT NULL,
  status TEXT DEFAULT 'scheduled',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_maint_start ON maintenances(start_at);
