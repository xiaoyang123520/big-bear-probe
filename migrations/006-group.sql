-- 监控分组
ALTER TABLE monitors ADD COLUMN group_name TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_monitors_group ON monitors(group_name);
