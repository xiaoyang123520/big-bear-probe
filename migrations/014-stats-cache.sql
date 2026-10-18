-- 预计算 7 天统计，避免每次请求现场扫全表
ALTER TABLE monitors ADD COLUMN uptime_7d TEXT DEFAULT '100.00';
ALTER TABLE monitors ADD COLUMN avg_ms_7d INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN stats_updated_at INTEGER DEFAULT 0;
