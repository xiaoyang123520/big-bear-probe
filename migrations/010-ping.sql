-- 三网延迟
ALTER TABLE agent_stats ADD COLUMN ping_telecom REAL DEFAULT 0;
ALTER TABLE agent_stats ADD COLUMN ping_unicom REAL DEFAULT 0;
ALTER TABLE agent_stats ADD COLUMN ping_mobile REAL DEFAULT 0;
