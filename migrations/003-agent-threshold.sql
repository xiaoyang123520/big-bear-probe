-- Agent 资源阈值告警
ALTER TABLE monitors ADD COLUMN cpu_threshold INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN mem_threshold INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN disk_threshold INTEGER DEFAULT 0;
-- 告警状态：记录哪些指标正在告警中（JSON，如 {"cpu":1,"mem":0,"disk":0}），避免重复轰炸
ALTER TABLE monitors ADD COLUMN agent_alert_state TEXT DEFAULT '{}';
