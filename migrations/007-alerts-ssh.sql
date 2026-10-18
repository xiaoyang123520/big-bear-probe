-- 新增告警渠道 + SSH 爆破检测
ALTER TABLE monitors ADD COLUMN alert_dingtalk INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN alert_bark INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN alert_wecom INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN ssh_threshold INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN ssh_alert_state TEXT DEFAULT '{}';
