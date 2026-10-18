-- SMTP/Server酱/WxPusher/飞书 + 到期提醒
ALTER TABLE monitors ADD COLUMN alert_smtp INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN alert_serverchan INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN alert_wxpusher INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN alert_feishu INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN expire_at INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN expire_alert_state TEXT DEFAULT '{}';
