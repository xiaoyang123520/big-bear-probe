-- 016: SSL 证书到期天数展示（agent 上报后存下来供前端显示）
ALTER TABLE monitors ADD COLUMN ssl_days INTEGER DEFAULT -1;
ALTER TABLE monitors ADD COLUMN ssl_domain TEXT DEFAULT '';
