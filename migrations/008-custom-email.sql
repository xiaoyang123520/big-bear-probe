-- 通用邮件接口（用户自建 HTTP 发邮件服务）
ALTER TABLE monitors ADD COLUMN alert_custom_email INTEGER DEFAULT 0;
