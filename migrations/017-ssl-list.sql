-- 017: SSL 多证书列表（JSON 存全部域名证书状态）
ALTER TABLE monitors ADD COLUMN ssl_list TEXT DEFAULT '';
