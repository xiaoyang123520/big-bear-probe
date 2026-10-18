-- 015: 补 ssl_domains 列（之前直接加到 D1 漏了迁移文件）
ALTER TABLE monitors ADD COLUMN ssl_domains TEXT DEFAULT '';
