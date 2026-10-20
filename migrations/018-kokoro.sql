-- 018: 借鉴 Kokoro 的主机信息 / 流量统计 / 一键体检
-- agent_stats: 实时速率 (Mbps) + 累计流量 (bytes, /proc/net/dev 累计值)
ALTER TABLE agent_stats ADD COLUMN rx_mbps REAL DEFAULT 0;
ALTER TABLE agent_stats ADD COLUMN tx_mbps REAL DEFAULT 0;
ALTER TABLE agent_stats ADD COLUMN net_rx INTEGER DEFAULT 0;
ALTER TABLE agent_stats ADD COLUMN net_tx INTEGER DEFAULT 0;
-- monitors: 主机配置 (JSON: cpu_model/cores/mem_mb/disk_gb/os/virt/arch)
ALTER TABLE monitors ADD COLUMN host_info TEXT DEFAULT '';
-- monitors: 价格展示文本 (如 "$16.93/月" / "¥99/年")
ALTER TABLE monitors ADD COLUMN price_text TEXT DEFAULT '';
-- monitors: 一键体检 (bench_requested=1 时随上报响应下发, agent 执行后回传结果)
ALTER TABLE monitors ADD COLUMN bench_requested INTEGER DEFAULT 0;
ALTER TABLE monitors ADD COLUMN bench_result TEXT DEFAULT '';
ALTER TABLE monitors ADD COLUMN bench_at INTEGER DEFAULT 0;
