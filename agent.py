#!/usr/bin/env python3
"""
探针站 Agent：服务器资源上报脚本
=================================
在要监控的服务器上运行，每分钟上报一次 CPU/内存/磁盘/负载。

部署：
  1. 下载本脚本到服务器：curl -sSL https://your-probe-domain.com/agent.py -o /opt/probe-agent.py
  2. 编辑下方 PROBE_URL 和 AGENT_TOKEN
  3. 加 cron 每分钟执行：
     (crontab -l 2>/dev/null; echo "*/1 * * * * /usr/bin/python3 /opt/probe-agent.py >> /var/log/probe-agent.log 2>&1") | crontab -

依赖：仅 Python3 标准库，无需 pip。
"""

import json
import shutil
import urllib.request

# ============ 配置（改这里） ============
PROBE_URL = "https://your-probe-domain.com"
AGENT_TOKEN = "在这里填后台生成的 Agent Token"
# ======================================


def read_cpu():
    """读 /proc/stat 算 CPU 使用率（两次采样取差值，3 秒窗口更稳定）"""
    def sample():
        with open("/proc/stat") as f:
            parts = f.readline().split()[1:]
        vals = list(map(int, parts))
        idle = vals[3] + vals[4]
        return sum(vals), idle
    t1, i1 = sample()
    __import__("time").sleep(3)
    t2, i2 = sample()
    total_d = t2 - t1
    if total_d == 0:
        return 0.0
    return round((1 - (i2 - i1) / total_d) * 100, 1)


def read_mem():
    with open("/proc/meminfo") as f:
        info = {}
        for line in f:
            k, v = line.split(":")
            info[k.strip()] = int(v.split()[0])
    total = info.get("MemTotal", 1)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    return round((1 - avail / total) * 100, 1)


def read_disk():
    u = shutil.disk_usage("/")
    return round(u.used / u.total * 100, 1)


def read_uptime():
    with open("/proc/uptime") as f:
        return int(float(f.read().split()[0]))


def read_load():
    with open("/proc/loadavg") as f:
        return float(f.read().split()[0])


def ping_isp():
    """TCP 测三网延迟（无需 root，比 ICMP 更可靠）
    电信 114.114.114.114:53 / 联通 123.125.81.6:53 / 移动 www.10086.cn:443
    （移动 DNS 不接受境外 TCP 连接，改测官网 443 端口）
    """
    import socket, time
    targets = {
        "telecom": [("114.114.114.114", 53)],
        "unicom": [("123.125.81.6", 53)],
        "mobile": [("www.10086.cn", 443)],
    }
    result = {}
    for key, addrs in targets.items():
        val = 0
        for host, port in addrs:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                t0 = time.time()
                s.connect((host, port))
                val = round((time.time() - t0) * 1000, 1)
                s.close()
                break
            except Exception:
                continue
        result[key] = val
    return result


def read_ssh_attacks():
    """统计 10 分钟内 SSH 失败登录次数和 Top IP
    支持 /var/log/auth.log (Debian) 和 /var/log/secure (RHEL)
    日志时间格式 Mon DD HH:MM:SS（无年份，按当年解析）
    """
    import os, re, time, datetime
    log_files = ["/var/log/auth.log", "/var/log/secure"]
    cutoff = time.time() - 600  # 10 分钟
    # 日志时间戳正则：Oct 17 20:45:01
    ts_pat = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
    months = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
              "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
    def parse_ts(line):
        m = ts_pat.match(line)
        if not m: return 0
        mon, day, hh, mm, ss = m.groups()
        try:
            year = datetime.datetime.now().year
            dt = datetime.datetime(year, months.get(mon, 1), int(day),
                                   int(hh), int(mm), int(ss))
            ts = dt.timestamp()
            # 跨年修正：如果解析出的时间在未来超过 1 天，说明是去年的日志
            if ts > time.time() + 86400:
                ts = datetime.datetime(year-1, months.get(mon, 1), int(day),
                                       int(hh), int(mm), int(ss)).timestamp()
            return ts
        except Exception:
            return 0
    fail_count = 0
    ip_count = {}
    # 匹配失败登录的关键字
    patterns = [
        re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"),
        re.compile(r"Failed login.*from (\d+\.\d+\.\d+\.\d+)"),
        re.compile(r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)"),
        re.compile(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)"),
    ]
    for logf in log_files:
        if not os.path.exists(logf):
            continue
        try:
            with open(logf, errors="ignore") as f:
                # 只读最后 5000 行，避免大文件太慢
                lines = f.readlines()[-5000:]
            for line in lines:
                # 快速过滤：只看含失败关键字的行
                low = line.lower()
                if "failed" not in low and "invalid user" not in low and "authentication failure" not in low:
                    continue
                # 时间窗口过滤：只要 10 分钟内的
                if parse_ts(line) < cutoff:
                    continue
                for pat in patterns:
                    mm = pat.search(line)
                    if mm:
                        fail_count += 1
                        ip = mm.group(1)
                        ip_count[ip] = ip_count.get(ip, 0) + 1
                        break
        except Exception:
            continue
    # Top 5 IP
    top_ips = sorted(ip_count.items(), key=lambda x: -x[1])[:5]
    ip_str = "\n".join(f"{ip}: {c}次" for ip, c in top_ips)
    return fail_count, ip_str


def read_netstat():
    """统计 TCP 连接数和 SYN_RECV 数量（DDoS/CC 症状检测）"""
    import os
    conn_count = 0
    syn_recv = 0
    try:
        # /proc/net/tcp 和 tcp6：每行一个连接，st 字段表示状态
        # TCP 状态码：01=ESTABLISHED, 03=SYN_RECV, 0A=LISTEN
        for f in ["/proc/net/tcp", "/proc/net/tcp6"]:
            if not os.path.exists(f):
                continue
            with open(f, errors="ignore") as fh:
                lines = fh.readlines()[1:]  # 跳过表头
                for line in lines:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    st = parts[3]
                    if st == "0A":  # LISTEN 不算
                        continue
                    conn_count += 1
                    if st == "03":  # SYN_RECV
                        syn_recv += 1
    except Exception:
        pass
    return conn_count, syn_recv


def read_bandwidth():
    """读取网络带宽（Mbps），通过两次采样 /proc/net/dev 计算"""
    import os, time
    def get_bytes():
        total_rx, total_tx = 0, 0
        try:
            with open("/proc/net/dev", errors="ignore") as f:
                for line in f.readlines()[2:]:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    iface = parts[0].rstrip(":")
                    if iface in ("lo",):
                        continue
                    total_rx += int(parts[1])
                    total_tx += int(parts[9])
        except Exception:
            pass
        return total_rx, total_tx
    rx1, tx1 = get_bytes()
    time.sleep(1)
    rx2, tx2 = get_bytes()
    # Mbps = bytes * 8 / 1e6
    rx_mbps = round((rx2 - rx1) * 8 / 1e6, 2)
    tx_mbps = round((tx2 - tx1) * 8 / 1e6, 2)
    return rx_mbps, tx_mbps


def check_processes():
    """检查关键进程存活 + 可疑进程（挖矿木马）"""
    import os, re
    # 挖矿/木马特征（进程名或命令行关键字）
    MINING_SIGS = ["xmrig", "minerd", "cpuminer", "ethminer", "t-rex",
                   "lolminer", "nbminer", "kthreaddi", "ddg."]
    watched = {}  # 从环境变量或配置文件读取，这里返回空由 Worker 端配置驱动
    suspect = []
    try:
        # 读 /proc 扫进程
        procs = {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/comm", errors="ignore") as f:
                    comm = f.read().strip()
                with open(f"/proc/{pid}/cmdline", errors="ignore") as f:
                    cmdline = f.read().replace("\x00", " ").strip()
                procs[pid] = (comm, cmdline)
                # 可疑进程检测
                low = (comm + " " + cmdline).lower()
                for sig in MINING_SIGS:
                    if sig in low:
                        suspect.append(f"{comm} (PID {pid})")
                        break
            except Exception:
                continue
        # 检查 /tmp/probe_watch_procs 文件指定的关键进程（服务端下发，跨进程持久化）
        try:
            watch_list = open("/tmp/probe_watch_procs").read().split(",")
        except Exception:
            watch_list = []
        for name in watch_list:
            name = name.strip()
            if not name:
                continue
            alive = any(name in comm or name in cmdline for comm, cmdline in procs.values())
            watched[name] = alive
    except Exception:
        pass
    return watched, "; ".join(suspect[:5])


def autoban_ssh(threshold=20):
    """SSH 爆破自动封禁：10 分钟内失败超阈值的 IP 用 iptables 封 24 小时"""
    import subprocess, os, re, time
    if os.geteuid() != 0:
        return ""  # 需要 root
    banned = []
    try:
        # 复用 read_ssh_attacks 的 IP 统计
        _, ip_str = read_ssh_attacks()
        for line in ip_str.split("\n"):
            m = re.match(r"(\d+\.\d+\.\d+\.\d+):\s*(\d+)次", line)
            if not m:
                continue
            ip, count = m.group(1), int(m.group(2))
            if count >= threshold:
                # 检查是否已封
                r = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                   capture_output=True, timeout=5)
                if r.returncode != 0:  # 未封过
                    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                                   capture_output=True, timeout=5)
                    banned.append(ip)
    except Exception:
        pass
    return ",".join(banned)


def check_ssl_cert(domain):
    """检查域名 SSL 证书剩余天数"""
    import ssl, socket
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # notAfter 格式：'Oct 17 20:00:00 2026 GMT'
                import datetime
                exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.datetime.utcnow()).days
                return days
    except Exception:
        return None


def handle_isolation(should_block):
    """一键断网/恢复：iptables 屏蔽所有入站（保留已建立连接 + SSH 端口 22）"""
    import subprocess, os
    if os.geteuid() != 0:
        return False
    CHAIN = "PROBE_ISOLATE"
    try:
        if should_block:
            # 建链（已存在则跳过）
            subprocess.run(["iptables", "-N", CHAIN], capture_output=True, timeout=5)
            subprocess.run(["iptables", "-F", CHAIN], capture_output=True, timeout=5)
            # 允许已建立连接
            subprocess.run(["iptables", "-A", CHAIN, "-m", "conntrack", "--ctstate",
                            "ESTABLISHED,RELATED", "-j", "ACCEPT"], capture_output=True, timeout=5)
            # 允许 SSH（22 端口，防把自己锁死）
            subprocess.run(["iptables", "-A", CHAIN, "-p", "tcp", "--dport", "22",
                            "-j", "ACCEPT"], capture_output=True, timeout=5)
            # 其余全部 DROP
            subprocess.run(["iptables", "-A", CHAIN, "-j", "DROP"], capture_output=True, timeout=5)
            # 插入到 INPUT 链首（如果还没插）
            r = subprocess.run(["iptables", "-C", "INPUT", "-j", CHAIN],
                               capture_output=True, timeout=5)
            if r.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "-j", CHAIN],
                               capture_output=True, timeout=5)
            # 标记状态
            open("/tmp/probe_isolated", "w").write("1")
        else:
            # 恢复：从 INPUT 链删除引用并清空
            subprocess.run(["iptables", "-D", "INPUT", "-j", CHAIN],
                           capture_output=True, timeout=5)
            subprocess.run(["iptables", "-F", CHAIN], capture_output=True, timeout=5)
            subprocess.run(["iptables", "-X", CHAIN], capture_output=True, timeout=5)
            try:
                os.remove("/tmp/probe_isolated")
            except Exception:
                pass
        return True
    except Exception:
        return False


def is_isolated():
    import os
    return os.path.exists("/tmp/probe_isolated")


def main():
    if "在这里填" in AGENT_TOKEN:
        print("请先编辑脚本，填入 AGENT_TOKEN")
        return
    import hmac, hashlib, time, os
    ssh_fail, ssh_ips = read_ssh_attacks()
    ping = ping_isp()
    conn_count, syn_recv = read_netstat()
    # 配置从服务端获取（首次运行用环境变量兜底，之后服务端下发）
    # 注意：进程检查用的 WATCH_PROCS 在上次上报的响应中设置
    # SSH 自动封禁：阈值服务端下发（复用 ssh_threshold）
    banned = ""
    try:
        # 从上次服务端响应获取的阈值（存在临时文件里）
        ban_threshold = 20
        try:
            with open("/tmp/probe_ssh_threshold", "r") as f:
                ban_threshold = int(f.read().strip() or "20")
        except Exception:
            ban_threshold = int(os.environ.get("SSH_BAN_THRESHOLD", "20"))
        if ban_threshold > 0:
            banned = autoban_ssh(ban_threshold)
    except Exception:
        pass
    # 进程检查
    proc_status, suspect_procs = check_processes()
    # SSL 证书检查：域名列表服务端下发（存在临时文件里）
    ssl_days, ssl_domain = None, ""
    ssl_list = []  # 所有域名的证书状态 [{domain, days}]
    try:
        domains = []
        try:
            with open("/tmp/probe_ssl_domains", "r") as f:
                domains = f.read().strip().split(",")
        except Exception:
            domains = os.environ.get("SSL_DOMAINS", "").split(",")
        for d in domains:
            d = d.strip()
            if not d:
                continue
            days = check_ssl_cert(d)
            if days is not None:
                ssl_list.append({"domain": d, "days": days})
                if ssl_days is None or days < ssl_days:
                    ssl_days, ssl_domain = days, d
    except Exception:
        pass
    ts = int(time.time())
    sig = hmac.new(AGENT_TOKEN.encode(), str(ts).encode(), hashlib.sha256).hexdigest()
    payload = json.dumps({
        "token": AGENT_TOKEN,
        "ts": ts,
        "sig": sig,
        "cpu": read_cpu(),
        "mem": read_mem(),
        "disk": read_disk(),
        "uptime": read_uptime(),
        "load1": read_load(),
        "ssh_fail": ssh_fail,
        "ssh_ips": ssh_ips,
        "ping_telecom": ping.get("telecom", 0),
        "ping_unicom": ping.get("unicom", 0),
        "ping_mobile": ping.get("mobile", 0),
        "conn_count": conn_count,
        "syn_recv": syn_recv,
        "banned_ips": banned,
        "proc_status": json.dumps(proc_status) if proc_status else "",
        "suspect_procs": suspect_procs,
        "ssl_days": ssl_days,
        "ssl_domain": ssl_domain,
        "ssl_list": ssl_list,
        "net_isolated": 1 if is_isolated() else 0,
    }).encode()
    req = urllib.request.Request(
        PROBE_URL + "/api/agent/report",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ProbeAgent/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        print("上报成功:", resp.status)
        # 处理服务端指令
        try:
            data = json.loads(resp.read().decode())
            # 断网指令
            should_block = data.get("net_blocked", 0) == 1
            currently = is_isolated()
            if should_block != currently:
                if handle_isolation(should_block):
                    print("断网状态已更新:", "已隔离" if should_block else "已恢复")
            # 配置下发：保存到临时文件供下次上报使用
            pw = data.get("process_watch", "")
            try:
                open("/tmp/probe_watch_procs", "w").write(pw)
            except Exception:
                pass
            sd = data.get("ssl_domains", "")
            try:
                open("/tmp/probe_ssl_domains", "w").write(sd)
            except Exception:
                pass
            st = data.get("ssh_threshold", 0)
            try:
                open("/tmp/probe_ssh_threshold", "w").write(str(st))
            except Exception:
                pass
        except Exception as e:
            print("指令处理失败:", e)


if __name__ == "__main__":
    main()
