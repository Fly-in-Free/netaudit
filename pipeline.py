#!/usr/bin/env python3
"""
用法：
  pipeline.py ingest    从 pcapng 提 (进程, 五元组, SNI, DNS) 入库，然后删除已入库的 pcap
  pipeline.py bytes     导出 powerlog 的按进程字节量（跨归档去重）
  pipeline.py report    生成 ~/netaudit/reports/YYYY-MM-DD.md 并更新基线
  pipeline.py check     部署自检（目录/依赖/权限/数据库）
  pipeline.py daily     bytes + report（每日任务用，不含 ingest）
  pipeline.py all       依次跑上面三个

环境变量：
  NETAUDIT_BASE       数据根目录（默认 = 脚本所在目录）
  NETAUDIT_TSHARK     tshark 路径（默认自动查找）
  PCAP_KEEP_DAYS      pcap 保留天数（默认 3）
  PCAP_MAX_GB         pcap 总字节上限，超出提前删最老的（默认 25）

设计前提：pcap 只作「异常定位窗口」，不做长期留存也不做内容审计；
长期资产是 SQLite（进程 + 域名/IP + 字节量），它体积小、可永久保留。

⚠️ 进程归属必须走 /usr/sbin/tcpdump -k，不能用 tshark：
   macOS 的 pktap 抓包写出的 pcapng，IDB 用真实 DLT（Ethernet/NULL）而非 DLT_PKTAP，
   进程元数据被放进 Apple 自定义 pcap-ng 选项（0x8001–0x800A）。
   Wireshark/tshark 不解析这些选项，所以 pktap.pid / pktap.cmdname 永远是空的。
   只有 Apple 自己的 tcpdump -k 会读它们。
"""
import collections
import datetime as dt
import glob
import gzip
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
# 可移植：默认拿脚本自己所在目录，而不是硬编码 $HOME/netaudit
BASE = os.environ.get("NETAUDIT_BASE") or os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "db", "audit.sqlite")
PCAP = os.path.join(BASE, "pcap")
TCPDUMP = "/usr/sbin/tcpdump"
PL_ARCH = "/private/var/db/powerlog/Library/BatteryLife/Archives/*.gz"
PL_CUR = "/private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL"


def _find_tshark():
    """tshark 不在 PATH 时回退到 Wireshark 的 app bundle 内部。"""
    for c in (os.environ.get("NETAUDIT_TSHARK"), shutil.which("tshark"),
              "/Applications/Wireshark.app/Contents/MacOS/tshark",
              "/opt/homebrew/bin/tshark", "/usr/local/bin/tshark"):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "/Applications/Wireshark.app/Contents/MacOS/tshark"


TSHARK = _find_tshark()
M = 1048576.0
PCAP_KEEP_DAYS = int(os.environ.get("PCAP_KEEP_DAYS", "3"))
# 容量硬上限。实测：空闲 0.46 GB/天，含 LLM 流式会话的突发可到 17.9 GB/天。
# 光靠天数保留不够，必须有字节上限兜底。
PCAP_MAX_GB = float(os.environ.get("PCAP_MAX_GB", "25"))
# 改 SCHEMA 时必须同步 +1，否则已存在的旧表不会自动更新
SCHEMA_VERSION = 2

# 表与索引必须分开：索引引用 conn 的列，而老库的 conn 可能缺列。
# 顺序必须是「建表 → 迁移 → 建索引」，否则老库会在建索引时直接报错。
SCHEMA_TABLES = """
CREATE TABLE IF NOT EXISTS conn (
  ts REAL, pid INTEGER, proc TEXT, eproc TEXT, ifname TEXT, dir TEXT,
  src TEXT, sport INTEGER, dst TEXT, dport INTEGER,
  sni TEXT, dns_qname TEXT, pkts INTEGER,
  PRIMARY KEY (ts, pid, dst, dport, ifname)
);
CREATE TABLE IF NOT EXISTS bytes (
  ts REAL, proc TEXT, wifi_in INT, wifi_out INT,
  wired_in INT, wired_out INT, cell_in INT, cell_out INT,
  PRIMARY KEY (ts, proc)
);
CREATE TABLE IF NOT EXISTS seen_domain (
  domain TEXT PRIMARY KEY, first_seen REAL, first_proc TEXT
);
CREATE TABLE IF NOT EXISTS seen_dst (
  dst TEXT PRIMARY KEY, first_seen REAL, first_proc TEXT
);
"""

SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_conn_ts   ON conn(ts);
CREATE INDEX IF NOT EXISTS idx_conn_sni  ON conn(sni);
CREATE INDEX IF NOT EXISTS idx_conn_proc ON conn(proc);
"""

# tcpdump -k PIND -tt -n -q 的输出：
# 1789736841.380484 (en0, proc apsd:577, eproc foo:1, out) IP 10.0.0.1.50441 > 192.0.2.1.443: tcp 38
RE_LINE = re.compile(
    r'^(?P<ts>\d+\.\d+) \((?P<meta>[^)]*)\) '
    r'(?P<l3>IP6?|IP) (?P<src>\S+) > (?P<dst>\S+): ?(?P<rest>.*)$'
)


def _split_endpoint(tok):
    """IPv4: a.b.c.d.port / IPv6: 2001:db8::1.port  →  (addr, port)"""
    addr, _, port = tok.rpartition(".")
    try:
        return addr, int(port)
    except ValueError:
        return None, None


def parse_tcpdump(path):
    """跑 tcpdump -k，把**双向合并**成一个规范流。

    方向必须合并：同一连接的正反两个方向在 pcapng 里是两条不同的五元组，
    而进程归属通常只在发包那一侧有，分开算会让归属率从 99% 掉到 70%。
    返回 {(epA, epB): {...}}，ep = "addr:port"。
    """
    cmd = [TCPDUMP, "-r", path, "-k", "PIND", "-tt", "-n", "-q"]
    flows = {}
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, errors="replace") as pr:
        for line in pr.stdout:
            m = RE_LINE.match(line)
            if not m:
                continue
            meta = m.group("meta")
            ifname = pid = proc = eproc = direction = None
            for tok in meta.split(", "):
                tok = tok.strip()
                if tok in ("in", "out"):
                    direction = tok
                elif tok.startswith("proc "):
                    name, _, p = tok[5:].rpartition(":")
                    proc, pid = name, (int(p) if p.isdigit() else 0)
                elif tok.startswith("eproc "):
                    eproc = tok[6:].rpartition(":")[0]
                elif tok.startswith(("svc ", "flowid ", "ch")):
                    continue
                elif tok and ifname is None:
                    ifname = tok

            # ICMP 等无端口的协议，tcpdump 不打印 :port，不能按 "." 切
            transport = m.group("rest").split()[0].rstrip(",").lower()
            if transport in ("tcp", "udp"):
                s_addr, s_port = _split_endpoint(m.group("src"))
                d_addr, d_port = _split_endpoint(m.group("dst"))
                if s_addr is None or d_addr is None:
                    continue
            else:
                s_addr, s_port = m.group("src"), 0
                d_addr, d_port = m.group("dst"), 0

            a, b = f"{s_addr}:{s_port}", f"{d_addr}:{d_port}"
            key = (a, b) if a <= b else (b, a)
            cur = flows.get(key)
            if cur is None:
                flows[key] = {
                    "ts": float(m.group("ts")), "pid": 0, "proc": "",
                    "eproc": "", "ifname": ifname or "", "pkts": 1,
                    "first": (s_addr, s_port, d_addr, d_port, direction or ""),
                }
            else:
                cur["pkts"] += 1
                # 每个流只留首个有归属的样本
                if not cur["proc"] and proc:
                    cur["pid"], cur["proc"], cur["eproc"] = pid or 0, proc, eproc or ""
    return flows


TS_FIELDS = [
    "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport",
    "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport",
    "tls.handshake.extensions_server_name", "dns.qry.name",
]


def parse_domains(path):
    """tshark 只负责抽 SNI / DNS 查询名，按**规范流**归位（双向都试）。"""
    cmd = [TSHARK, "-r", path, "-n", "-T", "fields",
           "-E", "separator=|", "-E", "occurrence=f",
           "-Y", "tls.handshake.extensions_server_name || dns.qry.name"]
    for f in TS_FIELDS:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")

    out = {}
    for line in res.stdout.splitlines():
        c = (line.split("|") + [""] * len(TS_FIELDS))[:len(TS_FIELDS)]
        src, dst = c[0] or c[1], c[4] or c[5]
        sport, dport = c[2] or c[3], c[6] or c[7]
        if not (src and dst and sport and dport):
            continue
        a, b = f"{src}:{int(sport)}", f"{dst}:{int(dport)}"
        key = (a, b) if a <= b else (b, a)
        cur = out.setdefault(key, ["", ""])
        if c[8] and not cur[0]:
            cur[0] = c[8]
        if c[9] and not cur[1]:
            cur[1] = c[9]
    return out


def db_connect():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    db = sqlite3.connect(DB)
    # 判是不是全新库：旧表不存在就不算「升级」，只是初始化
    fresh = db.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='conn'"
    ).fetchone()[0] == 0
    db.executescript(SCHEMA_TABLES)
    v = db.execute("PRAGMA user_version").fetchone()[0]
    if v != SCHEMA_VERSION:
        if fresh:
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            db.commit()
        else:
            # 老表结构：CREATE TABLE IF NOT EXISTS 不会改已存在的表，必须显式处理。
            # conn 是从 pcap 派生的，可以安全重建；有数据就先改名备份而不是直接删。
            n = db.execute("SELECT count(*) FROM conn").fetchone()[0]
            if n:
                bak = f"conn_v{v}"
                db.executescript(f"DROP TABLE IF EXISTS {bak}; ALTER TABLE conn RENAME TO {bak};")
                print(f"[db] 表结构升级 v{v}→v{SCHEMA_VERSION}，旧数据已备份为 {bak}")
            else:
                db.executescript("DROP TABLE IF EXISTS conn;")
                print(f"[db] 表结构升级 v{v}→v{SCHEMA_VERSION}")
            db.executescript(SCHEMA_TABLES)
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            db.commit()
    db.executescript(SCHEMA_INDEXES)   # 必须在迁移之后
    return db


def cmd_ingest():
    db = db_connect()
    files = sorted(glob.glob(f"{PCAP}/*.pcapng.gz")) + sorted(glob.glob(f"{PCAP}/*.pcapng"))
    total = 0
    for p in files:
        # 跳过可能还在写的活跃文件
        if time.time() - os.path.getmtime(p) < 180:
            continue
        tmp = p
        if p.endswith(".gz"):
            tmp = "/tmp/netaudit_cur.pcapng"
            with gzip.open(p, "rb") as fi, open(tmp, "wb") as fo:
                shutil.copyfileobj(fi, fo)

        flows = parse_tcpdump(tmp)
        domains = parse_domains(tmp)

        rows = []
        for key, v in flows.items():
            sni, dns_q = domains.get(key, ("", ""))
            # 用首包方向决定哪一端是"对端"，让 dst/dport 语义固定为"连到哪"
            s_addr, s_port, d_addr, d_port, first_dir = v["first"]
            rows.append((v["ts"], v["pid"], v["proc"], v["eproc"], v["ifname"],
                         first_dir, s_addr, s_port, d_addr, d_port,
                         sni, dns_q, v["pkts"]))
        db.executemany(
            "INSERT OR REPLACE INTO conn VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        db.commit()
        total += len(rows)
        withdom = sum(1 for r in rows if r[10])
        withproc = sum(1 for r in rows if r[2])
        print(f"[ingest] {os.path.basename(p)}: {len(rows)} 流 "
              f"（{withproc} 有进程归属，{withdom} 有域名）")
        if p.endswith(".gz"):
            os.unlink(tmp)
        os.unlink(p)

    # pcap 是唯一「过期即永久丢失」的数据，所以先告警再删。
    cutoff = time.time() - PCAP_KEEP_DAYS * 86400
    expiring = sorted(p for p in glob.glob(f"{PCAP}/*") if os.path.getmtime(p) < cutoff)
    if expiring:
        print(f"[ingest] ⚠️  {len(expiring)} 个 pcap 超过 {PCAP_KEEP_DAYS} 天即将删除 "
              f"—— 说明入库曾经失败，这些包没进 SQLite")
        for p in expiring[:5]:
            print(f"        - {os.path.basename(p)}")

    # 入库跟不上时告警（预期每 2 小时跑一次 ingest）
    stale = [p for p in glob.glob(f"{PCAP}/*")
             if time.time() - os.path.getmtime(p) > 6 * 3600]
    if stale:
        print(f"[ingest] ⚠️  {len(stale)} 个 pcap 超过 6 小时未被处理，检查 tcpdump 是否正常")

    for p in expiring:
        os.unlink(p)

    # 容量硬上限：超出就提前删最老的（不动正在写的那个）
    cap_bytes = PCAP_MAX_GB * 1024 ** 3
    remaining = sorted(glob.glob(f"{PCAP}/*"), key=os.path.getmtime)
    total_sz = sum(os.path.getsize(p) for p in remaining)
    while total_sz > cap_bytes and len(remaining) > 1:
        p = remaining.pop(0)
        total_sz -= os.path.getsize(p)
        os.unlink(p)
        print(f"[ingest] 🗜  超出 {PCAP_MAX_GB:.0f} GB 上限，提前删除 {os.path.basename(p)}")

    print(f"[ingest] 共 {total} 流；pcap 保留 {PCAP_KEEP_DAYS} 天、"
          f"当前 {total_sz/1024**3:.1f} GB / 上限 {PCAP_MAX_GB:.0f} GB")
    db.close()


def cmd_bytes():
    db = db_connect()
    for s in sorted(glob.glob(PL_ARCH)) + [PL_CUR]:
        if s.endswith(".gz"):
            with gzip.open(s, "rb") as fi, open("/tmp/netaudit_pl.sqlite", "wb") as fo:
                shutil.copyfileobj(fi, fo)
            p = "/tmp/netaudit_pl.sqlite"
        else:
            p = s
        src = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        rows = list(src.execute("""
            SELECT timestamp, ProcessName, WifiIn, WifiOut, WiredIn, WiredOut, CellIn, CellOut
            FROM PLProcessNetworkAgent_EventInterval_UsageDiff
            WHERE ProcessName IS NOT NULL AND ProcessName != ''"""))
        src.close()
        db.executemany(
            "INSERT OR REPLACE INTO bytes VALUES (?,?,?,?,?,?,?,?)",
            [(r[0], r[1], r[2] or 0, r[3] or 0, r[4] or 0,
              r[5] or 0, r[6] or 0, r[7] or 0) for r in rows])
        db.commit()
        print(f"[bytes] {os.path.basename(s)} -> {len(rows)} rows")
    db.close()


def cmd_report():
    db = db_connect()
    now = dt.datetime.now()
    t0 = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    t1 = t0 + 86400
    q = lambda s, *a: db.execute(s, a).fetchall()

    new_dom = q("""SELECT c.sni, c.proc, datetime(c.ts,'unixepoch','localtime'), c.dst
                   FROM conn c JOIN seen_domain d ON d.domain = c.sni
                   WHERE c.ts >= ? AND c.sni IS NOT NULL AND c.sni != ''
                   ORDER BY c.ts""", t0)
    new_dst = q("""SELECT c.dst, c.dport, c.proc FROM conn c
                   JOIN seen_dst d ON d.dst = c.dst
                   WHERE c.ts >= ? GROUP BY c.dst, c.dport, c.proc""", t0)
    bytes_top = q("""SELECT proc, SUM(wifi_in+wired_in+cell_in),
                            SUM(wifi_out+wired_out+cell_out)
                     FROM bytes WHERE ts >= ? AND ts < ? GROUP BY proc
                     ORDER BY 3 DESC LIMIT 25""", t0, t1)
    dom_by_proc = q("""SELECT proc, COUNT(DISTINCT sni) FROM conn
                       WHERE ts >= ? AND sni IS NOT NULL AND sni != ''
                       GROUP BY proc ORDER BY 2 DESC LIMIT 25""", t0)
    ip_direct = q("""SELECT dst, dport, proc, COUNT(*) FROM conn
                     WHERE ts >= ? AND (sni IS NULL OR sni = '')
                       AND (dns_qname IS NULL OR dns_qname = '')
                     GROUP BY dst, dport, proc ORDER BY 4 DESC LIMIT 25""", t0)
    odd_ports = q("""SELECT dst, dport, proc FROM conn
                     WHERE ts >= ? AND dport NOT IN (80,443,53)
                     GROUP BY dst, dport, proc LIMIT 30""", t0)
    dns_only = q("""SELECT dns_qname, proc FROM conn
                    WHERE ts >= ? AND (sni IS NULL OR sni = '')
                      AND dns_qname IS NOT NULL AND dns_qname != ''
                    GROUP BY dns_qname, proc LIMIT 40""", t0)

    L = [f"# 网络审计日报 {now:%Y-%m-%d}", ""]

    L += ["## 1. 新出现的域名（最高优先级）", ""]
    if new_dom:
        L += ["| 域名 | 进程 | 时间 | 目标 IP |", "|---|---|---|---|"]
        L += [f"| `{d}` | {p} | {t} | {ip} |" for d, p, t, ip in new_dom]
    else:
        L += ["（无）"]
    L += [""]

    L += ["## 2. 首次出现的 IP:端口", ""]
    L += [f"- `{d}:{port}` ← {proc}" for d, port, proc in new_dst] or ["（无）"]
    L += [""]

    L += ["## 3. 出站字节 Top（MiB）", ""]
    L += ["| 进程 | 入站 | 出站 |", "|---|---|---|"]
    L += [f"| `{p}` | {i/M:,.1f} | {o/M:,.1f} |" for p, i, o in bytes_top]
    L += [""]

    L += ["## 4. 各进程访问的域名数", ""]
    L += [f"- `{p}` — {n}" for p, n in dom_by_proc] or ["（无）"]
    L += [""]

    L += ["## 5. 值得看两眼", ""]
    L += ["**IP 直连（无 SNI、无 DNS 记录）**", ""]
    L += [f"- `{d}:{port}` ← {proc}（{n} 次）" for d, port, proc, n in ip_direct] or ["（无）"]
    L += ["", "**非 80/443/53 端口**", ""]
    L += [f"- `{d}:{port}` ← {proc}" for d, port, proc in odd_ports] or ["（无）"]
    L += ["", "**只有 DNS 没有 TLS 的目标**", ""]
    L += [f"- `{d}` ← {proc}" for d, proc in dns_only] or ["（无）"]
    L += [""]

    os.makedirs(f"{BASE}/reports", exist_ok=True)
    path = f"{BASE}/reports/{dt.date.today()}.md"
    with open(path, "w") as f:
        f.write("\n".join(L))

    # 基线更新必须放在报告生成之后。
    # 注意解包顺序必须与 SELECT 的列序一致：SELECT sni, ts, proc → (d, ts, p)
    db.executemany("INSERT OR IGNORE INTO seen_domain VALUES (?,?,?)",
                   [(d, ts, p) for d, ts, p in q(
                       """SELECT DISTINCT sni, ts, proc FROM conn
                          WHERE ts >= ? AND sni IS NOT NULL AND sni != ''""", t0)])
    db.executemany("INSERT OR IGNORE INTO seen_dst VALUES (?,?,?)",
                   [(d, ts, p) for d, ts, p in q(
                       """SELECT DISTINCT dst, ts, proc FROM conn
                          WHERE ts >= ? AND dst IS NOT NULL""", t0)])
    db.commit()
    db.close()
    print(f"[report] {path}")


def cmd_check():
    """部署自检：装完跑这个，比人肉排查快。"""
    ok = True

    def line(flag, label, detail=""):
        nonlocal ok
        if flag == "FAIL":
            ok = False
        print(f"  [{flag:<4}] {label}" + (f" — {detail}" if detail else ""))

    print(f"NetAudit 自检\n  repo: {BASE}\n  db:   {DB}\n")

    for d in (PCAP, os.path.dirname(DB), os.path.join(BASE, "logs"),
              os.path.join(BASE, "reports")):
        if not os.path.isdir(d):
            try:
                os.makedirs(d, exist_ok=True)
            except OSError as e:
                line("FAIL", f"目录缺失且无法创建 {d}", str(e))
                continue
        line("OK", f"目录 {os.path.relpath(d, BASE)}")

    if os.path.isfile(TCPDUMP):
        line("OK", "tcpdump", TCPDUMP)
    else:
        line("FAIL", "tcpdump 不存在", TCPDUMP)

    if os.path.isfile(TSHARK):
        line("OK", "tshark", TSHARK)
    else:
        line("WARN", "tshark 未找到，域名只能靠 DNS 查询名",
             "brew install --cask wireshark")

    # PKTAP 需要 root，非 root 会报 ioctl(SIOCIFCREATE): Operation not permitted
    if os.geteuid() != 0:
        probe = subprocess.run([TCPDUMP, "-i", "pktap,all", "-c", "1", "-w", "/dev/null"],
                               capture_output=True, text=True)
        if "not permitted" in (probe.stderr or ""):
            line("WARN", "PKTAP 需要 root（普通 BPF 权限不够）", "守护进程会以 root 跑，正常")
        else:
            line("OK", "PKTAP 可用（当前非 root 也能抓）")
    else:
        line("OK", "以 root 运行，PKTAP 可用")

    if os.path.exists(PL_CUR):
        line("OK", "powerlog 可读", PL_CUR)
    else:
        line("WARN", "powerlog 不可读，字节量统计会缺失")

    for f in glob.glob(os.path.join(PCAP, "*")):
        line("OK", f"已采集 {os.path.basename(f)}",
             f"{os.path.getsize(f)/1048576:.1f} MB")

    try:
        db = db_connect()
        for t in ("conn", "bytes", "seen_domain", "seen_dst"):
            n = db.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
            line("OK", f"表 {t}", f"{n} 行")
        db.close()
    except sqlite3.Error as e:
        line("FAIL", "数据库不可用", str(e))

    print(f"\n结果：{'全部通过' if ok else '有 FAIL 项，见上'}")
    return 0 if ok else 1


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "help"
    if action == "ingest":
        cmd_ingest()
    elif action == "check":
        sys.exit(cmd_check())
    elif action == "bytes":
        cmd_bytes()
    elif action == "report":
        cmd_report()
    elif action == "daily":
        # 每日任务：字节量 + 日报。ingest 由更频繁的独立任务负责
        cmd_bytes(); cmd_report()
    elif action == "all":
        cmd_ingest(); cmd_bytes(); cmd_report()
    else:
        print(__doc__)
