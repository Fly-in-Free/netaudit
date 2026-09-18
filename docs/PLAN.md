# macOS 持续网络审计方案 v2

目标：每天能看完整的「进程 → 域名/IP → 字节量」记录，并对新增目标做告警。

> v2 相对 v1 的变化：主干换成 **rustnet**（开源工具，替掉自写的 tshark 采集）；
> 4 个脚本合并为 **1 个**；被否掉的方案连同原因记录在 §1，避免以后重复调研。

---

## 0. 工具清单（结论）

| 层 | 工具 | 装法 | 是否常驻 |
|---|---|---|---|
| **A 抓包（带进程元数据）** | `tcpdump -i pktap,all` | 系统自带 | ✅ 常驻（LaunchDaemon） |
| **B 交互排查 + 按需结构化导出** | **rustnet** | `brew install rustnet` | ❌ 按需 |
| **C 字节量** | powerlog | 系统自带 | 每日 cron |
| **D 完整 URL** | mitmproxy | 已装 | ❌ 按需 |
| **实时阻断** | **LuLu** | 下载 dmg | 可选常驻 |
| **日报聚合** | 自写 `pipeline.py` | — | 每日 cron |

总计：**1 个脚本 + 3 个 plist + 1 个 brew 包**。

### 数据分层（关键设计）

| 数据 | 保留 | 体积 | 作用 |
|---|---|---|---|
| **SQLite**（进程 / 域名 / IP / 字节） | **永久** | ≈5 MB/天，≈1.8 GB/年 | 长期资产。日报、回溯、基线对比、告警全都在这里 |
| **pcap**（原始包，带进程归属） | **3 天** | ≈2.7 GB/天，≈8 GB | 一次性耗材。**只为异常定位**，过期自动删 |
| powerlog 归档 | 系统 ~5 天 | — | 需每日导出到 SQLite |
| rustnet `--json-log` | 会话级 | — | 临时结构化导出，按需 |

> 定位理念：**内容审计不做，行为审计做足**。pcap 不承担历史责任，SQLite 承担。
> 所以“异常发现”永远能靠 SQLite 回溯到任意久之前；pcap 只回答“当时到底是谁在发包”。

---

## 1. 为什么是这个架构（含已否掉的方案）

### 1.1 三条实测硬约束

| 约束 | 实测证据 |
|---|---|
| 统一日志不能当审计源 | 保留窗口仅 ~2 天；域名字段是**每进程一个盐**的哈希（单进程内恒定、跨进程不同、不可解密）。○Code 的 5 个哈希在其他进程出现 **0 次**。○Code 实际出站 1,995.5 MiB，统一日志只记录到 **769 字节** |
| powerlog 只有字节、没有目的地 | `/private/var/db/powerlog/Library/BatteryLife/`，全局可读，但 `Archives/` 只留 ~5 天 |
| **PKTAP 需要 root** | `tcpdump -i pktap,all` 非 root 报 `ioctl(SIOCIFCREATE): Operation not permitted`。你已在 `access_bpf` 组（Wireshark ChmodBPF 装的），但**普通 BPF 权限不等于 pktap 权限** → 抓包必须 LaunchDaemon |

### 1.2 为什么 rustnet 不常驻

rustnet 是 **TUI 应用，当前没有 headless 模式**。证据：

- issue **#600「headless mode with a JSONL event stream」closed 2026-09-04，但未合并**：`CHANGELOG.md` 无此项、`src/main.rs@main` 只有 `--json-log` 没有 `--headless`
- issue **#602「production headless monitoring」仍 open**
- 最新 release 是 **v1.6.0（2026-08-20）**，crates.io `rustnet-monitor` max 也是 1.6.0
- **已在本机装好后用 `rustnet --help` 实证**：`--json-log` ✅ 有、`--headless` ❌ 无、`--snapshot-interval` ❌ 无

所以常驻只能靠 `script -q /dev/null` 包一层 pty —— 官方不支持、升级可能坏、且它的 pcapng 不轮转，跑一天就是一个巨大文件。**不值得**。常驻交给 `tcpdump`（系统自带、无 TTY 依赖、30 分钟滚动）。

rustnet 的定位是：**交互式排查主力 + 需要结构化数据时按需导出**。

### 1.3 明确不要走的岔路

| 方案 | 为什么否掉 |
|---|---|
| **osquery** `socket_events` | 官方文档：macOS 走 OpenBSM，**只支持 10.15 及更早**。10.15+ 只有 `es_process_events`（**仅进程事件，无连接事件**），`bpf_socket_events` 是 Linux 专用。你在 macOS 26 上拿不到连接事件 |
| **OpenSnitch** | 著名「开源 Little Snitch」，**Linux/eBPF only**，macOS 不支持 |
| **Sniffnet** | ★41k、界面漂亮，但**接口级抓包，macOS 上无进程归因** |
| **Zeek / Suricata / Arkime / ntopng** | 域名解析一流，但**都没有进程归因**，且不解析 PKTAP 元数据 |
| App Store「网络监控」类 | 沙盒拿不到其他进程归属 |
| `log stream` 转存 | 域名哈希无法还原，转存也无意义 |
| LuLu 当唯一方案 | 它的日志走 `os_log`，**2 天就轮转**，必须另配转发；不如抓包直接落盘 |

---

## 2. 安装

```bash
# 采集主干（交互排查 + 结构化导出）
brew install rustnet

# 可选：实时阻断
#   https://objective-see.org/products/lulu.html   （免费，Apache/GPL 系）
```

已就绪、无需安装：`/usr/sbin/tcpdump` 4.99.1、`tshark` 4.4.3（Wireshark 自带）、`sqlite3`、`mitmproxy`、`access_bpf` 组成员资格。

tshark 不在 PATH，建议加个别名：

```bash
echo 'alias tshark="/Applications/Wireshark.app/Contents/MacOS/tshark"' >> ~/.zshrc
```

---

## 3. 常驻抓包（LaunchDaemon）

### 3.1 建目录

```bash
mkdir -p ~/netaudit/{pcap,db,reports,logs,rustnet}
```

### 3.2 `/Library/LaunchDaemons/local.netaudit.capture.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.netaudit.capture</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/sbin/tcpdump</string>
    <string>-i</string><string>pktap,all</string>
    <string>-s</string><string>0</string>
    <string>-G</string><string>1800</string>
    <string>-z</string><string>gzip</string>
    <string>-Z</string><string>YOUR_USER</string>
    <string>-w</string><string>$HOME/netaudit/pcap/%Y%m%d-%H%M%S.pcapng</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$HOME/netaudit/logs/capture.err</string>
</dict></plist>
```

```bash
sudo chown root:wheel /Library/LaunchDaemons/local.netaudit.capture.plist
sudo chmod 644 /Library/LaunchDaemons/local.netaudit.capture.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/local.netaudit.capture.plist

# 验证
sleep 60 && ls -la ~/netaudit/pcap/
```

参数说明：
- `pktap,all` — 覆盖所有接口，**含 lo0 和 utun（VPN）**。要排除本机 loopback 就在入库时按 `pktap.ifname != lo0` 过滤
- `-G 1800` — 每 30 分钟切一个文件
- `-z gzip` — 切完即压缩
- `-Z YOUR_USER` — 切出的文件归属你的用户，不用 sudo 就能读
- `-s 0` — 全包（3 天保留，见 §9）。想拉更长可改 `-s 1024`（仍够覆盖绝大多数 SNI）

### 3.3 立刻验证进程归属有没有真的进文件

⚠️ **不能用 tshark / Wireshark 验证** —— 见 §3.4。必须用 Apple 自己的读取开关：

```bash
# -k PIN = 打印进程名(N) / PID(P) / 接口(I)，D 再加方向
/usr/sbin/tcpdump -r "$(ls -S ~/netaudit/pcap/*.pcapng | head -1)" \
    -k PIND -tt -n -q | head
```

正确输出长这样（有 `proc 名字:pid` 即成功）：

```
1789736841.380484 (en0, proc apsd:577, out) IP 10.0.0.2.50441 > 203.0.113.20.5223: tcp 38
1789736841.766081 (en0, proc local-proxy:71725, out) IP 10.0.0.2.50323 > 203.0.113.50.443: tcp 46
```

### 3.4 ❗为什么不能用 tshark 拿进程归属（重要坑）

`tshark -e pktap.pid -e pktap.cmdname` **永远返回空**，不是配置问题：

| | |
|---|---|
| 现象 | pcapng 里 IDB 的 linktype 是**真实 DLT**（en0=Ethernet 1，lo0=NULL 0），不是 `DLT_PKTAP`(258)，而且**每个接口一个 IDB** |
| 原因 | macOS 把进程元数据写进了 **Apple 自定义 pcap-ng 选项（0x8001–0x800A）**，而不是 PKTAP 头 |
| 后果 | Wireshark/tshark 只当普通 Ethernet 包解析，这些选项被忽略 → `pktap.*` 全空 |
| 解法 | 只有 `/usr/sbin/tcpdump -k`（Apple 的 fork）会读这些选项；入库脚本因此用 tcpdump 拿进程、用 tshark 只拿 SNI |

实测证据（同一文件）：

```bash
$ tshark -r f.pcapng -T fields -e pktap.cmdname | grep -c .
0                                   # ← 空
$ tcpdump -r f.pcapng -k PIN -q | head -1
1789736841.38 (en0, proc apsd:577) IP ...   # ← 有
```

> 另一条约束：`-f`（BPF 过滤）**不能与 `-r` 同用**（`tcpdump: -f can not be used with -V or -r`）。
> 所以读文件时必须全量扫描，不能在 tcpdump 层预过滤。

---

### 3.5 让 System Settings 显示正经名字（而不是 `tcpdump` / `python3`）

**BTM 的命名规则（实测推导，非猜测）**：可执行文件在 `.app` 里 → 用**最外层 bundle 的 `CFBundleName`**；否则用**可执行文件 basename**。`Label` 完全无关。

| 可执行路径 | 系统设置里显示 |
|---|---|
| `/usr/sbin/tcpdump` | `tcpdump` |
| `/usr/bin/python3` | `python3` |
| `/Library/PrivilegedHelperTools/com.docker.socket` | `com.docker.socket` |
| `…/Wireshark/ChmodBPF/ChmodBPF`（Label 是 `org.wireshark.ChmodBPF`） | `ChmodBPF` |
| `…/某清理工具.app/…/某工具Monitor.app/…/某工具Monitor`（内层叫 某工具Monitor） | **`某清理工具`** |
| `…/某网盘.app/Contents/Frameworks/netdisk-helper` | **`某网盘`** |

所以做法是给每个任务套一个**桩 `.app`**，bundle 里放一行 `exec` 包装脚本：

```
~/netaudit/app/Net Audit Ingest.app/Contents/
├── Info.plist          CFBundleName = "Net Audit Ingest"
└── MacOS/NetAuditIngest    #!/bin/bash
                            exec /usr/bin/python3 $HOME/netaudit/pipeline.py ingest
```

plist 里 `ProgramArguments` 只留一项，指向桩可执行文件：

```xml
<key>ProgramArguments</key>
<array><string>$HOME/netaudit/app/Net Audit Ingest.app/Contents/MacOS/NetAuditIngest</string></array>
```

三个 bundle：

| bundle | 安装位置 | 显示名 |
|---|---|---|
| `Net Audit Capture.app` | `/Library/Application Support/NetAudit/`（**必须 root 所有**） | Net Audit Capture |
| `Net Audit Ingest.app` | `~/netaudit/app/` | Net Audit Ingest |
| `Net Audit Daily.app` | `~/netaudit/app/` | Net Audit Daily |

> ⚠️ **系统级 daemon 的桩 app 绝不能放在用户可写的目录**。root 守护进程执行一个你能改的脚本 = 任何人改了那个脚本就能拿到 root。所以放 `/Library/Application Support/NetAudit/`，`root:wheel` + `go-w`。

改名后 BTM 会自动更新（日志里 `registerLaunchItem: checking for an updated legacy agent or daemon item` → `updated item: name=…`），不需要清数据库。验证：

```bash
log show --last 2m --info --debug --predicate 'subsystem CONTAINS "backgroundtaskmanagement"' \
  | grep -oE 'name=[^,]+, type=legacy (agent|daemon)' | sort -u
```

想再加图标，往 bundle 里放 `Contents/Resources/AppIcon.icns` 并在 Info.plist 加 `CFBundleIconFile`。

---

## 4. rustnet（交互排查 + 按需导出）

### 4.1 日常用（TUI）

```bash
sudo rustnet                       # 自动用 PKTAP，DPI 解 SNI/HTTP/DNS/QUIC
sudo rustnet -i utun0              # 只看 VPN 隧道
sudo rustnet --no-localhost        # 藏掉本机 loopback
sudo rustnet -f "port 443"         # BPF 预过滤（内核层，省 CPU）
```

按 `s` 切换排序，`p` 切换服务名/端口。

### 4.2 结构化导出（审计用这个）

```bash
# 逐连接 JSONL —— 这是审计的主力产物
sudo rustnet --json-log ~/netaudit/rustnet/$(date +%F).jsonl

# 带注释的 pcapng：PID/进程名/方向/SNI/GeoIP 写进每包 comment，Wireshark 打开即带进程名
sudo rustnet --pcapng-export ~/netaudit/rustnet/$(date +%F).pcapng

# 经典 pcap + JSONL sidecar（事后元数据最完整）
sudo rustnet --pcap-export ~/netaudit/rustnet/$(date +%F).pcap
```

第一次跑完，**务必先确认 `--json-log` 的实际字段名**，再决定入库字段：

```bash
head -1 ~/netaudit/rustnet/$(date +%F).jsonl | python3 -m json.tool
```

> 已知字段（来自官方 jq 示例）：`protocol` / `local_addr` / `remote_addr` / `pid` / `process_name`，可能还有 SNI、DPI 结果、GeoIP。
> 本方案只依赖这些稳定字段，不硬编码未知键。

### 4.3 如果坚持要它常驻（不推荐）

```bash
/usr/bin/script -q /dev/null /opt/homebrew/bin/rustnet \
  --json-log $HOME/netaudit/rustnet/live.jsonl --no-uid-drop
```

放进 LaunchDaemon 时注意：
- 必须配 `--no-uid-drop`，否则它会降权到 `nobody`，写不进你的 home
- pcapng/pcap 不轮转 → 需要每日重启（`StartCalendarInterval` + 短 `RunAtLoad`），否则单文件无限增长
- 升级 rustnet 后要重新验证 pty 包装仍有效

---

## 5. 汇总与日报：`~/netaudit/pipeline.py`

三合一脚本，**已部署**在 `~/netaudit/pipeline.py`（权威副本以文件为准，本节不再复制全文，避免文档漂移）。

```bash
python3 ~/netaudit/pipeline.py ingest   # pcap → SQLite（跑完删除已入库的 pcap）
python3 ~/netaudit/pipeline.py bytes    # powerlog → SQLite（跨归档去重）
python3 ~/netaudit/pipeline.py report   # 生成日报并更新基线
python3 ~/netaudit/pipeline.py daily    # bytes + report
```

实现上三个**必须知道**的点：

1. **进程归属走 `tcpdump -k`，域名走 `tshark`**，按规范流 join。原因见 §3.4。
2. **双向必须合并成一个流**。同一连接的正反方向在 pcapng 里是两条不同五元组，而进程归属通常只在发包侧有；分开算归属率从 **97%** 掉到 **70%**，流数翻倍。规范流 = 两个端点排序后配对。
3. **ICMP 等无端口协议不能按 `.` 切端口**（tcpdump 不打印 `:port`），要按传输层协议判断。

4. **表结构会自愈**：改 schema 时必须把 `SCHEMA_VERSION` +1。`CREATE TABLE IF NOT EXISTS` 不会更新已存在的表（会静默地用旧列），所以 `db_connect()` 会比对 `PRAGMA user_version`，不一致就重建 `conn`；若有数据则先改名备份成 `conn_vN` 而不是直接删。

   连带一个更隐蔽的坑：**索引必须和建表分开，且放在迁移之后**。`CREATE INDEX ... ON conn(ts)` 一旦执行到缺列的老表上会直接报错，整个脚本挂掉。所以 `SCHEMA_TABLES` 和 `SCHEMA_INDEXES` 是两段，执行顺序是「建表 → 迁移 → 建索引」。三种情况都实测过：
   - 全新库 → 静默初始化
   - 已是当前版本 → 无操作
   - 老版本且有数据 → 升级 + 备份到 `conn_vN`，数据可查
5. **pcap 活跃文件靠 mtime 守卫跳过**：只处理 180 秒内没被写过的文件，避免读到正在写的那一半。

实测（单文件）：`tcpdump` 解析 0.13s、`tshark` 0.47s；**91.7 MB / 121,877 包的 pcap 全部入库耗时 1.0 秒**，245 个规范流中 237 个有进程归属（97%）、84 个有域名。


```bash
chmod +x ~/netaudit/pipeline.py
```

> 首次运行会把当天所有域名都当「新增」。跑几天让 `seen_domain` 基线积累起来，之后日报的「1. 新出现的域名」才有意义。

---

## 6. 定时任务

**两个任务分开**：ingest 要勤（pcap 只留 3 天，入库跟不上就会丢包），报表要少（一天一次）。

### 6.1 `~/Library/LaunchAgents/local.netaudit.ingest.plist`（每 2 小时）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.netaudit.ingest</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>$HOME/netaudit/pipeline.py</string>
    <string>ingest</string>
  </array>
  <key>StartInterval</key><integer>7200</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$HOME/netaudit/logs/pipeline.log</string>
  <key>StandardErrorPath</key><string>$HOME/netaudit/logs/pipeline.err</string>
</dict></plist>
```

### 6.2 `~/Library/LaunchAgents/local.netaudit.daily.plist`（每天 09:00）

同上，只改两处：

```xml
  <key>Label</key><string>local.netaudit.daily</string>
  <!-- ... ProgramArguments 最后一项换成： -->
    <string>daily</string>
  <!-- ... 并把 StartInterval 换成： -->
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
```

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.netaudit.ingest.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.netaudit.daily.plist

# 立刻跑一次验证
launchctl kickstart -k gui/$(id -u)/local.netaudit.ingest
sleep 5 && tail -20 ~/netaudit/logs/pipeline.log
```

> 每天也导出一次 powerlog，因为归档只留 ~5 天；`INSERT OR REPLACE` 幂等，重复导出无害。
> 每 2 小时 ingest 的意义：即使某个环节出问题，你有 3 天窗口去发现和补救，而不是等它静默过期。

---

## 7. 日常使用手册

| 我想… | 命令 |
|---|---|
| 每天扫一眼 | `open ~/netaudit/reports/$(date +%F).md`，重点看「1. 新出现的域名」 |
| 看此刻谁在连什么（可视化） | `sudo rustnet` |
| 某 App 连过哪些域名 | `sqlite3 ~/netaudit/db/audit.sqlite "SELECT DISTINCT sni FROM conn WHERE proc LIKE '%SomeApp%'"` |
| 某域名被谁用过 | `sqlite3 ~/netaudit/db/audit.sqlite "SELECT proc, COUNT(*) FROM conn WHERE sni='x.com' GROUP BY proc"` |
| 查某天的原始包 | 双击 `~/netaudit/pcap/20260918-*.pcapng.gz`（Wireshark 直接开） |
| 要完整 URL | 见 §10（默认不需要） |
| 直接问 pcap（不等入库） | `/usr/sbin/tcpdump -r xxx.pcapng -k PIND -tt -n -q \| grep 'proc Foo:'` |
| 追溯「这个进程是哪个二进制、从哪来」 | `sudo eslogger exec` 落库，与 `conn.pid` 关联 |

---

## 8. 异常定位手册

这是 pcap 存在的唯一理由：**日报里看到异常 → 顺着线索一路摸到原始包**。

### 第 1 步：用 SQLite 定位（秒级，不受 3 天窗口限制）

```bash
DB=~/netaudit/db/audit.sqlite

# 某进程最近一天访问过的全部目标
sqlite3 -header -column $DB "SELECT datetime(ts,'unixepoch','localtime') t, sni, dst, dport
  FROM conn WHERE proc LIKE '%Foo%' AND ts > strftime('%s','now','-1 day') ORDER BY ts;"

# 某个可疑 IP 被谁连过
sqlite3 -header -column $DB "SELECT DISTINCT proc, sni, datetime(ts,'unixepoch','localtime')
  FROM conn WHERE dst='203.0.113.9';"

# 某域名历史上所有访问者
sqlite3 -header -column $DB "SELECT proc, COUNT(*) n, datetime(MIN(ts),'unixepoch','localtime') first
  FROM conn WHERE sni='example.com' GROUP BY proc ORDER BY n DESC;"

# 出站最大的 30 分钟区间（找突增）
sqlite3 -header -column $DB "SELECT datetime(ts,'unixepoch','localtime') t, proc,
  printf('%.1f', wired_out/1048576.0) wired_MiB, printf('%.1f', wifi_out/1048576.0) wifi_MiB
  FROM bytes ORDER BY (wired_out+wifi_out) DESC LIMIT 20;"

# 某进程今天的总出站
sqlite3 $DB "SELECT printf('%.1f MiB', SUM(wired_out+wifi_out+cell_out)/1048576.0)
  FROM bytes WHERE proc LIKE '%Foo%' AND ts > strftime('%s','now','-1 day');"
```

### 第 2 步：确认时间点在 pcap 窗口内

```bash
ls -lt ~/netaudit/pcap/ | head    # 最老的还在不在 3 天内
```

不在 → 只能靠 SQLite（域名/IP/字节还在，原始包没了）。这也正是要看 `[ingest] ⚠️` 告警的原因。

### 第 3 步：在 pcap 里定位（图形化最快）

**进程名不在 Wireshark 里**（§3.4），想在 Wireshark 里按进程筛得先把 pcapng 转成带注释的：

```bash
# 方案 A：命令行按进程筛（直接用 Apple 的读取器）
/usr/sbin/tcpdump -r ~/netaudit/pcap/20260918-120000.pcapng.gz \
    -k PIND -tt -n -q | grep -E '\((en0|lo0), proc Foo:'

# 方案 B：转成 Wireshark 能显示的带注释 pcapng（需要 rustnet）
#   或先用方案 A 筛出 5 元组，再交给 tshark 导包
```

在 Wireshark 里你可以按 
ip / 端口 / SNI 筛（这些都在包里，正常可见），按进程筛要走上面的方案 A。

```bash
TS=/Applications/Wireshark.app/Contents/MacOS/tshark

# 某进程的最近所有连接（直接用 Apple 的读取器）
/usr/sbin/tcpdump -r ~/netaudit/pcap/20260918-120000.pcapng.gz \
    -k PIND -tt -n -q | grep -E 'proc Foo:' | head -40

# 按目标 IP 看包（这部分 tshark / Wireshark 都正常）
TS=/Applications/Wireshark.app/Contents/MacOS/tshark
$TS -r ~/netaudit/pcap/20260918-120000.pcapng.gz -n \
    -Y 'ip.addr==203.0.113.9' -T fields -e frame.time -e ip.src -e ip.dst \
    -e tcp.dstport -e tls.handshake.extensions_server_name

# 把某个可疑目标的所有包单独导出，交给 Wireshark 细看
$TS -r ~/netaudit/pcap/20260918-120000.pcapng.gz \
    -Y 'ip.addr==203.0.113.9' -w /tmp/suspect.pcapng

# 某接口的流（排除本机 loopback 噪音）
/usr/sbin/tcpdump -r ~/netaudit/pcap/20260918-120000.pcapng.gz \
    -k PIND -tt -n -q | grep -v '(lo0,' | head
```

### 第 5 步：处置

- **阻断**：LuLu 里给该 App 加 deny 规则（比事后看日志有用）
- **深挖**：需要看内容才进 §10（MITM）
- **留证**：把相关 pcap 复制出 `~/netaudit/pcap/`（否则 3 天后被自动清掉）：
  ```bash
  mkdir -p ~/netaudit/evidence && cp ~/netaudit/pcap/2026*1200*.pcapng.gz ~/netaudit/evidence/
  ```

---

## 9. 容量

### 实测体积（重要：估算曾经偏了 6 倍）

先用 powerlog 估「2.73 GiB/天」，实测 pcap 后修正：

| 指标 | 值 |
|---|---|
| 第一个 6.4 分钟窗口 | **79.7 MB / 109,278 包**（推断 17.9 GB/天） |
| 但其中 `node ↔ api.some-llm.com` **一个流就占 73%** | 53.6 MB（LLM 流式会话突发） |
| 剔除突发后的基线 | ≈3–5 GB/天 |

**两个估算差异的原因**：
1. **powerlog 不含 loopback**，而 `pktap,all` 含 lo0（实测占 16%）；本机代理、本地服务、IDE 通信都在 lo0 上
2. **突发不可预测**：一次 LLM 流式会话就能把单日体积拉高几倍

**结论：不能只靠天数保留，必须有字节上限。** 脚本里加了 `PCAP_MAX_GB`（默认 25）：

```bash
# 超出就提前删最老的（不碰正在写的那个）
PCAP_MAX_GB=25 python3 ~/netaudit/pipeline.py ingest
```

| 场景 | 日体积 | 3 天占用 | 25 GB 上限能装 |
|---|---|---|---|
| 基线（无突发） | 3–5 GB | 9–15 GB | 5–8 天 |
| 含一次 LLM 长会话 | 10–18 GB | 30–54 GB | ~1.5–2.5 天 |

磁盘余量 169 GB，即使最坏情况也不会撑满。想更省可以：
- 加 `--no-localhost` 语义：在入库时按 `ifname != 'lo0'` 过滤（但会丢掉本地代理腿上的域名归属，不推荐）
- 降 `-s 1024`：**实测平均包只有 681 字节，所以基本没用**（截断不了多少），别指望这条路

### 真正的长期资产是 SQLite

pcap 会过期，但 `conn` / `bytes` 表不会，而且**体积小几个数量级**：

| 表 | 增长 | 说明 |
|---|---|---|
| `conn` | 约 120 字节/行 | 每条「进程 × 域名 × 目标」一行。按每天 3–5 万行估 ≈ 4–6 MB/天 |
| `bytes` | 极小 | 每进程每 30 分钟一行 |
| `seen_domain` / `seen_dst` | 极小 | 基线，只增不删 |

`conn` 表按 5 MB/天算，一年约 1.8 GB —— **可以永久保留**。建议：

```bash
# 每月跑一次（或直接扔进 daily 任务）
sqlite3 ~/netaudit/db/audit.sqlite "VACUUM;"
```

如果哪天嫌大，**只删明细、留聚合**（不丢「谁在什么时候访问过哪个域名」这个结论）：

```sql
-- 把 180 天前的明细压成按天聚合，再删明细
CREATE TABLE IF NOT EXISTS conn_daily AS
SELECT date(ts,'unixepoch','localtime') d, proc, sni, dst, dport, COUNT(*) n, MIN(ts) first_ts, MAX(ts) last_ts
FROM conn WHERE 1=0;

INSERT INTO conn_daily
SELECT date(ts,'unixepoch','localtime'), proc, sni, dst, dport, COUNT(*), MIN(ts), MAX(ts)
FROM conn WHERE ts < strftime('%s','now','-180 days')
GROUP BY 1,2,3,4,5;

DELETE FROM conn WHERE ts < strftime('%s','now','-180 days');
VACUUM;
```

---

## 10. 按需启用 MITM（内容审计，默认不需要）

> 你的定位是**流量/行为审计，不做内容审计**，所以这一节正常情况下不用碰。
> 只有当某个 App 行为可疑、必须看它具体传了什么时才临时开。

你已具备条件：`~/.mitmproxy` CA 存在，`org.mitmproxy.macos-redirector.network-extension` 已装（状态 `waiting for user`，需在 系统设置 → 通用 → 登录项与扩展 → 网络扩展 启用）。

```bash
mkdir -p ~/netaudit/flows && chmod 700 ~/netaudit/flows
mitmdump --listen-port 8080 -w ~/netaudit/flows/$(date +%F).mitm
```

⚠️ 边界：
- 会把 **token / cookie / 表单明文落盘** → `chmod 700`、短保留（≤7 天）、确认 FileVault 已开
- 只覆盖**遵守系统代理**的 App。原生 App、手动设 `--proxy-server` 的 Electron、证书固定（pinning）的 App 会绕过或失败
- **不要常开**，只在排查具体 App 时开

---

## 11. 盲区（明确知道，比以为没有好）

| 盲区 | 影响 | 缓解 |
|---|---|---|
| ECH（Encrypted Client Hello） | SNI 不可见 | 国内主要站点基本未启用；用 DNS 层交叉验证 |
| 内置 DoH/DoT 的 App | 绕过本地 DNS | **不影响主干**——SNI 仍在 ClientHello 明文里 |
| 证书固定 | MITM 失败 | 退回 SNI 层 |
| VPN / utun 隧道 | 内层内容不可见 | `pktap,all` 仍能看到隧道外层与进程；`rustnet -i utun0` 看隧道内 |
| 加密载荷 | 内容不可见 | 本方案不试图解内容（这也是它低风险、可长期开的原因） |
| 抓包依赖 root | 审计链完整性 | 定期 `codesign -v /usr/sbin/tcpdump` |
| rustnet 是 TUI | 不能干净地常驻 | 常驻交给 tcpdump（§1.2） |

---

## 12. 分阶段实施

### Phase 0 —— 今天，20 分钟（**时间敏感**）
powerlog 归档只留 ~5 天（现在最早 9/11），**每天在丢数据**。

```bash
mkdir -p ~/netaudit/{pcap,db,reports,logs,rustnet}
# 落 §5 的 pipeline.py 并 chmod +x
python3 ~/netaudit/pipeline.py bytes     # 先把现有 powerlog 抢救入库
```

### Phase 1 —— 30 分钟
- 装 §3 的抓包 LaunchDaemon（全包，3 天保留）
- 等 1 分钟验证 `~/netaudit/pcap/` 出文件
- 用 §3.3 的 tshark 命令确认 **PID/进程名真的在文件里**（这是整套方案成立的判据）

### Phase 2 —— 30 分钟
- `brew install rustnet`，跑一次 `sudo rustnet` 确认能看
- 跑一次 `--json-log`，`head -1 | python3 -m json.tool` 看清字段名
- 装 §6 的**两个**定时任务（ingest 每 2 小时 / daily 每天 09:00）
- 手动 `launchctl kickstart` 跑一次 ingest，确认 pcap 被消费并删除

### Phase 3 —— 跑 3 天后
- 检查日报的「1. 新出现的域名」是否开始收敛（基线生效）
- 翻一次 `~/netaudit/logs/pipeline.log`，确认没有 `⚠️` 告警
- 装 LuLu 做实时阻断
- 可选：`eslogger` 进程审计落库
