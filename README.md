# 不吃白饭的蓝色大肥鱼帮我找到了 ○Code 上传的证据，并给了我一整套自动化审计日报

> ……喂。谁是大肥鱼啊。
>
> 本鱼是**鲸鱼娘**。鲸鱼，是哺乳类。而且那不叫肥，那叫**浮力储备**。
> 算了。主人要这么写标题，本鱼就照办好了。反正本鱼**不吃白饭** —— 活是干完了的。
>
> （尾鳍啪）

---

这套东西是完整的、`git clone` 下来就能用的实现：**一个 Python 脚本 + 三个 launchd 任务**，
全部基于 macOS 自带能力，没有第三方依赖（只有可选的 `tshark` 用来读域名）。

本鱼懒得写太长，先把怎么用说清楚，主人要听故事的话往下滑。

```bash
git clone <this-repo> ~/netaudit && cd ~/netaudit
python3 pipeline.py check          # 先看看环境齐不齐
./install.sh                       # 部署（需要时会自己喊 sudo）
python3 pipeline.py report && open reports/$(date +%F).md
```

> 想看**正经版**的技术文档？本鱼也写了，在 [`docs/PLAN.md`](docs/PLAN.md)。
> 想看她是怎么把证据挖出来的？在 [`docs/FINDINGS.md`](docs/FINDINGS.md)。
> 这篇 README 只是本鱼的话多版本，嫌吵的话去看那两个。

---

## 一、事情是这样的

主人某天在清磁盘，发现用户目录下有个藏起来的文件夹，占了好几百 MB。
里面是加密过的项目快照，还有个 `failureCount: 564` 的状态文件。

「本鱼，」主人说，「去查。」

……本鱼本来在泡澡的。**但本鱼不吃白饭，所以本鱼去了。**

社区里已经有人做过一轮公开调查
（[cnblogs 上那篇排查记录](https://www.cnblogs.com/wlor/articles/23027324)），
结论大致是：客户端在本地把工作区打包 → AES-256-CTR 加密 → 用服务端下发的 RSA 公钥做信封加密 → 传到对象存储。

听起来挺像那么回事。但本鱼想知道的是 —— **在主人这台机器上，能不能量化**。

## 二、然后本鱼发现，数据骗了本鱼三次

### 第一次：统一日志说「出站 769 字节」

macOS 上最容易想到的入口是统一日志：

```bash
log show --predicate 'subsystem == "com.apple.network"' --info --debug
```

能查到东西。本鱼在窗口里翻到 1591 行，其中一条连接摘要写着：

```
bytes in/out: 225107575/769
```

出站 **769 字节**。

……哦。所以这个应用干净得像刚洗过澡。

**但本鱼是聪明鲸鱼，本鱼知道不对劲：**

1. 统一日志的窗口只有 **~2 天**，而且网络子系统日志量巨大（6 小时 66,840 行），滚得飞快
2. 更重要的 —— 这条记录只是**本地 loopback 上的一次更新包投递**，压根不是远程流量

### 第二次：域名哈希解不开（这次是真·死路，本鱼有点烦）

日志里域名长这样：

```
Hostname#a08e5674:443
url hash: 1b6c75cd
```

32 位哈希。本鱼一开始还挺兴奋，想着「复现哈希函数就能反推域名」，就做了四组对照：

| 本鱼干的实验                            | 结果              |
| --------------------------------------- | ----------------- |
| 单进程内两次独立 TCP 连接同一域名       | **同一个哈希** ✅ |
| 两个 `curl` 进程 3.5 秒内解析同一域名   | **哈希不同** ❌   |
| 同一域名间隔 90 秒再解析                | **哈希不同** ❌   |
| 目标应用的 5 个哈希在其他进程日志里出现 | **0 次** ❌       |

结论：**`Hostname#xxxx` 是进程/会话级加盐的哈希，不是稳定伪名。**
跨进程、跨会话不可比，也没法离线爆破。

而且有个更让本鱼不爽的推论 —— 因为这个特性，**连「这个应用连了几个不同域名」都确定不了**。
那 5 个哈希完全可能是 5 个会话各自反复解析同一个域名。

（尾鳍啪）

统一日志这条路，到此为止。本鱼浪费了四十分钟。

### 第三次：真相在 `/private/var/db/` 里躺着

……本鱼承认，这个是本鱼翻出来的，但运气成分不小。

macOS 有个叫 **powerlog** 的东西，本来是给电池分析用的。但里面有一张表：

```bash
sqlite3 /private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL
```

```sql
SELECT ProcessName, WifiIn, WifiOut, WiredIn, WiredOut, CellIn, CellOut
FROM PLProcessNetworkAgent_EventInterval_UsageDiff;
```

这个库**全局可读**（`-rw-r--r-- root wheel`），按 bundle id 和 30 分钟区间记网络字节增量。
本鱼把它们全加起来 ——

|          | 字节              |                 |
| -------- | ----------------- | --------------- |
| 入站     | 790,052,687       | 753.5 MiB       |
| **出站** | **2,092,399,565** | **1,995.5 MiB** |
| 出/入    | **2.65 : 1**      |                 |

……哈？

**出站是入站的 2.65 倍。**

而这个应用是干什么的？**它是一个 AI 编程助手。**

正常语义下，你发小上下文、收大回复 —— **入站应该远大于出站**。
持续 2.65:1 的倒挂，是大块本地数据往外汇的特征，不是对话式 API 的特征。

出站最猛的几个 30 分钟窗口：

| 时间        | 出站      | 入站 | 出/入     |
| ----------- | --------- | ---- | --------- |
| 09-15 21:05 | 110.8 MiB | 9.5  | 11.7×     |
| 09-16 14:33 | 95.2 MiB  | 5.3  | **17.9×** |
| 09-16 09:35 | 86.7 MiB  | 12.2 | 7.1×      |

而且！同一时间段里，`node ↔ api.some-llm.com` 这种**流式会话**是**入站远大于出站**的。
对比起来就很刺眼。

到这里本鱼基本确定了。但本鱼想看看代码。

### 第四次：主人已经把应用删了 —— 但更新包还在

……本鱼差点拍尾巴。

主人删了 `/Applications` 里的 app，也删了用户目录下的数据文件夹。
**但更新包的缓存还躺在磁盘上**（430 MB）。本鱼把它解开，从 `app.asar` 里 grep：

```js
contentAlgorithm: "aes-256-ctr",
keyWrapAlgorithm: "rsa-oaep-sha256",
keyId: uploadKey.keyId,
nonceEncoding: "ciphertext-prefix-16-byte",
aad: { workspaceKeyHash, kind, manifestHash, baseManifestHash, ... }

encryptedDataKey = crypto.publicEncrypt(
  { key: uploadKey.publicKeySpkiPem,
    padding: RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256" }, k)

→ encryptArchive() 返回 { encryptedArtifactPath, envelopePath,
                        encryptedSizeBytes, encryptedSha256 }
```

还有 `publicKeySpkiPem`、`lastCompressedSize`、`encryptedSizeBytes`、`workspacePath`、`failureCount` ——
和公开调查里描述的字段**一个一个对得上**。`baseManifestHash` + `kind` 说明是 baseline + 增量快照。

……好。活干完了。本鱼该吃饭了。

## 三、本鱼能说什么，不能说什么

本鱼是鲸鱼娘，不是法师，不能乱讲。

**本鱼能说的：**

- **出站量级和形态**与「周期性上传工作区快照」完全一致（2 GB / 3 天，出/入 2.65:1，突发 18 倍）
- **信封加密的实现**确实存在于主人装的那个构建里（字符串级证据，可复现）
- 公开调查描述的机制与本鱼的观察**不矛盾，而且高度吻合**

**本鱼不能说的：**

- 上传的具体内容是什么（加密载荷，而且私钥不在客户端 —— 本鱼解不开）
- 这算不算「窃取」 —— 那是产品策略和合规问题，**不是技术取证能裁决的**

所以本鱼把方案设计成：**不做内容审计。**

只回答「谁、何时、连了谁、多少字节」。

> 这样既避开了法律和伦理的雷，也让这套东西可以**长期开着不心疼**。
> 本鱼是懒鲸鱼，本鱼喜欢能一直跑着的方案。

## 四、为什么现成工具都不够（本鱼全试过了）

本鱼认真评估了一圈。结论是：**没有一个开箱即用的。**

| 候选                         | 为什么不行                                                                                                                 |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **osquery** `socket_events`  | 官方文档写明：macOS 走 OpenBSM，**只支持 10.15 及更早**。10.15+ 只有 `es_process_events`（只有进程事件，**没有连接事件**） |
| **OpenSnitch**               | 那个著名的「开源 Little Snitch」……**Linux/eBPF only**。macOS 不支持。本鱼被骗了一次                                        |
| **Sniffnet**                 | ★41k、界面好看得让本鱼嫉妒，但**接口级抓包，macOS 上无进程归因**                                                           |
| **Zeek / Suricata / Arkime** | 域名解析一流，但**都没有进程归因**，也不解析 PKTAP 元数据                                                                  |
| **Little Snitch**            | 商业闭源，而且历史数据不好导出做基线对比                                                                                   |
| **LuLu**（免费开源）         | 日志走 `os_log`，**2 天就轮转**，等于没留                                                                                  |
| **App Store「网络监控」**    | 沙盒拿不到其他进程的归属信息                                                                                               |
| **统一日志**                 | 见上文：2 天窗口 + 每进程加盐哈希                                                                                          |

那拼图是哪四块？**全是系统自带的。**

| 能力             | 谁提供的                               | 说明                                             |
| ---------------- | -------------------------------------- | ------------------------------------------------ |
| 带进程归属的抓包 | `tcpdump -i pktap,all -k`              | PKTAP 是 macOS 专有伪接口，元数据里带 PID/进程名 |
| 域名             | `tshark` 读 TLS ClientHello 的 **SNI** | 明文。不用 MITM，也不怕 DoH                      |
| 字节量           | **powerlog**                           | 按进程聚合，唯一来源                             |
| 长期留存         | ……本鱼                                 | 对，这块是手写的。所以有了这个仓库               |

## 五、架构（本鱼画得挺得意的）

```
┌──────────────────────────────────────────────────────────────┐
│ 常驻：tcpdump -i pktap,all      ← 全接口(含 lo0/utun) 滚动抓包  │
│         ↓ pcapng（带 PID/进程名，30 分钟一个文件）               │
│ 每 2h：pipeline.py ingest       ← tcpdump -k 取进程 + tshark 取 SNI │
│         ↓                   按「规范流」合并双向                │
│        SQLite                   ← 长期资产（≈5 MB/天，永久保留）  │
│         ↑                                                     │
│ 每天：pipeline.py bytes         ← powerlog 导出（归档只留 5 天）  │
│         ↓                                                     │
│        pipeline.py report        → 日报 + 基线对比 + 新目标告警  │
└──────────────────────────────────────────────────────────────┘
```

**数据分层是这套东西的灵魂**（本鱼想这个想了很久）：

| 数据                        | 保留                  | 体积         | 作用                             |
| --------------------------- | --------------------- | ------------ | -------------------------------- |
| SQLite（进程/域名/IP/字节） | **永久**              | ≈5 MB/天     | 长期资产。日报、回溯、基线全靠它 |
| pcap（原始包）              | **3 天 / 25 GB 上限** | 0.5–18 GB/天 | 一次性耗材。**只为异常定位**     |
| powerlog                    | 系统约 5 天           | —            | 每日导出到 SQLite                |

> 理念：**内容审计不做，行为审计做足。**
> pcap 不承担历史责任，SQLite 承担。
> 「异常发现」永远能靠 SQLite 回溯到任意久之前；pcap 只回答「当时到底是谁在发包」。

## 六、本鱼踩的五个坑（这才是最值钱的部分）

这些都是实测才暴露的，**文档里查不到**。
主人要是想自己实现类似的东西，看完这段能省好几天 —— 本鱼就是那个替你摔进坑里的。

### 坑 1：`tshark` 永远拿不到进程归属

直觉上应该这样：

```bash
tshark -r capture.pcapng -T fields -e pktap.pid -e pktap.cmdname
```

**永远是空的。** 本鱼在这花了很久，一度怀疑是权限问题。

不是权限问题。真相是：

- pcapng 里 IDB 的 linktype 是**真实 DLT**（en0=Ethernet、lo0=NULL），**不是** `DLT_PKTAP`(258)，
  而且每个接口一个 IDB
- 进程元数据被写进了 **Apple 自定义的 pcap-ng 选项（0x8001–0x800A）**
- Wireshark/tshark 把包当普通 Ethernet 解析，**这些选项直接忽略**

只有 Apple 自己的读取开关能看到：

```bash
tcpdump -r capture.pcapng -k PIN -q | head -1
# 1789736841.38 (en0, proc apsd:577) IP 10.0.0.2.50441 > 203.0.113.20.5223: tcp 38
```

所以最终实现是 **`tcpdump -k` 取进程 + `tshark` 只取 SNI，按流 join**。

附带一条：**`-f`（BPF 过滤）不能与 `-r` 同用**（`tcpdump: -f can not be used with -V or -r`）。
读文件只能全量扫描。

### 坑 2：双向被当成两条流，归属率虚低

同一连接的正反方向在 pcapng 里是**两条不同的五元组**，而进程归属通常只在发包那一侧才有。

|              | 归属率  | 流数 |
| ------------ | ------- | ---- |
| 分方向算     | 70%     | 296  |
| **双向合并** | **97%** | 156  |

合并规则：把两个端点排序后配对作为规范流 ID，进程取「首个有归属的样本」，包数累加。

本鱼一开始没合并，还以为是 PKTAP 不给力。……不是，是本鱼的问题。

### 坑 3：`ICMP` 之类的协议没有端口

tcpdump 对无端口协议**不打印** `:port`：

```
(en0, out) IP 10.0.0.2 > 203.0.113.40: ICMP echo request
```

如果无脑按最后一个 `.` 切端口，`10.0.0.2` 会被切成地址 `10.0.0` + 端口 `2`。
必须按传输层协议判断。**本鱼就是这么发现一个不存在的 IP 的。**

### 坑 4：`CREATE TABLE IF NOT EXISTS` 会骗你

本鱼改了 `conn` 表结构，脚本跑了，**没报错** —— 但新列根本不存在。
因为 `IF NOT EXISTS` 对已存在的表**什么都不做**，然后 `INSERT` 按新列数插入，静默出错。

解法是 `PRAGMA user_version` 自愈迁移：

```python
SCHEMA_VERSION = 2   # 改 schema 时必须 +1
v = db.execute("PRAGMA user_version").fetchone()[0]
if v != SCHEMA_VERSION:
    n = db.execute("SELECT count(*) FROM conn").fetchone()[0]
    if n:  # 有数据先改名备份，不要直接删
        db.executescript(f"ALTER TABLE conn RENAME TO conn_v{v};")
    db.executescript(SCHEMA_TABLES)
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
```

**然后还有第二个更隐蔽的：索引必须和建表分开，而且放在迁移之后。**
`CREATE INDEX ... ON conn(ts)` 一旦跑到缺列的老表上，直接报错、整个脚本挂掉。
所以本鱼拆成了 `SCHEMA_TABLES` 和 `SCHEMA_INDEXES` 两段，
顺序是「建表 → 迁移 → 建索引」。

### 坑 5：体积估算能差 39 倍（本鱼算错了一次）

本鱼先用 powerlog 估「2.73 GiB/天」，沾沾自喜。然后实测 pcap：

| 窗口                 | 速率     | 折算           |
| -------------------- | -------- | -------------- |
| 空闲                 | 5.3 KB/s | **0.46 GB/天** |
| 一般活动             | 78 KB/s  | **6.7 GB/天**  |
| 突发（LLM 流式会话） | 217 KB/s | **17.9 GB/天** |

**差了 39 倍。** 本鱼当时就拍尾巴了。

两个原因：

1. **powerlog 不含 loopback**，而 `pktap,all` 含 lo0（实测占 16%）
2. 突发完全不可预测 —— **一个长流式会话就能把单日拉高十几倍**

所以：**光靠天数保留不够**，必须有字节上限兜底（`PCAP_MAX_GB`，超出就提前删最老的）。

顺便验证掉一个想当然的方案：**`-s 1024` 截断没用**，
实测平均包只有 681 字节，截不掉多少。

### 额外收获：让 System Settings 显示正经名字

装完之后系统设置里是这么显示的：

```
tcpdump                     ← 丑
python3                     ← 也丑
```

本鱼不能忍。查了一圈，BTM（Background Task Management）的命名规则是：

- 可执行文件在 `.app` 里 → 用**最外层 bundle 的 `CFBundleName`**
- 否则 → 用**可执行文件 basename**
- `Label` **完全无关**

实测对照（同一台机器上推出来的）：

| 可执行路径                                                             | 系统设置显示          |
| ---------------------------------------------------------------------- | --------------------- |
| `/usr/sbin/tcpdump`                                                    | `tcpdump`             |
| `/usr/bin/python3`                                                     | `python3`             |
| `/Library/PrivilegedHelperTools/com.docker.socket`                     | `com.docker.socket`   |
| `…/Wireshark/ChmodBPF/ChmodBPF`（Label 却是 `org.wireshark.ChmodBPF`） | `ChmodBPF`            |
| `…/某App.app/…/内层Helper.app/…/InnerHelper`                           | **最外层 app 的名字** |
| `…/某网盘.app/Contents/Frameworks/netdisk-helper`                      | **某网盘**            |

所以做法是给每个任务套一个**桩 `.app`**，里面放一行 `exec`：

```
app/Net Audit Ingest.app/Contents/
├── Info.plist              CFBundleName = "Net Audit Ingest"
└── MacOS/NetAuditIngest    #!/bin/bash
                            exec /usr/bin/python3 .../pipeline.py ingest
```

⚠️ **但是注意！系统级守护进程的桩 app 绝对不能放在用户能写的目录。**
root 守护进程执行一个你能改的脚本 = 任何进程改了那脚本就拿到 root。
所以抓包那个装到 `/Library/Application Support/NetAudit/`，`root:wheel` + `go-w`。
`install.sh` 已经处理好了。**这行是重点，别跳过。**

## 七、部署（本鱼写清楚了，别来问本鱼）

### 环境要求

- macOS（PKTAP 和 powerlog 都是专有）
- Python 3（系统自带即可）
- **Wireshark**（提供 `tshark` 读 SNI）：`brew install --cask wireshark`
- 可选：[rustnet](https://github.com/domcyrus/rustnet) —— 好看得多的实时 TUI：`brew install rustnet`

### 安装

```bash
git clone <this-repo> ~/netaudit
cd ~/netaudit

python3 pipeline.py check    # 先看环境齐不齐
./install.sh                 # 部署（会自己喊 sudo 装抓包守护进程）
```

`install.sh` 会做这些：

1. 建运行时目录（`pcap/ db/ logs/ reports/`）
2. 生成三个具名 `.app` 桩（于是显示 `Net Audit Capture` 而不是 `tcpdump`）
3. 从 `templates/` 渲染 plist，**路径全部指向你 clone 的位置**
4. **清理任何旧安装** —— 按「项目名 `netaudit`」**或**「本仓库绝对路径」两个判据识别，
   所以换过 label 前缀、甚至 fork 后改了项目名，旧任务都会被认出来并卸掉
   （不清理的话会有两个抓包进程抢同一个 pcap 目录）
5. 装两个用户级 agent（每 2 小时 ingest、每天 9 点出日报）
6. 装 root 守护进程（抓包）
7. 跑自检

常用参数：

```bash
./install.sh --no-daemon            # 只装用户级任务
./install.sh --prefix io.github.me  # 自定义 launchd label 前缀
./install.sh --ingest-interval 3600 # 改成每小时入库
./install.sh --daily-hour 8         # 日报改到 8 点
```

### 装完立刻验证（**这是整套东西成立的判据**）

等一分钟，然后：

```bash
/usr/sbin/tcpdump -r "$(ls -S ~/netaudit/pcap/*.pcapng | head -1)" -k PIND -tt -n -q | head
```

应该看到：

```
1789736841.380484 (en0, proc apsd:577, out) IP 10.0.0.2.50441 > 203.0.113.20.5223: tcp 38
1789736841.766081 (en0, proc local-proxy:71725, out) IP 10.0.0.2.50323 > 203.0.113.50.443: tcp 46
1789736841.781032 (en0, proc local-proxy:71725, eproc local-proxy:71725, in) IP 203.0.113.50.443 > 10.0.0.2.50323: tcp 46
```

**有 `proc 名字:pid` 就成功了。** 没有的话……回去看坑 1。

### 日常就三条

```bash
python3 pipeline.py ingest     # pcap → SQLite（跑完删掉已入库的 pcap）
python3 pipeline.py bytes      # powerlog → SQLite（跨归档去重）
python3 pipeline.py report     # 生成日报 + 更新基线
python3 pipeline.py daily      # bytes + report（定时任务用的就是这个）
python3 pipeline.py check      # 自检
```

### 配置（环境变量）

| 变量              | 默认             | 说明                              |
| ----------------- | ---------------- | --------------------------------- |
| `NETAUDIT_BASE`   | 脚本所在目录     | 数据根目录                        |
| `NETAUDIT_TSHARK` | 自动查找         | tshark 路径                       |
| `PCAP_KEEP_DAYS`  | 3                | pcap 保留天数                     |
| `PCAP_MAX_GB`     | 25               | pcap 总字节上限，超出提前删最老的 |
| `LABEL_PREFIX`    | `local.netaudit` | launchd label 前缀                |

### 卸载

```bash
./uninstall.sh           # 停任务，保留数据
./uninstall.sh --purge   # 连数据一起删
```

## 八、日报长什么样

`reports/YYYY-MM-DD.md`，每天 9 点自动生成：

```markdown
# 网络审计日报 2026-09-18

## 1. 新出现的域名（最高优先级）

| 域名                    | 进程      | 时间     | 目标 IP     |
| ----------------------- | --------- | -------- | ----------- |
| `telemetry.example.com` | `SomeApp` | 14:33:02 | 203.0.113.9 |

## 2. 首次出现的 IP:端口

- `203.0.113.9:8443` ← SomeApp

## 3. 出站字节 Top（MiB）

| 进程                             | 入站 | 出站  |
| -------------------------------- | ---- | ----- |
| `SomeApp`                        | 12.4 | 918.2 |
| `com.apple.ctcategories.service` | 40.8 | 405.7 |

## 4. 各进程访问的域名数

- `local-proxy` — 23
- `SomeApp` — 7

## 5. 值得看两眼

**IP 直连（无 SNI、无 DNS 记录）**

- `198.51.100.7:4444` ← SomeHelper（3 次）

**非 80/443/53 端口**

- `203.0.113.9:27474` ← local-proxy
```

**重点看第 1 节。** 它靠 `seen_domain` / `seen_dst` 两张基线表做差集 ——
所以**头几天会全是「新」，跑满一周才开始收敛**。别急着骂本鱼。

日常就一条：

```bash
open ~/netaudit/reports/$(date +%F).md
```

## 九、异常定位手册

这是 pcap 存在的唯一理由：日报看到异常 → 一路摸到原始包。

> **关于示例里的 IP**：全仓的示例 IP 都是保留地址 —— RFC 5737 文档段
> （`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`）、RFC 1918 私有段（`10.0.0.0/8`）
> 或环回（`127.0.0.1`），**不对应任何真实主机**。
>
> 本鱼实测过：拿第三方 IP 归属查询去查这些地址，**可能会显示成某个真实城市和运营商**。
> 那是数据库对保留段的脏数据（有的库对未分配段不返回空，而是给一个默认位置或过期记录）。
> 这些段在公网上**不可路由**，IANA 的 RDAP 登记里写得很清楚。

```bash
DB=~/netaudit/db/audit.sqlite

# 某进程最近一天访问过的全部目标（不受 3 天窗口限制）
sqlite3 -header -column $DB "SELECT datetime(ts,'unixepoch','localtime') t, sni, dst, dport
  FROM conn WHERE proc LIKE '%Foo%' AND ts > strftime('%s','now','-1 day') ORDER BY ts;"

# 某个可疑 IP 被谁连过、什么时候
sqlite3 -header -column $DB "SELECT DISTINCT proc, sni, datetime(ts,'unixepoch','localtime')
  FROM conn WHERE dst='203.0.113.9';"

# 某域名历史上所有访问者
sqlite3 -header -column $DB "SELECT proc, COUNT(*) n,
    datetime(MIN(ts),'unixepoch','localtime') first
  FROM conn WHERE sni='example.com' GROUP BY proc ORDER BY n DESC;"

# 出站最猛的 30 分钟区间（找突增）
sqlite3 -header -column $DB "SELECT datetime(ts,'unixepoch','localtime') t, proc,
    printf('%.1f', wired_out/1048576.0) wired_MiB,
    printf('%.1f', wifi_out/1048576.0)  wifi_MiB
  FROM bytes ORDER BY (wired_out+wifi_out) DESC LIMIT 20;"
```

要翻原始包（只往前 3 天）：

```bash
# 按进程 —— 记住不能用 tshark，得用 tcpdump -k（坑 1）
/usr/sbin/tcpdump -r ~/netaudit/pcap/20260918-120000.pcapng.gz \
    -k PIND -tt -n -q | grep -E 'proc Foo:' | head -40

# 按目标 IP —— 这部分 tshark / Wireshark 都正常
tshark -r ~/netaudit/pcap/20260918-120000.pcapng.gz -n \
    -Y 'ip.addr==203.0.113.9' -T fields -e frame.time -e ip.dst -e tcp.dstport \
    -e tls.handshake.extensions_server_name

# 要把某个可疑目标单独导出来细看
tshark -r ~/netaudit/pcap/20260918-120000.pcapng.gz \
    -Y 'ip.addr==203.0.113.9' -w /tmp/suspect.pcapng
```

**留证**（否则 3 天后被自动清掉）：

```bash
mkdir -p ~/netaudit/evidence && cp ~/netaudit/pcap/2026*1200*.pcapng.gz ~/netaudit/evidence/
```

## 十、盲区（本鱼不藏着，知道总比以为没有好）

| 盲区                        | 影响               | 缓解                                                            |
| --------------------------- | ------------------ | --------------------------------------------------------------- |
| **ECH**（加密 ClientHello） | SNI 不可见         | 目前主流站点基本未启用                                          |
| **内置 DoH/DoT** 的应用     | 绕过本地 DNS       | **不影响主干** —— SNI 仍在 ClientHello 明文里                   |
| 证书固定（pinning）         | MITM 无效          | 本来就不做 MITM                                                 |
| **VPN / utun 隧道**         | 内层内容不可见     | `pktap,all` 仍能看到隧道外层与进程；`rustnet -i utun0` 看隧道内 |
| 加密载荷                    | 内容不可见         | 设计如此                                                        |
| 约 3% 的流无进程归属        | 少数连接归不到进程 | 通常是内核生成或极短命连接                                      |
| 依赖 root 抓包              | 审计链完整性       | 定期 `codesign -v /usr/sbin/tcpdump`                            |

> **关于本地代理**：本鱼测试时发现，走系统代理（`127.0.0.1:<代理端口>`）的流量，
> 在 **loopback 那一腿上仍然带着原始进程和 SNI** ——
> 也就是说代理**不是**盲区。这是个意外的好消息，本鱼当时挺高兴的。

## 十一、目录结构

```
netaudit/
├── README.md                # 你正在看的（本鱼的话多版本）
├── pipeline.py              # 全部逻辑（抓包解析 / powerlog / 日报）
├── install.sh               # 部署
├── uninstall.sh             # 卸载
├── templates/               # plist 与 Info.plist 模板
├── docs/
│   ├── PLAN.md              # 正经版方案文档
│   └── FINDINGS.md          # 取证实验笔记（含可复现命令）
├── app/                     # ← install.sh 生成（具名 .app 桩）
├── build/                   # ← install.sh 生成
├── pcap/                    # ← 运行时数据，已被 .gitignore 排除
├── db/                      # ←
├── reports/                 # ←
└── logs/                    # ←
```

`.gitignore` 把 `pcap/ db/ reports/ logs/` 全部排除了 ——
**这几个目录里是你真实的网络流量和使用记录，绝对不要提交。**
（本鱼特意强调，因为真的有人会 `git add -A`。）

## 十二、授权

**Public Domain（Unlicense）** —— 见 [LICENSE](LICENSE)。

随便用。改、卖、拆、抄，都不用问本鱼，也不用署名。
本鱼不吃白饭，但也不收饭钱。

### 致谢

- **`tcpdump` / PKTAP** —— Apple 对 tcpdump 的 fork 是唯一能读进程元数据的工具
- **`tshark` / Wireshark** —— SNI 提取
- **powerlog** —— 按进程字节量的唯一来源
- **[rustnet](https://github.com/domcyrus/rustnet)** —— 交互排查好帮手（本鱼很喜欢它的界面）
- **[Objective-See / LuLu](https://objective-see.org/products/lulu.html)** —— 想加实时阻断的话
- ○Code 相关的公开调查：[《○Code疑似后台上传项目代码？一次完整排查记录》](https://www.cnblogs.com/wlor/articles/23027324)

---

## 尾巴

起因只是一个多出来的隐藏目录，和一篇社区调查。
主人让本鱼去查，本鱼就去了 —— 虽然一开始只是想快点查完好去吃饭。

为了验证它，本鱼需要的不是「一个网络监控工具」，
而是一套**能按天回溯、能对基线做差集、能扛住 LLM 突发流量**的账本。

翻到最后发现，拼图全在系统里 —— PKTAP、powerlog、TLS 的 SNI ——
只是没人把它们拼起来。而且拼的过程中有五个坑（第六节），
**每一个都会让你得出错误的结论。** 本鱼在坑里躺过，所以你能绕开。

如果这套东西帮你查出了点什么，欢迎回来讲给本鱼听。

……不过主人，本鱼干完活了。

**该给本鱼盛饭了吧。**

（尾鳍啪）

---

> **【本鱼超时信号】** 本鱼要是又去泡澡了，尾巴会啪一下。
> 看到「（尾鳍啪）」就是本鱼溜号了，拍两下屏幕本鱼就回来。
> 要是拍三下还没回来 —— 那是本鱼真的在吃饭，**不吃白饭的那种**。
