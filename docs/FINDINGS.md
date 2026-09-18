# 取证笔记

这里记录「为什么方案是现在这个样子」的原始实验。每一条都附可复现命令。
如果你想知道某个设计决定是怎么来的，先翻这里。

环境：macOS 26.6.2（25G83），Apple Silicon。

---

## 1. 统一日志：为什么不能当审计源

### 1.1 保留窗口只有 2 天

```bash
# 当前保留的最早一条
log show --last 30d --style compact \
  --predicate 'process == "kernel" OR process == "launchd"' | sed -n '2p'
```

实测结果：最早的条目就在 2 天前。原因也能量化 —— 网络子系统日志量极大：

```bash
log show --last 6h --style compact --predicate 'subsystem == "com.apple.network"' | wc -l
# → 66840
```

6 小时 66,840 行。滚动速度决定了它天生不适合做留存。

### 1.2 域名是「每进程加盐」的哈希

日志里域名长这样：

```
Hostname#a08e5674:443
url hash: 1b6c75cd
```

我做了四组对照来确认它是不是稳定的伪名。

**实验 A —— 同一进程内两次独立连接同一域名：**

```bash
curl -s -o /dev/null --max-time 3 --no-keepalive \
  "https://nonexistent-probe.example.com/a" \
  "https://nonexistent-probe.example.com/b"
sleep 4
log show --last 15s --info --predicate 'process == "curl" AND subsystem == "com.apple.network"' \
  | grep -oE 'Hostname#[0-9a-f]+' | sort -u
```

结果：**同一个哈希**。→ 进程内稳定。

**实验 B —— 两个独立进程解析同一域名：**

```bash
curl -s -o /dev/null --max-time 4 "https://nonexistent-probe.example.com/" ; sleep 3
curl -s -o /dev/null --max-time 4 "https://nonexistent-probe.example.com/" ; sleep 4
log show --last 25s --info --predicate 'process == "curl" AND subsystem == "com.apple.network"' \
  | grep -E 'Hostname#' | sed -E 's/^([0-9-]+ [0-9:.]+).*(Hostname#[0-9a-f]+).*/\1  \2/'
```

结果：

```
20:10:17  Hostname#04c39927
20:10:20  Hostname#e468dd06
```

**同一域名，不同哈希。** → 跨进程不可比。

**实验 C —— 同一域名间隔 90 秒：**

```
第 1 次 (20:06:23): Hostname#2097fb46
第 2 次 (20:08:23): Hostname#92928399
```

→ 跨会话不可比。

**实验 D —— 目标应用的哈希是否在其他进程日志里出现过：**

```bash
for h in <5 个哈希>; do
  log show --last 3d --info \
    --predicate 'subsystem == "com.apple.network" AND process != "THE_APP"' \
    | grep -c "Hostname#$h"
done
```

结果：**全部 0 次**。

### 1.3 结论

| 观察 | 推论 |
|---|---|
| 进程内同一域名 → 恒定 | 哈希函数是确定性的 |
| 跨进程/跨时间 → 不同 | 加了 per-process（或 per-session）的盐 |
| 无法离线复现 | 盐不可知 → **不可爆破** |
| 跨进程 0 命中 | **不可跨会话关联** |

**最要命的推论**：连「这个应用连了几个不同域名」都确定不了。因为跨进程的哈希不可比，
N 个哈希可能是 N 个会话各自解析同一个域名，也可能是 N 个不同域名。

> 顺带：`sudo log config --mode private_data:on` **只影响未来**写入的日志，
> 对已经落盘的哈希无效。别再试这条路了。

### 1.4 附：一个具体的「数据骗人」案例

统一日志里那条连接摘要写着：

```
bytes in/out: 225107575/769
```

出站 **769 字节**。

同一天、同一台机器、同一进程，powerlog 给出的是 **2,092,399,565 字节**。

覆盖率 **0.00004%**。原因：

1. 那条记录只是本地 loopback 上的一次更新包二次投递
2. `com.apple.network:connection` 默认并不完整上报 —— 大量真实连接不留痕

---

## 2. powerlog：按进程字节量的唯一来源

### 2.1 位置与可读性

```bash
ls -la /private/var/db/powerlog/Library/BatteryLife/
# -rw-r--r--  1 root  wheel  CurrentPowerlog.PLSQL      ← 全局可读！
ls -la /private/var/db/powerlog/Library/BatteryLife/Archives/
# powerlog_YYYY-MM-DD_XXXXXXXX.PLSQL.gz                 ← 约保留 5 天
```

这个数据库是 `root:wheel` 但 **`-rw-r--r--`** —— 不需要 sudo 就能读。
（这也意味着：**任何本地进程都能查出你这台机器上每个 App 的网络用量历史。**）

### 2.2 关键表

```sql
-- 按进程 × 30 分钟区间的字节增量
SELECT timestamp, ProcessName,
       WifiIn, WifiOut, WiredIn, WiredOut, CellIn, CellOut
FROM PLProcessNetworkAgent_EventInterval_UsageDiff;
```

字段说明：

| 字段 | 含义 |
|---|---|
| `ProcessName` | bundle id 或进程名（子进程流量常归到父 App） |
| `timestamp` | **已是 Unix 时间戳，不要再加 978307200**（加了会变成 2057 年） |
| `timestampEnd` | 区间结束，通常是 30 分钟窗口 |
| `WifiIn/WifiOut/WiredIn/WiredOut/CellIn/CellOut` | 该区间内的增量字节 |

同一个库里还有几张容易误用的表：

| 表 | 状态 |
|---|---|
| `PLProcessNetworkAgent_EventBackward_Usage` | 实测 **0 行**，空的 |
| `PLProcessNetworkAgent_EventPoint_Connection` | 实测 **0 行**，空的 |
| `PLProcessNetworkAgent_EventInterval_UsageDiff` | ✅ **唯一有数据的** |
| `PLProcessNetworkAgent_EventBackward_NetworkBitmap` | 有数据但只有 bundle 名，没有字节数 |

### 2.3 汇总时必须跨归档去重

归档文件之间、以及与 CurrentPowerlog 之间**有区间重叠**。实测：

| 文件 | 覆盖范围 |
|---|---|
| `powerlog_2026-09-16_XXXX.PLSQL.gz` | 09-15 23:49 → 09-17 00:20 |
| `CurrentPowerlog.PLSQL` | 09-16 23:50 → 现在 |

重叠了 30 分钟。不去重会多算。

**去重方法**：按 `(timestamp, ProcessName)` 做主键，`INSERT OR REPLACE`：

```sql
CREATE TABLE bytes (
  ts REAL, proc TEXT,
  wifi_in INT, wifi_out INT, wired_in INT, wired_out INT,
  cell_in INT, cell_out INT,
  PRIMARY KEY (ts, proc)
);
```

### 2.4 导出脚本

见 `pipeline.py` 的 `cmd_bytes()`。要点：

- 归档用 `gzip.open` 解到临时文件再 `sqlite3` 打开
- 打开时用只读 URI：`sqlite3.connect(f"file:{p}?mode=ro", uri=True)`
- **不要**用 `sqlite3 -readonly` 的 CLI 形式去读解压出来的归档 —— 实测会在某些文件上
  报 `unable to open database file (14)`

---

## 3. 信封加密的实现证据

目标应用已从 `/Applications` 删除，但**更新包缓存还在**（约 430 MB）：

```bash
ls -la ~/Library/Caches/*-updater/pending/
# 里面躺着完整的安装包 zip
```

解开后从 `app.asar`（约 300 MB 的 Electron 打包文件）里 grep：

```bash
for s in keyWrapAlgorithm publicKeySpkiPem rsa-oaep-sha256 \
         encryptedSizeBytes lastCompressedSize aes-256-ctr; do
  printf "%-22s %s\n" "$s" "$(grep -oa -- "$s" app.asar | wc -l)"
done
```

命中情况：

```
keyWrapAlgorithm        2
publicKeySpkiPem        2
rsa-oaep-sha256         2
encryptedSizeBytes      10
lastCompressedSize      3
aes-256-ctr             3
```

上下文：

```js
contentAlgorithm: "aes-256-ctr",
keyWrapAlgorithm: "rsa-oaep-sha256",
keyId: uploadKey.keyId,
nonceEncoding: "ciphertext-prefix-16-byte",
aadEncoding: "canonical-json-v1",
aad: { schema, workspaceKeyHash, kind, manifestHash, baseManifestHash, ... }
```

```js
encryptedDataKey: crypto.publicEncrypt(
  { key: e.uploadKey.publicKeySpkiPem,
    padding: RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256" }, k
).toString("base64"),
plaintextSha256: o
```

然后：

```js
encryptArchive() → {
  encryptedArtifactPath, envelopePath, manifestPath,
  encryptedSizeBytes, encryptedSha256
}
```

**解读**：内容用临时 AES-256-CTR 密钥加密，AES 密钥再用服务端下发的 RSA 公钥封装
（RSA-OAEP-SHA256）。`baseManifestHash` + `kind` 说明存在 baseline + 增量两种快照。

**能得出的结论**：信封加密的实现确实存在于该构建里。
**不能得出的结论**：上传了什么、服务端如何处理、私钥在谁手里。

---

## 4. 出站 / 入站的异常形态

同一台机器、同一进程，3 天的累计：

| | 字节 | MiB |
|---|---|---|
| 入站 | 790,052,687 | 753.5 |
| 出站 | **2,092,399,565** | **1,995.5** |
| 出/入 | **2.65 : 1** | |

按天：

| 日期 | 入站 MiB | 出站 MiB |
|---|---|---|
| day 1 | 124.7 | 357.3 |
| day 2 | 176.1 | **1,215.5** |
| day 3 | 452.3 | 422.4 |
| day 4 | 0.4 | 0.2 |

出站最猛的几个 30 分钟窗口：

| 时间 | 出站 MiB | 入站 MiB | 出/入 |
|---|---|---|---|
| day 1 21:05 | 110.8 | 9.5 | 11.7× |
| day 2 14:33 | 95.2 | 5.3 | **17.9×** |
| day 2 09:35 | 86.7 | 12.2 | 7.1× |
| day 2 11:28 | 80.6 | 7.3 | 11.0× |

对照组：同一时间段里 `node ↔ api.some-llm.com` 的流式会话是**入站远大于出站**
（单窗口出 5.6 MiB / 入 95 MiB 级别）。

**为什么这个形态有意义**：一个 AI 编程助手的正常语义是「发小上下文、收大回复」，
入站应当远大于出站。持续 2.65:1 的倒挂 + 出现 17.9× 的极端窗口，是
**大块本地数据外传**的特征，不是对话式 API 的特征。

---

## 5. 一些容易踩空的命令细节

```bash
# ---- tcpdump -k 的元数据字符 ----
# I 接口名   N 进程名   P PID   S 服务类别   D 方向   C 注释   F flags
# U 进程 UUID   f flow id   V 详细 pcapng 块
/usr/sbin/tcpdump -r f.pcapng -k PIND -tt -n -q
# -tt = epoch 时间，-n = 不做名字解析，-q = 精简输出

# ---- 两个硬约束 ----
# 1) -f（BPF）不能与 -r 同用
#    tcpdump: -f can not be used with -V or -r
#    → 读文件只能全量扫描，不能在 tcpdump 层预过滤
# 2) pktap 需要 root
#    tcpdump: ioctl(SIOCIFCREATE): Operation not permitted
#    → 普通 BPF 权限（access_bpf 组）不够，必须 root

# ---- 看 pcapng 的真实块结构（诊断元数据去向）----
python3 - <<'EOF'
import struct
d=open('f.pcapng','rb').read(); off=0; pad4=lambda n:(4-n%4)%4
while off+12<=len(d):
    bt,bl=struct.unpack_from('<II',d,off)
    if bl<12 or off+bl>len(d): break
    body=d[off+8:off+bl-4]
    if bt==1:                                    # IDB
        lt,_,snap=struct.unpack_from('<HHI',body,0)
        p=8; nm=''
        while p+4<=len(body):
            c,l=struct.unpack_from('<HH',body,p)
            if c==0: break
            if c==2: nm=body[p+4:p+4+l].decode('utf-8','replace').rstrip('\0')
            p+=4+l+pad4(l)
        print(f'IDB linktype={lt} snaplen={snap} if={nm}')
    elif bt==6:                                  # EPB
        iface,th,tl,cap,orig=struct.unpack_from('<IIIII',body,0)
        p=20+cap+pad4(cap)                       # ← 别忘了跳过包体
        codes=[]
        while p+4<=len(body):
            c,l=struct.unpack_from('<HH',body,p)
            if c==0: break
            codes.append(hex(c)); p+=4+l+pad4(l)
        print('EPB if=%d caplen=%d opts=%s'%(iface,cap,codes)); break
    off+=bl
EOF
# 预期输出：IDB linktype=1 (en0) / 0 (lo0)，EPB opts 含 0x8001..0x800a
# → 证明元数据在 Apple 自定义选项里，而不是 DLT_PKTAP

# ---- 看 BTM 给任务起了什么名字（验证 .app 桩是否生效）----
log show --last 2m --info --debug \
  --predicate 'subsystem CONTAINS "backgroundtaskmanagement"' \
  | grep -oE 'name=[^,]+, type=legacy (agent|daemon)' | sort -u
```

---

## 6. 未解之谜 / 待验证

- **哈希盐的粒度**：是 per-process 还是 per-nw_path_evaluator？实测一个进程内稳定，
  但没能确定粒度。需要在单进程内制造多个 evaluator 来验证。
- **ECH（Encrypted Client Hello）** 普及后 SNI 会失效。目前主流站点基本未启用。
- **约 3% 的流无进程归属**，怀疑是内核生成或极短命连接，未逐一确认。
- **`-G` 轮转与 `-z gzip` 的时序**：轮转瞬间的文件是否总是完整？目前用 mtime 守卫
  （180 秒）规避，但没有做压力验证。
