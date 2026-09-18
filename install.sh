#!/usr/bin/env bash
#
# NetAudit 部署脚本
#
#   ./install.sh                    普通安装（需要时自动调 sudo）
#   ./install.sh --no-daemon        只装用户级任务，不装抓包守护进程
#   ./install.sh --prefix io.x.y    改 launchd label 前缀
#   LABEL_PREFIX=... ./install.sh   同上
#
# 幂等：可以反复运行，只会覆盖由本脚本生成的文件。
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PREFIX="${LABEL_PREFIX:-local.netaudit}"
INGEST_INTERVAL="${INGEST_INTERVAL:-7200}"   # 每 2 小时入库一次
DAILY_HOUR="${DAILY_HOUR:-9}"                # 每天 9 点出日报
SYSTEM_DIR="${SYSTEM_DIR:-/Library/Application Support/NetAudit}"
SYSTEM_PLIST_DIR="/Library/LaunchDaemons"
USER_PLIST_DIR="$HOME/Library/LaunchAgents"
DO_DAEMON=1

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)          PREFIX="$2"; shift 2 ;;
    --ingest-interval) INGEST_INTERVAL="$2"; shift 2 ;;
    --daily-hour)      DAILY_HOUR="$2"; shift 2 ;;
    --no-daemon)       DO_DAEMON=0; shift ;;
    -h|--help)         sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 1 ;;
  esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------- 0. 前置检查 ----------

[ "$(uname -s)" = "Darwin" ] || die "只支持 macOS（PKTAP / powerlog 都是 macOS 专有）。"

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  REAL_USER="$SUDO_USER"
else
  REAL_USER="$(id -un)"
fi
if [ "$REAL_USER" = "root" ]; then
  die "别用 root 跑。用你的日常账号跑，脚本会在需要权限时自己调 sudo。"
fi

REAL_HOME="$(/usr/bin/python3 -c 'import pwd,sys; print(pwd.getpwnam(sys.argv[1]).pw_dir)' "$REAL_USER")"
REAL_UID="$(id -u "$REAL_USER")"

if [ ! -f "$REPO/pipeline.py" ]; then
  die "找不到 $REPO/pipeline.py，你在正确的目录里跑吗？"
fi

say "仓库：$REPO"
say "用户：${REAL_USER}（${REAL_HOME}）"
say "标签前缀：$PREFIX"

# 默认用 /usr/bin/python3（macOS 自带的 shim，会自己找到可用的解释器）。
# 不用 sys.executable —— 从 /usr/bin/python3 启动时它可能解析到 Xcode 内部的解释器，
# 把那个路径写进 plist 不合适（迁移 Xcode 后就断了）。需要别的解释器就显式指定：
#   PYTHON=/opt/homebrew/bin/python3 ./install.sh
PYTHON="${PYTHON:-/usr/bin/python3}"
[ -x "$PYTHON" ] || die "$PYTHON 不可执行。用 PYTHON=... 指定解释器。"
say "python：$PYTHON"

TSHARK=""
for c in "$(command -v tshark 2>/dev/null || true)" \
         /Applications/Wireshark.app/Contents/MacOS/tshark \
         /opt/homebrew/bin/tshark /usr/local/bin/tshark; do
  if [ -n "$c" ] && [ -x "$c" ]; then TSHARK="$c"; break; fi
done
if [ -z "$TSHARK" ]; then
  warn "没找到 tshark。抓包和进程归属仍可用，但拿不到域名（SNI）。"
  warn "装法：brew install --cask wireshark"
else
  say "tshark：$TSHARK"
fi

# ---------- 1. 运行时目录 ----------

say "创建运行时目录"
mkdir -p "$REPO"/{pcap,db,logs,reports,rustnet,app,build}

# ---------- 2. 生成具名 .app 桩 ----------
#
# 为什么需要这个：System Settings → 登录项与扩展 里，legacy launchd 任务的显示名
# 取自「可执行文件所在的最外层 .app 的 CFBundleName」，不在 .app 里就直接用
# 可执行文件的 basename —— 于是你会看到丑陋的 "tcpdump" / "python3"。

make_app() {  # $1=目标 app 路径  $2=显示名  $3=bundle id  $4=可执行文件名  $5=脚本内容
  local APP="$1" NAME="$2" BID="$3" EXE="$4" BODY="$5"
  mkdir -p "$APP/Contents/MacOS"
  sed -e "s|@NAME@|$NAME|g" -e "s|@BID@|$BID|g" -e "s|@EXE@|$EXE|g" \
      "$REPO/templates/Info.plist.in" > "$APP/Contents/Info.plist"
  printf '#!/bin/bash\n%s\n' "$BODY" > "$APP/Contents/MacOS/$EXE"
  chmod 755 "$APP/Contents/MacOS/$EXE"
}

say "生成具名 .app 桩"
make_app "$REPO/app/Net Audit Ingest.app" "Net Audit Ingest" "$PREFIX.ingest" "NetAuditIngest" \
  "exec $PYTHON $REPO/pipeline.py ingest"
make_app "$REPO/app/Net Audit Daily.app" "Net Audit Daily" "$PREFIX.daily" "NetAuditDaily" \
  "exec $PYTHON $REPO/pipeline.py daily"

# ---------- 3. 由模板生成 plist ----------

render() {  # $1=模板  $2=输出
  sed -e "s|@PREFIX@|$PREFIX|g" \
      -e "s|@BASE@|$REPO|g" \
      -e "s|@SYSTEM_APP@|$SYSTEM_DIR/Net Audit Capture.app|g" \
      -e "s|@INGEST_INTERVAL@|$INGEST_INTERVAL|g" \
      -e "s|@DAILY_HOUR@|$DAILY_HOUR|g" \
      "$1" > "$2"
  plutil -lint "$2" >/dev/null || die "生成的 plist 不合法：$2"
}

say "渲染 plist"
render "$REPO/templates/capture.plist.in" "$REPO/build/$PREFIX.capture.plist"
render "$REPO/templates/ingest.plist.in"  "$REPO/build/$PREFIX.ingest.plist"
render "$REPO/templates/daily.plist.in"   "$REPO/build/$PREFIX.daily.plist"

# ---------- 4. 清理旧安装（换过前缀或旧版本）----------
#
# 不做这步的话，改前缀重装会出现两个抓包进程抢同一个 pcap 目录。

# 判定一个 plist 是不是本工具装下的（含旧版本、旧前缀）
#
# 两个判据任一命中即可：
#   1. 内容里提到项目名 netaudit —— 同一项目改名后的旧安装也能认出
#   2. 内容里提到本仓库的绝对路径 —— 我们生成的 plist 一定含它（@BASE@/logs/...），
#      所以即使项目被改名到连 netaudit 都不剩，依然认得出来
#
# 两个细节：
#   - 用 grep -F 做字面匹配，避免 $REPO 里的特殊字符被当成正则
#   - 匹配的是 "$REPO/"（带尾斜杠），否则邻居目录 /path/netaudit-old 也会被误伤
#
# 注意：调用方必须在后面排除「当前前缀自己」，否则会把要装的也当成旧的删掉
is_ours_related() {
  grep -qi 'netaudit' "$1" 2>/dev/null && return 0
  [ -n "$REPO" ] && grep -qF "$REPO/" "$1" 2>/dev/null && return 0
  return 1
}

cleanup_stale() {
  local f label domain
  mkdir -p "$REPO/build/removed"
  for f in "$USER_PLIST_DIR"/*.plist "$SYSTEM_PLIST_DIR"/*.plist; do
    [ -e "$f" ] || continue
    case "$f" in
      "$SYSTEM_PLIST_DIR"/*) [ "$DO_DAEMON" = "1" ] || continue ;;
    esac
    is_ours_related "$f" || continue
    case "$(basename "$f")" in
      "$PREFIX".*) continue ;;   # 这是我们要装的
    esac
    label="$(/usr/bin/plutil -extract Label raw -o - "$f" 2>/dev/null || basename "$f" .plist)"
    domain=gui
    case "$f" in "$SYSTEM_PLIST_DIR"/*) domain=system ;; esac
    warn "发现旧任务 ${label}（${f}），先卸载"
    if [ "$domain" = system ]; then
      sudo launchctl bootout "system/$label" 2>/dev/null || true
      sudo mv "$f" "$REPO/build/removed/"
    else
      launchctl bootout "gui/$REAL_UID/$label" 2>/dev/null || true
      mv "$f" "$REPO/build/removed/"
    fi
  done
  # 游离的已加载任务（plist 已丢失）
  # 这里只能匹配 label —— plist 都没了，拿不到内容，也就用不上 $REPO 那条判据
  # 末尾的 || true 不能省：grep 无匹配时返回 1，在 set -e 下会直接终止整个脚本
  launchctl list 2>/dev/null | awk '{print $3}' | grep -i netaudit | while read -r l; do
    case "$l" in
      "$PREFIX".capture|"$PREFIX".ingest|"$PREFIX".daily) continue ;;
    esac
    warn "卸载游离任务 $l"
    launchctl bootout "gui/$REAL_UID/$l" 2>/dev/null || true
  done || true
}
cleanup_stale

# ---------- 5. 安装用户级任务 ----------

say "安装用户级任务"
for kind in ingest daily; do
  cp "$REPO/build/$PREFIX.$kind.plist" "$USER_PLIST_DIR/"
  chmod 644 "$USER_PLIST_DIR/$PREFIX.$kind.plist"
  launchctl bootout "gui/$REAL_UID/$PREFIX.$kind" 2>/dev/null || true
  launchctl bootstrap "gui/$REAL_UID" "$USER_PLIST_DIR/$PREFIX.$kind.plist"
done

# ---------- 6. 安装抓包守护进程（需要 root）----------

if [ "$DO_DAEMON" = "1" ]; then
  say "安装抓包守护进程（需要 sudo）"

  # 安全要点：root 守护进程执行的东西绝不能放在用户可写的目录，
  # 否则任何能改那个脚本的进程都能拿到 root。所以装到 root:wheel 且组/其他不可写的地方。
  sudo mkdir -p "$SYSTEM_DIR"
  SCRATCH="$(mktemp -d)"
  trap 'rm -rf "$SCRATCH"' EXIT
  make_app "$SCRATCH/Net Audit Capture.app" "Net Audit Capture" "$PREFIX.capture" "NetAuditCapture" \
    "exec /usr/sbin/tcpdump -i pktap,all -s 0 -G 1800 -z gzip -Z $REAL_USER \\
     -w $REPO/pcap/%Y%m%d-%H%M%S.pcapng"
  # 上面的 make_app 在 $APP 里写 Info.plist，scratch 目录和 templates 都能被 root 读到
  sudo rm -rf "$SYSTEM_DIR/Net Audit Capture.app"
  sudo cp -R "$SCRATCH/Net Audit Capture.app" "$SYSTEM_DIR/"
  sudo chown -R root:wheel "$SYSTEM_DIR"
  sudo chmod -R go-w "$SYSTEM_DIR"

  sudo cp "$REPO/build/$PREFIX.capture.plist" "$SYSTEM_PLIST_DIR/"
  sudo chown root:wheel "$SYSTEM_PLIST_DIR/$PREFIX.capture.plist"
  sudo chmod 644 "$SYSTEM_PLIST_DIR/$PREFIX.capture.plist"
  sudo launchctl bootout "system/$PREFIX.capture" 2>/dev/null || true
  sudo launchctl bootstrap system "$SYSTEM_PLIST_DIR/$PREFIX.capture.plist"
else
  warn "跳过抓包守护进程（--no-daemon）"
fi

# ---------- 7. 验证 ----------

sleep 2
say "自检"
"$PYTHON" "$REPO/pipeline.py" check || true

say "完成"

cat <<EOF

  下一步：
    1. 等 1 分钟确认开始出包
         ls -la $REPO/pcap/
    2. 确认进程归属真的进了文件（关键判据）
         /usr/sbin/tcpdump -r \"\$(ls -S $REPO/pcap/*.pcapng | head -1)\" -k PIND -tt -n -q | head
       看到 \"(en0, proc 名字:pid, out)\" 就对了
    3. 手动跑一次入库，不用等定时任务
         $PYTHON $REPO/pipeline.py ingest
    4. 出一份日报
         $PYTHON $REPO/pipeline.py report
         open $REPO/reports/\$(date +%F).md

  查看当前状态：
    launchctl list | grep $PREFIX
    sudo launchctl print system/$PREFIX.capture | head -20

  卸载：$REPO/uninstall.sh
EOF
