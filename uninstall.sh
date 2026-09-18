#!/usr/bin/env bash
#
# NetAudit 卸载脚本
#
#   ./uninstall.sh            停掉并移除任务，保留已采集的数据
#   ./uninstall.sh --purge    连数据一起删（pcap / 数据库 / 日报 / 日志）
#   ./uninstall.sh --prefix io.x.y
#
# 注意：不会动 /usr/sbin/tcpdump 等系统文件，也不会删你 clone 下来的仓库本身。
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${LABEL_PREFIX:-local.netaudit}"
SYSTEM_DIR="${SYSTEM_DIR:-/Library/Application Support/NetAudit}"
PURGE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --purge)  PURGE=1; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 1 ;;
  esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  REAL_USER="$SUDO_USER"
else
  REAL_USER="$(id -un)"
fi
REAL_UID="$(id -u "$REAL_USER")"
USER_PLIST_DIR="$(/usr/bin/python3 -c 'import pwd,sys; print(pwd.getpwnam(sys.argv[1]).pw_dir)' "$REAL_USER")/Library/LaunchAgents"

say "停止用户级任务"
for kind in ingest daily; do
  launchctl bootout "gui/$REAL_UID/$PREFIX.$kind" 2>/dev/null || true
  rm -f "$USER_PLIST_DIR/$PREFIX.$kind.plist"
  say "  已移除 $PREFIX.$kind"
done

say "停止抓包守护进程（需要 sudo）"
sudo launchctl bootout "system/$PREFIX.capture" 2>/dev/null || true
sudo rm -f "/Library/LaunchDaemons/$PREFIX.capture.plist"
say "  已移除 $PREFIX.capture"

if [ -d "$SYSTEM_DIR" ]; then
  say "移除系统级桩 app"
  sudo rm -rf "$SYSTEM_DIR"
fi

rm -rf "$REPO/app" "$REPO/build"

# 清掉 launchd 里可能残留的空目录项不需要额外操作，BTM 会自动跟随 plist 消失。

if [ "$PURGE" = "1" ]; then
  warn "--purge：删除全部采集数据（不可恢复）"
  rm -rf "$REPO"/{pcap,db,reports,logs,rustnet}
  say "数据已清空"
else
  say "数据保留在 $REPO/{pcap,db,reports,logs}"
  say "要一并删除请重跑：./uninstall.sh --purge"
fi

say "完成"
