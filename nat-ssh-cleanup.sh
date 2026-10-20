#!/usr/bin/env bash
#==============================================================================
#  nat-ssh-cleanup.sh  v1.3.0
#  LXD / LXC 容器内 SSH 后门清理与加固（在容器终端里直接执行）
#
#  适用场景
#    攻击者经宿主机进入容器，向 /root/.ssh/authorized_keys（或其他用户）
#    写入公钥，建立持久化 SSH 访问。本脚本在容器内部完成取证、清理、加固。
#
#  支持系统
#    Debian / Ubuntu / CentOS 等 systemd、sysvinit 系统
#    Alpine（需要 bash：apk add --no-cache bash）
#
#  安全设计（请先读这段）
#    1. 默认只体检：不加 --apply 绝不修改任何文件
#    2. 所有改动前先做取证备份，并生成 sha256 清单
#    3. authorized_keys 只保留「你勾选的公钥」
#    4. 不碰密码登录设置（PermitRootLogin / PasswordAuthentication 完全不动）
#    5. sshd 配置改完必须 sshd -t 通过，否则自动回滚
#    6. cron/systemd/PAM/rc 等持久化项默认只报告，
#       加 --quarantine 才隔离（复制到备份区后删除原文件，不硬删）
#
#  用法
#    bash nat-ssh-cleanup.sh                        # 交互菜单（推荐）
#    bash nat-ssh-cleanup.sh --interactive          # 强制交互菜单
#    bash nat-ssh-cleanup.sh --allow-pubkey my.pub
#    bash nat-ssh-cleanup.sh --allow-pubkey my.pub --apply
#    bash nat-ssh-cleanup.sh --apply --quarantine --allow-pubkey my.pub
#    bash nat-ssh-cleanup.sh --verify               # 复查清理是否仍然生效
#    bash nat-ssh-cleanup.sh --unlock               # 临时解除 chattr 锁以便运维
#    bash nat-ssh-cleanup.sh --install-watchdog 5   # 装每 5 分钟的定时巡检
#    bash nat-ssh-cleanup.sh --uninstall            # 卸载本脚本和它装的所有东西
#    bash nat-ssh-cleanup.sh --help
#==============================================================================
set -uo pipefail

VERSION="1.3.0"
PROG="$(basename "${BASH_SOURCE[0]:-$0}")"

PREFIX="/"
MODE="scan"          # scan | apply | verify | unlock | uninstall
FORCE=0
STRICT=0
QUARANTINE=0
WATCHDOG_MIN=5
KEEP_OPTIONS=0     # 1=保留带 command=/environment= 的行（默认移除，视为后门）
QUIET=0            # 1=抑制过程输出（交互模式的清理流程用）
declare -A BAD_FPS=()   # 指纹 -> 成功登录过的来源 IP（来自 auth.log）
declare -A ALLOW_EMPTY_FILES=()   # 交互模式下用户确认可以清空的 authorized_keys
JSON_OUT=""
TS="$(date +%Y%m%dT%H%M%S)"
BACKUP_ROOT=""

ALLOW_FPS=()
ALLOW_KEYS=()
FINDINGS=()
CHANGES=()
KEYFILES=()

if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_YLW=$'\033[33m'; C_GRN=$'\033[32m'
  C_CYN=$'\033[36m'; C_DIM=$'\033[2m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=; C_YLW=; C_GRN=; C_CYN=; C_DIM=; C_BLD=; C_RST=
fi

#------------------------------------------------------------------------------
# 基础工具
#------------------------------------------------------------------------------
die()  { printf '%s[FATAL]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 2; }
log()  { [[ "$QUIET" -eq 1 ]] && return 0; printf '%s[*]%s %s\n' "$C_CYN" "$C_RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YLW" "$C_RST" "$*"; }
crit() { printf '%s[X]%s %s\n' "$C_RED" "$C_RST" "$*"; }
dim()  { [[ "$QUIET" -eq 1 ]] && return 0; printf '%s    %s%s\n' "$C_DIM" "$*" "$C_RST"; }

# 根目录前缀拼接
P() { printf '%s%s' "${PREFIX%/}" "$1"; }

# find_add <SEVERITY> <ID> <摘要> [明细]  —— 同一 (严重性,ID,明细) 只记一次
declare -A _FSEEN=()
find_add() {
  local key="$1|$2|${4:-}"
  [[ -n "${_FSEEN[$key]:-}" ]] && return 0
  _FSEEN[$key]=1
  FINDINGS+=("$1"$'\t'"$2"$'\t'"$3"$'\t'"${4:-}")
}

count_sev() {
  local want="$1" n=0 f
  for f in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
    [[ "${f%%$'\t'*}" == "$want" ]] && n=$((n + 1))
  done
  printf '%s' "$n"
}

has_sev() { [[ "$(count_sev "$1")" -gt 0 ]]; }

usage() {
  cat <<'USAGE'
nat-ssh-cleanup.sh — LXD/LXC 容器内 SSH 后门清理与加固（在容器终端里直接执行）

参数
  -i, --interactive       交互式菜单（无参数启动时自动进入）
  --apply                 实际执行清理与加固（默认只体检）
  --verify                复查模式：确认清理项仍然生效
  --unlock                解除 chattr 不可变锁（自己改 key 前用）
  --uninstall             卸载本脚本和它安装的所有东西（巡检、配置、脚本文件）
  --allow-fp FP[,FP...]   可信公钥指纹白名单，如 SHA256:abc123...
  --allow-pubkey FILE     可信公钥文件（每行一个），自动提取指纹
  --quarantine            隔离命中的持久化文件（复制后删除，不硬删）
  --strict                额外禁用 TCP/Agent 转发等（可能影响业务）
  --keep-options          保留 authorized_keys 里带 command=/environment= 的行
                          （默认视为后门移除；只有确认是自有运维用法才开）
  --force                 无白名单也强制执行 --apply（极不推荐）
  --install-watchdog [N]  装容器内定时巡检（默认每 5 分钟）
  --uninstall-watchdog    移除定时巡检任务
  --backup-dir DIR        取证备份目录（默认 /var/backups/nat-ssh-incident-<时间>）
  --json FILE             额外输出 JSON 报告
  --root-prefix DIR       分析指定根目录（离线快照取证；此模式下禁止 --apply）
  -h, --help              显示本帮助

退出码  0=无高危  1=存在 CRIT  2=参数或环境错误
USAGE
}

#------------------------------------------------------------------------------
# 公钥指纹
#------------------------------------------------------------------------------
key_fp() {
  local line="$1" fp=""
  if command -v ssh-keygen >/dev/null 2>&1; then
    fp=$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
  fi
  if [[ -z "$fp" ]]; then
    # 降级：对 base64 blob 直接算 sha256（与 ssh-keygen 的 SHA256: 表示不同，仅作内部比对）
    fp=$(printf '%s\n' "$line" \
      | awk '{for(i=1;i<=NF;i++) if($i ~ /^(ssh-|ecdsa-|sk-)/){print $(i+1); exit}}' \
      | base64 -d 2>/dev/null | sha256sum 2>/dev/null | awk '{print "RAW:"$1}')
  fi
  printf '%s' "$fp"
}

load_allow_keys() {
  local f="$1" line fp n=0
  [[ -r "$f" ]] || die "无法读取白名单文件: $f"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" == \#* ]] && continue
    fp=$(key_fp "$line")
    if [[ -n "$fp" ]]; then
      ALLOW_FPS+=("$fp"); ALLOW_KEYS+=("$line"); n=$((n + 1))
    else
      warn "白名单文件中有无法解析的行，已跳过: ${line:0:40}..."
    fi
  done < "$f"
  log "从 $f 载入 $n 个可信公钥"
}

fp_allowed() {
  local fp="$1" a
  for a in ${ALLOW_FPS[@]+"${ALLOW_FPS[@]}"}; do
    [[ "$fp" == "$a" ]] && return 0
    # 允许用户省略 SHA256: 前缀
    [[ "SHA256:${a#SHA256:}" == "$fp" ]] && return 0
    [[ "${fp#SHA256:}" == "${a#SHA256:}" ]] && return 0
  done
  return 1
}

#------------------------------------------------------------------------------
# 备份
#------------------------------------------------------------------------------
backup_path() {
  local src="$1" dest
  [[ -e "$src" ]] || return 0
  [[ -n "$BACKUP_ROOT" ]] || return 0
  dest="$BACKUP_ROOT/files${src}"
  mkdir -p "$(dirname "$dest")"
  cp -a "$src" "$dest" 2>/dev/null && {
    printf '%s  %s\n' "$(sha256sum "$src" 2>/dev/null | awk '{print $1}')" "$src" \
      >> "$BACKUP_ROOT/sha256-manifest.txt"
    return 0
  }
  warn "备份失败: $src"
  return 1
}

#------------------------------------------------------------------------------
# 环境自检：容器内常见差异（Alpine/busybox、无 systemd、无 ssh-keygen）
#------------------------------------------------------------------------------
CONTAINER_KIND="unknown"
INIT_SYS="none"
DISTRO="unknown"
ENV_NOTES=()

is_alpine() { [[ "$DISTRO" == "alpine" ]]; }

fmt_epoch() {
  local t="$1" out
  out=$(date -d "@$t" '+%F %T' 2>/dev/null) || out="$t"
  printf '%s' "$out"
}

check_env() {
  # 关联数组需要 bash 4+
  if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
    die "需要 bash 4.0+（当前 $BASH_VERSION）。Alpine 请先执行: apk add --no-cache bash"
  fi

  # 容器类型
  local ct=""
  if [[ -r /proc/1/environ ]]; then
    ct=$(tr '\0' '\n' < /proc/1/environ 2>/dev/null \
         | grep -m1 -oE '^container=[a-zA-Z0-9]+' | cut -d= -f2)
  fi
  [[ -z "$ct" && -f /run/systemd/container ]] && ct=$(cat /run/systemd/container 2>/dev/null)
  CONTAINER_KIND="${ct:-unknown}"

  # 发行版（决定 cron / sshd 的处理方式，尤其是 Alpine）
  if [[ -f "$(P /etc/alpine-release)" ]]; then
    DISTRO="alpine"
  elif [[ -f "$(P /etc/debian_version)" ]]; then
    DISTRO="debian"
  elif [[ -f "$(P /etc/redhat-release)" || -f "$(P /etc/centos-release)" ]]; then
    DISTRO="rhel"
  fi

  # 必需命令
  local c
  local -a missing=()
  for c in awk sed grep find stat chmod; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  [[ ${#missing[@]} -gt 0 ]] && die "缺少必需命令: ${missing[*]}"

  # 可选命令 → 降级
  command -v ssh-keygen >/dev/null 2>&1 || ENV_NOTES+=("没装 ssh-keygen：公钥指纹用备用算法算，请人工核对公钥内容")
  command -v chattr     >/dev/null 2>&1 || ENV_NOTES+=("没装 chattr：加不了文件锁，改用 --install-watchdog 定时巡检兜底")
  command -v lsattr     >/dev/null 2>&1 || ENV_NOTES+=("没装 lsattr：复查时确认不了锁状态")
  command -v ss         >/dev/null 2>&1 || ENV_NOTES+=("没装 ss/netstat：跳过监听端口检查")
  command -v sha256sum  >/dev/null 2>&1 || ENV_NOTES+=("没装 sha256sum：备份清单没法校验")

  # init 系统（决定 sshd 怎么重载）
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    INIT_SYS="systemd"
  elif command -v rc-service >/dev/null 2>&1 && [[ -d /run/openrc ]]; then
    INIT_SYS="openrc"
  elif [[ -x /sbin/service || -x /usr/sbin/service ]]; then
    INIT_SYS="sysv"
  else
    INIT_SYS="none"
  fi
  [[ "$INIT_SYS" == "none" ]] && ENV_NOTES+=("没找到 systemd/service：重载 SSH 服务将用 pkill -HUP")
}

reload_sshd_hint() {
  case "$INIT_SYS" in
    systemd) printf 'systemctl reload ssh 2>/dev/null || systemctl reload sshd' ;;
    openrc)  printf 'rc-service sshd reload 2>/dev/null || rc-service sshd restart' ;;
    sysv)    printf 'service ssh reload 2>/dev/null || service sshd reload' ;;
    *)       printf 'pkill -HUP sshd' ;;
  esac
}

#------------------------------------------------------------------------------
# 检查 1：authorized_keys
#------------------------------------------------------------------------------
collect_keyfiles() {
  local user _ uid _ _ home shell f
  local -a cands=("/root/.ssh/authorized_keys" "/root/.ssh/authorized_keys2")
  local passwd; passwd="$(P /etc/passwd)"
  if [[ -r "$passwd" ]]; then
    while IFS=: read -r user _ uid _ _ home shell; do
      [[ -z "$user" || "$user" == \#* ]] && continue
      [[ "$uid" =~ ^[0-9]+$ ]] || continue
      (( uid == 0 || uid >= 1000 )) || continue
      [[ -z "$home" || "$home" == "/" ]] && continue
      cands+=("$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2")
    done < "$passwd"
  fi
  for f in "${cands[@]}"; do
    [[ -f "$(P "$f")" ]] && KEYFILES+=("$(P "$f")")
  done
  # 去重
  if [[ ${#KEYFILES[@]} -gt 0 ]]; then
    local -a u=()
    while IFS= read -r f; do u+=("$f"); done < <(printf '%s\n' "${KEYFILES[@]}" | awk '!seen[$0]++')
    KEYFILES=("${u[@]}")
  fi
}

check_authorized_keys() {
  local f line lineno first opts fp blob n_key n_bad
  if [[ ${#KEYFILES[@]} -eq 0 ]]; then
    find_add INFO SSH-KEY-000 "未发现任何 authorized_keys 文件" ""
    return
  fi
  for f in "${KEYFILES[@]}"; do
    n_key=0; n_bad=0; lineno=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      lineno=$((lineno + 1))
      line="${line%$'\r'}"
      [[ -z "${line//[[:space:]]/}" ]] && continue
      [[ "$line" == \#* ]] && continue
      first=$(awk '{print $1}' <<<"$line")
      case "$first" in
        ssh-*|ecdsa-*|sk-*) opts="" ;;
        # 选项部分可能含空格（command="..."），用 sed 截到 key 类型之前
        *) opts=$(printf '%s' "$line" | sed -E 's/[[:space:]]+(ssh-(rsa|dss|ed25519)|ecdsa-sha2-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]].*$//') ;;
      esac
      fp=$(key_fp "$line")
      n_key=$((n_key + 1))
      if fp_allowed "$fp"; then
        dim "$f:$lineno 白名单内 ${fp:-<无指纹>}"
        continue
      fi
      n_bad=$((n_bad + 1))
      if [[ "$opts" == *command=* || "$opts" == *environment=* ]]; then
        find_add CRIT SSH-KEY-001 \
          "authorized_keys 含非白名单公钥，且带强制命令/环境注入选项" \
          "$f:$lineno | fp=${fp:-unknown} | opts=${opts}"
      else
        find_add HIGH SSH-KEY-002 "authorized_keys 含非白名单公钥" \
          "$f:$lineno | fp=${fp:-unknown}"
      fi
      dim "$f:$lineno ${C_RED}非白名单${C_RST} ${fp:-<无指纹>} ${opts:+[$opts]}"
    done < "$f"
    [[ "$n_key" -eq 0 ]] && find_add MED SSH-KEY-003 "authorized_keys 为空（攻击者可能已清空以隐蔽）" "$f"
    dim "$f 共 $n_key 把公钥，其中 $n_bad 把不在白名单"
  done
}

#------------------------------------------------------------------------------
# 检查 2：.ssh 目录与用户级后门
#------------------------------------------------------------------------------
check_ssh_dir() {
  local f d perm owner u
  local -a dirs=("/root/.ssh")
  local passwd; passwd="$(P /etc/passwd)"
  if [[ -r "$passwd" ]]; then
    while IFS=: read -r u _ _ _ _ d _; do
      [[ -z "$u" ]] && continue
      [[ -d "$(P "$d/.ssh")" ]] && dirs+=("$d/.ssh")
    done < "$passwd"
  fi
  if [[ ${#dirs[@]} -gt 0 ]]; then
    local -a _u=()
    while IFS= read -r f; do _u+=("$f"); done < <(printf '%s\n' "${dirs[@]}" | awk '!s[$0]++')
    dirs=("${_u[@]}")
  fi
  for d in "${dirs[@]}"; do
    local pd; pd="$(P "$d")"
    [[ -d "$pd" ]] || continue
    perm=$(stat -c '%a' "$pd" 2>/dev/null)
    owner=$(stat -c '%U:%G' "$pd" 2>/dev/null)
    [[ "$perm" != "700" ]] && find_add MED SSH-DIR-001 ".ssh 目录权限过宽" "$pd perm=$perm 期望=700 owner=$owner"
    # 用户级后门文件
    for f in rc environment config authorized_keys.bak authorized_keys.old \
             authorized_keys.orig authorized_keys.old.1 known_hosts.bak; do
      [[ -e "$pd/$f" ]] && find_add HIGH SSH-DIR-002 "存在可疑的 .ssh 附属文件" "$pd/$f"
    done
    # .ssh/config 里的命令执行
    if [[ -r "$pd/config" ]]; then
      if grep -qiE '^[[:space:]]*(ProxyCommand|LocalCommand|PermitLocalCommand)' "$pd/config"; then
        find_add HIGH SSH-DIR-003 ".ssh/config 含命令执行指令" \
          "$d/config: $(grep -iE '^[[:space:]]*(ProxyCommand|LocalCommand)' "$pd/config" | head -3 | tr '\n' ' ')"
      fi
    fi
    # .ssh/rc 会在登录时执行
    if [[ -s "$pd/rc" ]]; then
      find_add CRIT SSH-DIR-004 ".ssh/rc 存在且非空（登录即执行）" "$d/rc ($(wc -c < "$pd/rc") 字节)"
    fi
  done
}

#------------------------------------------------------------------------------
# 检查 3：账号与凭据
#------------------------------------------------------------------------------
check_accounts() {
  local u line
  local passwd; passwd="$(P /etc/passwd)"
  # UID 0 的非 root 账号
  if [[ -r "$passwd" ]]; then
    while IFS=: read -r u _ uid _ _ _ shell; do
      [[ "$uid" == "0" && "$u" != "root" ]] && \
        find_add CRIT ACC-001 "存在 UID=0 的非 root 账号" "$u (shell=$shell)"
    done < "$passwd"
    # 空密码账号
    local shadow; shadow="$(P /etc/shadow)"
    if [[ -r "$shadow" ]]; then
      while IFS=: read -r u _ hash _; do
        [[ -z "$hash" ]] && find_add HIGH ACC-002 "账号密码为空" "$u"

      done < "$shadow"
    fi
    # 异常 shell / 近期新增账号（按 passwd mtime 无法判断，改为提示）
    local pw_mtime; pw_mtime=$(stat -c '%Y' "$passwd" 2>/dev/null || echo 0)
    local now; now=$(date +%s)
    if [[ "$pw_mtime" -gt 0 ]] && (( now - pw_mtime < 7 * 86400 )); then
      find_add MED ACC-004 "/etc/passwd 近 7 天内被修改，请核对是否新增账号" \
        "$(fmt_epoch "$pw_mtime")"
    fi
  fi
  # sudoers
  local sf
  for sf in "$(P /etc/sudoers)" $(ls "$(P /etc/sudoers.d)"/* 2>/dev/null); do
    [[ -f "$sf" ]] || continue
    if grep -qiE 'NOPASSWD' "$sf" 2>/dev/null; then
      find_add MED ACC-005 "sudoers 中存在 NOPASSWD 规则" \
        "$sf: $(grep -iE 'NOPASSWD' "$sf" | head -3 | tr '\n' ' ')"
    fi
    # 备份文件往往是攻击者留下的
    [[ "$sf" == *~ || "$sf" == *.bak || "$sf" == *.old ]] && \
      find_add MED ACC-006 "sudoers 目录存在备份文件" "$sf"
  done
}

#------------------------------------------------------------------------------
# 检查 4：sshd 配置
#------------------------------------------------------------------------------
sshd_bin() {
  local b
  for b in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do
    [[ -x "$b" ]] && { printf '%s' "$b"; return 0; }
  done
  command -v sshd 2>/dev/null && return 0
  return 1
}

sshd_effective() {
  local b; b=$(sshd_bin) || return 1
  [[ "$PREFIX" != "/" ]] && return 1
  "$b" -T 2>/dev/null
}

# 从 sshd -T 的生效配置中取值
eff_get() {
  printf '%s\n' "${SSHD_EFF:-}" | awk -v k="$1" '$1==k {print $2; exit}'
}

check_sshd_config() {
  local cfg; cfg="$(P /etc/ssh/sshd_config)"
  if [[ ! -f "$cfg" ]]; then
    find_add INFO SSH-CFG-000 "未安装 sshd（容器内无 SSH 服务）" ""
    return
  fi
  local eff; eff=$(sshd_effective) || eff=""
  SSHD_EFF="$eff"

  # 配置文本层面：攻击者最爱的两个字段
  local akf akc
  akf=$(grep -iE '^[[:space:]]*AuthorizedKeysFile' "$cfg" | awk '{print $2}')
  akc=$(grep -iE '^[[:space:]]*AuthorizedKeysCommand' "$cfg" | awk '{print $2}')
  [[ -n "$akf" && "$akf" != ".ssh/authorized_keys" && "$akf" != "%h/.ssh/authorized_keys" ]] && \
    find_add CRIT SSH-CFG-001 "AuthorizedKeysFile 被改到非标准路径" "$cfg -> $akf"
  [[ -n "$akc" && "$akc" != "none" ]] && \
    find_add CRIT SSH-CFG-002 "AuthorizedKeysCommand 被启用（可绕过 authorized_keys）" "$cfg -> $akc"

  # drop-in 目录
  local dd; dd="$(P /etc/ssh/sshd_config.d)"
  if [[ -d "$dd" ]]; then
    local df
    while IFS= read -r df; do
      [[ -z "$df" ]] && continue
      if grep -qiE '^[[:space:]]*(AuthorizedKeysCommand|AuthorizedKeysFile|ForceCommand)' "$df"; then
        find_add HIGH SSH-CFG-003 "sshd drop-in 含高风险指令" \
          "$df: $(grep -iE '^[[:space:]]*(AuthorizedKeysCommand|AuthorizedKeysFile|ForceCommand)' "$df" | head -2 | tr '\n' ' ')"
      fi
    done < <(ls "$dd"/*.conf 2>/dev/null)
  fi

  # 生效配置（密码登录相关设置本脚本完全不动）
  if [[ -n "$eff" ]]; then
    local pue
    pue=$(eff_get permituserenvironment)
    [[ "$pue" == "yes" ]] && find_add HIGH SSH-CFG-012 "PermitUserEnvironment=yes（可注入环境变量）" "生效值: $pue"
  else
    : # 无 sshd -T 时没有可用的替代检查
  fi

  # 主配置被改动过
  local m; m=$(stat -c '%Y' "$cfg" 2>/dev/null || echo 0)
  local now; now=$(date +%s)
  if [[ "$m" -gt 0 ]] && (( now - m < 7 * 86400 )); then
    find_add MED SSH-CFG-013 "sshd_config 近 7 天内被修改" "$(fmt_epoch "$m")"
  fi
}

#------------------------------------------------------------------------------
# 检查 5：SSH 主机密钥 / 客户端配置
#------------------------------------------------------------------------------
check_hostkeys() {
  local f n=0
  for f in "$(P /etc/ssh)"/ssh_host_*_key.pub; do
    [[ -f "$f" ]] || continue
    n=$((n + 1))
    local fp m now
    fp=$(ssh-keygen -lf "$f" 2>/dev/null | awk '{print $2}')
    m=$(stat -c '%Y' "$f" 2>/dev/null || echo 0)
    now=$(date +%s)
    dim "hostkey $f ${fp:-<无>}"
    if [[ "$m" -gt 0 ]] && (( now - m < 7 * 86400 )); then
      find_add MED HOSTKEY-001 "SSH 主机密钥近 7 天内被重新生成（可能中间人/重建）" \
        "$f mtime=$(fmt_epoch "$m")"
    fi
  done
  [[ "$n" -eq 0 ]] && find_add INFO HOSTKEY-000 "未找到 SSH 主机密钥" ""
  # 客户端配置后门
  local sc; sc="$(P /etc/ssh/ssh_config)"
  if [[ -r "$sc" ]] && grep -qiE '^[[:space:]]*ProxyCommand' "$sc"; then
    find_add HIGH HOSTKEY-002 "/etc/ssh/ssh_config 含 ProxyCommand（可劫持出站连接）" "$sc"
  fi
}

#------------------------------------------------------------------------------
# 检查 6：持久化（cron / systemd / apt / rc）
#------------------------------------------------------------------------------
MAL_RE='(curl|wget)[^|]*\|[[:space:]]*(ba)?sh|/dev/tcp/|base64[[:space:]]+(-d|--decode)|(nc|ncat)[[:space:]]+(-e|-c)|socat[[:space:]]|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|mkfifo|chmod[[:space:]]+\+x[[:space:]]+/tmp'

scan_text_for_malice() {
  local f="$1" tag="$2"
  [[ -r "$f" ]] || return 0
  local hits
  hits=$(grep -nEi "$MAL_RE" "$f" 2>/dev/null | head -5)
  if [[ -n "$hits" ]]; then
    find_add CRIT "$tag" "持久化文件中发现可疑命令" "$f: $(printf '%s' "$hits" | head -1 | cut -c1-160)"
    printf '%s\n' "$hits" | while IFS= read -r l; do dim "  $l"; done
    return 1
  fi
  return 0
}

check_persistence() {
  local f
  # cron
  for f in "$(P /etc/crontab)" "$(P /etc/anacrontab)"; do
    [[ -f "$f" ]] && scan_text_for_malice "$f" PERSIST-001
  done
  local d
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
           /etc/periodic/15min /etc/periodic/hourly /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly \
           /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d "$(P "$d")" ]] || continue
    while IFS= read -r f; do
      [[ -z "$f" || -d "$f" ]] && continue
      scan_text_for_malice "$f" PERSIST-001
      # cron 目录里出现可执行脚本本身就是可疑信号
      if [[ "$d" == /etc/cron.d || "$d" == /var/spool/cron* ]]; then
        [[ -x "$f" ]] && find_add MED PERSIST-002 "cron 目录中存在可执行文件" "$f"
      fi
    done < <(ls "$(P "$d")"/* 2>/dev/null)
  done

  # systemd
  for d in /etc/systemd/system /etc/systemd/user /lib/systemd/system; do
    [[ -d "$(P "$d")" ]] || continue
    while IFS= read -r f; do
      [[ -z "$f" || -d "$f" ]] && continue
      scan_text_for_malice "$f" PERSIST-003
      # 指向 /tmp /dev/shm 的 ExecStart
      if grep -qE '^[[:space:]]*(ExecStart|ExecStartPre|ExecStopPost)=.*(/tmp/|/dev/shm/|/var/tmp/)' "$f" 2>/dev/null; then
        find_add CRIT PERSIST-004 "systemd 单元从临时目录执行程序" \
          "$f: $(grep -E '^[[:space:]]*Exec' "$f" | head -1 | cut -c1-140)"
      fi
    done < <(ls "$d"/*.service "$d"/*.timer 2>/dev/null)
  done

  # rc.local / init.d / network hooks
  for f in "$(P /etc/rc.local)" "$(P /etc/rc.d/rc.local)"; do
    [[ -s "$f" ]] && scan_text_for_malice "$f" PERSIST-005
  done
  for d in /etc/init.d /etc/network/if-up.d /etc/network/if-pre-up.d /etc/network/if-post-down.d; do
    [[ -d "$(P "$d")" ]] || continue
    while IFS= read -r f; do
      [[ -z "$f" || -d "$f" ]] && continue
      scan_text_for_malice "$f" PERSIST-005
    done < <(ls "$(P "$d")"/* 2>/dev/null)
  done

  # apt 钩子
  for d in /etc/apt/apt.conf.d; do
    [[ -d "$(P "$d")" ]] || continue
    while IFS= read -r f; do
      [[ -z "$f" || -d "$f" ]] && continue
      if grep -qiE '^(DPkg|APT)::(Update|Install)?::?Pre-Invoke' "$f" 2>/dev/null; then
        find_add CRIT PERSIST-006 "apt 钩子会在安装/更新时执行命令" \
          "$f: $(grep -iE 'Pre-Invoke' "$f" | head -1 | cut -c1-140)"
      fi
    done < <(ls "$(P "$d")"/* 2>/dev/null)
  done

  # at 任务
  if [[ -d "$(P /var/spool/cron/atjobs)" ]]; then
    while IFS= read -r f; do
      [[ -z "$f" || -d "$f" ]] && continue
      find_add MED PERSIST-007 "存在 at 定时任务" "$f"
    done < <(ls "$(P /var/spool/cron/atjobs)"/* 2>/dev/null)
  fi
}

#------------------------------------------------------------------------------
# 检查 7：shell 启动脚本注入
#------------------------------------------------------------------------------
check_shell_rc() {
  local f
  local -a files=(/etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/zshrc /root/.bashrc /root/.profile /root/.bash_profile /root/.bash_login /root/.zshrc)
  local d
  for d in /etc/profile.d; do
    [[ -d "$(P "$d")" ]] || continue
    while IFS= read -r f; do
      [[ -z "$f" || -d "$f" ]] && continue
      files+=("${f#"${PREFIX%/}"}")
    done < <(ls "$(P "$d")"/* 2>/dev/null)
  done
  local u home
  local passwd; passwd="$(P /etc/passwd)"
  if [[ -r "$passwd" ]]; then
    while IFS=: read -r u _ _ _ _ home _; do
      [[ -z "$u" || "$home" == "/" || -z "$home" ]] && continue
      files+=("$home/.bashrc" "$home/.profile" "$home/.bash_profile")
    done < "$passwd"
  fi
  if [[ ${#files[@]} -gt 0 ]]; then
    local -a _u=()
    while IFS= read -r f; do _u+=("$f"); done < <(printf '%s\n' "${files[@]}" | awk '!s[$0]++')
    files=("${_u[@]}")
  fi
  for f in "${files[@]}"; do
    scan_text_for_malice "$(P "$f")" RC-001
  done
  # /etc/environment 里的 LD_PRELOAD 是经典手法
  local envf; envf="$(P /etc/environment)"
  [[ -r "$envf" ]] && grep -qiE 'LD_PRELOAD|LD_LIBRARY_PATH' "$envf" && \
    find_add CRIT RC-002 "/etc/environment 注入 LD_* 变量（动态库劫持）" "$envf"
}

#------------------------------------------------------------------------------
# 检查 8：动态库劫持 / PAM 后门
#------------------------------------------------------------------------------
check_preload_pam() {
  local f; f="$(P /etc/ld.so.preload)"
  if [[ -s "$f" ]]; then
    find_add CRIT LIB-001 "/etc/ld.so.preload 非空（全局动态库劫持）" \
      "$(tr '\n' ' ' < "$f" | cut -c1-200)"
  fi
  local d; d="$(P /etc/ld.so.conf.d)"
  if [[ -d "$d" ]]; then
    while IFS= read -r f; do
      [[ -z "$f" || -d "$f" ]] && continue
      # 指向 /tmp /dev/shm 的库路径
      grep -qE '^\s*(/tmp|/dev/shm|/var/tmp)' "$f" 2>/dev/null && \
        find_add CRIT LIB-002 "动态库搜索路径指向临时目录" "$f"
    done < <(ls "$d"/*.conf 2>/dev/null)
  fi
  # PAM
  local pd; pd="$(P /etc/pam.d)"
  if [[ -d "$pd" ]]; then
    while IFS= read -r f; do
      [[ -z "$f" || -d "$f" ]] && continue
      if grep -qE 'pam_exec\.so|pam_python|pam_script' "$f" 2>/dev/null; then
        find_add CRIT PAM-001 "PAM 配置含 pam_exec/pam_python（可执行任意命令）" \
          "$f: $(grep -E 'pam_exec|pam_python|pam_script' "$f" | head -1 | cut -c1-140)"
      fi
    done < <(ls "$pd"/* 2>/dev/null)
  fi
}

#------------------------------------------------------------------------------
# 检查 9：可疑文件 / 网络
#------------------------------------------------------------------------------
check_suspicious_files() {
  local d f
  for d in /tmp /var/tmp /dev/shm; do
    [[ -d "$(P "$d")" ]] || continue
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      # ELF
      if [[ "$(head -c 4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')" == "7f454c46" ]]; then
        find_add HIGH FILE-001 "临时目录中存在 ELF 可执行文件" "$f ($(stat -c '%s' "$f" 2>/dev/null) 字节)"
      elif [[ -x "$f" ]]; then
        find_add MED FILE-002 "临时目录中存在可执行脚本" "$f"
      fi
    done < <(find "$(P "$d")" -maxdepth 2 -type f -mtime -30 2>/dev/null | head -50)
  done
  # 近期新增的 SUID
  local n
  n=$(find "$(P /)" -xdev -perm -4000 -type f -mtime -14 2>/dev/null | head -20)
  if [[ -n "$n" ]]; then
    find_add HIGH FILE-003 "近 14 天新增/变更的 SUID 文件" "$(printf '%s' "$n" | tr '\n' ' ' | cut -c1-300)"
  fi
}

check_network() {
  local out=""
  if command -v ss >/dev/null 2>&1; then
    out=$(ss -tulpn 2>/dev/null)
  elif command -v netstat >/dev/null 2>&1; then
    # Alpine 的 busybox 自带 netstat，功能等价
    out=$(netstat -tulpn 2>/dev/null)
  else
    find_add INFO NET-000 "无 ss/netstat 命令，跳过监听端口检查" ""
    return
  fi
  [[ -z "$out" ]] && return
  # 非标准端口上的 sshd
  local suspicious
  suspicious=$(printf '%s\n' "$out" | grep -iE 'sshd' | grep -vE ':(22)[[:space:]]')
  if [[ -n "$suspicious" ]]; then
    find_add HIGH NET-001 "sshd 监听在非标准端口（可能是攻击者另起的实例）" \
      "$(printf '%s' "$suspicious" | head -3 | tr '\n' ' ' | cut -c1-240)"
  fi
  # 监听 0.0.0.0 的 shell 类端口
  printf '%s\n' "$out" | grep -qE ':(4444|5555|6666|1337|31337)[[:space:]]' && \
    find_add HIGH NET-002 "存在反弹 shell 常用端口监听" "$(printf '%s\n' "$out" | grep -E ':(4444|5555|6666|1337|31337)' | head -2 | tr '\n' ' ')"
}

#------------------------------------------------------------------------------
# 检查 10：认证日志里的登录记录（关键证据）
#------------------------------------------------------------------------------
check_auth_logs() {
  local logs=() f
  for f in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/secure.1; do
    [[ -r "$(P "$f")" ]] && logs+=("$(P "$f")")
  done
  if [[ ${#logs[@]} -eq 0 ]]; then
    find_add INFO LOG-000 "无 auth 日志（容器可能未运行 rsyslog）" ""
    return
  fi
  local out
  out=$(cat "${logs[@]}" 2>/dev/null)
  # 成功登录使用的公钥指纹
  local fps
  fps=$(printf '%s\n' "$out" | grep -oE 'Accepted publickey for [^ ]+ from [0-9a-f.:]+.*(SHA256|MD5):[A-Za-z0-9+/=]+' \
        | awk '{print $4, $6, $NF}' | sort | uniq -c | sort -rn | sed 's/^ *//' | head -10)
  if [[ -n "$fps" ]]; then
    find_add INFO LOG-001 "历史公钥登录记录（用户 来源IP 指纹）" "$(printf '%s' "$fps" | tr '\n' ';' | cut -c1-400)"
    printf '%s\n' "$fps" | while IFS= read -r l; do dim "  $l"; done
    # 若登录指纹不在白名单，直接标红
    while read -r cnt user ip fp; do
      [[ -z "${fp:-}" ]] && continue
      # 规范化：日志格式偶见 SHA256:SHA256:xxx，统一成单前缀
      fp=$(printf '%s' "$fp" | sed -E 's/^(SHA256:)+/SHA256:/')
      # 记录指纹 -> 来源 IP，交互选 key 时用来标注"这把真的登录过"
      BAD_FPS[$fp]="${BAD_FPS[$fp]:-}${ip} "
      if ! fp_allowed "$fp"; then
        find_add CRIT LOG-002 "有非白名单公钥成功登录过（这就是攻击者的 key）" \
          "user=$user from=$ip fp=$fp 次数=$cnt"
      fi
    done <<< "$fps"
  fi
  # 密码登录成功
  local pw
  pw=$(printf '%s\n' "$out" | grep -E 'Accepted (password|keyboard-interactive) for' | tail -5)
  [[ -n "$pw" ]] && find_add HIGH LOG-003 "存在密码方式成功登录记录" \
    "$(printf '%s' "$pw" | tail -1 | cut -c1-200)"
  # 大量失败
  local fails
  fails=$(printf '%s\n' "$out" | grep -cE 'Failed password|Invalid user')
  [[ "$fails" -gt 50 ]] && find_add MED LOG-004 "暴力破解痕迹" "失败次数=$fails"
}

#------------------------------------------------------------------------------
# 加固：authorized_keys
#------------------------------------------------------------------------------
apply_authorized_keys() {
  local f kept removed opts
  if [[ ${#KEYFILES[@]} -eq 0 ]]; then
    ok "无 authorized_keys 需要处理"
    return 0
  fi
  if [[ ${#ALLOW_FPS[@]} -eq 0 && "$FORCE" -ne 1 ]]; then
    crit "未提供可信公钥白名单，拒绝重建 authorized_keys"
    warn "请先用 --allow-pubkey / --allow-fp 指定你自己的公钥，或加 --force 强制清空"
    return 1
  fi
  for f in "${KEYFILES[@]}"; do
    backup_path "$f"
    local tmp; tmp=$(mktemp)
    kept=0; removed=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      if [[ -z "${line//[[:space:]]/}" || "$line" == \#* ]]; then
        continue
      fi
      local fp; fp=$(key_fp "$line")
      # 提取选项部分（key 类型之前的所有内容）
      opts=""
      case "$(awk '{print $1}' <<<"$line")" in
        ssh-*|ecdsa-*|sk-*) ;;
        *) opts=$(printf '%s' "$line" | sed -E 's/[[:space:]]+(ssh-(rsa|dss|ed25519)|ecdsa-sha2-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]].*$//') ;;
      esac
      # 即使指纹在白名单，带 command=/environment= 也视为后门
      if [[ "$KEEP_OPTIONS" -ne 1 && ( "$opts" == *command=* || "$opts" == *environment=* ) ]]; then
        removed=$((removed + 1))
        CHANGES+=("REMOVED_OPTION|$f|$fp|${opts:0:60}")
        continue
      fi
      if fp_allowed "$fp"; then
        printf '%s\n' "$line" >> "$tmp"
        kept=$((kept + 1))
      else
        removed=$((removed + 1))
        CHANGES+=("REMOVED_KEY|$f|$fp")
      fi
    done < "$f"
    if [[ "$removed" -eq 0 && "$kept" -gt 0 ]]; then
      ok "$f 无需变更（$kept 把全部在白名单内）"
      rm -f "$tmp"; continue
    fi
    if [[ "$kept" -eq 0 && "$removed" -eq 0 ]]; then
      ok "$f 本来就是空的，跳过"
      rm -f "$tmp"; continue
    fi
    if [[ "$kept" -eq 0 && "$FORCE" -ne 1 && -z "${ALLOW_EMPTY_FILES[$f]:-}" ]]; then
      crit "$f 清理后为空，会导致无法登录，已跳过"
      warn "你在容器终端里，清空它不会断开当前会话；如确认该账号不需要 SSH 登录，加 --force"
      rm -f "$tmp"; continue
    fi
    chmod 600 "$tmp"
    chown "$(stat -c '%u:%g' "$f" 2>/dev/null || echo 0:0)" "$tmp" 2>/dev/null || true
    if mv -f "$tmp" "$f"; then
      ok "$f 已重建：保留 $kept 把，移除 $removed 把"
      CHANGES+=("REBUILT|$f|kept=$kept removed=$removed")
    else
      crit "写入失败: $f"; rm -f "$tmp"
    fi
  done
}

apply_ssh_permissions() {
  local d f pd perm
  local -a dirs=("/root/.ssh")
  local passwd; passwd="$(P /etc/passwd)"
  if [[ -r "$passwd" ]]; then
    while IFS=: read -r _ _ uid _ _ home _; do
      [[ "$uid" =~ ^[0-9]+$ ]] || continue
      (( uid == 0 || uid >= 1000 )) || continue
      [[ -n "$home" && "$home" != "/" ]] && dirs+=("$home/.ssh")
    done < "$passwd"
  fi
  # 去重（root 和 UID=0 的隐藏账号 home 可能相同）
  local -a uniq=()
  while IFS= read -r d; do uniq+=("$d"); done < <(printf '%s\n' "${dirs[@]}" | awk '!s[$0]++')

  for d in "${uniq[@]}"; do
    pd="$(P "$d")"
    [[ -d "$pd" ]] || continue
    perm=$(stat -c '%a' "$pd" 2>/dev/null)
    if [[ "$perm" != "700" ]]; then
      chmod 700 "$pd" 2>/dev/null && CHANGES+=("CHMOD|$pd|${perm}->700")
    fi
    for f in authorized_keys authorized_keys2; do
      if [[ -f "$pd/$f" ]]; then
        chmod 600 "$pd/$f" 2>/dev/null
        chown "$(stat -c '%u:%g' "$pd")" "$pd/$f" 2>/dev/null
      fi
    done
  done
  ok "权限已收紧（.ssh 700 / authorized_keys 600）"
}

apply_sshd_hardening() {
  local cfg; cfg="$(P /etc/ssh/sshd_config)"
  [[ -f "$cfg" ]] || { warn "无 sshd_config，跳过"; return 0; }
  local b; b=$(sshd_bin) || { warn "找不到 sshd，跳过"; return 0; }

  local dropin_dir dropin
  if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$cfg"; then
    dropin_dir="$(P /etc/ssh/sshd_config.d)"
    dropin="$dropin_dir/99-incident-hardening.conf"
    mkdir -p "$dropin_dir"
  else
    dropin="$cfg"
  fi

  backup_path "$cfg"
  [[ -d "$(P /etc/ssh/sshd_config.d)" ]] && backup_path "$(P /etc/ssh/sshd_config.d)" 2>/dev/null

  local block
  block=$(cat <<'EOF'
# --- 事故加固（由 nat-ssh-cleanup.sh 生成） ---

PubkeyAuthentication yes
PermitEmptyPasswords no
AuthorizedKeysFile .ssh/authorized_keys
AuthorizedKeysCommand none
PermitUserEnvironment no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
EOF
)
  if [[ "$STRICT" -eq 1 ]]; then
    block+=$'\nAllowAgentForwarding no\nAllowTcpForwarding no\n'
  fi

  if [[ "$dropin" == "$cfg" ]]; then
    printf '\n%s\n' "$block" >> "$cfg"
  else
    printf '%s\n' "$block" > "$dropin"
  fi

  if "$b" -t 2>/dev/null; then
    ok "sshd 配置已加固并通过 sshd -t 校验（$dropin）"
    CHANGES+=("SSHD|$dropin|hardened")
  else
    crit "sshd -t 校验失败，正在回滚"
    "$b" -t 2>&1 | head -5 | while IFS= read -r l; do dim "  $l"; done
    if [[ "$dropin" == "$cfg" ]]; then
      backup_path "$cfg"
      # 用备份覆盖回去
      if [[ -f "$BACKUP_ROOT/files$cfg" ]]; then
        cp -a "$BACKUP_ROOT/files$cfg" "$cfg"
      fi
    else
      rm -f "$dropin"
    fi
    find_add HIGH SSHD-ROLLBACK "sshd 加固被回滚（配置校验失败）" "$dropin"
    return 1
  fi
  # 提示需要 reload
  warn "配置已写入，需重载才生效：$(reload_sshd_hint)"
}

apply_immutable() {
  local f n_ok=0 n_fail=0
  for f in /root/.ssh/authorized_keys "$(P /root/.ssh)"; do
    f="$(P "${f#"${PREFIX%/}"}")"
    [[ -e "$f" ]] || continue
    if chattr +i "$f" 2>/dev/null; then
      n_ok=$((n_ok + 1)); CHANGES+=("CHATTR|$f|+i")
    else
      n_fail=$((n_fail + 1))
      dim "chattr +i 失败: $f（文件系统可能不支持，如 zfs/btrfs/overlay）"
    fi
  done
  if [[ "$n_ok" -gt 0 ]]; then
    ok "已加文件锁：$n_ok 个路径（想自己改 key 前，用菜单 [5] 或 --unlock 解锁）"
  fi
  if [[ "$n_fail" -gt 0 ]]; then
    warn "有 $n_fail 个路径无法加锁（该文件系统不支持不可变属性）"
    warn "改用容器内定时巡检：$PROG --install-watchdog 5"
    find_add MED IMMUT-001 "文件系统不支持 chattr +i，需依赖定时巡检兜底" "失败 $n_fail 个"
  fi
}

apply_quarantine() {
  local f="$1" reason="$2" dest
  [[ -n "$BACKUP_ROOT" ]] || { warn "无备份目录，跳过隔离"; return 1; }
  dest="$BACKUP_ROOT/quarantine${f}"
  mkdir -p "$(dirname "$dest")"
  if mv "$f" "$dest" 2>/dev/null || { cp -a "$f" "$dest" && rm -f "$f"; }; then
    ok "已隔离: $f -> $dest ($reason)"
    CHANGES+=("QUARANTINED|$f|$dest")
    return 0
  fi
  warn "隔离失败: $f"
  return 1
}

#------------------------------------------------------------------------------
# 巡检守护：--guard（被 cron 调用） / --install-watchdog（安装）
#   chattr +i 在 overlay/zfs/btrfs 上不可用，靠这个兜底
#------------------------------------------------------------------------------
GUARD_DIR="${NAT_GUARD_DIR:-/etc/nat-ssh-guard}"
GUARD_CRON="${NAT_GUARD_CRON:-/etc/cron.d/nat-ssh-guard}"
GUARD_LOG="${NAT_GUARD_LOG:-/var/log/nat-ssh-guard.log}"
GUARD_SCRIPT="${NAT_GUARD_SCRIPT:-/usr/local/sbin/nat-ssh-cleanup.sh}"

load_guard_fps() {
  local fpfile="$GUARD_DIR/allow_fps" l
  [[ -r "$fpfile" ]] || return 1
  while IFS= read -r l; do
    l="${l%$'\r'}"
    [[ -z "${l//[[:space:]]/}" ]] && continue
    ALLOW_FPS+=("$l")
  done < "$fpfile"
  [[ ${#ALLOW_FPS[@]} -gt 0 ]]
}

# 轻量校验：只看 authorized_keys，发现未授权公钥即清除。有修复返回 1
guard_run() {
  load_guard_fps || { printf '%s [ERR] 缺少白名单 %s/allow_fps\n' "$(date '+%F %T')" "$GUARD_DIR"; return 2; }
  collect_keyfiles
  local f changed=0 alert=0 kept removed line tmp ts safe
  for f in ${KEYFILES[@]+"${KEYFILES[@]}"}; do
    tmp=$(mktemp) || continue
    kept=0; removed=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      [[ -z "${line//[[:space:]]/}" || "$line" == \#* ]] && continue
      if fp_allowed "$(key_fp "$line")"; then
        printf '%s\n' "$line" >> "$tmp"; kept=$((kept + 1))
        # 白名单内但带强制命令选项：巡检只告警，交给人判断
        if [[ "$line" == *command=* || "$line" == *environment=* ]]; then
          printf '%s [WARN] %s 中有一把白名单内的公钥带 command=/environment= 选项，请人工确认\n' \
            "$(date '+%F %T')" "$f"
          alert=1
        fi
      else
        removed=$((removed + 1))
      fi
    done < "$f"

    if [[ "$removed" -gt 0 ]]; then
      ts=$(date +%Y%m%dT%H%M%S)
      mkdir -p "$GUARD_DIR/backup"
      # 用完整路径做文件名，避免不同用户的 authorized_keys 互相覆盖
      safe=$(printf '%s' "$f" | sed 's|^/||; s|/|_|g')
      cp -a "$f" "$GUARD_DIR/backup/${safe}.$ts" 2>/dev/null
      if [[ "$kept" -eq 0 ]]; then
        # 全被清空会导致 SSH 全断，留给人判断
        printf '%s [ALERT] %s 的 %d 把公钥均不在白名单，未自动清空（避免全锁死），请人工确认\n' \
          "$(date '+%F %T')" "$f" "$removed"
        alert=1
      elif mv -f "$tmp" "$f"; then
        chmod 600 "$f" 2>/dev/null
        printf '%s [FIX] %s 清除 %d 把未授权公钥，保留 %d 把（原件备份在 %s/backup/）\n' \
          "$(date '+%F %T')" "$f" "$removed" "$kept" "$GUARD_DIR"
        changed=1
      fi
    fi
    rm -f "$tmp"
  done
  # 备份目录只保留最近 200 个，避免长期堆积
  local n; n=$(ls -1 "$GUARD_DIR/backup" 2>/dev/null | wc -l)
  if [[ "$n" -gt 200 ]]; then
    ls -1t "$GUARD_DIR/backup" 2>/dev/null | tail -n +201 \
      | while IFS= read -r f; do rm -f "$GUARD_DIR/backup/$f"; done
  fi
  (( changed == 1 || alert == 1 )) && return 1
  return 0
}

install_watchdog() {
  local mins="${1:-5}"
  [[ "$mins" =~ ^[0-9]+$ ]] && (( mins >= 1 && mins <= 59 )) || die "--install-watchdog 需要 1-59 之间的分钟数"
  [[ "$PREFIX" != "/" ]] && die "--install-watchdog 不能在 --root-prefix 模式下使用"
  if [[ ${#ALLOW_FPS[@]} -eq 0 ]]; then
    die "装巡检前必须先给出白名单：--allow-pubkey <你的公钥文件> 或 --allow-fp <指纹>"
  fi

  mkdir -p "$GUARD_DIR" || die "无法创建 $GUARD_DIR"
  chmod 700 "$GUARD_DIR"
  printf '%s\n' "${ALLOW_FPS[@]}" > "$GUARD_DIR/allow_fps"
  chmod 600 "$GUARD_DIR/allow_fps"
  ok "白名单已固化：$GUARD_DIR/allow_fps（${#ALLOW_FPS[@]} 个指纹）"

  # 脚本固化到持久路径（避免脚本在 /tmp 里被清掉）
  # 用 BASH_SOURCE 而非 $0：被 source 引入时 $0 指向调用者
  local self; self=$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "${BASH_SOURCE[0]:-$0}")
  if [[ "$self" != "$GUARD_SCRIPT" ]]; then
    mkdir -p "$(dirname "$GUARD_SCRIPT")"
    if cp -f "$self" "$GUARD_SCRIPT" 2>/dev/null; then
      chmod 755 "$GUARD_SCRIPT"
      ok "脚本已固化到 $GUARD_SCRIPT"
    else
      warn "无法写入 $GUARD_SCRIPT，巡检将引用 $self"
      GUARD_SCRIPT="$self"
    fi
  fi

  if is_alpine; then
    # Alpine 的 busybox crond 只读 /var/spool/cron/crontabs/，不读 /etc/cron.d
    local ctab; ctab="/var/spool/cron/crontabs/root"
    mkdir -p /var/spool/cron/crontabs
    touch "$ctab"; chmod 600 "$ctab"
    # 先去掉旧条目，再追加新条目
    grep -v 'nat-ssh-guard' "$ctab" 2>/dev/null > "$ctab.tmp" || true
    mv "$ctab.tmp" "$ctab"
    printf '*/%s * * * * %s --guard >> %s 2>&1\n' "$mins" "$GUARD_SCRIPT" "$GUARD_LOG" >> "$ctab"
    chmod 600 "$ctab"
    ok "已安装巡检任务：$ctab（每 ${mins} 分钟）"
  elif [[ -d "$(dirname "$GUARD_CRON")" ]]; then
    cat > "$GUARD_CRON" <<EOF
# nat-ssh-guard: 每 ${mins} 分钟校验 authorized_keys 是否被重新写入
# 由 nat-ssh-cleanup.sh --install-watchdog 生成
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/${mins} * * * * root ${GUARD_SCRIPT} --guard >> ${GUARD_LOG} 2>&1
EOF
    chmod 644 "$GUARD_CRON"
    ok "已安装巡检任务：$GUARD_CRON（每 ${mins} 分钟）"
  else
    warn "容器内没有 $(dirname "$GUARD_CRON")，无法安装定时任务"
    printf '请手动加入调度：\n  */%s * * * * root %s --guard >> %s 2>&1\n' \
      "$mins" "$GUARD_SCRIPT" "$GUARD_LOG"
    return 1
  fi

  if pgrep -x cron >/dev/null 2>&1 || pgrep -x crond >/dev/null 2>&1; then
    ok "cron 守护进程正在运行，任务会按时触发"
  else
    warn "cron 守护进程没在跑，任务不会触发，需要启动："
    case "$INIT_SYS" in
      systemd) printf '    systemctl enable --now cron\n' ;;
      openrc)  printf '    rc-update add crond default && rc-service crond start\n' ;;
      sysv)    printf '    service cron start\n' ;;
      *)       printf '    crond    # Alpine/busybox；其他系统试 /etc/init.d/cron start\n' ;;
    esac
  fi
  printf '    巡检日志：%s\n' "$GUARD_LOG"
  return 0
}

remove_cron_entries() {
  local removed=0
  if [[ -f "$GUARD_CRON" ]]; then
    rm -f "$GUARD_CRON" && { ok "已删除巡检任务 $GUARD_CRON"; removed=1; }
  fi
  # Alpine：条目嵌在 /var/spool/cron/crontabs/root 里，按行删除
  local ctab; ctab="/var/spool/cron/crontabs/root"
  if [[ -f "$ctab" ]] && grep -q 'nat-ssh-guard' "$ctab" 2>/dev/null; then
    sed -i '/nat-ssh-guard/d' "$ctab" && { ok "已从 $ctab 移除巡检条目"; removed=1; }
  fi
  (( removed == 0 )) && dim "没有找到定时巡检任务"
  return 0
}

uninstall_watchdog() {
  remove_cron_entries
  if [[ -d "$GUARD_DIR" ]]; then
    ok "保留 $GUARD_DIR（含白名单与备份），如需彻底删除请手动 rm -rf"
  else
    ok "巡检相关内容已全部移除"
  fi
  return 0
}

uninstall_all() {
  echo
  printf '卸载会删除这些东西：\n'
  printf '  %s·%s 定时巡检任务（如果装了）\n' "$C_YLW" "$C_RST"
  printf '  %s·%s 巡检目录 %s（含白名单和历史备份）\n' "$C_YLW" "$C_RST" "$GUARD_DIR"
  printf '  %s·%s 固化的脚本副本 %s\n' "$C_YLW" "$C_RST" "$GUARD_SCRIPT"
  printf '  %s·%s 脚本文件本身\n' "$C_YLW" "$C_RST"
  echo
  printf '清理加固留下的取证备份（%s）不会被删，需要的话自己处理。\n' '/var/backups/nat-ssh-incident-*'
  echo
  if ! confirm "确认卸载？"; then echo "已取消"; return 0; fi

  remove_cron_entries
  if [[ -d "$GUARD_DIR" ]]; then
    rm -rf "$GUARD_DIR" && ok "已删除巡检目录 $GUARD_DIR"
  fi
  local self; self=$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "${BASH_SOURCE[0]:-$0}")
  if [[ -f "$GUARD_SCRIPT" && "$self" != "$GUARD_SCRIPT" ]]; then
    rm -f "$GUARD_SCRIPT" && ok "已删除脚本副本 $GUARD_SCRIPT"
  fi
  if [[ -f "$self" && "$self" != "$GUARD_SCRIPT" ]]; then
    rm -f "$self" && ok "已删除脚本文件 $self"
  fi
  echo
  ok "卸载完成，本脚本装的东西已全部清理。祝顺利。"
  return 0
}

#------------------------------------------------------------------------------
# 报告
#------------------------------------------------------------------------------
report() {
  local sev id msg detail
  echo
  printf '%s================ 体检报告 ================%s\n' "$C_BLD" "$C_RST"
  printf '主机: %s   系统: %s   时间: %s\n' \
    "$(hostname 2>/dev/null || echo unknown)" "$DISTRO" "$(date '+%F %T')"
  printf '容器: %s\n' "$(cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -m1 -o 'container=[a-z]*' || echo '非容器/未知')"
  printf '合计: 严重=%s 高危=%s 中危=%s 低危=%s\n\n' \
    "$(count_sev CRIT)" "$(count_sev HIGH)" "$(count_sev MED)" "$(count_sev LOW)"

  local order=(CRIT HIGH MED LOW INFO) s
  for s in "${order[@]}"; do
    local any=0
    for f in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
      IFS=$'\t' read -r sev id msg detail <<< "$f"
      [[ "$sev" != "$s" ]] && continue
      any=1
      local color="$C_DIM"
      case "$sev" in
        CRIT) color="$C_RED" ;;
        HIGH) color="$C_YLW" ;;
        MED)  color="$C_CYN" ;;
      esac
      printf '%s[%-4s]%s %-12s %s\n' "$color" "$sev" "$C_RST" "$id" "$msg"
      [[ -n "$detail" ]] && printf '         %s\n' "$detail"
    done
    [[ "$any" -eq 1 ]] && echo
  done

  echo
  printf '%s怎么看待这些等级：%s\n' "$C_BLD" "$C_RST"
  printf '  %s严重%s = 攻击者的后门，必须马上处理\n' "$C_RED" "$C_RST"
  printf '  %s高危%s = 大概率有问题，建议处理\n' "$C_YLW" "$C_RST"
  printf '  %s中危%s = 需要你人工确认是不是自己弄的\n' "$C_CYN" "$C_RST"
  printf '  低危/提示 = 仅供参考\n'
}

json_esc() {
  # 先转义反斜杠，再转义双引号，最后压掉换行/制表
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n' | sed -e 's/\t/ /g'
}

write_json() {
  local out="$1"
  {
    printf '{\n'
    printf '  "generated": "%s",\n' "$(date -Iseconds 2>/dev/null || date '+%F %T')"
    printf '  "host": "%s",\n' "$(hostname 2>/dev/null || echo unknown)"
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "summary": {"CRIT": %s, "HIGH": %s, "MED": %s, "LOW": %s},\n' \
      "$(count_sev CRIT)" "$(count_sev HIGH)" "$(count_sev MED)" "$(count_sev LOW)"
    printf '  "findings": [\n'
    local first=1 f sev id msg detail s
    for s in CRIT HIGH MED LOW INFO; do
      for f in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
        IFS=$'\t' read -r sev id msg detail <<< "$f"
        [[ "$sev" != "$s" ]] && continue
        [[ "$first" -eq 1 ]] || printf ',\n'
        first=0
        printf '    {"severity":"%s","id":"%s","message":"%s","detail":"%s"}' \
          "$sev" "$id" "$(json_esc "$msg")" "$(json_esc "$detail")"
      done
    done
    printf '\n  ],\n'
    printf '  "changes": [\n'
    first=1
    local c
    for c in ${CHANGES[@]+"${CHANGES[@]}"}; do
      [[ "$first" -eq 1 ]] || printf ',\n'
      first=0
      printf '    "%s"' "$(json_esc "$c")"
    done
    printf '\n  ]\n}\n'
  } > "$out" 2>/dev/null || { warn "无法写入 JSON: $out"; return 1; }
  log "JSON 报告: $out"
}

#------------------------------------------------------------------------------
# 交互模式（无参数启动且是终端时自动进入）
#------------------------------------------------------------------------------
ASK_REPLY=""

hr() {
  local i line=""
  for ((i = 0; i < 64; i++)); do line+="─"; done
  printf '%s%s%s\n' "$C_DIM" "$line" "$C_RST"
}

ask() {
  local prompt="$1" def="${2:-}" reply
  if [[ -n "$def" ]]; then
    printf '%s%s%s [%s]: ' "$C_BLD" "$prompt" "$C_RST" "$def"
  else
    printf '%s%s%s: ' "$C_BLD" "$prompt" "$C_RST"
  fi
  IFS= read -r reply || return 1
  ASK_REPLY="${reply:-$def}"
  return 0
}

confirm() {
  local q="$1" r
  printf '%s%s%s (yes/no): ' "$C_YLW" "$q" "$C_RST"
  IFS= read -r r || return 1
  case "$r" in yes|y|Y|YES) return 0 ;; *) return 1 ;; esac
}

pause_key() {
  printf '%s按回车继续...%s' "$C_DIM" "$C_RST"
  IFS= read -r _ 2>/dev/null || true
  echo
}

reset_state() {
  FINDINGS=(); CHANGES=(); KEYFILES=(); ALLOW_FPS=(); ALLOW_KEYS=()
  _FSEEN=(); BAD_FPS=(); ALLOW_EMPTY_FILES=()
  FORCE=0; STRICT=0; QUARANTINE=0; QUIET=0
  JSON_OUT=""
}

print_banner() {
  echo
  printf '%s==============================================================%s\n' "$C_CYN" "$C_RST"
  printf '%s   NAT/容器 SSH 后门清理工具   v%s%s\n' "$C_CYN" "$VERSION" "$C_RST"
  printf '%s==============================================================%s\n' "$C_CYN" "$C_RST"
  printf '  系统: %s    启动方式: %s    bash: %s\n' \
    "$DISTRO" "$INIT_SYS" "${BASH_VERSION%%(*}"
  printf '  主机: %s    时间: %s\n' \
    "$(hostname 2>/dev/null || echo -)" "$(date '+%F %T')"
  if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    printf '  %s! 当前不是 root，只能做体检（1/3），清理需要 root%s\n' "$C_YLW" "$C_RST"
  fi
  local n
  for n in ${ENV_NOTES[@]+"${ENV_NOTES[@]}"}; do
    printf '  %s!%s %s\n' "$C_YLW" "$C_RST" "$n"
  done
  echo
}

print_menu() {
  hr
  printf '  %s1%s  体检        只查不改：看看系统里有没有可疑的公钥和后门\n' "$C_GRN" "$C_RST"
  printf '  %s2%s  一键清理    删掉可疑公钥 + 修好 SSH 配置 + 锁上文件\n' "$C_YLW" "$C_RST"
  printf '  %s3%s  再查一遍    清理之后，确认有没有清干净\n' "$C_CYN" "$C_RST"
  printf '  %s4%s  定时巡逻    每隔几分钟自动检查，坏公钥被写回来就删掉\n' "$C_CYN" "$C_RST"
  printf '  %s5%s  解锁文件    想自己改 SSH key 文件？先来这里解锁\n' "$C_CYN" "$C_RST"
  printf '  %s6%s  卸载        把本脚本和它装的所有东西全部删掉\n' "$C_YLW" "$C_RST"
  printf '  %s0%s  退出\n' "$C_DIM" "$C_RST"
  hr
}

# ---- 1. 体检 ----
menu_scan() {
  reset_state
  run_all_checks
  report
  if has_sev CRIT; then
    echo
    printf '%s发现严重问题（攻击者的后门）。建议接着执行 [2] 一键清理。%s\n' "$C_RED" "$C_RST"
  elif has_sev HIGH; then
    echo
    printf '%s存在高危项，建议执行 [2] 一键清理。%s\n' "$C_YLW" "$C_RST"
  fi
}

# 预检：哪些文件的公钥全部不在白名单（清理后会变空）
EMPTY_FILES=()
precheck_empty_files() {
  EMPTY_FILES=()
  local f line fp has
  for f in ${KEYFILES[@]+"${KEYFILES[@]}"}; do
    has=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      [[ -z "${line//[[:space:]]/}" || "$line" == \#* ]] && continue
      if fp_allowed "$(key_fp "$line")"; then has=1; break; fi
    done < "$f"
    [[ "$has" -eq 0 ]] && EMPTY_FILES+=("$f")
  done
}

# ---- 2. 清理 + 加固 ----
# 列出所有公钥，标注"是否真的登录过""是否带后门选项"，让用户勾选
menu_pick_keys() {
  local -a fps=() notes=() flags=()
  local -A seen=()
  local f line fp optflag fl

  for f in ${KEYFILES[@]+"${KEYFILES[@]}"}; do
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      [[ -z "${line//[[:space:]]/}" || "$line" == \#* ]] && continue
      fp=$(key_fp "$line")
      [[ -z "$fp" ]] && continue

      optflag=0
      [[ "$line" == *command=* || "$line" == *environment=* ]] && optflag=1

      if [[ -n "${seen[$fp]:-}" ]]; then
        # 同一把 key 又出现一次：若这次带危险选项，补标记到已有条目
        if [[ "$optflag" -eq 1 ]]; then
          local i
          for i in "${!fps[@]}"; do
            if [[ "${fps[$i]}" == "$fp" ]]; then
              flags[$i]+="  ${C_RED}该指纹下另有带 command=/environment= 的行（会被强制移除）${C_RST}"
            fi
          done
        fi
        continue
      fi
      seen[$fp]=1
      fps+=("$fp")
      notes+=("$(printf '%s' "$line" | awk '{print $NF}')")

      fl=""
      [[ "$optflag" -eq 1 ]] && fl+="${C_RED}带 command=/environment= 强制命令${C_RST}  "
      [[ -n "${BAD_FPS[$fp]:-}" ]] && fl+="${C_RED}曾从 $(printf '%s' "${BAD_FPS[$fp]}" | sed 's/ *$//') 成功登录过${C_RST}"
      flags+=("$fl")
    done < "$f"
  done

  if [[ ${#fps[@]} -eq 0 ]]; then
    warn "没有找到任何公钥"
    return 1
  fi

  echo
  printf '当前 authorized_keys 里共有 %s%d%s 把不同的公钥：\n\n' "$C_BLD" "${#fps[@]}" "$C_RST"
  local i short
  for i in "${!fps[@]}"; do
    short="${fps[$i]}"
    (( ${#short} > 30 )) && short="${short:0:20}...${short: -6}"
    printf '  [%s%d%s] %-34s %s\n' "$C_BLD" "$((i + 1))" "$C_RST" "$short" "${notes[$i]}"
    [[ -n "${flags[$i]}" ]] && printf '       %s%s%s\n' "$C_RED" "${flags[$i]}" "$C_RST"
  done
  echo
  printf '%s  标红的不要保留。你自己电脑上的 key 通常是唯一一把正常的。%s\n' "$C_DIM" "$C_RST"
  echo

  ALLOW_FPS=()
  if ! ask "输入要保留的编号（逗号分隔，如 1）" ""; then return 1; fi
  local input="$ASK_REPLY" p
  if [[ -n "${input//[[:space:]]/}" ]]; then
    IFS=', ' read -ra _picks <<< "$input"
    for p in "${_picks[@]}"; do
      [[ "$p" =~ ^[0-9]+$ ]] || continue
      if (( p >= 1 && p <= ${#fps[@]} )); then
        ALLOW_FPS+=("${fps[$((p - 1))]}")
      else
        warn "编号 $p 超出范围，已忽略"
      fi
    done
  fi
  [[ ${#ALLOW_FPS[@]} -gt 0 ]] && ok "将保留 ${#ALLOW_FPS[@]} 把公钥"
  return 0
}

menu_apply() {
  if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    crit "清理需要 root 权限，当前用户不是 root"
    return 1
  fi

  echo
  printf '%s[1/3] 正在扫描 ...%s\n' "$C_CYN" "$C_RST"
  reset_state
  QUIET=1
  run_all_checks
  QUIET=0

  if [[ ${#KEYFILES[@]} -eq 0 ]]; then
    warn "没有找到 authorized_keys 文件，无需清理"
    return 0
  fi

  printf '%s[2/3] 扫描完成%s：CRIT=%s  HIGH=%s  MED=%s\n' "$C_CYN" "$C_RST" \
    "$(count_sev CRIT)" "$(count_sev HIGH)" "$(count_sev MED)"
  if has_sev CRIT; then
    echo
    printf '%s高危项预览：%s\n' "$C_RED" "$C_RST"
    local f sev id msg detail shown=0
    for f in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
      IFS=$'\t' read -r sev id msg detail <<< "$f"
      [[ "$sev" != "CRIT" ]] && continue
      printf '  %s·%s %s\n' "$C_RED" "$C_RST" "$msg"
      shown=$((shown + 1))
      if [[ "$shown" -ge 8 ]]; then
        printf '  ...（完整列表请跑 [1] 体检）\n'
        break
      fi
    done
  fi

  echo
  printf '%s[3/3] 选择要保留的公钥%s\n' "$C_CYN" "$C_RST"
  menu_pick_keys || return 1

  if [[ -z "$BACKUP_ROOT" ]]; then
    BACKUP_ROOT="/var/backups/nat-ssh-incident-$(date +%Y%m%dT%H%M%S)"
  fi

  echo
  hr
  printf '即将执行：\n'
  if [[ ${#ALLOW_FPS[@]} -eq 0 ]]; then
    printf '  %s·%s 清空 authorized_keys（%s 个文件）\n' "$C_RED" "$C_RST" "${#KEYFILES[@]}"
    printf '  %s·%s 移除所有带 command=/environment= 的行\n' "$C_RED" "$C_RST"
  else
    printf '  · 重建 authorized_keys，只保留选中的 %s 把\n' "${#ALLOW_FPS[@]}"
  fi
  printf '  · 收紧 .ssh 权限（700/600）\n'
  if [[ -f "$(P /etc/ssh/sshd_config)" ]]; then
    printf '  · 加固 sshd_config（关掉后门配置项，不动你的登录方式）\n'
  fi
  printf '  · 给 .ssh 和 authorized_keys 加不可变锁\n'
  printf '  · 原件备份到 %s\n' "$BACKUP_ROOT"
  hr

  if [[ ${#ALLOW_FPS[@]} -eq 0 ]]; then
    warn "你一把都没选，authorized_keys 会被清空"
    warn "当前是容器终端，不会断线；密码登录不受影响，你还能用密码 SSH 进来"
    confirm "确认清空？" || { echo "已取消"; return 0; }
    FORCE=1
  fi

  # 预检：有些文件清理后会变空，单独确认
  precheck_empty_files
  if [[ ${#EMPTY_FILES[@]} -gt 0 ]]; then
    echo
    printf '%s以下文件里的公钥全部不在白名单，清理后会变空：%s\n' "$C_YLW" "$C_RST"
    local ef
    for ef in "${EMPTY_FILES[@]}"; do printf '  %s\n' "$ef"; done
    printf '%s  这意味着该账号之后不能用公钥 SSH 登录（容器终端不受影响，密码登录也不受影响）%s\n' "$C_DIM" "$C_RST"
    if confirm "把这些文件也清空？"; then
      for ef in "${EMPTY_FILES[@]}"; do ALLOW_EMPTY_FILES[$ef]=1; done
      ok "已授权清空 ${#EMPTY_FILES[@]} 个文件"
    else
      warn "保留原样，这些文件里的可疑公钥不会被清除"
    fi
  fi

  # 是否顺带隔离持久化后门
  local has_persist=0 f sev id msg detail
  for f in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
    IFS=$'\t' read -r sev id msg detail <<< "$f"
    [[ "$sev" != "CRIT" ]] && continue
    case "$id" in PERSIST-*|RC-*|PAM-*|LIB-*) has_persist=1; break ;; esac
  done
  if [[ "$has_persist" -eq 1 ]]; then
    echo
    printf '%s发现 cron / systemd / PAM / rc 等持久化后门。%s\n' "$C_YLW" "$C_RST"
    printf '隔离 = 复制到备份区后删除原文件（不是硬删，可以还原）\n'
    if confirm "同时隔离这些文件？"; then
      QUARANTINE=1
      ok "将隔离命中的持久化文件"
    else
      warn "跳过，只清理 authorized_keys"
    fi
  fi

  echo
  if ! confirm "开始执行？"; then echo "已取消"; return 0; fi

  if ! mkdir -p "$BACKUP_ROOT" 2>/dev/null; then
    BACKUP_ROOT="/root/nat-ssh-incident-$(date +%Y%m%dT%H%M%S)"
    mkdir -p "$BACKUP_ROOT" || { crit "无法创建备份目录，已中止"; return 1; }
  fi
  chmod 700 "$BACKUP_ROOT"
  : > "$BACKUP_ROOT/sha256-manifest.txt"
  {
    echo "incident_time: $(date '+%F %T %Z')"
    echo "hostname: $(hostname 2>/dev/null)"
    echo "kernel: $(uname -a 2>/dev/null)"
    echo "uid: $(id 2>/dev/null)"
    echo "container: $CONTAINER_KIND"
  } > "$BACKUP_ROOT/context.txt"

  echo
  apply_authorized_keys
  apply_ssh_permissions
  apply_sshd_hardening

  if [[ "$QUARANTINE" -eq 1 ]]; then
    local path
    for f in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
      IFS=$'\t' read -r sev id msg detail <<< "$f"
      [[ "$sev" != "CRIT" ]] && continue
      case "$id" in
        PERSIST-*|RC-*|PAM-*|LIB-*)
          path="${detail%%:*}"
          path="${path%% |*}"
          if [[ -f "$path" ]]; then
            backup_path "$path"
            apply_quarantine "$path" "$id"
          fi
          ;;
      esac
    done
  fi

  apply_immutable

  echo
  hr
  printf '%s变更摘要%s\n' "$C_BLD" "$C_RST"
  if [[ ${#CHANGES[@]} -eq 0 ]]; then
    echo "  无变更"
  else
    local c
    for c in "${CHANGES[@]}"; do echo "  $c"; done
  fi
  printf '\n  取证备份: %s\n' "$BACKUP_ROOT"
  hr

  if [[ -f "$(P /etc/ssh/sshd_config)" ]] && sshd_bin >/dev/null 2>&1; then
    echo
    if confirm "现在重载 sshd 让配置生效？（$(reload_sshd_hint)）"; then
      local rcmd; rcmd=$(reload_sshd_hint)
      if bash -c "$rcmd" >/dev/null 2>&1; then ok "已重载"; else warn "重载命令失败，请手动执行: $rcmd"; fi
      if "$(sshd_bin)" -t 2>/dev/null; then ok "sshd 配置校验通过"; else crit "sshd 配置校验失败！请立刻检查"; fi
    else
      warn "未重载，配置暂不生效。稍后手动执行: $(reload_sshd_hint)"
    fi
  fi

  echo
  printf '%s强烈建议接下来做的事：%s\n' "$C_BLD" "$C_RST"
  printf '  1. 轮换所有 SSH 密钥 —— 攻击者已经能读文件，私钥当已泄露\n'
  printf '  2. 去你的云平台面板改 root 密码（脚本不替你改，密码登录设置也没动）\n'
  printf '  3. 用 [4] 定时巡逻，防止入口没堵住、坏公钥又被写回来\n'
}

# ---- 3. 复查 ----
do_verify() {
  local f b eff
  echo
  printf '%s================ 复查 ================%s\n' "$C_BLD" "$C_RST"
  for f in /root/.ssh/authorized_keys /root/.ssh; do
    f="$(P "$f")"
    [[ -e "$f" ]] || continue
    local attr; attr=$(lsattr -d "$f" 2>/dev/null | awk '{print $1}')
    if [[ "$attr" == *i* ]]; then ok "不可变属性生效: $f"; else warn "未加锁: $f"; fi
  done
  b=$(sshd_bin)
  if [[ -n "$b" ]]; then
    if "$b" -t 2>/dev/null; then ok "sshd 配置语法正常"; else crit "sshd 配置异常"; fi
  fi
  eff=$(sshd_effective)
  if [[ -n "$eff" ]]; then
    printf 'SSH 服务生效配置: PubkeyAuthentication=%s  PermitUserEnvironment=%s\n' \
      "$(printf '%s\n' "$eff" | awk '$1=="pubkeyauthentication"{print $2}')" \
      "$(printf '%s\n' "$eff" | awk '$1=="permituserenvironment"{print $2}')"
  fi
  reset_state
  QUIET=1
  collect_keyfiles
  QUIET=0
  if [[ ${#KEYFILES[@]} -eq 0 ]]; then
    warn "没有任何 authorized_keys 文件"
  else
    local nf nk
    nf=${#KEYFILES[@]}
    nk=$(cat "${KEYFILES[@]}" 2>/dev/null | grep -vcE '^[[:space:]]*(#|$)' || echo 0)
    printf 'authorized_keys: %s 个文件，共 %s 把公钥\n' "$nf" "$nk"
  fi
  if [[ -f "$GUARD_CRON" ]]; then
    ok "巡检任务已安装: $GUARD_CRON"
  else
    warn "未安装巡检任务"
  fi
}

# ---- 4. 定时巡逻 ----
menu_watchdog() {
  local m iv
  while true; do
    echo
    hr
    printf '  %s定时巡逻%s\n' "$C_BLD" "$C_RST"
    hr
    if [[ -f "$GUARD_CRON" ]] || (is_alpine && grep -q 'nat-ssh-guard' /var/spool/cron/crontabs/root 2>/dev/null); then
      printf '  当前状态: %s已安装%s  (每隔几分钟自动检查一次)\n' "$C_GRN" "$C_RST"
      if [[ -f "$GUARD_CRON" ]]; then
        iv=$(grep -oE '^\*/[0-9]+' "$GUARD_CRON" 2>/dev/null | head -1)
        [[ -n "$iv" ]] && printf '  执行间隔: 每 %s 分钟\n' "${iv#\*/}"
      else
        iv=$(grep -oE '^\*/[0-9]+ .*nat-ssh-guard' /var/spool/cron/crontabs/root 2>/dev/null | head -1)
        [[ -n "$iv" ]] && printf '  执行间隔: 每 %s 分钟\n' "${iv#\*/}"
      fi
    else
      printf '  当前状态: %s未安装%s\n' "$C_DIM" "$C_RST"
    fi
    echo
    printf '  %s1%s  安装（每 5 分钟自动检查）\n' "$C_GRN" "$C_RST"
    printf '  %s2%s  自己定间隔安装\n' "$C_CYN" "$C_RST"
    printf '  %s3%s  看看最近的巡逻记录\n' "$C_CYN" "$C_RST"
    printf '  %s4%s  卸载定时巡逻（只删定时任务，保留脚本）\n' "$C_RED" "$C_RST"
    printf '  %s0%s  返回主菜单\n' "$C_DIM" "$C_RST"
    hr
    ask "输入编号选择" "0" || return 0
    case "$ASK_REPLY" in
      1)
        reset_state
        echo
        printf '先选一把你自己的公钥，脚本靠它判断哪些 key 是坏的。\n'
        QUIET=1; run_all_checks; QUIET=0
        if [[ ${#KEYFILES[@]} -eq 0 ]]; then
          warn "没有找到 authorized_keys，无法确定白名单"
        elif menu_pick_keys; then
          [[ ${#ALLOW_FPS[@]} -gt 0 ]] && install_watchdog 5
        fi
        ;;
      2)
        ask "间隔多少分钟（1-59）" "10" || return 0
        m="$ASK_REPLY"
        if [[ ! "$m" =~ ^[0-9]+$ ]] || (( m < 1 || m > 59 )); then
          warn "需要 1-59 之间的整数"
        else
          reset_state
          QUIET=1; run_all_checks; QUIET=0
          if [[ ${#KEYFILES[@]} -gt 0 ]] && menu_pick_keys; then
            [[ ${#ALLOW_FPS[@]} -gt 0 ]] && install_watchdog "$m"
          fi
        fi
        ;;
      3)
        if [[ -f "$GUARD_LOG" ]]; then
          echo
          printf '%s最近 20 条巡逻记录：%s\n' "$C_BLD" "$C_RST"
          tail -20 "$GUARD_LOG"
        else
          warn "还没有巡逻记录（$GUARD_LOG）"
        fi
        ;;
      4)
        if confirm "确认卸载定时巡逻？（只删定时任务，脚本还留着）"; then uninstall_watchdog; fi
        ;;
      0) return 0 ;;
      *) warn "没有这个选项" ;;
    esac
    pause_key
  done
}

# ---- 5. 解锁 ----
menu_unlock() {
  echo
  printf '解锁后才能自己修改 .ssh 下的文件（比如换 key）。改完记得重新加锁。\n\n'
  if ! confirm "确认解锁？"; then echo "已取消"; return 0; fi
  local f
  for f in /root/.ssh/authorized_keys /root/.ssh; do
    f="$(P "$f")"
    [[ -e "$f" ]] || continue
    if chattr -i "$f" 2>/dev/null; then ok "已解锁 $f"; else warn "解锁失败 $f"; fi
  done
  echo
  printf '%s改完 key 之后，重新跑 [2] 一键清理 就会再次上锁。%s\n' "$C_DIM" "$C_RST"
}

interactive_main() {
  trap 'echo; echo "已中断。"; exit 130' INT
  reset_state
  print_banner

  while true; do
    print_menu
    if ! ask "输入编号选择（直接回车默认 1）" "1"; then echo; break; fi
    case "$ASK_REPLY" in
      1) menu_scan ;;
      2) menu_apply ;;
      3) do_verify ;;
      4) menu_watchdog ;;
      5) menu_unlock ;;
      6) menu_uninstall ;;
      0|q|Q|exit) break ;;
      *) warn "没有这个选项：$ASK_REPLY（输入 0-6 的编号）" ;;
    esac
    pause_key
  done
  printf '\n已退出。\n'
  return 0
}

#------------------------------------------------------------------------------
# 采集流程（CLI 与交互模式共用）
#------------------------------------------------------------------------------
run_all_checks() {
  log "扫描 authorized_keys ..."
  collect_keyfiles
  check_authorized_keys
  log "扫描 .ssh 目录 ..."
  check_ssh_dir
  log "扫描账号与 sudoers ..."
  check_accounts
  log "扫描 sshd 配置 ..."
  check_sshd_config
  log "扫描 SSH 主机密钥 ..."
  check_hostkeys
  log "扫描持久化项（cron/systemd/rc/apt）..."
  check_persistence
  log "扫描 shell 启动脚本 ..."
  check_shell_rc
  log "扫描动态库与 PAM ..."
  check_preload_pam
  log "扫描可疑文件 ..."
  check_suspicious_files
  log "扫描网络监听 ..."
  check_network
  log "分析认证日志 ..."
  check_auth_logs
}

#------------------------------------------------------------------------------
# 主流程
#------------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply)      MODE="apply"; shift ;;
      --verify)     MODE="verify"; shift ;;
      --unlock)     MODE="unlock"; shift ;;
      --guard)      MODE="guard"; shift ;;
      -i|--interactive) MODE="interactive"; shift ;;
      --uninstall)  MODE="uninstall"; shift ;;
      --uninstall-watchdog) MODE="uninstall-watchdog"; shift ;;
      --install-watchdog)
        MODE="install-watchdog"
        if [[ "${2:-}" =~ ^[0-9]+$ ]]; then WATCHDOG_MIN="$2"; shift 2; else WATCHDOG_MIN=5; shift; fi ;;
      --force)      FORCE=1; shift ;;
      --strict)     STRICT=1; shift ;;
      --keep-options) KEEP_OPTIONS=1; shift ;;
      --quarantine) QUARANTINE=1; shift ;;
      --allow-fp)
        [[ -z "${2:-}" ]] && die "--allow-fp 需要参数"
        IFS=',' read -ra _fps <<< "$2"
        ALLOW_FPS+=("${_fps[@]}"); shift 2 ;;
      --allow-pubkey)
        [[ -z "${2:-}" ]] && die "--allow-pubkey 需要参数"
        load_allow_keys "$2"; shift 2 ;;
      --backup-dir)
        [[ -z "${2:-}" ]] && die "--backup-dir 需要参数"
        BACKUP_ROOT="$2"; shift 2 ;;
      --json)
        [[ -z "${2:-}" ]] && die "--json 需要参数"
        JSON_OUT="$2"; shift 2 ;;
      --root-prefix)
        [[ -z "${2:-}" ]] && die "--root-prefix 需要参数"
        PREFIX="$2"; shift 2 ;;
      -h|--help)    usage; exit 0 ;;
      *) die "未知参数: $1（--help 查看用法）" ;;
    esac
  done
}

main() {
  local nargs=$#
  parse_args "$@"

  [[ -r "$(P /etc/passwd)" ]] || die "找不到 $(P /etc/passwd)，请在 Linux 容器内运行"
  if [[ "$PREFIX" != "/" && "$MODE" == "apply" ]]; then
    die "--root-prefix 模式只读，不允许 --apply"
  fi
  if [[ "$MODE" =~ ^(apply|install-watchdog|uninstall-watchdog|unlock|uninstall)$ \
        && "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    die "$MODE 需要 root 权限"
  fi

  check_env

  # 无参数 + 终端 → 交互菜单（脚本化调用仍走 CLI）
  if [[ "$nargs" -eq 0 && "$MODE" == "scan" && -t 0 && -t 1 ]]; then
    interactive_main
    exit 0
  fi

  # 巡检/安装类模式：静默执行，不打印体检报告
  case "$MODE" in
    interactive)
      interactive_main; exit $? ;;
    guard)
      guard_run; exit $? ;;
    uninstall)
      printf '%sNAT SSH 清理脚本卸载  v%s%s\n' "$C_BLD" "$VERSION" "$C_RST"
      uninstall_all; exit $? ;;
    install-watchdog)
      printf '%sNAT SSH 定时巡逻安装  v%s%s\n' "$C_BLD" "$VERSION" "$C_RST"
      install_watchdog "${WATCHDOG_MIN:-5}"; exit $? ;;
    uninstall-watchdog)
      remove_cron_entries
      if [[ -d "$GUARD_DIR" ]]; then
        ok "保留 $GUARD_DIR（含白名单与备份），如需彻底删除用 --uninstall"
      else
        ok "巡检相关内容已全部移除"
      fi
      exit $? ;;
  esac

  printf '%sNAT/容器 SSH 后门清理与加固  v%s%s\n' "$C_BLD" "$VERSION" "$C_RST"
  printf '容器类型: %s   init: %s   模式: %s\n' "$CONTAINER_KIND" "$INIT_SYS" "$MODE"
  if [[ ${#ENV_NOTES[@]} -gt 0 ]]; then
    local _n
    for _n in "${ENV_NOTES[@]}"; do warn "$_n"; done
  fi

  # --unlock
  if [[ "$MODE" == "unlock" ]]; then
    local f
    for f in /root/.ssh/authorized_keys /root/.ssh; do
      f="$(P "$f")"
      [[ -e "$f" ]] || continue
      if chattr -i "$f" 2>/dev/null; then ok "已解锁 $f"; else warn "解锁失败 $f"; fi
    done
    warn "改完 key 记得重新执行 --apply 或手动 chattr +i 加锁"
    exit 0
  fi

  # 备份目录
  if [[ "$MODE" == "apply" ]]; then
    BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/nat-ssh-incident-$TS}"
    mkdir -p "$BACKUP_ROOT" || die "无法创建备份目录 $BACKUP_ROOT"
    chmod 700 "$BACKUP_ROOT"
    : > "$BACKUP_ROOT/sha256-manifest.txt"
    log "取证备份目录: $BACKUP_ROOT"
    {
      echo "incident_time: $(date '+%F %T %Z')"
      echo "hostname: $(hostname 2>/dev/null)"
      echo "kernel: $(uname -a 2>/dev/null)"
      echo "uid: $(id 2>/dev/null)"
    } > "$BACKUP_ROOT/context.txt"
  fi

  # ---- 采集 ----
  run_all_checks
  report

  # ---- 处置 ----
  if [[ "$MODE" == "apply" ]]; then
    echo
    printf '%s================ 处置 ================%s\n' "$C_BLD" "$C_RST"
    if [[ "$(count_sev CRIT)" -gt 0 || "$(count_sev HIGH)" -gt 0 ]]; then
      warn "检测到高危项，开始处置"
    fi
    apply_authorized_keys
    apply_ssh_permissions
    apply_sshd_hardening

    # 持久化隔离（仅 --quarantine）
    if [[ "$QUARANTINE" -eq 1 ]]; then
      local f sev id msg detail
      for f in ${FINDINGS[@]+"${FINDINGS[@]}"}; do
        IFS=$'\t' read -r sev id msg detail <<< "$f"
        [[ "$sev" != "CRIT" ]] && continue
        case "$id" in
          PERSIST-*|RC-*|PAM-*|LIB-*)
            local path="${detail%%:*}"
            path="${path%% |*}"
            if [[ -f "$path" ]]; then
              backup_path "$path"
              apply_quarantine "$path" "$id"
            fi
            ;;
        esac
      done
    elif [[ "$(count_sev CRIT)" -gt 0 ]]; then
      warn "存在 CRIT 级持久化项，但未加 --quarantine，仅报告不隔离"
      warn "确认无误后执行：$PROG --apply --quarantine --allow-pubkey <你的公钥>"
    fi

    apply_immutable

    echo
    printf '%s================ 变更摘要 ================%s\n' "$C_BLD" "$C_RST"
    if [[ ${#CHANGES[@]} -eq 0 ]]; then
      echo "无变更"
    else
      local c
      for c in "${CHANGES[@]}"; do echo "  $c"; done
    fi
    echo
    printf '取证备份: %s\n' "$BACKUP_ROOT"
    printf '清单文件: %s\n' "$BACKUP_ROOT/sha256-manifest.txt"
  fi

  # ---- 复查 ----
  if [[ "$MODE" == "verify" ]]; then
    do_verify
  fi

  [[ -n "$JSON_OUT" ]] && write_json "$JSON_OUT"

  echo
  if has_sev CRIT; then
    crit "发现 $(count_sev CRIT) 个严重问题（攻击者后门），必须处理"
    printf '下一步：\n'
    printf '  1. 先确认你的公钥指纹，然后执行 --apply --allow-pubkey <文件>\n'
    printf '  2. 装定时巡逻兜底：%s --install-watchdog 5\n' "$PROG"
    printf '  3. 去云平台面板改 root 密钥与密码\n'
    exit 1
  fi
  if has_sev HIGH; then
    warn "发现 $(count_sev HIGH) 个高危问题，建议尽快处理"
    exit 0
  fi
  ok "没有发现问题，系统看起来是干净的"
  exit 0
}

# 仅在直接执行时运行 main（被 source / bash -c 时只暴露函数，便于单元测试）
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
  main "$@"
fi
