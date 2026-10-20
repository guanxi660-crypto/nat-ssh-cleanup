# nat-ssh-cleanup.sh

LXD / LXC 容器内 SSH 后门清理与加固脚本。**在容器终端里直接执行**，不需要在宿主机上跑任何东西。

针对场景：攻击者拿到宿主机权限后进入容器，往 `/root/.ssh/authorized_keys`（或其他用户）写公钥，建立持久化 SSH 访问。

单文件、无外部依赖（bash 4+ / awk / sed / find），默认只读，`--apply` 才动手。**支持 Debian / Ubuntu / CentOS / Alpine**。

> 本脚本**完全不碰密码登录设置**（`PermitRootLogin` / `PasswordAuthentication` 一律不动），不会因为你跑了这个脚本而把自己锁在外面。

---

## 快速启动

拿到容器终端，**一条命令**，复制粘贴回车就完事：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/guanxi660-crypto/nat-ssh-cleanup/main/nat-ssh-cleanup.sh)"
```

直接进交互菜单，跟着提示走就行：

```
==============================================================
   NAT/容器 SSH 后门清理工具   v1.3.0
==============================================================
  系统: debian    启动方式: systemd    bash: 5.1.16
  主机: web-01    时间: 2026-10-20 18:30:00

────────────────────────────────────────────────────────────────
  1  体检        只查不改：看看系统里有没有可疑的公钥和后门
  2  一键清理    删掉可疑公钥 + 修好 SSH 配置 + 锁上文件
  3  再查一遍    清理之后，确认有没有清干净
  4  定时巡逻    每隔几分钟自动检查，坏公钥被写回来就删掉
  5  解锁文件    想自己改 SSH key 文件？先来这里解锁
  6  卸载        把本脚本和它装的所有东西全部删掉
  0  退出
────────────────────────────────────────────────────────────────
输入编号选择（直接回车默认 1）:
```

**正常流程就是 `1` → 看报告 → `2` → 按提示选自己的公钥 → 确认 → `4` 装定时巡逻。**


清理时会把你所有的公钥列出来，标出哪些有问题，你勾选保留哪几把：

```
当前 authorized_keys 里共有 2 把不同的公钥：

  [1] SHA256:y3PkXsixrzpcE...G/anDY      jack@macbook
  [2] SHA256:rcHM5oW2w9JeX...IJICDQ      root@kali
       曾从 45.9.148.37 成功登录过  该指纹下另有带 command=/environment= 的行（会被强制移除）

  标红的不要保留。你自己电脑上的 key 通常是唯一一把正常的。

输入要保留的编号（逗号分隔，如 1）:
```

`[2]` 这种标红的，要么真的从陌生 IP 登录过，要么带 `command=` 后门选项 —— 都是攻击者的。

---

## 交互模式菜单说明

| 选项 | 做什么 | 会改文件吗 |
|---|---|---|
| **1 体检** | 跑全部 11 组检查，输出分级报告 | 否 |
| **2 一键清理** | 列出所有公钥供你勾选 → 重建 authorized_keys → 收紧权限 → 加固 sshd → 加文件锁 → 可选隔离持久化后门 | 是，全程有确认 |
| **3 再查一遍** | 检查锁是否还在、sshd 配置是否正常、当前有几把 key | 否 |
| **4 定时巡逻** | 安装 / 自己定间隔 / 看记录 / 卸载定时巡逻 | 写 cron 和 `/etc/nat-ssh-guard/` |
| **5 解锁文件** | `chattr -i`，想自己改 key 前先来做 | 是 |
| **6 卸载** | 删除定时巡逻、巡检目录、脚本副本和脚本文件本身 | 是，有确认 |

`2` 的确认环节一共三道：选公钥 → 是否隔离持久化文件 → 是否开始执行。任何一步答 `no` 都会安全退出，不做修改。

---

## 命令行用法（脚本化 / 自动化）

不想走菜单就传参数，行为完全一样：

```bash
# 只体检
bash nat-ssh-cleanup.sh

# 清理 + 加固，保留指定指纹
bash nat-ssh-cleanup.sh --allow-fp SHA256:你的指纹 --apply --quarantine

# 用自己的公钥文件，省去算指纹
bash nat-ssh-cleanup.sh --allow-pubkey /root/my.pub --apply

# 再查一遍
bash nat-ssh-cleanup.sh --verify

# 卸载本脚本和它装的所有东西
bash nat-ssh-cleanup.sh --uninstall
```

指纹怎么拿：

```bash
ssh-keygen -lf ~/.ssh/id_ed25519.pub
# 256 SHA256:bQHEjQ8eUSt0hasVyo8jIehZ67pE1wzOOWf5YViQ+MM jack@laptop (ED25519)
#            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 这一段
```

装定时巡逻兜底（防止入口没堵住、几分钟后又被写回来）：

```bash
bash /root/nat-ssh-cleanup.sh --install-watchdog 5
```

> 无参数 + 终端 → 进菜单；无参数 + 管道/重定向 → 走体检（方便写进自动化脚本不会卡住）。

---

## 详细步骤

### 1. 把脚本弄进容器

容器有外网，一条命令搞定：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/guanxi660-crypto/nat-ssh-cleanup/main/nat-ssh-cleanup.sh)"
```

这条命令跑完直接进菜单，脚本不落盘。想留下脚本就用备选：

```bash
curl -fsSL https://raw.githubusercontent.com/guanxi660-crypto/nat-ssh-cleanup/main/nat-ssh-cleanup.sh \
  -o /root/nat-ssh-cleanup.sh && bash /root/nat-ssh-cleanup.sh
```

没外网就在容器终端里直接粘贴（`cat` 到文件，避免终端转义问题）：

```bash
cat > /root/nat-ssh-cleanup.sh <<'SCRIPT_EOF'
...（把脚本全文粘进来）...
SCRIPT_EOF
chmod 700 /root/nat-ssh-cleanup.sh
```

或者从宿主机推（在宿主机执行，不属于本脚本职责，仅备选）：

```bash
lxc file push nat-ssh-cleanup.sh <容器名>/root/
```

### 2. 先体检，什么都别改

```bash
bash /root/nat-ssh-cleanup.sh
```

默认就是只查不改，只输出报告，不动任何文件。

### 3. 确认你自己的公钥指纹

```bash
ssh-keygen -lf ~/.ssh/id_ed25519.pub
```

或者直接把公钥文件传进容器，用 `--allow-pubkey` 让脚本自己算：

```bash
bash /root/nat-ssh-cleanup.sh --allow-pubkey /root/my.pub --apply
```

### 4. 清理 + 加固

```bash
bash /root/nat-ssh-cleanup.sh \
  --allow-fp SHA256:bQHEjQ8eUSt0hasVyo8jIehZ67pE1wzOOWf5YViQ+MM \
  --apply \
  --quarantine
```

### 5. 装定时巡逻兜底

```bash
bash /root/nat-ssh-cleanup.sh --install-watchdog 5
```

每 5 分钟校验一次 `authorized_keys`，发现被重新写入就自动清掉并记日志到 `/var/log/nat-ssh-guard.log`。

### 6. 用完想卸载

菜单里选 `6`，或者：

```bash
bash /root/nat-ssh-cleanup.sh --uninstall
```

会删掉定时巡逻、巡检目录（`/etc/nat-ssh-guard/`）、固化到 `/usr/local/sbin/` 的脚本副本和脚本文件本身。清理时留在 `/var/backups/` 的取证备份不会被删。

---

## 检查项一览

| ID 前缀 | 查什么 | 默认动作 |
|---|---|---|
| `SSH-KEY-*` | `authorized_keys` 里的每一把公钥，逐把算指纹比对白名单；检测 `command=` / `environment=` 等注入选项 | **自动重建**（只留白名单） |
| `SSH-DIR-*` | `.ssh` 目录权限、`.ssh/rc`、`.ssh/environment`、`.ssh/config` 里的 `ProxyCommand`/`LocalCommand`、`authorized_keys.bak` 等残留 | 只报告 |
| `ACC-*` | UID=0 的非 root 账号、空密码、sudoers 里的 `NOPASSWD` | 只报告 |
| `SSH-CFG-*` | `AuthorizedKeysFile` 被改到 `/tmp` 之类、`AuthorizedKeysCommand` 被启用、drop-in 目录里的高风险指令 | **自动加固**（密码登录设置不动） |
| `HOSTKEY-*` | SSH 主机密钥近 7 天内被重新生成、`/etc/ssh/ssh_config` 里的 `ProxyCommand` | 只报告 |
| `PERSIST-*` | cron / systemd unit / rc.local / init.d / if-up.d / apt 钩子 / at 任务里的 `curl\|bash`、`/dev/tcp`、`base64 -d` 等特征 | 只报告，`--quarantine` 才隔离 |
| `RC-*` | `/etc/profile`、`profile.d/*`、各用户 `.bashrc`/`.profile` 里的注入；`/etc/environment` 里的 `LD_PRELOAD` | 只报告，`--quarantine` 才隔离 |
| `LIB-*` / `PAM-*` | `/etc/ld.so.preload` 非空、库路径指向 `/tmp`、PAM 里的 `pam_exec.so` | 只报告，`--quarantine` 才隔离 |
| `FILE-*` | `/tmp`、`/var/tmp`、`/dev/shm` 里的 ELF 与可执行脚本；近 14 天新增的 SUID | 只报告 |
| `NET-*` | sshd 监听在非 22 端口、4444/31337 等反弹 shell 常用端口 | 只报告 |
| `LOG-*` | **认证日志里哪些公钥指纹成功登录过、从哪个 IP** —— 这是判断哪把是攻击者 key 最硬的证据 | 只报告 |

最后一项很关键：`/var/log/auth.log` 里的 `Accepted publickey ... SHA256:xxx` 会直接告诉你攻击者用的是哪把 key、从哪个 IP 进来的。如果那个指纹不在你的白名单里，脚本会标成 CRIT。

---

## 加固动作（`--apply` 时执行）

| 动作 | 说明 |
|---|---|
| 重建 `authorized_keys` | 只保留白名单指纹对应的行，权限 `600`，属主不变 |
| 收紧 `.ssh` 权限 | 目录 `700`，文件 `600` |
| 加固 `sshd_config` | 写入 `/etc/ssh/sshd_config.d/99-incident-hardening.conf`：`AuthorizedKeysCommand none`、`PermitUserEnvironment no`、`MaxAuthTries 3` 等；**改完必须 `sshd -t` 通过，否则自动回滚**。密码登录设置（`PermitRootLogin` / `PasswordAuthentication`）完全不动 |
| 加不可变属性 | `chattr +i` 锁住 `/root/.ssh` 和 `authorized_keys`，防止再次写入 |
| 取证备份 | 全部落在 `/var/backups/nat-ssh-incident-<时间>/`，附 `sha256-manifest.txt` |

`--strict` 会额外关掉 TCP 转发和 Agent 转发，可能影响正常运维，按需开。

---

## 参数

```
-i, --interactive       交互式菜单（无参数启动时自动进入）
--apply                 实际执行清理与加固（默认只体检）
--verify                复查模式：确认清理项仍然生效
--unlock                解除 chattr 不可变锁（改 key 前必须先解锁）
--uninstall             卸载本脚本和它安装的所有东西（巡检、配置、脚本文件）
--guard                 轻量巡检，只查 authorized_keys（供 cron 调用）
--install-watchdog [N]  安装定时巡检，默认每 5 分钟
--uninstall-watchdog    移除定时巡检任务（保留脚本）
--allow-fp FP[,FP...]   可信公钥指纹，逗号分隔
--allow-pubkey FILE     可信公钥文件（每行一个），自动提取指纹
--quarantine            隔离命中的持久化文件（复制到备份区后删除原文件）
--strict                额外禁用 TCP/Agent 转发
--keep-options          保留 authorized_keys 里带 command=/environment= 的行
                        （默认视为后门移除，只有确认是自有运维用法才开）
--force                 无白名单也强制执行（会清空 authorized_keys）
--backup-dir DIR        自定义取证备份目录
--json FILE             额外输出 JSON 报告
--root-prefix DIR       分析离线快照（只读，禁止 --apply）
```

退出码：`0` 无高危 / `1` 存在 CRIT / `2` 参数或环境错误。

---

## 处置完之后必须做的事

脚本能清掉文件，但清不掉已经泄露的东西：

1. **轮换所有 SSH 密钥**。攻击者已经能读文件，你机器上的私钥、`~/.ssh/id_*`、部署用的 key 全部当作已泄露。
2. **改密码**，包括 root 和所有业务账号，以及容器里配的任何 API Token、数据库口令。脚本不会替你改，密码登录设置（`PermitRootLogin` / `PasswordAuthentication`）也完全不动，由你自己决定。
3. **重载 sshd** 让加固生效（脚本会提示具体命令，Debian/Ubuntu 容器通常是 `systemctl reload ssh`，Alpine 是 `rc-service sshd reload`）。
4. **复查**：`bash /root/nat-ssh-cleanup.sh --verify`。
5. 如果容器里跑的是业务服务，**评估是否需要重建容器**。清理只能处理已知的落地点，rootkit 和内存马不在这个脚本的覆盖范围内 —— 拿不准就重建。

---

## 常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| `chattr +i` 失败，提示 Operation not supported | 容器的 overlayfs / zfs / btrfs 不支持不可变属性 | 脚本会自动降级并提示用 `--install-watchdog`，靠定时巡逻兜底 |
| `需要 bash 4.0+` | Alpine 容器默认只有 ash | `apk add --no-cache bash`，装完再跑 |
| `--apply` 被拒绝：未提供可信公钥白名单 | 防误清空把自己锁死 | 加 `--allow-pubkey` 或 `--allow-fp`；确认不要 SSH 登录可加 `--force` |
| 装了定时巡逻但不触发 | 容器里 cron 没在跑（LXC 容器常见） | Debian/Ubuntu: `service cron start`；Alpine: `rc-update add crond default && rc-service crond start` |
| 改完 key 改不动了 | `chattr +i` 生效了 | 先菜单 `5`（或 `--unlock`）解锁，改完再跑一次 `--apply` 重新上锁 |
| `无 ssh-keygen` | 精简镜像没装 openssh-client | 指纹降级为 sha256 比对，建议 `apk add openssh-client`（Alpine）或 `apt install openssh-client`（Debian/Ubuntu） |
| Alpine 上定时巡逻没生效 | busybox crond 不读 `/etc/cron.d` | 脚本已自动把任务装到 `/var/spool/cron/crontabs/root`，无需手动处理 |

---

## Alpine 支持

v1.3.0 起原生支持 Alpine：

1. **先装 bash**（Alpine 默认只有 ash）：

```bash
apk add --no-cache bash
```

2. 然后照常跑快速启动的那条命令即可。

脚本会自动适配 Alpine 的差异：

| 差异点 | 脚本的处理 |
|---|---|
| init 系统是 OpenRC（不是 systemd） | 重载 SSH 服务用 `rc-service sshd reload` |
| busybox crond 不读 `/etc/cron.d` | 定时巡逻任务自动装到 `/var/spool/cron/crontabs/root` |
| 定时任务目录是 `/etc/periodic/*` | 后门扫描会检查 `/etc/periodic/` 下的目录 |
| 没装 `ss`（iproute2） | 自动降级用 busybox 自带的 `netstat` |
| 精简镜像缺命令（chattr / ssh-keygen 等） | 自动降级并在启动时提示 |

---

## 说明

脚本只处理容器内部。它能清掉已经写进去的东西，但**攻击者是从容器外面进来的，清完之后如果入口还在，几分钟内就会被重新写一遍**。这就是 `--install-watchdog` 存在的意义：至少让下一次写入留下时间戳和备份。
