# -*- coding: utf-8 -*-
"""
SENTINEL / Linux IR  --  检查项知识库
覆盖 CTF / 实战应急中 Linux 主机侧高频考点：
影子账号、SSH 公钥后门、计划任务/启动项、SUID 与 capabilities、挖矿进程、
反弹 Shell、WebShell、Nginx/Tomcat/MySQL/PHP 配置缺陷、权限与加固、日志痕迹。

每一项 = 若干条只读命令 + 一个解析规则 -> 结构化「发现」(说明 + 证据 + 整改方案)
"""
import re

# ------------------------------------------------------------------ 模块定义
MODULES = [
    {"id": "identity",    "name": "目标画像",     "code": "01", "color": "#38bdf8"},
    {"id": "accounts",    "name": "账号与提权",   "code": "02", "color": "#a78bfa"},
    {"id": "sshkeys",     "name": "SSH 与密钥",   "code": "03", "color": "#22d3ee"},
    {"id": "persistence", "name": "持久化后门",   "code": "04", "color": "#fb7185"},
    {"id": "procnet",     "name": "进程与网络",   "code": "05", "color": "#f97316"},
    {"id": "forensics",   "name": "文件与痕迹",   "code": "06", "color": "#facc15"},
    {"id": "hardening",   "name": "权限与加固",   "code": "07", "color": "#4ade80"},
    {"id": "webstack",    "name": "Web 服务栈",   "code": "08", "color": "#e879f9"},
    {"id": "logs",        "name": "日志与审计",   "code": "09", "color": "#94a3b8"},
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ------------------------------------------------------------------ 工具函数
def F(severity, title, summary, evidence="", fix=None, tag=""):
    return {
        "severity": severity,
        "title": title,
        "summary": summary,
        "evidence": (evidence or "").strip()[:1600],
        "fix": fix or [],
        "tag": tag or "通用",
    }


def o(outputs, key):
    return outputs.get(key, (-1, ""))[1] or ""


def ev(outputs, *keys, limit=1600):
    parts = []
    for k in keys:
        t = o(outputs, k).strip()
        if t:
            parts.append(t)
    return "\n".join(parts)[:limit]


def hits(text, pattern, maxn=12):
    try:
        rx = re.compile(pattern, re.I | re.M)
    except re.error:
        return []
    found, seen = [], set()
    for line in text.splitlines():
        if rx.search(line) and line.strip():
            key = line.strip()[:160]
            if key not in seen:
                seen.add(key)
                found.append(line.strip()[:220])
            if len(found) >= maxn:
                break
    return found


def res(findings=None, note="未发现异常"):
    return {"findings": findings or [], "note": note}


def generic_rule(rule):
    """通用规则：命中关键字即产生一条发现。"""
    def _h(outputs, session):
        text = "\n".join(o(outputs, k) for k in rule["keys"])
        matched = hits(text, rule["pattern"], rule.get("maxn", 12))
        if not matched:
            return res(note=rule.get("pass_note", "未发现异常"))
        return res([F(
            rule["severity"], rule["title"], rule["summary"],
            "\n".join(matched), rule["fix"], rule.get("tag", "可疑特征"),
        )])
    return _h


# ------------------------------------------------------------------ 检查项
CHECKS = []


def add(cid, module, name, desc, cmds, handler=None, rule=None, timeout=25):
    item = {
        "id": cid, "module": module, "name": name, "desc": desc,
        "cmds": cmds, "timeout": timeout,
    }
    CHECKS.append(item)
    if handler:
        HANDLERS[cid] = handler
    elif rule:
        HANDLERS[cid] = generic_rule(rule)


HANDLERS = {}

# ============================================================ 01 目标画像
add("sys.info", "identity", "系统基线与版本",
    "采集发行版、内核、主机时间、当前身份，判断是否为过时/停止维护的系统",
    [("os", "cat /etc/os-release 2>/dev/null | head -8"),
     ("uname", "uname -a"),
     ("host", "hostname; hostname -I 2>/dev/null"),
     ("id", "id; whoami"),
     ("time", "date '+%Y-%m-%d %H:%M:%S %Z'; uptime")],
    handler=lambda outputs, s: _sys_info(outputs, s))


def _sys_info(outputs, s):
    os_out = o(outputs, "os")
    uname = o(outputs, "uname")
    findings = []
    low = os_out.lower()
    if re.search(r"(centos linux 6|ubuntu 1[024]\.|ubuntu 16\.04|debian [67]|rhel 6|red hat.* 6\.)", low):
        findings.append(F("medium", "操作系统已停止维护",
                          "目标为 EOL 发行版，官方不再提供安全补丁，CTF 与实战中常被用作内核提权跳板。",
                          ev(outputs, "os", "uname"),
                          ["备份数据后升级到受支持的发行版大版本（Ubuntu 22.04+/CentOS Stream/Rocky 9）",
                           "过渡期用防火墙严格限制管理口来源，并禁用不必要服务"],
                          "基线"))
    if not s.root:
        findings.append(F("high", "未取得 root 权限，检查覆盖不完整",
                          "当前会话不是 root，/etc/shadow、进程 cmdline、日志等只读检查会被系统拒绝，结论存在盲区。",
                          ev(outputs, "id"),
                          ["确认账号在 sudoers 内且 sudo 允许非交互（Defaults !requiretty）",
                           "改用 root 直接登录，或修正 sudo 权限后重新排查"],
                          "权限"))
    return res(findings, "基线采集完成；%s" % (os_out.splitlines()[0][:90] if os_out else uname[:90]))


add("id.priv", "identity", "当前特权与可提权面",
    "检查免密 sudo、危险 sudo 授权、capabilities 等本地提权入口",
    [("sudo_l", "grep -REn 'NOPASSWD|ALL=\\(ALL|ALL=\\(ALL:ALL\\)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -40"),
     ("sudo_eff", "echo '--- sudo -l (当前用户生效授权) ---'; sudo -l 2>/dev/null | head -25; echo '--- sudo -l -U (各登录用户) ---'; for u in $(awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd | head -12); do echo \"### user=$u\"; sudo -l -U $u 2>/dev/null | grep -Ei 'NOPASSWD|\\(ALL' | head -6; done"),
     ("caps", "getcap -r / 2>/dev/null | grep -Ei 'setuid|dac_override|sys_admin|setgid' | head -20")],
    handler=lambda outputs, s: _id_priv(outputs, s))


def _id_priv(outputs, s):
    fs = []
    sudo_l = o(outputs, "sudo_l")
    eff = o(outputs, "sudo_eff")
    nop = hits(sudo_l, r"NOPASSWD")
    if nop:
        fs.append(F("high", "存在免密 sudo 授权（NOPASSWD）",
                    "主体切换 root 无需口令，一旦该账号被拿下即可直接提权；CTF 中 d2 / d2-min 靶场用 sudo -l -U <user> 直接命中。",
                    "\n".join(nop) + "\n--- sudo -l 生效授权 ---\n" + eff.strip()[:700],
                    ["编辑 /etc/sudoers（用 visudo）删除 NOPASSWD，改为按需的精确命令白名单",
                     "用 sudo -l -U <user> 逐个复核可登录账号的实际生效授权（配置文件的 Include/组策略可能遗漏）",
                     "限制可 sudo 的用户组：usermod -G <安全组> <user>"],
                    "提权"))
    elif re.search(r"NOPASSWD", eff):
        fs.append(F("high", "sudo -l 显示生效的免密提权授权",
                    "配置文件未直接写明，但 sudo -l 的实际生效策略中出现 NOPASSWD，说明授权来自组策略或 Include 片段。",
                    eff.strip()[:900],
                    ["用 sudo -l -U <user> 定位具体主体，visudo -f /etc/sudoers.d/<文件> 修正",
                     "收敛为精确命令白名单，避免 NOPASSWD: ALL"],
                    "提权"))
    caps = o(outputs, "caps")
    if caps.strip():
        fs.append(F("high", "文件被授予危险 capabilities",
                    "cap_setuid/cap_dac_override 等能力等价于部分 root 权限，是 CTF 提权常见考点。",
                    caps[:900],
                    ["定位文件：getcap -r / 2>/dev/null",
                     "移除能力：setcap -r <文件路径>；非必要二进制不应带 cap_setuid+ep"],
                    "提权"))
    return res(fs, "未发现明显的免密 sudo / 危险 capabilities")


# ============================================================ 02 账号与提权
add("acct.uid0", "accounts", "影子 root 账号（UID=0）",
    "排查 /etc/passwd 中除 root 外 UID 为 0 的隐藏特权账号",
    [("uid0", "awk -F: '$3==0 {print $0}' /etc/passwd 2>/dev/null")],
    handler=lambda outputs, s: _uid0(outputs))


def _uid0(outputs):
    txt = o(outputs, "uid0")
    bad = [l for l in txt.splitlines() if l.strip() and not l.strip().startswith("root:")]
    if bad:
        return res([F("critical", "存在 UID=0 的影子 root 账号",
                      "passwd 中除 root 外还有 UID 0 的账号，等同于第二个 root，是最典型的权限维持后门。",
                      "\n".join(bad[:10]),
                      ["先确认该账号用途与登录记录：last <user>; grep <user> /var/log/auth.log*",
                       "锁定并删除：usermod -L <user>; userdel -r <user>（保留证据后再操作）",
                       "核查 /etc/shadow 与 authorized_keys 中该账号的残留项"],
                      "后门账号")])
    return res(note="仅 root 拥有 UID 0")


add("acct.shadow", "accounts", "空口令与弱 Hash",
    "检查 /etc/shadow 中的空口令、锁定异常及 MD5 弱哈希账号",
    [("empty", "awk -F: 'length($2)<3 {print $1\" => [\"$2\"]\"}' /etc/shadow 2>/dev/null | head -30"),
     ("md5", "awk -F: '$2 ~ /^\\$1\\$/ {print $1}' /etc/shadow 2>/dev/null | head -20"),
     ("nopass", "grep -REn 'nullok|pam_permit' /etc/pam.d/ 2>/dev/null | head -20")],
    handler=lambda outputs, s: _shadow(outputs))


def _shadow(outputs):
    fs = []
    empty = o(outputs, "empty")
    real_empty = [l for l in empty.splitlines() if re.search(r"=>\s*\[\s*\]", l)]
    if real_empty:
        fs.append(F("critical", "存在空口令账号",
                    "shadow 第二字段为空，可直接 su / SSH 登录，无需任何凭据。",
                    "\n".join(real_empty[:10]),
                    ["立即锁定：passwd -l <user> 或 usermod -L <user>",
                     "设置强口令：passwd <user>；无用账号直接 userdel -r",
                     "检查 PAM 是否含 nullok 并移除"],
                    "弱口令"))
    md5 = o(outputs, "md5").strip()
    if md5:
        fs.append(F("medium", "账号仍使用 MD5($1$) 口令哈希",
                    "MD5-crypt 可被离线暴力快速破解，不符合当前基线要求。",
                    md5[:500],
                    ["为相关账号重设口令，使系统以 SHA-512($6$) 重新生成哈希",
                     "确认 /etc/pam.d/common-password 或 system-auth 使用 sha512/yescrypt"],
                    "口令策略"))
    nullok = o(outputs, "nopass").strip()
    if nullok:
        fs.append(F("high", "PAM 配置含 nullok / pam_permit",
                    "允许空口令认证或无条件放行，可直接绕过口令校验。",
                    nullok[:600],
                    ["从 /etc/pam.d/ 对应文件中删除 nullok 与 pam_permit.so",
                     "改完后用新会话验证登录（务必保留一个已登录会话）"],
                    "认证绕过"))
    return res(fs, "未发现空口令 / MD5 弱哈希账号")


add("acct.service_shell", "accounts", "服务账号可登录 Shell",
    "排查 www-data/mysql/nginx/tomcat 等服务账号被改成 /bin/bash 的情况",
    [("shells", "awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1\" uid=\"$3\" shell=\"$7}' /etc/passwd 2>/dev/null | head -40")],
    handler=lambda outputs, s: _service_shell(outputs))


def _service_shell(outputs):
    txt = o(outputs, "shells")
    suspicious = hits(txt, r"^(www-data|apache|nginx|mysql|mariadb|tomcat|redis|postgres|ftp|nobody|daemon|backup|git)\s", 12)
    if suspicious:
        return res([F("high", "服务账号被赋予可登录 Shell",
                      "Web/DB 服务账号本应 nologin；被改为 bash 后攻击者可直接 su 过去并写入 Web 目录。",
                      "\n".join(suspicious),
                      ["改回不可登录：usermod -s /usr/sbin/nologin <user>",
                       "检查该账号的 ~/.ssh/authorized_keys 与 crontab 是否被植入后门"],
                      "账号滥用")])
    return res(note="服务账号均为 nologin/false")


add("acct.newuser", "accounts", "近期新增账号与家目录",
    "枚举 UID>=1000 的账号并定位近期创建的家目录",
    [("users", "awk -F: '$3>=1000 && $3<65534 {print $1\" uid=\"$3\" home=\"$6\" shell=\"$7}' /etc/passwd 2>/dev/null"),
     ("newhome", "find /home -maxdepth 1 -type d -mtime -14 -printf '%TY-%Tm-%Td %p\\n' 2>/dev/null | head -20"),
     ("passwdstat", "stat -c '%y %a %U:%G %n' /etc/passwd /etc/shadow 2>/dev/null")],
    handler=lambda outputs, s: _newuser(outputs))


def _newuser(outputs):
    fs = []
    newhome = o(outputs, "newhome").strip()
    if newhome:
        fs.append(F("medium", "近 14 天内新建用户家目录",
                    "新增账号/家目录常与攻击者建立落脚账号同步出现，需与运维变更单核对。",
                    newhome[:700],
                    ["核对账号来源：grep <user> /var/log/auth.log* /var/log/secure*",
                     "非授权账号：userdel -r <user> 并清理其 crontab、SSH 公钥、sudoers 条目"],
                    "账号变更"))
    return res(fs, "未发现近期新建家目录；%d 个普通账号已记录" % len(o(outputs, "users").splitlines()))


# ============================================================ 03 SSH 与密钥
add("ssh.authkeys", "sshkeys", "authorized_keys 公钥后门",
    "检查所有用户的授权公钥、文件权限与可疑备注，识别免密登录通道",
    [("keys", "for f in $(find /root /home /var/www /opt -maxdepth 5 -type f -name 'authorized_keys*' 2>/dev/null | head -25); do echo \"=== $f\"; stat -c 'perm=%a owner=%U:%G' \"$f\" 2>/dev/null; cat \"$f\" 2>/dev/null; done"),
     ("keys2", "find / -xdev -name 'authorized_keys' -type f 2>/dev/null | head -25")],
    handler=lambda outputs, s: _authkeys(outputs))


def _authkeys(outputs):
    fs = []
    txt = o(outputs, "keys")
    allkeys = o(outputs, "keys2")
    blocks = [b.strip() for b in txt.split("===") if b.strip()]
    suspicious_path = hits(allkeys, r"/var/www|/tmp|/opt/|/dev/shm|/var/tmp", 10)
    suspicious_note = hits(txt, r"(hack|backdoor|attacker|kali|pentest|shell|test@|x@|root@\S*kali|evil|pwn)", 10)
    if suspicious_path or suspicious_note:
        fs.append(F("critical", "检测到可疑 SSH 授权公钥路径/备注",
                    "非标准路径或带攻击特征的 authorized_keys 通常意味着攻击者留下的免密登录通道。",
                    (("\n".join(suspicious_path) + "\n") if suspicious_path else "") +
                    ("\n".join(suspicious_note) if suspicious_note else "") + "\n\n" + txt[:700],
                    ["保留证据后删除该公钥行：vim <authorized_keys 路径>",
                     "检查该账号最近登录：last <user>; grep 'Accepted publickey' /var/log/auth.log*",
                     "全局排查：find / -name authorized_keys -exec ls -l {} \\;"],
                    "公钥后门"))
    # 权限检查
    perm_bad = hits(txt, r"perm=(?!600|400)\d{3}", 10)
    if perm_bad:
        fs.append(F("medium", "authorized_keys 权限过宽",
                    "不为 600/400 时 sshd 的 StrictModes 会拒绝公钥，或允许同组用户篡改公钥。",
                    "\n".join(perm_bad) + "\n" + txt[:400],
                    ["chmod 600 ~/.ssh/authorized_keys; chmod 700 ~/.ssh",
                     "chown -R <user>:<user> ~/.ssh；确认 StrictModes yes"],
                    "文件权限"))
    # 多把公钥
    key_lines = hits(txt, r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2|ssh-dss)\s", 20)
    if len(key_lines) >= 3 and not suspicious_note and not suspicious_path:
        fs.append(F("low", "单个账号配置多把授权公钥",
                    "多把公钥增加管理面；CTF 中常在正常公钥后追加一行攻击者公钥。",
                    "\n".join(key_lines[:8]),
                    ["逐把核对来源，删除未知公钥；统一走堡垒机/密钥管理平台下发",
                     "开启 sshd 日志 LogLevel VERBOSE 记录所用公钥指纹"],
                    "密钥管理"))
    if not txt.strip():
        return res(note="未发现 authorized_keys 文件")
    return res(fs, "已核查 %d 个 authorized_keys 文件，未发现明显后门公钥" % len(blocks or allkeys.splitlines()))


add("ssh.private", "sshkeys", "私钥文件与权限",
    "全盘定位 SSH 私钥，检查权限是否过宽、是否落在 Web 可下载目录",
    [("privs", "for f in $(find / -xdev -type f \\( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' -o -name '*.p12' \\) 2>/dev/null | head -40); do stat -c '%a %U:%G %n' \"$f\" 2>/dev/null; done")],
    handler=lambda outputs, s: _private(outputs))


def _private(outputs):
    txt = o(outputs, "privs").strip()
    if not txt:
        return res(note="未发现散落的 SSH 私钥文件")
    fs = []
    web = hits(txt, r"/var/www|/usr/share/nginx|/opt/tomcat|/home/[^/]+/public|webapps", 10)
    if web:
        fs.append(F("critical", "私钥落在 Web 可访问目录",
                    "攻击者可直接通过 HTTP 下载私钥并横向登录其他主机。",
                    "\n".join(web),
                    ["立即移出 Web 根目录：mv <file> /root/.ssh/ 并 chmod 600",
                     "视为已泄露，吊销并重新签发该密钥对（ssh-keygen -R / 更换 authorized_keys）"],
                    "密钥泄露"))
    loose = hits(txt, r"^(6[0-7]{2}|7[0-7]{2}|[0-9]{3})\s.*id_|^(6[0-7]{2}|7[0-7]{2})\s", 12)
    # 更精确：权限 >= 640 视为过宽
    loose = [l for l in txt.splitlines() if re.match(r"^\s*(6[4-9]\d|7\d\d|66\d)\s", l)]
    if loose:
        fs.append(F("high", "私钥文件权限过宽",
                    "SSH 私钥必须仅属主可读（600）；644/755 意味任意本地用户可读取并冒用身份。",
                    "\n".join(loose[:10]),
                    ["chmod 600 <私钥>; chown <属主>:<属主> <私钥>",
                     "检查是否已被复制，必要时重新签发密钥对"],
                    "文件权限"))
    if not fs:
        fs.append(F("low", "主机上存在 SSH 私钥文件",
                    "服务器上存放私钥会扩大横向移动面，CTF 中常用于读取其他主机的凭据。",
                    txt[:700],
                    ["确认业务必要性；改用跳板机代理转发（ProxyJump）而非在主机留存私钥",
                     "为私钥设置 passphrase 并限制文件权限 600"],
                    "密钥管理"))
    return res(fs)


add("ssh.config", "sshkeys", "sshd_config 安全配置",
    "逐项核查 root 登录、空口令、用户环境变量、StrictModes 等 sshd 配置",
    [("cfg", "grep -REn '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|StrictModes|AuthorizedKeysFile|PermitUserEnvironment|AllowUsers|DenyUsers|Port|X11Forwarding|LogLevel|MaxAuthTries)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | head -50"),
     ("eff", "echo '--- sshd -T 生效配置 ---'; sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|permitemptypasswords|passwordauthentication|pubkeyauthentication|strictmodes|permituserenvironment|x11forwarding|maxauthtries|port|allowusers|denyusers|loglevel)\\b' | head -30")],
    handler=lambda outputs, s: _sshcfg(outputs))


def _sshcfg(outputs):
    txt = o(outputs, "cfg")
    fs = []
    def val(key):
        m = re.search(r"^\S+:\d+:\s*" + key + r"\s+(\S+)", txt, re.I | re.M)
        return (m.group(1).lower() if m else "")
    if "permitemptypasswords" in txt.lower() and re.search(r"PermitEmptyPasswords\s+yes", txt, re.I):
        fs.append(F("critical", "sshd 允许空口令登录",
                    "PermitEmptyPasswords yes 与空口令账号组合可导致无凭据 SSH 登录。",
                    hits(txt, r"PermitEmptyPasswords", 3)[0],
                    ["改为 PermitEmptyPasswords no，然后 systemctl restart sshd",
                     "同时排查 /etc/shadow 中的空口令账号"],
                    "认证绕过"))
    if re.search(r"^\S+.*PermitUserEnvironment\s+yes", txt, re.I | re.M):
        fs.append(F("high", "sshd 允许 PermitUserEnvironment",
                    "配合 ~/.ssh/environment 注入 LD_PRELOAD 可劫持登录进程，是隐蔽后门手法。",
                    "\n".join(hits(txt, r"PermitUserEnvironment", 3)),
                    ["设为 PermitUserEnvironment no 并重启 sshd",
                     "检查各用户 ~/.ssh/environment 内容"],
                    "环境劫持"))
    if re.search(r"PermitRootLogin\s+(yes|without-password|prohibit-password)", txt, re.I) and not re.search(r"PermitRootLogin\s+no", txt, re.I):
        fs.append(F("medium", "允许 root 直接 SSH 登录",
                    "root 直登使暴力破解与凭据泄露的收益最大化，应改用普通账号 + sudo。",
                    "\n".join(hits(txt, r"PermitRootLogin", 3)),
                    ["设为 PermitRootLogin no；使用普通账号登录后再 sudo -i",
                     "配合 AllowUsers 白名单限制来源账号"],
                    "远程管理"))
    if re.search(r"StrictModes\s+no", txt, re.I):
        fs.append(F("medium", "sshd StrictModes 被关闭",
                    "关闭后 sshd 不再校验 ~/.ssh 权限，便于攻击者放置宽松权限的公钥。",
                    "\n".join(hits(txt, r"StrictModes", 3)),
                    ["改回 StrictModes yes 并修正各用户 .ssh 目录权限"],
                    "远程管理"))
    if re.search(r"X11Forwarding\s+yes", txt, re.I):
        fs.append(F("low", "开启 X11 转发",
                    "非必要功能，扩大攻击面。", "\n".join(hits(txt, r"X11Forwarding", 3)),
                    ["设为 X11Forwarding no 并重启 sshd"], "加固"))
    # sshd -T 才是最终生效值（含 Include / Match 片段），d2 靶场 H01 以此为判定口径
    eff = o(outputs, "eff")
    def eval_(key):
        m = re.search(r"^" + key + r"\s+(\S+)", eff, re.I | re.M)
        return (m.group(1).lower() if m else "")
    titles = {f["title"] for f in fs}
    if eval_("permitrootlogin") == "yes" and "允许 root 直接 SSH 登录" not in titles:
        fs.append(F("high", "sshd 生效配置允许 root 密码登录（sshd -T）",
                    "配置文件可能写了 no，但 Include / Match 覆盖后实际仍为 yes；root 直登使暴力破解与凭据泄露收益最大化。",
                    eff.strip()[:700],
                    ["用 sshd -T | grep permitrootlogin 确认生效值，定位覆盖来源（/etc/ssh/sshd_config.d/）",
                     "设为 PermitRootLogin no 并 systemctl restart sshd；改前保留一个已登录会话避免自锁"],
                    "远程管理"))
    if eval_("permitemptypasswords") == "yes" and not any("空口令登录" in f["title"] for f in fs):
        fs.append(F("critical", "sshd 生效配置允许空口令登录",
                    "生效配置中 permitemptypasswords yes，与空口令账号组合可导致无凭据 SSH 登录。",
                    eff.strip()[:700],
                    ["改为 PermitEmptyPasswords no 并重启 sshd",
                     "排查 /etc/shadow 第二字段为空的账号并立即锁定"],
                    "认证绕过"))
    if not txt.strip() and not eff.strip():
        return res(note="未读取到 sshd_config / sshd -T（可能未安装 sshd）")
    return res(fs, "sshd 配置与 sshd -T 生效值已核查，未发现高危放行项")


add("ssh.perms", "sshkeys", ".ssh 目录与主机私钥权限",
    "核查 .ssh 目录 700、主机私钥 600，避免密钥被同机其他用户读取",
    [("perms", "stat -c '%a %U:%G %n' /root/.ssh /home/*/.ssh /etc/ssh/ssh_host_*_key /root/.ssh/known_hosts 2>/dev/null | head -30")],
    handler=lambda outputs, s: _sshperms(outputs))


def _sshperms(outputs):
    txt = o(outputs, "perms").strip()
    if not txt:
        return res(note="未发现 .ssh 目录或主机私钥")
    bad = [l for l in txt.splitlines() if re.match(r"^\s*(7[1-9]\d|6[4-9]\d|7\d\d|6\d\d)\s+.*\.ssh/?\s*$", l) and not l.strip().startswith("600")]
    hostkey = [l for l in txt.splitlines() if "ssh_host" in l and re.match(r"^\s*(?!600|640|400)\d{3}", l)]
    fs = []
    if bad:
        fs.append(F("medium", ".ssh 目录权限非 700",
                    "目录可被同组/其他用户遍历或写入公钥。", "\n".join(bad[:8]),
                    ["chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"],
                    "文件权限"))
    if hostkey:
        fs.append(F("high", "SSH 主机私钥权限过宽",
                    "ssh_host_*_key 泄露可导致中间人伪装与会话解密。", "\n".join(hostkey[:8]),
                    ["chmod 600 /etc/ssh/ssh_host_*_key; chown root:root /etc/ssh/ssh_host_*_key",
                     "若已泄露，ssh-keygen -A 重新生成主机密钥"],
                    "密钥泄露"))
    return res(fs, ".ssh 与主机私钥权限正常")


# ============================================================ 04 持久化后门
add("persist.cron", "persistence", "计划任务后门",
    "扫描 root/全部用户 crontab、/etc/cron* 中的下载执行、反弹 Shell 片段",
    [("allcron", "for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u $u 2>/dev/null); [ -n \"$c\" ] && echo \"### user=$u\" && echo \"$c\"; done | head -120"),
     ("syscron", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ /etc/cron.daily/ 2>/dev/null | head -40"),
     ("susp", "grep -REni '(curl|wget|/dev/tcp|bash -i|nc -e|base64 -d|python.*socket|chmod \\+s|/tmp/|/var/tmp/|/dev/shm|\\.sh\\b|sh -c)' /etc/crontab /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null | head -50"),
     ("reboot", "echo '--- @reboot 开机自启 ---'; grep -REni '@reboot' /etc/cron.d/ /etc/crontab /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null | head -25; echo '--- /etc/cron.d 清单 ---'; ls -la --time-style=long-iso /etc/cron.d/ 2>/dev/null | head -30"),
     ("perm", "find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /usr/local/sbin /opt /srv -xdev -maxdepth 2 -type f -perm /022 -printf '%m %u:%g %p\\n' 2>/dev/null | head -30")],
    timeout=35,
    handler=lambda outputs, s: _cron(outputs))


def _cron(outputs):
    fs = []
    susp = hits(o(outputs, "susp"),
                r"curl|wget|/dev/tcp|bash -i|nc -e|base64 -d|python.*socket|chmod \+s|/tmp/|/var/tmp/|/dev/shm|\.sh\b", 14)
    if susp:
        fs.append(F("critical", "计划任务中存在可疑执行片段",
                    "定时任务调用下载器、反弹 Shell 或临时目录脚本，是 CTF 与真实入侵中最常见的权限维持方式（d4-webshell / d5-mining / d5-ransom 均以此复活）。",
                    "\n".join(susp),
                    ["先取证：crontab -l; cat /etc/crontab; ls -la /etc/cron.d/；保存输出与脚本样本",
                     "注释或删除恶意行：crontab -e / vim /etc/cron.d/<file>，然后 systemctl restart cron(crond)",
                     "追溯脚本内容并查杀对应进程：ps aux | grep <脚本名>; kill -9 <PID>"],
                    "持久化"))
    perm = o(outputs, "perm").strip()
    if perm:
        fs.append(F("high", "root 计划任务脚本被组/其他用户可写",
                    "cron 以 root 执行的脚本若可被普通用户改写，等于把任意命令提权到 root（d2 H05 / hardening-lab N06 判定口径）。",
                    perm,
                    ["立即收紧：chmod 755 <脚本>; chown root:root <脚本>",
                     "核对脚本内容是否被植入：cat <脚本>; stat <脚本> 看 mtime",
                     "排查引用它的 /etc/cron.d/<file> 与 systemd unit"],
                    "提权面"))
    reboot = [l for l in o(outputs, "reboot").splitlines()
              if "@reboot" in l.lower() and not l.startswith("---")]
    if reboot:
        fs.append(F("medium", "存在 @reboot 开机自启任务",
                    "@reboot 无需 cron 常驻即可在每次开机执行，矿机与勒索载荷常用它做复活链（d5-mining M04）。",
                    "\n".join(reboot[:12]),
                    ["核对来源：grep -R '@reboot' /etc/cron* /var/spool/cron/；确认对应脚本内容",
                     "非业务项删除并用 systemctl list-units --all 检查配套 transient 单元"],
                    "复活链"))
    return res(fs, "各级 crontab / cron.d 未发现下载反弹、可写脚本或未登记 @reboot")

add("persist.systemd", "persistence", "systemd 服务后门",
    "枚举服务单元，定位近期新增或 ExecStart 可疑的 unit",
    [("units", "systemctl list-unit-files --type=service --no-pager 2>/dev/null | head -60"),
     ("susp", "grep -REni 'ExecStart=.*(curl|wget|/dev/tcp|nc |base64|/tmp/|/var/tmp/|\\.sh|python|bash -i|sh -c)' /etc/systemd/system/ /lib/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null | head -30"),
     ("recent", "find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 2 -name '*.service' -mtime -14 -printf '%TY-%Tm-%Td %p\\n' 2>/dev/null | head -20")],
    timeout=30,
    handler=lambda outputs, s: _systemd(outputs))


def _systemd(outputs):
    fs = []
    susp = o(outputs, "susp").strip()
    if susp:
        fs.append(F("critical", "systemd 单元含可疑 ExecStart",
                    "服务单元直接拉起下载器/反弹 Shell/临时目录脚本，重启后自动复活，隐蔽性高于 crontab。",
                    susp[:900],
                    ["定位 unit：systemctl status <name>；cat <unit文件> 取证",
                     "停止并禁用：systemctl stop <name>; systemctl disable --now <name>; rm <unit文件>; systemctl daemon-reload",
                     "核查 ExecStart 指向的脚本并清除落地文件"],
                    "持久化"))
    recent = o(outputs, "recent").strip()
    if recent and not susp:
        fs.append(F("medium", "近 14 天新增 systemd 服务单元",
                    "新增服务需与发布记录核对；攻击者常伪装为 syslogd / kworker / network 等名称。",
                    recent[:700],
                    ["逐个核对：systemctl cat <unit> 检查 ExecStart 与 User 字段",
                     "非业务服务：systemctl disable --now <unit> 并删除单元文件"],
                    "持久化"))
    return res(fs, "systemd 单元未见可疑 ExecStart / 近期新增项")


add("persist.startup", "persistence", "启动脚本与 Shell 配置劫持",
    "检查 rc.local、profile.d、bashrc 中的下载执行、命令别名劫持、history 抹除",
    [("rc", "cat /etc/rc.local 2>/dev/null; ls -la /etc/profile.d/ 2>/dev/null | head -30"),
     ("susp", "grep -REni '(curl |wget |/dev/tcp|base64 -d|history -c|unset HIST|export HISTFILE=/dev/null|LD_PRELOAD|alias (ls|ps|netstat|top|su|sudo)=|/tmp/|/dev/shm/)' /etc/profile /etc/bash.bashrc /etc/profile.d/ /etc/rc.local /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null | head -50")])

HANDLERS["persist.startup"] = generic_rule({
    "keys": ["susp"],
    "pattern": r"curl |wget |/dev/tcp|base64 -d|history -c|unset HIST|HISTFILE=/dev/null|LD_PRELOAD|alias (ls|ps|netstat|top|su|sudo)=|/tmp/|/dev/shm/",
    "severity": "high", "title": "启动脚本 / Shell 初始化文件被植入",
    "summary": "登录即触发的脚本或 alias 劫持可长期窃取口令、隐藏进程、重新下载后门，是 CTF 高频隐藏点。",
    "fix": ["核对文件：grep -Rn <关键字> /etc/profile /etc/profile.d/ ~/.bashrc；保存被篡改文件",
            "删除恶意行，恢复默认配置（可从同版本系统拷贝）",
            "检查文件属主与不可变属性：lsattr <file>; chattr -i <file> 后再修改"],
    "tag": "持久化", "pass_note": "启动脚本与 Shell 初始化文件未见异常",
})

add("persist.ldpreload", "persistence", "LD_PRELOAD 动态链接劫持",
    "检查 /etc/ld.so.preload 与全局环境变量，识别用户态 rootkit",
    [("preload", "cat /etc/ld.so.preload 2>/dev/null; echo '--- env ---'; grep -REn 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d/ /etc/ld.so.conf /etc/ld.so.conf.d/ 2>/dev/null | head -20"),
     ("procenv", "for p in $(ls -d /proc/[0-9]* 2>/dev/null | head -120); do e=$(tr '\\0' ' ' < $p/environ 2>/dev/null | grep -Eio 'LD_PRELOAD=\\S+' | head -1); [ -n \"$e\" ] && echo \"$p $e\"; done | head -20")])

HANDLERS["persist.ldpreload"] = generic_rule({
    "keys": ["preload", "procenv"],
    "pattern": r"^\s*/\S+\.so|LD_PRELOAD=\S+",
    "severity": "critical", "title": "检测到 LD_PRELOAD 动态链接劫持",
    "summary": "/etc/ld.so.preload 中的 .so 会被所有进程自动加载，可劫持 readdir/read 来隐藏文件、进程与网络连接，属典型用户态 rootkit。",
    "fix": ["先备份样本：cp /etc/ld.so.preload /root/ir_evidence/；lsof <so路径> 查占用",
            "清空劫持：> /etc/ld.so.preload（或 rm 后重建），必要时进单用户模式处理",
            "删除恶意 .so 并用静态编译的 busybox 复核 ps / ls / ss 输出"],
    "tag": "Rootkit", "pass_note": "未发现 LD_PRELOAD / ld.so.preload 劫持",
})

add("persist.suid", "persistence", "SUID/SGID 与提权可执行文件",
    "全盘枚举 SUID/SGID，识别异常路径与 GTFOBins 提权程序",
    [("suid", "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -150")],
    timeout=45,
    handler=lambda outputs, s: _suid(outputs))


def _suid(outputs):
    txt = o(outputs, "suid")
    all_files = [l.strip() for l in txt.splitlines() if l.strip()]
    weird = [p for p in all_files if re.match(r"^/(tmp|var/tmp|dev/shm|home|opt|srv|var/www|usr/local/share)/", p)]
    gtfobins = [p for p in all_files if re.search(
        r"/(bash|sh|find|vim|nmap|python[0-9.]*|perl|awk|cp|mv|nano|less|more|cat|tee|env|php|ruby|lua|node|tar|zip|gdb|socat|nc|arp|man|git|wget|curl|base64|xxd|od|taskset|setarch|date|dd|chown|chmod|chfn|mount|su|newgrp|passwd|screen|tmux|exim|pkexec|at)$", p)]
    fs = []
    if weird:
        fs.append(F("critical", "非系统目录存在 SUID/SGID 文件",
                    "临时目录/家目录中的 SUID 程序几乎必为攻击者留下的本地提权后门（如 /tmp/bash -p）。",
                    "\n".join(weird[:12]),
                    ["取证：ls -l <file>; file <file>; md5sum <file>；记录属主与时间",
                     "清除：chmod -s <file> 或直接 rm <file>（先确认无业务依赖）",
                     "排查谁创建的：stat <file>; grep -R <file> /var/log/auth.log* ~/.bash_history"],
                    "提权后门"))
    if gtfobins:
        fs.append(F("high", "存在可被用于提权的 SUID 程序",
                    "bash/find/vim/python/nmap/cp 等带 SUID 时可借助 GTFOBins 直接获得 root shell。",
                    "\n".join(gtfobins[:12]),
                    ["对非必要程序移除 SUID：chmod -s /path/to/binary",
                     "保持系统默认：多数发行版仅 su/sudo/passwd/mount 等需要 SUID",
                     "用 find / -perm -4000 -type f -exec ls -l {} \\; 建立基线并定期比对"],
                    "提权面"))
    return res(fs, "已核查 %d 个 SUID/SGID 文件，未发现异常路径或危险程序" % len(all_files))


add("persist.worldwrite", "persistence", "全局可写目录与文件",
    "查找无 sticky bit 的全局可写目录、以及全局可写的配置文件",
    [("dirs", "find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -40"),
     ("files", "find /etc /usr/local/etc /var/www -xdev -type f -perm -0002 2>/dev/null | head -30")],
    timeout=40,
    handler=lambda outputs, s: _worldwrite(outputs))


def _worldwrite(outputs):
    fs = []
    dirs = o(outputs, "dirs").strip()
    if dirs:
        fs.append(F("medium", "存在无 sticky bit 的全局可写目录",
                    "任意用户可删除/替换该目录下的文件，可能导致符号链接攻击与配置劫持。",
                    dirs[:700],
                    ["收敛权限：chmod 750 <dir> 或 chmod +t <dir>（如 /tmp 应为 1777）",
                     "确认属主：chown root:root <dir>"],
                    "文件权限"))
    files = o(outputs, "files").strip()
    if files:
        fs.append(F("high", "全局可写的配置 / Web 文件",
                    "/etc 或网站目录中任意用户可写的文件可被直接篡改以植入后门。",
                    files[:700],
                    ["chmod 644 <file>（配置）或 755 <dir>；Web 目录禁止 777",
                     "Web 可写目录单独挂载 noexec,nosuid"],
                    "文件权限"))
    return res(fs, "未发现无 sticky 位的全局可写目录 / 全局可写配置")


add("persist.at", "persistence", "at 一次性计划任务",
    "检查 at 队列与 spool 目录中的延迟执行任务",
    [("at", "atq 2>/dev/null; ls -la /var/spool/at/ /var/spool/atjobs/ /var/spool/cron/atjobs/ 2>/dev/null | head -30")])

HANDLERS["persist.at"] = generic_rule({
    "keys": ["at"], "pattern": r"^\s*\d+\s+\w{3}\s|^-rwx|atjob",
    "severity": "medium", "title": "存在 at 延迟执行任务",
    "summary": "at 任务不显示在 crontab -l 中，常被用来做一次性反连与二次投放，容易漏查。",
    "fix": ["查看内容：at -c <jobid>；确认无异常后 atrm <jobid>",
            "检查 /var/spool/at/ 下脚本内容并清理"],
    "tag": "持久化", "pass_note": "at 队列为空",
})

add("persist.hosts", "persistence", "hosts / TCP Wrappers 异常",
    "检查域名劫持与 hosts.allow 中的 ALL:ALL 放行",
    [("hosts", "cat /etc/hosts 2>/dev/null; echo '--- allow ---'; cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -v '^#' | head -20")])

HANDLERS["persist.hosts"] = generic_rule({
    "keys": ["hosts"],
    "pattern": r"ALL:\s*ALL|pool\.|xmr\.|mining|\.onion|stratum",
    "severity": "high", "title": "hosts / TCP Wrappers 存在异常项",
    "summary": "矿池域名解析劫持或 hosts.allow 全放行会让挖矿流量与未授权访问长期存在。",
    "fix": ["核对 /etc/hosts 每一行，删除矿池/未知域名映射",
            "hosts.allow 改为按来源 IP 白名单，hosts.deny 置 ALL: ALL"],
    "tag": "网络劫持", "pass_note": "hosts 与 TCP Wrappers 未见异常",
})


# ============================================================ 05 进程与网络
add("proc.ps", "procnet", "高 CPU 进程与异常进程树",
    "按 CPU 排序枚举进程，定位资源异常与父子关系可疑的进程",
    [("top", "ps -eo pid,ppid,user,pcpu,pmem,lstart,args --sort=-pcpu 2>/dev/null | head -25"),
     ("tree", "ps auxfww 2>/dev/null | head -40")],
    handler=lambda outputs, s: _procps(outputs))


def _procps(outputs):
    txt = o(outputs, "top")
    hot = []
    for line in txt.splitlines()[1:]:
        parts = line.split(None, 6)
        if len(parts) >= 4:
            try:
                if float(parts[3]) >= 80:
                    hot.append(line.strip()[:200])
            except ValueError:
                pass
    fs = []
    if hot:
        fs.append(F("high", "存在 CPU 占用 ≥80% 的进程",
                    "持续满载通常是挖矿木马的典型表现，需结合命令行与外联确认。",
                    "\n".join(hot[:8]),
                    ["记录：ps -fp <PID>; readlink /proc/<PID>/exe; ls -l /proc/<PID>/cwd",
                     "取证后终止：kill -9 <PID>；同时清理其计划任务/服务/落地文件",
                     "检查同源子进程与父进程，避免只杀子进程导致复活"],
                    "挖矿"))
    return res(fs, "进程 CPU 占用未见持续异常；已记录 TOP25 基线")


add("proc.miner", "procnet", "挖矿木马特征",
    "匹配矿工程序名、矿池协议、伪装内核线程名与钱包特征",
    [("miner", "ps -eo pid,ppid,user,pcpu,args ww 2>/dev/null | grep -Ei 'xmrig|minerd|cpuminer|kthreadd|stratum|cryptonight|ethminer|nbminer|phoenix|coinhive|monero|xmr|pool\\.|nicehash|watchbog|kerberods|kworkerds|sysupdate|networkservice|/tmp/\\.|\\.so\\s*$' | grep -v grep | head -30"),
     ("cmdline", "for p in $(ls -d /proc/[0-9]* 2>/dev/null | head -200); do c=$(tr '\\0' ' ' < $p/cmdline 2>/dev/null); echo \"$c\" | grep -Eiq 'stratum\\+tcp|stratum\\+ssl|--donate-level|--cpu-priority|xmr|wallet|pool\\.' && echo \"$p => $c\"; done | head -20")])

HANDLERS["proc.miner"] = generic_rule({
    "keys": ["miner", "cmdline"],
    "pattern": r"xmrig|minerd|cpuminer|stratum|cryptonight|ethminer|nbminer|phoenix|coinhive|monero|\bxmr\b|pool\.|nicehash|watchbog|kerberods|kworkerds|sysupdate|networkservice|--donate-level|wallet",
    "maxn": 14,
    "severity": "critical", "title": "检测到挖矿进程 / 矿池连接特征",
    "summary": "命令行命中矿工程序或 stratum 矿池协议，通常伴随高 CPU、定时任务守护与矿池外联；CTF 中常伪装为 kworkerds / kthreadd 等内核线程名。",
    "fix": ["先取证：ps -fp <PID>; readlink /proc/<PID>/exe; cat /proc/<PID>/cmdline; 保存样本与矿池地址",
            "阻断外联：iptables -A OUTPUT -d <矿池IP> -j DROP（或防火墙策略）",
            "杀进程并清除复活链：kill -9 <PID> → 清理 crontab / systemd unit / rc.local / ld.so.preload / 落地文件",
            "检查是否存在 SSH 公钥后门与新增账号，防止再次入侵"],
    "tag": "挖矿", "pass_note": "未命中矿工程序名 / stratum 矿池特征",
})

add("proc.deleted", "procnet", "已删除但仍运行的进程",
    "比对 /proc/*/exe，识别无文件落地的内存马/删除自身的可执行体",
    [("deleted", "for p in /proc/[0-9]*; do e=$(readlink $p/exe 2>/dev/null); case \"$e\" in *deleted*) echo \"$p => $e\";; esac; done | head -30"),
     ("delmaps", "grep -REl '\\(deleted\\)' /proc/[0-9]*/maps 2>/dev/null | head -15")],
    timeout=35)

HANDLERS["proc.deleted"] = generic_rule({
    "keys": ["deleted"], "pattern": r"=>\s*/.*\(deleted\)",
    "severity": "high", "title": "可执行文件已被删除但进程仍在运行",
    "summary": "攻击者运行后删除自身文件以规避文件扫描，需从 /proc/<PID>/exe 内存中 dump 样本分析。",
    "fix": ["取证：cp /proc/<PID>/exe /root/ir_evidence/<name>.bin; cat /proc/<PID>/cmdline",
            "终止进程：kill -9 <PID>；排查其监听端口与父进程",
            "注意：包升级后正常进程也会短暂出现 (deleted)，需结合时间戳与业务判断"],
    "tag": "无文件落地", "pass_note": "未发现 (deleted) 可执行体常驻进程",
})

add("proc.hidden", "procnet", "隐藏进程检测（ps vs /proc）",
    "对比进程数量与 ps 列表，初步识别进程隐藏型 rootkit",
    [("count", "echo \"proc=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l) ps=$(ps -e --no-headers 2>/dev/null | wc -l)\"; lsmod 2>/dev/null | grep -Ei 'diamorphine|reptile|adore|rootkit|hide|enyelkm|suterusu' | head -10")],
    handler=lambda outputs, s: _hidden(outputs))


def _hidden(outputs):
    txt = o(outputs, "count")
    m = re.search(r"proc=(\d+)\s+ps=(\d+)", txt)
    fs = []
    if m and int(m.group(1)) - int(m.group(2)) > 6:
        fs.append(F("high", "/proc 与 ps 进程数量不一致，疑似进程隐藏",
                    "差值较大时可能存在 hook readdir / getdents 的 rootkit，ps、top、ss 输出均不可信。",
                    txt[:500],
                    ["使用静态编译 busybox 复核：busybox ps; busybox ls /proc",
                     "检查 lkm：lsmod、/proc/modules、/sys/module；可疑模块用 rmmod 卸载并清理 /lib/modules",
                     "必要时离线挂载磁盘做取证，避免依赖被劫持的系统命令"],
                    "Rootkit"))
    lkm = hits(txt, r"diamorphine|reptile|adore|rootkit|enyelkm|suterusu", 5)
    if lkm:
        fs.append(F("critical", "加载了可疑内核模块（LKM Rootkit）",
                    "该类模块可隐藏进程、文件、端口并提权，属于深度失陷信号。",
                    "\n".join(lkm) + "\n" + txt[:400],
                    ["记录模块与路径：modinfo <module>; lsmod | grep <module>",
                     "卸载：rmmod <module>；删除 .ko 文件并重建 initramfs 后重启",
                     "建议在取证镜像完成后重装系统，LKM rootkit 难以保证彻底清除"],
                    "Rootkit"))
    return res(fs, "进程计数一致，未发现已知 LKM rootkit 模块")


add("proc.net", "procnet", "网络连接与反弹 Shell",
    "分析监听端口、外联地址、常见反弹/矿池端口与高危服务暴露",
    [("conn", "ss -tunap 2>/dev/null | head -100; echo '--- netstat ---'; netstat -antup 2>/dev/null | head -60"),
     ("listen", "ss -lntup 2>/dev/null | head -60")],
    handler=lambda outputs, s: _net(outputs))


def _net(outputs):
    conn = o(outputs, "conn")
    listen = o(outputs, "listen")
    fs = []
    # 反弹 Shell / 矿池常见端口的已建立连接
    rev = hits(conn, r"ESTAB.*:(4444|5555|6666|7777|8888|9999|1234|2333|31337|4445|14444|55555)\b", 12)
    if rev:
        fs.append(F("critical", "疑似反弹 Shell / C2 外联连接",
                    "已建立连接到典型的反弹 Shell 端口，意味着主机可能正被交互式控制。",
                    "\n".join(rev),
                    ["定位进程：ss -tunap | grep <端口>; ps -fp <PID>; readlink /proc/<PID>/exe",
                     "立即断链：iptables -A OUTPUT -d <对端IP> -j DROP；kill -9 <PID>",
                     "排查复活机制（cron/systemd/启动脚本）后再恢复网络"],
                    "C2"))
    pool = hits(conn, r"ESTAB.*:(3333|45700|14433|8333|14444|5555)\b", 10)
    if pool:
        fs.append(F("critical", "疑似矿池外联连接",
                    "3333/45700/14433 等是 xmrig 类矿机常用 stratum 端口；d5-mining 的 M02 即以 3333 ESTAB 为判定依据。",
                    "\n".join(pool),
                    ["ss -tnp state established '( dport = :3333 or sport = :3333 )' 定位 PID",
                     "readlink /proc/<PID>/exe 找到矿机落地文件，先取证再终止并清复活链",
                     "防火墙阻断矿池 IP/端口，复查 CPU 负载是否回落"],
                    "挖矿"))
    ext = hits(conn, r"ESTAB\s+\d+\s+\d+\s+\S+:\d+\s+(\d+\.){3}\d+:(3333|4444|5555|8333|14433|45700|80|443)\b", 12)
    public = [l for l in ext if not re.search(r"127\.0\.0\.1|10\.\d+\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.", l)]
    if public and not rev:
        fs.append(F("medium", "存在对外建立的活跃连接",
                    "非内网地址的持续外联可能是矿池、C2 心跳或数据外传，需核对目标归属。",
                    "\n".join(public[:10]),
                    ["确认对端：whois <IP>; ss -tunap | grep <IP> 找到对应进程",
                     "非业务连接用防火墙阻断并终止进程"],
                    "外联"))
    # 高危端口监听在 0.0.0.0
    danger = {"3306": "MySQL", "6379": "Redis", "9200": "Elasticsearch",
              "27017": "MongoDB", "11211": "Memcached", "2375": "Docker API",
              "8009": "Tomcat AJP", "8080": "HTTP 管理端", "5601": "Kibana",
              "9000": "未授权文件浏览/调试服务", "21": "FTP 明文服务",
              "23": "Telnet 明文服务", "4444": "反弹 Shell 监听",
              "8000": "调试 Web 服务", "4848": "GlassFish 管理端"}
    exposed = []
    for line in listen.splitlines():
        for p, name in danger.items():
            if re.search(r"(0\.0\.0\.0|\*|\[::\]):" + p + r"\b", line):
                exposed.append("%-18s %s" % (name, line.strip()[:160]))
                break
    if exposed:
        fs.append(F("high", "高危服务监听在全部网络接口",
                    "数据库/中间件/AJP/Redis/调试服务直接暴露公网，是未授权访问与 RCE 的主要入口（d2 H08、hardening-lab N03/N09）。",
                    "\n".join(exposed[:14]),
                    ["绑定回环：MySQL bind-address=127.0.0.1；Redis bind 127.0.0.1 + requirepass + protected-mode yes",
                     "下线调试/明文服务：systemctl disable --now lab-debug vsftpd inetd；删除对应 unit 文件",
                     "关闭不必要的 AJP Connector；用防火墙/安全组仅放行业务来源 IP"],
                    "暴露面"))
    revshell = [l.strip() for l in listen.splitlines()
                if re.search(r"(0\.0\.0\.0|\*|\[::\]|127\.0\.0\.1):4444\b", l)]
    if revshell:
        fs.append(F("critical", "检测到 4444 反弹 Shell 监听端口",
                    "4444 是 Metasploit / nc 反弹 Shell 的经典默认端口，d4-webshell W02 即以该监听为判定项。",
                    "\n".join(revshell[:8]),
                    ["取证：ss -lntp | grep 4444; ps -fp <PID>; readlink /proc/<PID>/exe 与 /proc/<PID>/cmdline",
                     "先隔离网络再终止：kill -9 <PID>，随后清除 webshell、cron 与落地文件并复查监听"],
                    "反弹 Shell"))
    return res(fs, "监听端口与外联连接未见高危特征")


# ============================================================ 06 文件与痕迹
add("fore.history", "forensics", "命令历史攻击痕迹",
    "检索 bash_history 中的下载、提权、清日志、加账号等操作",
    [("hist", "cat /root/.bash_history /home/*/.bash_history 2>/dev/null | tail -120"),
     ("susp", "grep -REni '(wget |curl |/dev/tcp|nc -e|bash -i|chmod \\+s|chmod 777|useradd|passwd |ssh-keygen|mysql -e|rm -rf /var/log|history -c|base64 -d|iptables -F|setenforce 0|chattr -i|echo .* >> /etc/|visudo|sudo -i)' /root/.bash_history /home/*/.bash_history 2>/dev/null | tail -50")],
    handler=lambda outputs, s: _hist(outputs))


def _hist(outputs):
    fs = []
    susp = o(outputs, "susp").strip()
    if susp:
        fs.append(F("high", "命令历史中存在高危操作痕迹",
                    "下载执行、加账号、清空日志、关防火墙等序列可还原攻击路径与时间点。",
                    susp[:1000],
                    ["按时间线对照 auth.log / 文件 mtime，还原攻击者操作链",
                     "根据历史中的路径逐个核查落地文件、账号与公钥是否仍存在",
                     "加固：统一走堡垒机审计，禁用 history -c 类抹除手段（PROMPT_COMMAND 实时上报）"],
                    "入侵痕迹"))
    hist = o(outputs, "hist").strip()
    if not hist:
        fs.append(F("low", "命令历史为空或被清空",
                    "history 被清空/重定向到 /dev/null 属于反取证行为，常见于入侵收尾阶段。",
                    "未读取到 .bash_history 内容",
                    ["检查 HISTFILE 是否被改：grep -R HISTFILE /etc/profile* ~/.bashrc",
                     "依赖 auth.log、auditd、堡垒机日志补齐操作审计"],
                    "反取证"))
    return res(fs, "命令历史未见明显攻击指令；已记录最近 120 条")


add("fore.webshell", "forensics", "WebShell 特征文件",
    "在 Web 根目录扫描一句话木马、JSP 马、加密马与近期落地的脚本",
    [("roots", "find / -xdev -maxdepth 6 -type d \\( -name www -o -name html -o -name webapps -o -name public_html -o -name wwwroot -o -name ROOT \\) 2>/dev/null | head -20"),
     ("susp", "grep -REn --include='*.php' --include='*.jsp' --include='*.jspx' --include='*.asp' --include='*.aspx' --include='*.phtml' --include='*.py' '(eval\\(|assert\\(|system\\(|passthru\\(|shell_exec\\(|popen\\(|proc_open\\(|base64_decode\\(|preg_replace\\(.{0,60}/e|\\$_(POST|GET|REQUEST|COOKIE)\\[.{0,30}\\]\\s*\\(|Runtime\\.getRuntime|ProcessBuilder|getParameter\\(\"(cmd|pass|shell)\"|antSword|Behinder|冰蝎|蚁剑)' /var/www /usr/share/nginx /usr/local/nginx /opt/tomcat /usr/local/tomcat /home /srv 2>/dev/null | head -35"),
     ("recent", "find /var/www /usr/share/nginx /opt/tomcat /usr/local/tomcat /srv -xdev -type f \\( -name '*.php' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.war' -o -name '*.phtml' \\) -mtime -14 2>/dev/null | head -30")],
    timeout=45,
    handler=lambda outputs, s: _webshell(outputs))


def _webshell(outputs):
    fs = []
    susp = o(outputs, "susp").strip()
    if susp:
        fs.append(F("critical", "Web 目录存在 WebShell 特征文件",
                    "命中 eval/assert/$_POST 动态执行、Runtime.getRuntime 等特征，通常为一句话木马或冰蝎/蚁剑马。",
                    susp[:1100],
                    ["先取证：cp <file> /root/ir_evidence/; stat <file> 记录时间与属主",
                     "隔离删除：mv <file> /root/quarantine/（勿直接 rm，便于溯源）",
                     "查访问日志定位入口：grep <filename> /var/log/nginx/access.log*；修补对应上传/解析/RCE 漏洞",
                     "全盘复查近期落地的 .php/.jsp/.war 文件"],
                    "WebShell"))
    recent = o(outputs, "recent").strip()
    if recent and not susp:
        fs.append(F("medium", "Web 目录近 14 天新增脚本文件",
                    "新增的 php/jsp/war 需与发布记录核对，攻击者常改名伪装为正常文件。",
                    recent[:800],
                    ["逐个核对内容：grep -REn 'eval|base64_decode|Runtime' <目录>",
                     "对比代码仓库/发布包哈希，删除非授权文件",
                     "Web 目录设置不可写或 noexec，上传目录禁止脚本执行"],
                    "Web 落地"))
    return res(fs, "Web 目录未命中 WebShell 特征；已核查 %d 个根目录" % len(o(outputs, "roots").splitlines()))


add("fore.backup", "forensics", "备份文件与敏感信息泄露",
    "查找 Web 目录下的 .bak/.sql/.git/编辑器缓存/密钥等可直接下载的文件",
    [("bak", "find /var/www /usr/share/nginx /opt /srv /home /var/lib/tomcat* /usr/local/tomcat* /opt/tomcat* -xdev -maxdepth 7 -type f \\( -name '*.bak' -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.zip' -o -name '*.tar.gz' -o -name '*~' -o -name '*.swp' -o -name '.git' -o -name '.env' -o -name 'id_rsa*' -o -name '*.pem' -o -name 'config.php*' -o -iname 'handover*' -o -iname '*account*.txt' -o -iname '*password*.txt' \\) 2>/dev/null | head -50")],
    timeout=35)

HANDLERS["fore.backup"] = generic_rule({
    "keys": ["bak"], "pattern": r"\.bak|\.sql|~$|\.swp|\.git|\.env|id_rsa|\.pem|config\.php",
    "severity": "medium", "title": "Web 路径存在备份 / 配置 / 密钥泄露",
    "summary": "网站源码备份、数据库 dump、.git 与 .env 常被直接 HTTP 下载，进而泄露数据库口令与密钥（CTF 常见得分点）。",
    "fix": ["将备份移出 Web 根目录：mv <file> /backup/ 并设置 600 权限",
            "Nginx 拦截：location ~* \\.(bak|sql|zip|tar.gz|swp|git|env)$ { deny all; }",
            "若含凭据，立即轮换数据库口令与密钥"],
    "tag": "信息泄露", "pass_note": "Web 路径未发现备份/敏感配置文件",
})

add("fore.recent", "forensics", "近期被修改的系统文件",
    "定位 /etc、系统命令目录、Web 目录中近期变更的文件，辅助完整性比对",
    [("recent", "find /etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /var/www -xdev -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM %p\\n' 2>/dev/null | sort -r | head -60"),
     ("binnew", "find /bin /sbin /usr/bin /usr/sbin -maxdepth 1 -type f -mtime -3 -printf '%TY-%Tm-%Td %p\\n' 2>/dev/null | head -25")],
    timeout=45,
    handler=lambda outputs, s: _recent(outputs))


def _recent(outputs):
    fs = []
    binnew = o(outputs, "binnew").strip()
    if binnew:
        fs.append(F("high", "系统命令目录近期出现新增/被修改文件",
                    "/bin、/usr/bin 下的新文件极可能是被替换的系统命令（ps/ls/netstat）或后门二进制。",
                    binnew[:800],
                    ["逐个人工核对：file <file>; dpkg -S <file> / rpm -qf <file> 校验归属",
                     "用包管理器校验完整性：rpm -Va（CentOS）或 debsums -c（Ubuntu）",
                     "从同版本干净机器拷贝恢复被替换命令"],
                    "命令替换"))
    else:
        rec = o(outputs, "recent").strip()
        important = [l for l in rec.splitlines() if re.search(r"/etc/(passwd|shadow|sudoers|cron|ssh|rc\.local|profile)|/var/www|/usr/local/bin", l)]
        if important:
            fs.append(F("medium", "关键配置 / Web 文件近 7 天被修改",
                        "敏感路径的近期变更需与变更单核对，可能是后门写入或配置被篡改。",
                        "\n".join(important[:12]),
                        ["对照配置管理/版本库 diff，确认变更来源",
                         "用 stat + auth.log 交叉定位修改时间与操作账号",
                         "对关键文件建立 AIDE / tripwire 完整性基线"],
                        "完整性"))
    return res(fs, "关键系统目录近 7 天无高危变更")


add("fore.cmdreplace", "forensics", "系统命令被替换 / 别名化",
    "检查 ps/ls/top/netstat 等是否为脚本伪装，以及是否存在命令别名劫持",
    [("files", "file /bin/ps /bin/ls /bin/netstat /usr/bin/top /usr/bin/find /bin/bash /usr/bin/ss 2>/dev/null; ls -l --time-style=long-iso /bin/ps /bin/ls /usr/bin/top /usr/bin/find 2>/dev/null"),
     ("alias", "grep -REn 'alias (ps|ls|top|netstat|ss|find|id|whoami|last|cat|grep)=' /etc/bash.bashrc /etc/profile /etc/profile.d/ /root/.bashrc /home/*/.bashrc 2>/dev/null | head -20")],
    handler=lambda outputs, s: _cmdreplace(outputs))


def _cmdreplace(outputs):
    fs = []
    files = o(outputs, "files")
    script = hits(files, r"(ASCII text|shell script|Python script|Perl script|a /.*script)", 10)
    if script:
        fs.append(F("critical", "核心系统命令被替换为脚本",
                    "ps / ls / top / netstat 变成文本脚本是最经典的 rootkit 手法，用于隐藏进程与端口。",
                    "\n".join(script),
                    ["查看内容取证：cat <file>；md5sum <file> 与同版本系统比对",
                     "从安装介质恢复：rpm -qf <file> && yum reinstall <pkg> 或 apt install --reinstall <pkg>",
                     "用静态 busybox 复核进程与端口，避免被劫持命令误导"],
                    "命令替换"))
    alias = o(outputs, "alias").strip()
    if alias:
        fs.append(F("high", "存在系统命令别名劫持",
                    "alias ps=... 可让管理员每次排查都看到被过滤后的结果。",
                    alias[:600],
                    ["删除 /etc/profile.d/ 与 ~/.bashrc 中的恶意 alias",
                     "排查时使用绝对路径 /bin/ps 或 \\ps 绕过别名"],
                    "命令替换"))
    return res(fs, "核心命令均为 ELF 二进制，未发现别名劫持")


add("fore.tmp", "forensics", "临时目录可执行文件",
    "枚举 /tmp、/var/tmp、/dev/shm 下的可执行文件与可疑落地样本",
    [("tmp", "ls -la --time-style=long-iso /tmp /var/tmp /dev/shm 2>/dev/null | head -70"),
     ("exec", "find /tmp /var/tmp /dev/shm -maxdepth 3 -type f -perm /111 -printf '%TY-%Tm-%Td %m %p\\n' 2>/dev/null | head -30")],
    timeout=30,
    handler=lambda outputs, s: _tmp(outputs))


def _tmp(outputs):
    exe = o(outputs, "exec").strip()
    if not exe:
        return res(note="临时目录未发现可执行文件")
    sev = "high" if re.search(r"\.(sh|py|pl|so|elf|bin)$|\.(sh|py|pl|so)\s|/dev/shm/", exe) else "medium"
    return res([F(sev, "临时目录存在可执行 / 可疑落地文件",
                  "/tmp、/var/tmp、/dev/shm 是木马、矿机与提权 EXP 的首选落地位置（内存目录重启即消失）。",
                  exe[:900],
                  ["取证后清理：cp <file> /root/ir_evidence/; rm -f <file>",
                   "检查是否有进程占用：lsof <file>; fuser -v <file>",
                   "加固：/tmp 与 /dev/shm 使用 noexec,nosuid 挂载，并定期清理"],
                  "落地文件")])


# ============================================================ 07 权限与加固
add("hard.fileperm", "hardening", "核心系统文件权限",
    "校验 passwd/shadow/sudoers/sshd_config/crontab 的权限与属主",
    [("perm", "stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab 2>/dev/null")],
    handler=lambda outputs, s: _fileperm(outputs))


def _fileperm(outputs):
    txt = o(outputs, "perm").strip()
    if not txt:
        return res(note="未读取到核心文件权限（权限不足或路径不存在）")
    fs = []
    for line in txt.splitlines():
        m = re.match(r"^\s*(\d{3,4})\s+(\S+)\s+(.+)$", line)
        if not m:
            continue
        mode, owner, path = m.group(1), m.group(2), m.group(3).strip()
        name = path.rsplit("/", 1)[-1]
        try:
            others_writable = bool(int(mode, 8) & 0o002)
        except ValueError:
            others_writable = False
        if others_writable:
            # 其他用户可写
            fs.append(F("critical", "%s 对其他用户可写" % path,
                        "全局可写的 passwd/shadow/sudoers 可被任意本地用户改写以添加 root 账号或直接提权。",
                        line,
                        ["立即修正：chmod 644 /etc/passwd; chmod 000 /etc/shadow; chmod 440 /etc/sudoers",
                         "chown root:root <file>；检查文件内容是否已被篡改（尤其 UID=0 与 NOPASSWD 行）"],
                        "文件权限"))
            continue
        if name in ("shadow", "gshadow") and mode not in ("000", "600", "640", "400") and not mode.endswith("0"):
            fs.append(F("high", "%s 权限过宽（%s）" % (path, mode),
                        "shadow 泄露可被离线破解全机口令哈希。", line,
                        ["chmod 000 /etc/shadow（root 仍可读）；或 chmod 600 /etc/shadow",
                         "检查属主应为 root:root / root:shadow"], "文件权限"))
    return res(fs, "passwd/shadow/sudoers 等核心文件权限符合基线")


add("hard.firewall", "hardening", "主机防火墙状态",
    "检查 ufw/firewalld/iptables 是否启用及默认策略",
    [("fw", "echo '--- ufw ---'; ufw status verbose 2>/dev/null | head -15; echo '--- firewalld ---'; systemctl is-active firewalld 2>/dev/null; firewall-cmd --state 2>/dev/null; echo '--- iptables ---'; iptables -L -n 2>/dev/null | head -25")],
    handler=lambda outputs, s: _fw(outputs))


def _fw(outputs):
    txt = o(outputs, "fw")
    active = ("Status: active" in txt) or ("running" in txt.lower()) or re.search(r"Chain INPUT \(policy \w+\)", txt)
    rules = len([l for l in txt.splitlines() if re.match(r"^(ACCEPT|DROP|REJECT)\s", l.strip())])
    if not active or rules == 0:
        return res([F("medium", "主机防火墙未启用或无有效规则",
                      "无主机层访问控制时，任何监听端口都对全网可达，管理口与数据库直接暴露。",
                      txt[:600],
                      ["Ubuntu：ufw default deny incoming; ufw allow from <管理IP> to any port 22; ufw enable",
                       "CentOS：systemctl enable --now firewalld; firewall-cmd --permanent --remove-service=... ",
                       "同时在云安全组收敛来源，仅放行 80/443 与堡垒机 SSH"],
                      "边界加固")])
    return res(note="防火墙已启用并存在规则（%d 条）" % rules)


add("hard.selinux", "hardening", "SELinux / AppArmor 强制访问控制",
    "检查 CentOS SELinux 与 Ubuntu AppArmor 是否被关闭",
    [("mac", "echo -n 'getenforce: '; getenforce 2>/dev/null; grep -E '^SELINUX=' /etc/selinux/config 2>/dev/null; echo '--- apparmor ---'; aa-status 2>/dev/null | head -8; systemctl is-active apparmor 2>/dev/null")],
    handler=lambda outputs, s: _mac(outputs, s))


def _mac(outputs, s):
    txt = o(outputs, "mac")
    if re.search(r"Disabled|disabled|SELINUX=disabled", txt, re.I) and session_is_redhat(s):
        return res([F("low", "SELinux 处于 Disabled 状态",
                      "关闭 MAC 后 Web 服务进程可读取任意文件，扩大 RCE 后的横向面（CTF 常见加固失分点）。",
                      txt[:400],
                      ["改为 enforcing：setenforce 1; vim /etc/selinux/config → SELINUX=enforcing",
                       "先切 permissive 观察审计日志，避免业务被策略阻断"],
                      "强制访问控制")])
    return res(note="强制访问控制状态已记录，未见显式关闭")


def session_is_redhat(s):
    return getattr(s, "os_family", "") == "redhat"


add("hard.umask", "hardening", "默认 umask 与口令策略",
    "检查 umask、口令有效期与复杂度策略",
    [("umask", "grep -REn '^[[:space:]]*umask|^UMASK|^PASS_MAX_DAYS|^PASS_MIN_LEN' /etc/profile /etc/bash.bashrc /etc/login.defs /etc/profile.d/ 2>/dev/null | head -25"),
     ("pam", "grep -REn '(pam_pwquality|pam_cracklib|minlen|nullok|remember=)' /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | head -20")],
    handler=lambda outputs, s: _policy(outputs))


def _policy(outputs):
    fs = []
    um = o(outputs, "umask")
    weak = hits(um, r"umask\s+00[0-2]\b|UMASK\s+00[0-2]", 6)
    if weak:
        fs.append(F("medium", "默认 umask 过于宽松",
                    "umask 000/002 会让新建文件默认全局可读/可写，敏感配置易泄露。",
                    "\n".join(weak),
                    ["在 /etc/profile 与 /etc/login.defs 设置 umask 027（或 077）",
                     "对已有敏感文件批量修正：find /etc -type f -perm /o+r -ls 复核"],
                    "默认权限"))
    pam = o(outputs, "pam")
    if pam.strip() and not re.search(r"minlen|pam_pwquality|pam_cracklib", pam, re.I):
        fs.append(F("low", "未配置口令复杂度策略",
                    "可设置弱口令，易被暴力破解。", pam[:500],
                    ["Ubuntu：apt install libpam-pwquality，配置 pam_pwquality.so minlen=12 ...",
                     "CentOS：在 /etc/pam.d/system-auth 增加 pam_pwquality.so retry=3 minlen=12"],
                    "口令策略"))
    return res(fs, "umask 与口令策略基本符合基线")


# ============================================================ 08 Web 服务栈
add("web.nginx", "webstack", "Nginx 配置缺陷",
    "检查目录列表、版本泄露、alias 路径穿越、PHP 解析配置",
    [("conf", "nginx -T 2>/dev/null | head -100 || cat /etc/nginx/nginx.conf 2>/dev/null | head -80"),
     ("flags", "grep -REn '(autoindex|server_tokens|alias[[:space:]]+|fastcgi_pass|fastcgi_split_path_info|try_files|location[[:space:]]+~|add_header|cgi.fix_pathinfo)' /etc/nginx/ /usr/local/nginx/conf/ 2>/dev/null | head -70")],
    timeout=30,
    handler=lambda outputs, s: _nginx(outputs))


def _nginx(outputs):
    flags = o(outputs, "flags")
    if not flags.strip():
        return res(note="未发现 Nginx 配置文件（目标可能未部署 Nginx）")
    fs = []
    if re.search(r"autoindex\s+on", flags, re.I):
        fs.append(F("medium", "Nginx 开启目录列表 autoindex on",
                    "可直接枚举备份、配置与源码文件，常作为 CTF 信息泄露入口。",
                    "\n".join(hits(flags, r"autoindex\s+on", 5)),
                    ["改为 autoindex off; 然后 nginx -t && nginx -s reload",
                     "补充拦截面：location ~* \\.(bak|sql|zip|git|env)$ { deny all; }"],
                    "Nginx"))
    alias_bad = [l for l in flags.splitlines() if re.search(r"location\s+\^?~?\s*/[^/\s]+\s*\{", l) is None and "alias" in l and not re.search(r"alias\s+/\S+/\s*;", l)]
    if alias_bad and re.search(r"location\s+/[^/{\s]*\s*\{", flags):
        fs.append(F("high", "Nginx alias 配置疑似路径穿越",
                    "location 与 alias 结尾斜杠不一致时，可用 ../ 读取上级目录任意文件。",
                    "\n".join(alias_bad[:6]),
                    ["确保 location /x/ 与 alias /path/to/x/ 同时以 / 结尾",
                     "或对 location 使用 ^~ 并限制可访问后缀；nginx -t 后 reload"],
                    "Nginx"))
    if "server_tokens off" not in flags.lower() and re.search(r"nginx", o(outputs, "conf"), re.I):
        fs.append(F("low", "Nginx 暴露版本号 server_tokens",
                    "响应头中显示精确版本，便于攻击者匹配已知 CVE。",
                    hits(flags, r"server_tokens", 3) and "\n".join(hits(flags, r"server_tokens", 3)) or "未在配置中发现 server_tokens off",
                    ["在 http{} 中加入 server_tokens off; 并 nginx -s reload"],
                    "信息泄露"))
    if re.search(r"fastcgi_pass", flags, re.I) and re.search(r"PATH_INFO|fastcgi_split_path_info", flags) and not re.search(r"try_files\s+\$uri\s*=\s*404", flags):
        fs.append(F("high", "Nginx + PHP-FPM 解析配置存在任意代码执行风险",
                    "缺少 try_files $uri =404 / cgi.fix_pathinfo=1 时，上传图片马可经 /1.jpg/xxx.php 被解析执行。",
                    "\n".join(hits(flags, r"fastcgi_pass|fastcgi_split_path_info|try_files", 8)),
                    ["在 location ~ \\.php$ 内加 try_files $uri =404;",
                     "php.ini 设置 cgi.fix_pathinfo=0；限制上传目录脚本执行"],
                    "Nginx/PHP"))
    return res(fs, "Nginx 配置已核查，未发现高危项")


add("web.nginxlog", "webstack", "Nginx 访问日志攻击痕迹",
    "检索 WebShell 访问、扫描器、路径穿越与 SQL 注入特征",
    [("log", "for f in /var/log/nginx/access.log /var/log/nginx/access.log.1 /var/log/httpd/access_log /usr/local/nginx/logs/access.log; do [ -f \"$f\" ] && tail -100 \"$f\"; done 2>/dev/null | grep -Ei '(\\.(php|jsp|asp)\\?|POST /|union\\+select|union select|\\.\\./|%2e%2e|/etc/passwd|eval|base64|antsword|behinder|冰蝎|蚁剑|cmd=|whoami|\\.env|\\.git/|wp-content|shell\\.php)' | tail -35")],
    timeout=30)

HANDLERS["web.nginxlog"] = generic_rule({
    "keys": ["log"],
    "pattern": r"\.(php|jsp|asp)\?|POST /|union[ +]select|\.\./|%2e%2e|/etc/passwd|eval|base64|antsword|behinder|冰蝎|蚁剑|cmd=|whoami|\.env|\.git/|shell\.php",
    "maxn": 12,
    "severity": "high", "title": "Web 访问日志存在攻击 / WebShell 利用痕迹",
    "summary": "日志中出现对可疑脚本的 POST、路径穿越、注入或蚁剑/冰蝎 UA，说明漏洞已被实际利用，需按时间线回溯落点。",
    "fix": ["按命中 URL 与 IP 全量检索：grep <IP> /var/log/nginx/access.log*，还原请求序列",
            "核查该 URL 对应文件是否仍在，结合 mtime 找落地 WebShell",
            "修补入口漏洞（上传/解析/RCE），并对来源 IP 做临时封禁"],
    "tag": "Web 攻击", "pass_note": "近期访问日志未命中攻击特征（或日志不可读）",
})

add("web.tomcat", "webstack", "Tomcat 弱口令与后门应用",
    "检查 tomcat-users.xml 默认口令、manager 暴露、AJP、示例应用与 JSP 马",
    [("users", "for f in $(find / -xdev -maxdepth 7 -name 'tomcat-users.xml' 2>/dev/null | head -5); do echo \"=== $f\"; cat \"$f\" 2>/dev/null | grep -v '^<!--' | head -40; done"),
     ("proc", "ps -ef | grep -Ei '[c]atalina|[t]omcat|[j]ava' | head -10"),
     ("apps", "for d in $(find / -xdev -maxdepth 7 -type d -name webapps 2>/dev/null | head -5); do echo \"=== $d\"; ls -la --time-style=long-iso \"$d\" 2>/dev/null | head -25; done"),
     ("server", "grep -REn '(port=\"8009\"|AJP|secretRequired|allowLinking|privileged=\"true\"|crossContext|autoDeploy|unpackWARs)' $(find / -xdev -maxdepth 7 -name 'server.xml' -path '*conf*' 2>/dev/null | head -3) 2>/dev/null | head -25"),
     ("jsp", "find /opt /usr/local /var/lib /usr/share -xdev -maxdepth 9 -name '*.jsp' -mtime -30 2>/dev/null | head -25")],
    timeout=45,
    handler=lambda outputs, s: _tomcat(outputs))


def _tomcat(outputs):
    fs = []
    users = o(outputs, "users")
    if not users.strip() and not o(outputs, "proc").strip():
        return res(note="未发现 Tomcat 实例")
    weak = hits(users, r'(username|password)="(tomcat|admin|root|manager|both|role1|s3cret|password|123456|test)"', 10)
    if weak:
        fs.append(F("critical", "Tomcat 使用默认 / 弱口令",
                    "manager-gui 弱口令可直接部署 WAR 包 Getshell，是 CTF 与实战中最经典的 Tomcat 打点方式。",
                    "\n".join(weak) + "\n" + users[:500],
                    ["立即改为 16 位以上强口令，或删除 tomcat-users.xml 中不需要的角色",
                     "限制访问：manager 应用仅允许内网/回环，Nginx 层加白名单",
                     "检查 webapps 下是否被部署未知 WAR 包并清理"],
                    "弱口令"))
    server = o(outputs, "server")
    if re.search(r'port="8009"', server) and not re.search(r'secretRequired="true"|secret=', server):
        fs.append(F("critical", "Tomcat AJP 8009 无 secret 暴露（Ghostcat）",
                    "AJP 协议未设 secret 且对外可达时，可读取 WEB-INF 任意文件甚至 RCE（CVE-2020-1938）。",
                    "\n".join(hits(server, r'8009|AJP|secretRequired', 5)),
                    ["升级 Tomcat 至已修复版本，或注释掉 server.xml 中的 AJP Connector",
                     "必须使用时绑定 address=\"127.0.0.1\" 并配置 secret / requiredSecret"],
                    "中间件 RCE"))
    apps = o(outputs, "apps")
    demo = hits(apps, r"\b(docs|examples|manager|host-manager)\b", 8)
    if demo and "manager" in apps:
        fs.append(F("medium", "Tomcat 示例 / 管理应用未移除",
                    "docs/examples 与 manager 常含已知漏洞与默认入口，生产环境应删除。",
                    "\n".join(demo[:6]),
                    ["删除 webapps 下的 docs、examples、host-manager；manager 按需保留并加访问白名单",
                     "设置 autoDeploy=\"false\"，部署走受控发布流程"],
                    "暴露面"))
    jsp = o(outputs, "jsp").strip()
    if jsp:
        fs.append(F("high", "近 30 天新增 JSP 文件（疑似 WebShell）",
                    "Tomcat 被打点后通常落地 JSP 马于 ROOT 或随机目录。",
                    jsp[:700],
                    ["逐个核查：grep -REn 'Runtime|ProcessBuilder|getParameter' <jsp文件>",
                     "隔离非授权文件并重启 Tomcat，同时修补上传/WAR 部署入口"],
                    "WebShell"))
    return res(fs, "Tomcat 实例已核查，未发现默认口令 / AJP / 异常 JSP")


add("web.mysql", "webstack", "MySQL 安全配置",
    "检查空口令、root 远程、secure_file_priv、UDF、日志写马与明文口令",
    [("proc", "ps -ef | grep -E '[m]ysqld|[m]ariadbd' | head -8"),
     ("db", "mysql -uroot -N -B -e \"select concat(user,'@',host,' plugin=',ifnull(plugin,''),' authlen=',length(ifnull(authentication_string,''))) from mysql.user; show variables like 'secure_file_priv'; show variables like 'general_log%'; show variables like 'log_bin'; select version();\" 2>&1 | head -35"),
     ("cnf", "grep -REn '^[[:space:]]*(user|password|pass)[[:space:]]*=' /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/conf.d/ /root/.my.cnf /etc/my.cnf.d/ 2>/dev/null | head -20"),
     ("udf", "ls -la /usr/lib/mysql/plugin/ /usr/lib64/mysql/plugin/ /usr/lib/mariadb/plugin/ 2>/dev/null | head -25; find / -xdev -name '*.so' -path '*plugin*' -mtime -30 2>/dev/null | head -15"),
     ("hist", "cat /root/.mysql_history 2>/dev/null | tail -25")],
    timeout=35,
    handler=lambda outputs, s: _mysql(outputs))


def _mysql(outputs):
    fs = []
    db = o(outputs, "db")
    cnf = o(outputs, "cnf")
    if not o(outputs, "proc").strip() and "mysql" not in db.lower():
        return res(note="未发现 MySQL/MariaDB 实例")
    if re.search(r"Access denied|ERROR 1045|command not found", db, re.I):
        fs.append(F("low", "无法以 root 免密读取 MySQL 用户表",
                    "说明已设置 root 口令（正向），但需人工用受控账号核对以下项：空口令账号、root@%、secure_file_priv。",
                    db[:400],
                    ["使用运维保管的高权账号登录复核：mysql -u<user> -p -e \"select user,host from mysql.user;\"",
                     "禁止把数据库口令写入命令行历史或明文配置文件"],
                    "数据库"))
    userlines = hits(db, r"^.+@.+\s+plugin=", 15)
    if userlines:
        anon = [l for l in userlines if re.match(r"^@|^\s+@", l)]
        if anon:
            fs.append(F("high", "MySQL 存在匿名用户",
                        "匿名账号可无用户名登录数据库。", "\n".join(anon),
                        ["DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;",
                         "执行 mysql_secure_installation 统一清理"], "弱口令"))
        rootall = [l for l in userlines if l.strip().startswith("root@%")]
        if rootall:
            fs.append(F("critical", "MySQL root 允许任意主机远程登录（root@%）",
                        "数据库最高权限对全网开放，配合弱口令可直接接管，并可经 outfile/UDF 提权到系统。",
                        "\n".join(rootall) + "\n" + db[:400],
                        ["限制来源：RENAME USER 'root'@'%' TO 'root'@'localhost'; FLUSH PRIVILEGES;",
                         "为 root 设置强口令；业务使用最小权限的独立账号",
                         "防火墙仅放行应用服务器到 3306"], "数据库"))
        emptypass = [l for l in userlines if re.search(r"authlen=0\b", l)]
        if emptypass:
            fs.append(F("critical", "MySQL 存在空口令账号",
                        "无需口令即可登录数据库，CTF 中常与 UDF/outfile 组合提权。",
                        "\n".join(emptypass[:8]),
                        ["ALTER USER '<user>'@'<host>' IDENTIFIED BY '<强口令>'; FLUSH PRIVILEGES;",
                         "运行 mysql_secure_installation 清理匿名账号与测试库"], "弱口令"))
    if re.search(r"secure_file_priv\s*$|secure_file_priv\s+\n", db) or re.search(r"secure_file_priv\s+(\n|$)", db):
        fs.append(F("high", "MySQL secure_file_priv 未限制（可写任意路径）",
                    "允许 INTO OUTFILE 写 WebShell 到网站目录，或写插件目录做 UDF 提权。",
                    hits(db, r"secure_file_priv", 3) and "\n".join(hits(db, r"secure_file_priv", 3)) or db[:300],
                    ["my.cnf 中设置 secure_file_priv=/var/lib/mysql-files 并重启 mysqld",
                     "数据库账号不授予 FILE 权限；plugin_dir 设为仅 root 可写"],
                    "数据库提权"))
    if re.search(r"general_log\s+ON", db, re.I):
        fs.append(F("high", "MySQL general_log 已开启",
                    "若 general_log_file 指向 Web 目录，可直接写入一句话木马（经典 getshell 手法）。",
                    "\n".join(hits(db, r"general_log", 4)),
                    ["SET GLOBAL general_log=OFF; 检查 general_log_file 路径是否在 Web 目录",
                     "审查 .mysql_history 中是否有 set global general_log_file 语句"],
                    "数据库提权"))
    udf = o(outputs, "udf")
    udf_susp = hits(udf, r"mysqludf|lib_mysqludf|udf\.so|udf_", 8)
    if udf_susp:
        fs.append(F("critical", "MySQL 插件目录疑似存在 UDF 提权库",
                    "自定义 UDF .so 可通过 sys_exec/sys_eval 以 mysqld 运行身份执行系统命令。",
                    "\n".join(udf_susp),
                    ["DROP FUNCTION IF EXISTS <func>; 删除对应 .so 文件并重启 mysqld",
                     "限制 plugin_dir 目录权限，数据库账号不授予 SUPER / FILE 权限"],
                    "数据库提权"))
    cnf_bad = hits(cnf, r"password\s*=|pass\s*=", 8)
    if cnf_bad:
        fs.append(F("medium", "MySQL 配置文件含明文口令",
                    "my.cnf / .my.cnf 中明文口令可被任意读取该文件的本地用户复用。",
                    "\n".join(cnf_bad),
                    ["chmod 600 /root/.my.cnf；改用 mysql_config_editor 或密钥管理",
                     "轮换已暴露的口令"],
                    "凭据泄露"))
    hist = o(outputs, "hist")
    if re.search(r"into\s+(out|dump)file|udf|general_log_file|set\s+global", hist, re.I):
        fs.append(F("critical", ".mysql_history 出现 outfile / UDF 提权操作",
                    "攻击者已尝试通过数据库写文件或加载 UDF 获取系统权限。",
                    hits(hist, r"into\s+(out|dump)file|udf|general_log_file|set\s+global", 8) and "\n".join(hits(hist, r"into\s+(out|dump)file|udf|general_log_file|set\s+global", 8)) or hist[:400],
                    ["核对目标路径是否生成 WebShell：ls -la <Web目录> / <plugin_dir>",
                     "清理恶意文件与 UDF：DROP FUNCTION <func>; 删除 .so",
                     "限制 FILE 权限与 secure_file_priv"],
                    "数据库提权"))
    return res(fs, "MySQL 实例已核查，未见空口令 / root@% / 写文件痕迹")


add("web.php", "webstack", "PHP 安全配置",
    "检查 disable_functions、allow_url_include、expose_php、open_basedir",
    [("ini", "php -i 2>/dev/null | grep -Ei '^(disable_functions|expose_php|allow_url_include|allow_url_fopen|open_basedir|display_errors|enable_dl)' | head -20; grep -REn '^[[:space:]]*(disable_functions|expose_php|allow_url_include|open_basedir)[[:space:]]*=' /etc/php* /usr/local/php*/etc/ 2>/dev/null | head -25")],
    handler=lambda outputs, s: _php(outputs))


def _php(outputs):
    txt = o(outputs, "ini")
    if not txt.strip():
        return res(note="未发现 PHP 环境")
    fs = []
    m = re.search(r"disable_functions\s*(=>|:|=)\s*([^\n]*)", txt, re.I)
    if m and not m.group(2).strip():
        fs.append(F("high", "PHP 未设置 disable_functions",
                    "WebShell 可直接调用 system/exec/passthru 执行系统命令，RCE 后无二次阻碍。",
                    "\n".join(hits(txt, r"disable_functions", 4)),
                    ["php.ini 配置 disable_functions=exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,dl,putenv",
                     "按业务回归测试后重启 php-fpm；同时 open_basedir 限制到站点目录"],
                    "PHP"))
    if re.search(r"allow_url_include\s*(=>|:|=)\s*On", txt, re.I):
        fs.append(F("high", "PHP allow_url_include = On",
                    "允许远程文件包含，可直接加载远程 WebShell。",
                    "\n".join(hits(txt, r"allow_url_include", 3)),
                    ["设为 allow_url_include=Off，必要时同时 allow_url_fopen=Off"], "PHP"))
    if re.search(r"expose_php\s*(=>|:|=)\s*On", txt, re.I):
        fs.append(F("low", "PHP 暴露版本信息",
                    "响应头 X-Powered-By 泄露 PHP 版本。",
                    "\n".join(hits(txt, r"expose_php", 3)),
                    ["expose_php=Off；Nginx 层 proxy_hide_header X-Powered-By"], "信息泄露"))
    if re.search(r"display_errors\s*(=>|:|=)\s*On", txt, re.I):
        fs.append(F("low", "PHP 生产环境显示错误详情",
                    "报错会泄露绝对路径、SQL 语句与配置。",
                    "\n".join(hits(txt, r"display_errors", 3)),
                    ["display_errors=Off; log_errors=On; error_log 指向受保护路径"], "信息泄露"))
    return res(fs, "PHP 关键配置符合基线")


add("web.serviceuser", "webstack", "中间件运行身份",
    "检查 nginx/tomcat/mysql/php-fpm 是否以 root 身份运行",
    [("procs", "ps -eo user:20,pid,args ww 2>/dev/null | grep -Ei '[n]ginx|[t]omcat|[c]atalina|[m]ysqld|[m]ariadbd|[h]ttpd|[p]hp-fpm|[r]edis-server' | head -25")],
    handler=lambda outputs, s: _svcuser(outputs))


def _svcuser(outputs):
    txt = o(outputs, "procs")
    if not txt.strip():
        return res(note="未发现常见中间件进程")
    rootrun = [l for l in txt.splitlines() if l.strip().lower().startswith("root ") and not re.search(r"nginx: master|php-fpm: master", l, re.I)]
    if rootrun:
        return res([F("high", "Web/DB 服务以 root 身份运行",
                      "服务被攻破即等于获得 root，且可写任意路径（CTF 常见 getshell 后直接读 flag）。",
                      "\n".join(rootrun[:10]),
                      ["Nginx：nginx.conf 首行 user www-data; 并 reload",
                       "Tomcat/MySQL：使用专用低权账号启动（systemd Unit 中 User= 指定）",
                       "确认数据目录属主同步调整，避免启动失败"],
                      "最小权限")])
    return res(note="中间件均使用非 root 账号运行")


# ============================================================ 09 日志与审计
add("log.auth", "logs", "SSH 登录与 sudo 审计",
    "检索认证日志中的爆破、异常成功登录、公钥登录与 sudo 命令",
    [("auth", "grep -REhi '(Failed password|Accepted password|Accepted publickey|Invalid user|authentication failure|sudo:.*COMMAND|useradd|new user|su:.*session opened)' /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/secure-1 2>/dev/null | tail -90")],
    timeout=30,
    handler=lambda outputs, s: _authlog(outputs))


def _authlog(outputs):
    txt = o(outputs, "auth")
    if not txt.strip():
        return res(note="未读取到认证日志（路径不同或日志被清空）")
    fs = []
    failed = hits(txt, r"Failed password|authentication failure|Invalid user", 30)
    if len(failed) >= 10:
        ips = {}
        for l in failed:
            m = re.search(r"from\s+((?:\d{1,3}\.){3}\d{1,3})", l)
            if m:
                ips[m.group(1)] = ips.get(m.group(1), 0) + 1
        top = sorted(ips.items(), key=lambda x: -x[1])[:5]
        fs.append(F("high", "认证日志存在大量登录失败（疑似暴力破解）",
                    "近期采样中命中 %d 条失败记录，需确认是否有成功爆破后的登录。" % len(failed),
                    "Top 来源：%s\n\n%s" % (
                        ", ".join("%s(%d次)" % (ip, n) for ip, n in top) or "未解析到 IP",
                        "\n".join(failed[:8])),
                    ["封禁来源：iptables -A INPUT -s <IP> -j DROP 或 fail2ban",
                     "关闭口令登录改用密钥：PasswordAuthentication no；限制 AllowUsers",
                     "核对失败时间窗内是否出现 Accepted 记录"],
                    "暴力破解"))
    accepted = hits(txt, r"Accepted (publickey|password) for (root|admin|mysql|www-data|test|guest)", 10)
    if accepted:
        fs.append(F("critical", "特权 / 异常账号登录成功记录",
                    "root 或非常用账号出现成功登录，需核对来源 IP 与所用公钥指纹。",
                    "\n".join(accepted[:8]),
                    ["核对 IP 归属与时间点：grep 'Accepted' /var/log/auth.log*",
                     "若为入侵：立即吊销对应公钥 / 改口令，并检查该会话后续操作",
                     "设置 PermitRootLogin no + AllowUsers 白名单"],
                    "异常登录"))
    sudo_cmds = hits(txt, r"sudo:.*COMMAND=.*(bash|sh|su|vi|vim|find|nmap|python|chmod|chown|passwd|cat /etc/shadow|useradd)", 10)
    if sudo_cmds:
        fs.append(F("medium", "sudo 日志出现敏感命令",
                    "涉及 shell 逃逸或凭据读取的命令需与运维操作核对。",
                    "\n".join(sudo_cmds[:8]),
                    ["对照堡垒机工单确认操作人；收紧 sudoers 命令白名单",
                     "开启 auditd 记录 execve，补齐命令级审计"],
                    "审计"))
    newu = hits(txt, r"useradd|new user", 8)
    if newu:
        fs.append(F("high", "认证日志出现新建用户操作",
                    "可能是攻击者建立持久化账号的直接证据。",
                    "\n".join(newu[:8]),
                    ["核对 /etc/passwd 中该账号是否仍存在，删除非授权账号",
                     "清理其 crontab、SSH 公钥、sudoers 授权"],
                    "账号变更"))
    return res(fs, "认证日志未见爆破成功 / 异常特权登录痕迹")


add("log.session", "logs", "登录会话与在线用户",
    "检查 last/lastb/w 中的异常终端与来源",
    [("sess", "echo '--- last ---'; last -20 2>/dev/null; echo '--- lastb ---'; lastb -8 2>/dev/null; echo '--- online ---'; w -h 2>/dev/null; who 2>/dev/null")],
    handler=lambda outputs, s: _session(outputs))


def _session(outputs):
    txt = o(outputs, "sess")
    pts = [l for l in txt.splitlines() if re.search(r"\bpts/\d+\b", l) and not l.startswith("---")]
    if pts and len(pts) > 3:
        return res([F("low", "存在多个历史 / 在线终端会话",
                      "多会话并行时需确认是否为同一操作者；CTF 中常用来发现残留的攻击者会话。",
                      "\n".join(pts[:8]),
                      ["核对来源 IP：last -a | head -30；异常会话用 pkill -u <user> 或 kill <pts进程>",
                       "启用会话超时 TMOUT=600 并记录堡垒机审计"],
                      "会话审计")])
    return res(note="登录会话记录正常")


add("log.tamper", "logs", "日志完整性与审计服务",
    "检查日志是否被清空、auditd/rsyslog 是否运行",
    [("files", "ls -la --time-style=long-iso /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null; find /var/log -maxdepth 1 -type f -size 0 -printf '%p\\n' 2>/dev/null | head -15"),
     ("svc", "echo -n 'auditd='; systemctl is-active auditd 2>/dev/null; echo -n 'rsyslog='; systemctl is-active rsyslog 2>/dev/null; echo -n 'journald='; systemctl is-active systemd-journald 2>/dev/null")],
    handler=lambda outputs, s: _tamper(outputs))


def _tamper(outputs):
    fs = []
    files = o(outputs, "files")
    empty = [l for l in files.splitlines() if l.startswith("/") and not re.search(r"\s", l)]
    auth_missing = bool(files.strip()) and re.search(r"auth\.log|secure", files) is None
    zero_auth = any(re.search(r"(auth\.log|secure|wtmp|btmp)$", l) for l in empty)
    if auth_missing or zero_auth:
        fs.append(F("high", "关键审计日志缺失或被清空",
                    "auth.log / secure / wtmp 被清空是典型的反取证行为，导致无法还原入侵路径。",
                    (files[:500] or "未找到 /var/log/auth.log 或 /var/log/secure"),
                    ["检查是否有 chattr +a 保护需求：chattr +a /var/log/auth.log",
                     "配置远程日志服务器（rsyslog @@<logserver>:514）防止本地删除",
                     "结合堡垒机、云审计与文件 mtime 补齐时间线"],
                    "反取证"))
    svc = o(outputs, "svc")
    if "auditd=inactive" in svc or "auditd=unknown" in svc or "auditd=" == svc.strip():
        fs.append(F("low", "auditd 未运行",
                    "缺少系统调用级审计，无法追踪 execve、文件改写等细粒度行为。",
                    svc[:300],
                    ["systemctl enable --now auditd；配置 /etc/audit/rules.d/ 监控 /etc/passwd、/etc/shadow、sudoers",
                     "日志集中转发到独立日志服务器"],
                    "审计"))
    return res(fs, "关键日志存在且审计服务正常")


# ============================================================ 靶场专项补强
# 依据 lab-ir/states 下 d2、d2-min、d4-webshell、d5-mining、d5-ransom、
# d5-final、hardening-lab(N01–N10) 的 check.sh 判定口径补充。
# 全部为只读命令；每条发现均附带「排查方法」（思路 + 实际命令 + 判定口径）。

add("id.load", "identity", "系统负载与资源异常",
    "采集 loadavg、CPU 核数与高占用进程，识别挖矿/勒索加密导致的持续高负载",
    [("load", "cat /proc/loadavg; nproc; uptime"),
     ("top", "ps -eo pid,ppid,user,pcpu,pmem,stat,comm,args --sort=-pcpu 2>/dev/null | head -18"),
     ("mem", "free -m 2>/dev/null | head -4")],
    handler=lambda outputs, s: _load(outputs))


def _load(outputs):
    fs = []
    txt = o(outputs, "load").strip()
    lines = txt.splitlines()
    load = None
    cores = 1
    if lines:
        m = re.match(r"^(\d+\.\d+)", lines[0])
        if m:
            load = float(m.group(1))
    for l in lines[1:]:
        if re.fullmatch(r"\d+", l.strip()):
            cores = max(1, int(l.strip()))
            break
    if load is not None and load >= max(2.0, cores * 1.5):
        fs.append(F("medium", "系统负载持续偏高（疑似挖矿 / 加密占用）",
                    "1 分钟负载 %.2f / %d 核，显著超过正常水位。挖矿木马与勒索加密常导致 CPU 长期满载（d5-mining M06 判定项）。" % (load, cores),
                    ev(outputs, "load", "top"),
                    ["ps -eo pid,pcpu,comm,args --sort=-pcpu | head 定位高占用进程",
                     "readlink /proc/<PID>/exe、ls -l /proc/<PID>/cwd 找到落地文件",
                     "终止恶意进程并清除复活链后复查 /proc/loadavg 是否回落"],
                    "资源异常"))
    top = o(outputs, "top")
    if re.search(r"\.pm/|kworker[^\n]*python|xmrig|minerd|stratum|\.winlin", top, re.I):
        fs.append(F("high", "高占用进程名疑似伪装或矿机",
                    "进程名/参数中出现矿池、隐蔽目录或伪装内核线程特征，需按 /proc/<PID>/exe 辨真假。",
                    top[:900],
                    ["readlink /proc/<PID>/exe；真内核线程无 exe 路径，指向 python 的必为伪装",
                     "取证样本后终止进程，并清除 cron/systemd 复活链"],
                    "伪装进程"))
    return res(fs, "负载与进程资源占用未见异常")


add("acct.locked", "accounts", "交付账号锁定状态与可登录面",
    "核对可交互登录账号是否已 nologin + 锁定，识别交付遗留服务账号",
    [("status", "echo '--- 可登录账号 ---'; getent passwd | awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1\" \"$3\" \"$6\" \"$7}'; echo '--- passwd -S ---'; for u in $(getent passwd | awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' | head -25); do echo -n \"$u \"; passwd -S $u 2>/dev/null; done"),
     ("groups", "echo '--- sudo/wheel/admin 组 ---'; getent group sudo wheel admin root 2>/dev/null | head -10")],
    handler=lambda outputs, s: _locked(outputs))


def _locked(outputs):
    fs = []
    txt = o(outputs, "status")
    status = txt.split("--- passwd -S ---")[-1]
    svc_like = re.compile(r"^(svc_|service|backup|deploy|guest|test|temp|ops|hruser|webadm|admin|lab)", re.I)
    unlocked = []
    for l in status.splitlines():
        m = re.match(r"^(\S+)\s+\S+\s+([PSL])", l.strip())
        if m and svc_like.match(m.group(1)) and m.group(2) == "P":
            unlocked.append(l.strip())
    if unlocked:
        fs.append(F("high", "交付 / 服务账号仍可用口令登录且未锁定",
                    "svc_backup、deploy 一类交付遗留账号应为 nologin + passwd -S 显示 L（锁定）。P 表示口令可用，配合弱口令即可直接登录（hardening-lab N01）。",
                    "\n".join(unlocked[:12]) + "\n" + txt.split("--- passwd -S ---")[0][:500],
                    ["usermod -s /usr/sbin/nologin <user>; passwd -l <user>；用 passwd -S <user> 复核为 L",
                     "同时清理该账号的 authorized_keys、crontab 与 sudoers.d 条目",
                     "若曾在交接单/历史命令中出现明文口令，必须轮换"],
                    "账号收权"))
    groups = o(outputs, "groups")
    if re.search(r"^(sudo|wheel|admin)\b.*\b(hruser|webadm|backdoor|toor)\b", groups, re.I | re.M):
        fs.append(F("high", "异常账号被加入 sudo/wheel 提权组",
                    "后门账号常通过加入 sudo 组获得提权（d5-ransom 的 hruser 即走此路径）。",
                    groups[:600],
                    ["gpasswd -d <user> sudo; 核查 /etc/sudoers.d/ 中该账号的残留授权",
                     "审计 auth.log 中该账号的登录与 sudo 记录"],
                    "提权"))
    return res(fs, "可登录账号锁定状态与提权组未见异常")


add("persist.unitscript", "persistence", "服务启动脚本被普通用户可写",
    "追踪 systemd ExecStart 与计划任务调用的脚本，检查组/其他用户可写造成的 root 劫持面",
    [("units", "grep -REn '^[[:space:]]*ExecStart=' /etc/systemd/system/ /lib/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null | head -45"),
     ("scripts", "for f in $(grep -RhE '^[[:space:]]*ExecStart=' /etc/systemd/system/ /lib/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null | sed -E 's/^[^=]*=//' | awk '{print $1}' | grep '^/' | sort -u | head -30); do [ -f \"$f\" ] && stat -c '%a %U:%G %n' \"$f\" 2>/dev/null; done"),
     ("perm", "find /etc/cron.d /etc/cron.daily /etc/cron.weekly /usr/local/sbin /opt /srv /var/lib -xdev -maxdepth 3 -type f -perm /022 -printf '%m %u:%g %p\\n' 2>/dev/null | head -35")],
    timeout=40,
    handler=lambda outputs, s: _unitscript(outputs))


def _unitscript(outputs):
    fs = []
    bad = []
    for key in ("scripts", "perm"):
        for l in o(outputs, key).splitlines():
            m = re.match(r"^\s*(\d{3,4})\s+(\S+)\s+(.+)$", l.strip())
            if not m:
                continue
            try:
                bits = int(m.group(1), 8)
            except ValueError:
                continue
            if bits & 0o022:
                bad.append(l.strip())
    if bad:
        fs.append(F("high", "root 服务 / 计划脚本被组或其他用户可写",
                    "以 root 启动的 run.sh 若可被普通用户改写，任意本地用户即可借服务重启执行任意命令（hardening-lab N06 / d2 H05）。",
                    "\n".join(dict.fromkeys(bad))[:1200],
                    ["立即收紧：chmod 755 <脚本>; chown root:root <脚本>",
                     "systemctl cat <单元名> 看 ExecStart 指向，核对脚本内容是否被植入后门",
                     "对 /opt /srv 业务目录统一收敛组写位并建立变更审计"],
                    "提权面"))
    return res(fs, "systemd ExecStart 与计划脚本未见组/其他可写")


add("proc.fakekernel", "procnet", "伪装内核线程与矿机落地路径",
    "比对 ps 中 [kworker/*] 等内核线程名与 /proc/<pid>/exe，识别伪装矿机",
    [("pids", "ps -eo pid,ppid,user,stat,comm,args 2>/dev/null | head -130"),
     ("exe", "for p in $(ls -d /proc/[0-9]* 2>/dev/null | sed 's#/proc/##' | head -250); do n=$(cat /proc/$p/comm 2>/dev/null); case \"$n\" in kworker*|ksoftirqd*|migration*|watchdog*|kthreadd*|kswapd*) e=$(readlink /proc/$p/exe 2>/dev/null); [ -n \"$e\" ] && echo \"$p $n -> $e\";; esac; done | head -30"),
     ("hidden", "ls -la --time-style=long-iso /usr/local/lib/.pm /usr/local/share /opt/.cache /var/tmp/.cache /dev/shm 2>/dev/null | head -50")],
    timeout=40,
    handler=lambda outputs, s: _fakekernel(outputs))


def _fakekernel(outputs):
    fs = []
    exe = o(outputs, "exe").strip()
    if exe:
        fs.append(F("critical", "发现伪装成内核线程的进程",
                    "真内核线程（[kworker/...]）在 /proc/<PID>/exe 上无路径；若 exe 指向 python/bash 等真实文件即为伪装矿机（d5-mining M01 教学点）。",
                    exe + "\n--- ps ---\n" + o(outputs, "pids")[:700],
                    ["取证：readlink /proc/<PID>/exe; ls -la /proc/<PID>/cwd; cat /proc/<PID>/cmdline",
                     "先断矿池外联，再 kill -9 <PID>；删除落地目录与 @reboot/transient 单元",
                     "杀掉后观察是否复活，复活说明持久化未清干净"],
                    "伪装进程"))
    hidden = o(outputs, "hidden")
    if re.search(r"\.pm/?|\.sysmaint|kworker-helpt|\.winlin", hidden, re.I):
        fs.append(F("high", "存在隐蔽矿机 / 载荷落地目录",
                    "点号开头的目录（如 /usr/local/lib/.pm）用于隐藏矿机源码与配置，是 d5-mining M03 的判定路径。",
                    hidden[:900],
                    ["取证打包：tar czf /root/evidence/miner.tgz <目录> 后删除",
                     "清理前先终止占用进程并移除复活链，避免删除后自动重建"],
                    "落地文件"))
    return res(fs, "未发现伪装内核线程或隐蔽矿机目录")


add("proc.legacy", "procnet", "未授权服务与遗留明文端口",
    "识别 21/23/9000/6379 等调试、无认证、明文服务及其 systemd 单元",
    [("listen", "ss -lntup 2>/dev/null | head -90; echo '--- netstat ---'; netstat -lntup 2>/dev/null | head -60"),
     ("units", "systemctl list-units --type=service --all --no-pager 2>/dev/null | grep -Ei 'lab-|debug|cache|ftp|telnet|vsftpd|inetd|redis|mining|pool|webshell|reindex' | head -35"),
     ("redis", "grep -REn '^[[:space:]]*(bind|protected-mode|requirepass)' /etc/redis/redis.conf /etc/redis.conf /etc/redis/*.conf 2>/dev/null | head -25; echo '--- conf files ---'; ls -la /etc/systemd/system/lab-*.service /etc/systemd/system/*debug*.service /etc/systemd/system/*cache*.service 2>/dev/null | head -20")],
    handler=lambda outputs, s: _legacy(outputs))


def _legacy(outputs):
    fs = []
    listen = o(outputs, "listen")
    plain = [l.strip() for l in listen.splitlines() if re.search(r":(21|23)\b", l)]
    if plain:
        fs.append(F("high", "FTP / Telnet 明文服务仍在监听",
                    "21/23 为明文协议，凭据可被嗅探，属于上线前应下线的多余服务（d2 H08）。",
                    "\n".join(plain[:10]),
                    ["systemctl disable --now vsftpd inetd xinetd telnetd；删除对应 unit 文件",
                     "用 ss -lntp 复核 21/23 已无监听"],
                    "明文服务"))
    debug = [l.strip() for l in listen.splitlines() if re.search(r":(9000|8000|8081)\b", l)]
    if debug:
        fs.append(F("high", "非标准端口存在调试 / 文件浏览服务",
                    "9000 一类端口上的静态文件服务可直接下载源码与配置（hardening-lab N03）。",
                    "\n".join(debug[:10]),
                    ["ss -lntp | grep <端口> 找到 PID；systemctl cat <单元名> 看 ExecStart",
                     "systemctl disable --now <单元名> 并删除 unit 文件，复查端口无监听",
                     "用 curl http://127.0.0.1:<端口>/ 复测应拒连"],
                    "暴露面"))
    redis = [l.strip() for l in listen.splitlines() if re.search(r":6379\b", l)]
    conf = o(outputs, "redis")
    if redis and not re.search(r"requirepass\s+\S", conf, re.I):
        fs.append(F("critical", "Redis 无认证监听（可直接执行任意命令）",
                    "6379 对外且未设置 requirepass，可通过写 crontab / 主从复制直接 getshell（hardening-lab N09）。",
                    "\n".join(redis[:6]) + "\n" + conf[:500],
                    ["立即设置 requirepass <强口令> 并 bind 127.0.0.1、protected-mode yes",
                     "systemctl disable --now lab-cache 一类未授权单元并删除 unit 文件",
                     "排查是否已被写入 ~/.ssh/authorized_keys 或 crontab"],
                    "未授权访问"))
    units = [l.strip() for l in o(outputs, "units").splitlines()
             if re.search(r"lab-|debug|mining|pool|reindex|cache", l, re.I)]
    if units:
        fs.append(F("medium", "存在未登记的调试 / 病毒类 systemd 单元",
                    "lab-mining-pool、lab-debug、dbreindex 一类单元是挖矿与勒索常用的复活链，需与资产清单核对。",
                    "\n".join(units[:14]),
                    ["systemctl cat <单元名> 看 ExecStart；systemctl stop <单元名> 后 disable 并删除 unit 文件",
                     "systemctl list-units --all 复查，再清理对应落地脚本"],
                    "复活链"))
    return res(fs, "未发现明文 / 调试 / 无认证服务监听")


add("fore.ransom", "forensics", "勒索加密残留与恢复材料",
    "查找勒索信、.locked 加密文件、本机密钥与离线备份完整性，评估可恢复性",
    [("notes", "find /srv /var/www /home /opt /root -xdev -maxdepth 5 -type f \\( -iname 'RECOVER*' -o -iname '*README*DECRYPT*' -o -iname '*ransom*' -o -iname '*HOW_TO*' -o -iname '*.locked' \\) -printf '%TY-%Tm-%Td %s %p\\n' 2>/dev/null | head -40"),
     ("locked", "find /srv /home /var/www /opt -xdev -type f \\( -name '*.locked' -o -name '*.encrypted' -o -name '*.enc' -o -name '*.wncry' -o -name '*.crypto' \\) 2>/dev/null | head -30"),
     ("keys", "ls -la --time-style=long-iso /var/tmp/.syskey /var/tmp/.winlin /tmp/.syskey /root/.syskey /var/log/ransom-activity.log 2>/dev/null; echo '--- 备份 ---'; ls -la --time-style=long-iso /srv/backup /backup /var/backups 2>/dev/null | head -30; echo '--- 数据首行 ---'; head -1 /srv/hrdata/employee_roster.csv 2>/dev/null")],
    timeout=40,
    handler=lambda outputs, s: _ransom(outputs))


def _ransom(outputs):
    fs = []
    notes = o(outputs, "notes").strip()
    locked = o(outputs, "locked").strip()
    if notes or locked:
        fs.append(F("critical", "检测到勒索加密事件残留",
                    "存在勒索信或 .locked 加密文件，说明业务数据已被加密（d5-ransom X01/X02）。处置顺序必须是「隔离 → 取证 → 清除 → 恢复」。",
                    (notes + "\n--- 加密文件 ---\n" + locked)[:1200],
                    ["先隔离主机网络并取证：cp 加密样本、勒索信、日志到 /root/evidence/",
                     "查找本机密钥（/var/tmp/.syskey）与离线备份，先解密/恢复再删除 .locked，切勿先删加密文件",
                     "清除后门账号、cron 持久化与落地载荷，最后校验业务文件明文可读"],
                    "勒索"))
    keys = o(outputs, "keys")
    if re.search(r"\.syskey|ransom-activity\.log|\.winlin", keys):
        fs.append(F("high", "勒索载荷 / 本机密钥 / 行为链日志仍在磁盘",
                    "密钥与行为日志既是恢复线索也是攻击者痕迹，必须先取证保存再清理（d5-ransom X05）。",
                    keys[:900],
                    ["取证打包到只读目录：tar czf /root/evidence/ransom.tgz <路径>",
                     "按日志时间线还原下载源、执行方式与后门账号，再删除 /var/tmp/.winlin 等载荷",
                     "验证离线备份 nightly.tar.gz 是否完好，避免在线备份一同被加密"],
                    "取证线索"))
    return res(fs, "未发现勒索信 / 加密残留 / 本机密钥")


add("fore.credentials", "forensics", "散落凭据与交接单泄露",
    "查找私钥、.env、明文账号清单与历史命令中的口令，避免二次失陷",
    [("files", "find /home /srv /opt /var/www /root -xdev -maxdepth 6 -type f \\( -name '*.pem' -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '.env' -o -name '*.key' -o -iname 'handover*' -o -iname '*password*.txt' -o -iname '*account*.txt' -o -name 'credentials*' -o -name '.my.cnf' -o -name '.netrc' \\) -printf '%m %u:%g %p\\n' 2>/dev/null | head -50"),
     ("hist", "grep -REni '(password|passwd|pwd|secret|token|mysql -u|sshpass|export .*PASS)[[:space:]]*[:=]' /root/.bash_history /home/*/.bash_history /root/.mysql_history /etc/environment 2>/dev/null | head -30")],
    timeout=35,
    handler=lambda outputs, s: _credentials(outputs))


def _credentials(outputs):
    fs = []
    files = o(outputs, "files").strip()
    if files:
        fs.append(F("high", "磁盘散落私钥 / .env / 明文账号清单",
                    "交付机上残留 id_rsa_lab.pem、.env、handover.txt 一类文件可直接读取数据库口令与登录凭据（hardening-lab N07）。",
                    files[:1100],
                    ["先取证再删除：tar czf /root/evidence/creds.tgz <路径>; rm -f <路径>",
                     "清理历史命令中的口令行，并检查 git 提交、配置备份是否含同一凭据",
                     "凭据已暴露必须轮换：数据库口令、SSH 密钥对、API Token 全部重发"],
                    "凭据泄露"))
    hist = o(outputs, "hist").strip()
    if hist:
        fs.append(F("medium", "命令历史中存在明文口令",
                    "history 中的 mysql -p<口令>、export PASS= 会被任意可读取家目录的用户利用。",
                    hist[:800],
                    ["编辑 ~/.bash_history 删除口令行并设置 HISTCONTROL=ignorespace",
                     "改用凭据文件（chmod 600）或密钥认证，轮换已出现的口令"],
                    "凭据泄露"))
    return res(fs, "未发现散落凭据文件与历史明文口令")


add("fore.hidden", "forensics", "隐蔽目录与异常落地文件",
    "扫描点号开头的隐藏目录、已知载荷路径与 Web 目录近期新增脚本",
    [("hidden", "find /usr/local /opt /srv /var/tmp /tmp /var/www /home -xdev -maxdepth 5 -name '.*' -printf '%TY-%Tm-%Td %m %y %p\\n' 2>/dev/null | head -70"),
     ("payload", "ls -la --time-style=long-iso /tmp/.x9f3d /var/tmp/.winlin /usr/local/lib/.pm /usr/local/share/.sysmaint.sh /etc/cron.d/sys-maint /etc/cron.d/kworker-helpt /etc/cron.d/dbreindex 2>/dev/null"),
     ("weirdphp", "find /var/www /usr/share/nginx /var/lib/tomcat* /opt/tomcat* -xdev -type f -name '*.php' -newermt '-30 days' -printf '%TY-%Tm-%Td %p\\n' 2>/dev/null | head -25")],
    timeout=40,
    handler=lambda outputs, s: _hiddenfiles(outputs))


_GOOD_HIDDEN = (".bashrc", ".profile", ".bash_history", ".ssh", ".cache", ".config",
                ".git", ".local", ".vim", ".viminfo", ".mysql_history", ".npm", ".pki",
                ".gnupg", ".ansible", ".docker", ".wget-hsts", ".lesshst",
                ".python_history", ".selected_editor", ".sudo_as_admin_successful")


def _hiddenfiles(outputs):
    fs = []
    payload = o(outputs, "payload").strip()
    if payload:
        fs.append(F("critical", "命中已知攻击载荷 / 持久化路径",
                    "webshell 落地文件、矿机隐蔽目录、可疑 cron.d 文件仍在磁盘，说明入侵残留未清除（d4-webshell W04/W05、d5-mining、d5-ransom）。",
                    payload[:1000],
                    ["先取证打包样本与 mtime：cp -a <路径> /root/evidence/; stat <路径>",
                     "按「停进程 → 清复活链 → 删文件」顺序处置，删除后复查 ls 与 crontab",
                     "用 find / -mtime -7 复核是否有同源新落地文件"],
                    "入侵残留"))
    hidden = []
    for l in o(outputs, "hidden").splitlines():
        p = l.split()[-1] if l.split() else ""
        name = p.rsplit("/", 1)[-1]
        if not p or name in _GOOD_HIDDEN:
            continue
        if re.search(r"/(\.pm|\.cache|\.sysmaint|\.winlin|\.x9|[.][a-z0-9]{5,})$", p):
            hidden.append(l.strip())
    if hidden:
        fs.append(F("medium", "存在可疑隐藏目录 / 隐藏落地文件",
                    "攻击者习惯用点号目录与随机名文件规避常规 ls；需与变更单核对创建时间。",
                    "\n".join(hidden[:18]),
                    ["ls -la <目录>; stat <文件> 看创建时间与属主；file <文件> 判断类型",
                     "非业务项取证后删除，并检查是否有进程或 cron 引用它"],
                    "落地文件"))
    php = o(outputs, "weirdphp").strip()
    if php:
        fs.append(F("medium", "Web 目录近期新增 PHP 文件",
                    "webshell 常伪装成正常目录里的普通文件（如 images/sitemap.php），关键词为 system(、$_POST[、eval(、assert(（d4-webshell W01）。",
                    php[:800],
                    ["grep -REn 'eval\\(|assert\\(|system\\(|\\$_POST|base64_decode' <文件>",
                     "确认后删除，并回溯 access.log 找到上传入口漏洞"],
                    "WebShell"))
    return res(fs, "未发现可疑隐藏目录、已知载荷路径或近期新增 PHP")


add("hard.sysctl", "hardening", "内核与网络参数基线",
    "核查 IP 转发、ASLR、ICMP 重定向、SYN 防护等 sysctl 基线",
    [("sys", "for k in net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies kernel.randomize_va_space fs.suid_dumpable kernel.dmesg_restrict; do printf '%s=%s\\n' \"$k\" \"$(sysctl -n $k 2>/dev/null)\"; done")],
    handler=lambda outputs, s: _sysctl(outputs))


def _sysctl(outputs):
    txt = o(outputs, "sys")
    d = {}
    for l in txt.splitlines():
        m = re.match(r"^([^=\s]+)=(\S*)", l.strip())
        if m:
            d[m.group(1)] = m.group(2)
    if not any(v for v in d.values()):
        return res(note="未读取到 sysctl 参数（容器或权限受限）")
    bad = []
    if d.get("net.ipv4.ip_forward", "0") not in ("0", ""):
        bad.append("net.ipv4.ip_forward=%s（主机可被用作横向中继/跳板）" % d.get("net.ipv4.ip_forward"))
    if d.get("kernel.randomize_va_space", "2") in ("0", ""):
        bad.append("kernel.randomize_va_space=0（ASLR 关闭，栈溢出利用成功率大增）")
    for k in ("net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.all.send_redirects",
              "net.ipv4.conf.all.accept_source_route"):
        if d.get(k, "0") not in ("0", ""):
            bad.append("%s=%s（ICMP 重定向 / 源路由可被用于中间人）" % (k, d.get(k)))
    if d.get("net.ipv4.tcp_syncookies", "1") == "0":
        bad.append("net.ipv4.tcp_syncookies=0（SYN Flood 防护关闭）")
    if bad:
        fs = F("medium", "内核 / 网络参数未收敛",
               "d2 靶场 H07 以 ip_forward=0、ASLR≠0、accept_redirects=0 为基线；当前 %d 项不达标。" % len(bad),
               "\n".join(bad) + "\n--- sysctl 原始值 ---\n" + txt[:700],
               ["写入 /etc/sysctl.d/99-hardening.conf：net.ipv4.ip_forward=0 / kernel.randomize_va_space=2 / accept_redirects=0",
                "执行 sysctl --system 生效，用 sysctl -a | grep <key> 复测",
                "除非主机确实承担路由/网关职责，否则不要开启 ip_forward"],
               "内核基线")
        return res([fs])
    return res(note="内核网络参数符合基线")


add("hard.passpolicy", "hardening", "口令老化与全局口令策略",
    "核对 PASS_MAX_DAYS / PASS_MIN_LEN 与 chage -l，识别永不过期的弱口令账号",
    [("defs", "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)' /etc/login.defs 2>/dev/null"),
     ("chage", "for u in $(getent passwd | awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $1}' | head -15); do echo \"### $u\"; chage -l $u 2>/dev/null | grep -Ei 'Maximum|Minimum|Last password'; done")],
    handler=lambda outputs, s: _passpolicy(outputs))


def _passpolicy(outputs):
    fs = []
    defs = o(outputs, "defs")
    chg_all = o(outputs, "chage")
    if not defs.strip() and not chg_all.strip():
        return res(note="未读取到 /etc/login.defs 与 chage 输出（权限受限或容器环境）")
    m = re.search(r"^PASS_MAX_DAYS\s+(\d+)", defs, re.M)
    if not m or int(m.group(1)) > 90:
        cur = m.group(1) if m else "未配置"
        fs.append(F("medium", "全局口令有效期未收敛（当前 PASS_MAX_DAYS=%s）" % cur,
                    "交付机常保留 99999（永不过期）；配合弱口令可长期复用（hardening-lab N02）。",
                    defs[:500] or "未找到 /etc/login.defs 中的 PASS_MAX_DAYS",
                    ["sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t90/' /etc/login.defs",
                     "同时设置 PASS_MIN_LEN 6 以上并启用 pam_pwquality",
                     "策略之外必须改强口令本身：passwd <user>；用 passwd -S 复测"],
                    "口令策略"))
    chg = chg_all
    never = hits(chg, r"Maximum number of days.*(99999|-1|never)", 10)
    if never:
        fs.append(F("medium", "存在口令永不过期的可登录账号",
                    "chage -l 显示 Maximum number of days 为 99999/-1，账号口令长期不轮换。",
                    "\n".join(never) + "\n" + chg[:400],
                    ["chage -M 90 <user>; chage -W 7 <user>；用 chage -l <user> 复核",
                     "对交付/服务账号改为 nologin 并锁定，避免口令策略形同虚设"],
                    "口令老化"))
    return res(fs, "全局口令策略与账号老化设置符合基线")


add("hard.auditd", "hardening", "auditd 文件监控规则",
    "核对 auditd 是否运行并配置了 -w 文件监控规则，保障可追溯性",
    [("rules", "echo -n 'state='; systemctl is-active auditd 2>/dev/null; echo '--- rules ---'; auditctl -l 2>/dev/null | head -30; echo -n '--- watch_count='; auditctl -l 2>/dev/null | grep -c '^-w'")],
    handler=lambda outputs, s: _auditd(outputs))


def _auditd(outputs):
    txt = o(outputs, "rules")
    if not txt.strip():
        return res(note="未读取到 auditd 状态（可能未安装或权限受限）")
    m = re.search(r"watch_count=(\d+)", txt)
    n = int(m.group(1)) if m else -1
    if n == 0 or (n < 0 and "state=active" not in txt):
        return res([F("medium", "auditd 未配置文件监控规则",
                      "没有 -w 规则时无法追踪 /etc/passwd、/etc/shadow、sudoers 与 Web 目录的改写，入侵后难以还原时间线（d2 H09）。",
                      txt[:600],
                      ["systemctl enable --now auditd",
                       "在 /etc/audit/rules.d/ir.rules 写入：-w /etc/passwd -p wa -k identity；-w /etc/shadow -p wa；-w /etc/sudoers -p wa",
                       "augenrules --load 后用 auditctl -l 复核规则数量 > 0；日志转发到独立日志服务器"],
                      "审计")])
    return res(note="auditd 已配置 %d 条文件监控规则" % max(n, 0))


add("hard.logrotate", "hardening", "应用日志权限与轮转",
    "核查应用日志是否被其他用户可读、是否配置 logrotate 防止日志失控与泄露",
    [("logs", "find /var/log -maxdepth 3 -type f \\( -name '*.log' -o -name '*.out' \\) -printf '%m %u:%g %s %p\\n' 2>/dev/null | head -50"),
     ("rotate", "echo -n 'app_logrotate_rules='; grep -Rl '/var/log/app' /etc/logrotate.d/ 2>/dev/null | wc -l; echo '--- logrotate.d ---'; ls /etc/logrotate.d/ 2>/dev/null | head -25")],
    handler=lambda outputs, s: _logrotate(outputs))


def _logrotate(outputs):
    fs = []
    logs = o(outputs, "logs")
    applog = [l.strip() for l in logs.splitlines()
              if re.search(r"/var/log/(app|labapp|application|business)/|/var/log/app", l)]
    bad = []
    for l in applog:
        m = re.match(r"^(\d{3,4})\s", l)
        if m:
            try:
                if int(m.group(1), 8) & 0o007:
                    bad.append(l)
            except ValueError:
                pass
    if bad:
        fs.append(F("medium", "应用日志对其他用户可读",
                    "应用日志常含令牌、SQL 与个人信息，其他用户可读即信息泄露（hardening-lab N05）。",
                    "\n".join(bad[:12]),
                    ["chmod 640 <日志>; chown root:adm <日志>；用 stat -c %a 复测其他位为 0",
                     "日志中的凭据按泄露处理并轮换"],
                    "日志权限"))
    rot = o(outputs, "rotate")
    m = re.search(r"app_logrotate_rules=(\d+)", rot)
    if applog and (not m or int(m.group(1)) == 0):
        fs.append(F("low", "应用日志未纳入 logrotate 轮转",
                    "应用日志不会自动进入系统轮转，需交付方单独写规则，否则体积失控、旧日志被覆盖（hardening-lab N05）。",
                    (rot[:400] + "\n--- 应用日志 ---\n" + "\n".join(applog[:8])),
                    ["新建 /etc/logrotate.d/labapp：/var/log/app/*.log { weekly rotate 4 compress missingok notifempty }",
                     "用 logrotate -d /etc/logrotate.d/labapp 预演语法后再启用"],
                    "日志轮转"))
    return res(fs, "应用日志权限与轮转配置正常")


add("log.incident", "logs", "事件行为链与证据包",
    "检查勒索/挖矿行为日志、攻击者历史证据与 /srv/incident 推演包，辅助时间线与 IOC 关联",
    [("evidence", "ls -la --time-style=long-iso /var/log/ransom-activity.log /root/.history_evidence /srv/incident 2>/dev/null | head -45"),
     ("chain", "echo '--- ransom-activity.log ---'; tail -n 30 /var/log/ransom-activity.log 2>/dev/null; echo '--- attacker history ---'; cat /root/.history_evidence/attacker_hist 2>/dev/null | tail -25; echo '--- incident files ---'; ls /srv/incident/ 2>/dev/null | head -20")],
    handler=lambda outputs, s: _incident(outputs))


def _incident(outputs):
    evd = o(outputs, "evidence").strip()
    chain = o(outputs, "chain")
    fs = []
    if re.search(r"ransom-activity\.log|attacker_hist|history_evidence", evd):
        fs.append(F("high", "发现事件行为链日志 / 攻击者历史证据",
                    "这些文件记录了下载源、执行方式与被拉入 sudo 组的账号，是串联根因链与 IOC 的关键证据（d5-ransom、d4-webshell）。",
                    evd[:500] + "\n" + chain[:800],
                    ["先原样取证到 /root/evidence/ 并计算 sha256，按时间线还原攻击者动作",
                     "提取下载源 IP、落地文件名、进程名加入 IOC 清单，横向排查其他主机",
                     "关联 webshell C2 / 矿池 / 勒索下载源是否同一地址，判断是否一条攻击链"],
                    "取证链"))
    if re.search(r"firewall\.log|_sysmon\.log|web01_auth\.log", chain):
        fs.append(F("low", "存在内网横向传播推演证据包",
                    "/srv/incident/ 下有多主机日志，可用于还原零号主机、感染顺序、传播端口与 beacon 外联（d5-spread）。",
                    chain[:700],
                    ["按 firewall.log 时间线画「谁在何时连谁的哪个端口」，区分入站被打与出站肉鸡",
                     "排除固定运维扫描器 IP 的批量 deny 噪声，产出 IOC 与遏制优先级报告"],
                    "横向分析"))
    return res(fs, "未发现事件行为链日志与推演证据包")


# ------------------------------------------------------------------ 排查方法
# 每条发现的「排查方法」= 该检查项的设计思路 + 工具实际执行的只读命令 + 判定口径。
METHOD_HINT = {
    "sys.info": "对照发行版生命周期与内核版本，判断是否 EOL；非 root 时结论存在盲区。",
    "id.priv": "对比 sudoers 配置文件与 sudo -l 生效授权，出现 NOPASSWD 或危险 capabilities 即命中。",
    "id.load": "loadavg 1 分钟值超过 CPU 核数 1.5 倍即视为异常；结合 ps 按 CPU 排序辨认真凶。",
    "acct.uid0": "取 /etc/passwd 第三字段为 0 且用户名不为 root 的行，任何一个都是影子 root。",
    "acct.shadow": "取 /etc/shadow 第二字段为空或 $1$ 开头的行；同时检查 PAM 是否含 nullok。",
    "acct.service_shell": "筛出 shell 不是 nologin/false 的系统服务账号，与资产清单核对。",
    "acct.newuser": "按 home 目录 mtime 与 passwd 新增行比对近 14 天变更，核对运维变更单。",
    "acct.locked": "passwd -S 第二列为 P 表示口令可用；交付/服务账号应为 L 且 shell 为 nologin。",
    "ssh.authkeys": "逐用户读取 authorized_keys，比对已知运维公钥清单；陌生公钥即持久化后门。",
    "ssh.private": "查找 Web 目录与家目录中的私钥文件，权限非 600 或出现在可下载路径即命中。",
    "ssh.config": "同时看 sshd_config 文件与 sshd -T 生效值，后者含 Include/Match 覆盖结果。",
    "ssh.perms": "stat 校验 .ssh 目录 700、私钥 600、authorized_keys 600。",
    "persist.cron": "grep 各级 crontab 中的下载器/反弹 shell/临时目录脚本；@reboot 与可写脚本同样计入。",
    "persist.systemd": "遍历 unit 的 ExecStart 与近期新增文件，定位指向脚本或临时目录的服务。",
    "persist.unitscript": "解析 ExecStart 得到脚本路径，stat 权限位含组写或其他写（0022）即命中。",
    "persist.startup": "核查 rc.local、profile.d、各用户 .bashrc 中的 alias 与追加执行行。",
    "persist.ldpreload": "读取 /etc/ld.so.preload 与全局环境变量，非空且指向陌生 .so 即动态链接劫持。",
    "persist.suid": "find / -perm -4000 全量枚举，重点看 /tmp /opt /usr/local 等非系统目录与 GTFOBins 程序。",
    "persist.worldwrite": "查找无 sticky bit 的全局可写目录，以及 /etc、Web 目录下 o+w 文件。",
    "persist.at": "atq / /var/spool/at 枚举一次性任务，核对命令内容。",
    "persist.hosts": "核查 /etc/hosts、hosts.allow/deny 中是否被加入攻击者 IP 或放行规则。",
    "proc.ps": "按 CPU/内存排序看进程树，关注父子关系异常与陌生可执行文件。",
    "proc.miner": "匹配 xmrig/stratum/矿池域名与高 CPU 组合特征。",
    "proc.fakekernel": "真内核线程无 /proc/<PID>/exe 路径；方括号名却指向 python/bash 即为伪装矿机。",
    "proc.legacy": "ss -lntup 逐个端口问「该不该对外开」，重点 21/23/9000/6379/4444 与 lab-* 单元。",
    "proc.deleted": "比对 /proc/<PID>/exe 的 (deleted) 标记与 lsof，识别删文件仍在运行的进程。",
    "proc.hidden": "对比 ps 列出的 PID 与 /proc 下的数字目录，差集可能是被 rootkit 隐藏的进程。",
    "proc.net": "看 ESTAB 连接的端口与对端，以及 0.0.0.0 上的高危监听；3333=矿池、4444=反弹 Shell。",
    "fore.history": "grep 历史命令中的下载、提权、清日志、加账号动作，还原攻击者操作序列。",
    "fore.webshell": "在 Web 目录按 eval(/system(/$_POST/base64_decode 扫描，并看近 30 天新增脚本。",
    "fore.backup": "枚举 Web 可达路径下的 .bak/.sql/.zip/.env/.git/私钥，能被 HTTP 下载即泄露。",
    "fore.ransom": "find 勒索信与 .locked 文件，再找本机密钥与行为日志，判断能否恢复。",
    "fore.credentials": "枚举 .pem/.env/handover/.my.cnf 与历史命令明文口令，确认是否已暴露。",
    "fore.hidden": "find 点号隐藏目录与已知载荷路径，按 mtime/属主核对是否为攻击者落地。",
    "fore.recent": "按 mtime 排序列出 /etc、系统命令目录与 Web 目录近期变更，与变更单比对。",
    "fore.cmdreplace": "file 判断系统命令是否被换成脚本，grep 各用户 alias 与 PATH 劫持。",
    "fore.tmp": "枚举 /tmp /var/tmp /dev/shm 中可执行文件与隐藏落地样本。",
    "hard.fileperm": "stat -c '%a %U:%G %n' 取权限位，passwd/shadow/sudoers 出现其他用户可写即严重。",
    "hard.firewall": "ufw status verbose / firewall-cmd --state / iptables -L 判断是否有默认拒绝与放行规则。",
    "hard.sysctl": "sysctl -n 逐项读取；ip_forward=0、ASLR≠0、accept_redirects=0 为基线。",
    "hard.passpolicy": "grep PASS_* /etc/login.defs 与 chage -l，最长有效期应 ≤90 天。",
    "hard.auditd": "auditctl -l 统计 -w 规则条数，为 0 说明无文件级审计。",
    "hard.logrotate": "stat 应用日志其他位，并 grep /etc/logrotate.d/ 是否有对应轮转规则。",
    "hard.selinux": "getenforce / aa-status 看强制访问控制是否被关闭。",
    "hard.umask": "grep umask 与 PAM pwquality 配置，判断是否 027 且启用复杂度策略。",
    "web.nginx": "审 nginx.conf 的 alias、autoindex、php 解析与 location 越权配置。",
    "web.nginxlog": "在 access.log 中按 SQL 注入、文件包含、webshell 路径与高频 200 小文件统计。",
    "web.tomcat": "核查 tomcat-users.xml 默认口令、webapps 示例应用、AJP Connector 与 manager 暴露。",
    "web.mysql": "查 mysql.user 的 root@%、空口令、secure_file_priv、local_infile 与 UDF 落地。",
    "web.php": "php -i 看 disable_functions、expose_php、allow_url_include 等危险项。",
    "web.serviceuser": "ps -o user= 看 java/mysqld/httpd 是否以 root 运行。",
    "log.auth": "在 auth.log/secure 中统计 Failed password、Accepted、useradd/usermod 与 sudo 记录。",
    "log.session": "last / w / utmp 看在线与历史会话，核对来源 IP。",
    "log.tamper": "检查关键日志是否存在、是否被清空（size 0），以及 auditd/rsyslog 服务状态。",
    "log.incident": "读取事件行为链日志与 /srv/incident 证据包，按时间线关联 IOC。",
}


def check_method(chk):
    """生成该检查项的「排查方法」：思路 + 工具实际执行的只读命令 + 判定口径。"""
    return {
        "intro": chk.get("desc", ""),
        "cmds": [cmd for _, cmd in chk.get("cmds", [])],
        "judge": METHOD_HINT.get(chk["id"], "对照上述命令输出与系统基线、资产清单、变更单交叉核验，命中异常特征即为风险项。"),
    }


def _norm_lines(text, minlen=4):
    """规范化输出行（去掉 CR、缩进与连续空白），用于证据溯源。"""
    lines = []
    for line in (text or "").splitlines():
        s = " ".join(line.strip().split())
        if len(s) >= minlen:
            lines.append(s)
    return lines


def finding_method(chk, outputs=None, evidence=""):
    """每条发现的排查方法：主体是「产出该条关键证据」的只读命令。

    实机扫描时把证据行与各命令的原始输出做比对（精确行 + 截断行前缀），
    命中即认为该命令是证据来源；无法关联时退回本检查项全部命令，绝不返回空方法。
    演示 / 导入报告没有原始输出，使用检查项定义的完整复现命令。
    """
    base = check_method(chk)
    pairs = list(chk.get("cmds", []))
    method = dict(base)
    method["cmds_all"] = [cmd for _, cmd in pairs]
    method["inferred"] = False

    if outputs is None:
        method["source_note"] = "本检查项在真实主机执行的只读命令，用于在目标机复现取证"
        return method

    ev_lines = _norm_lines(evidence, 6)
    if not ev_lines:
        method["source_note"] = "该发现由规则组合判定，列出本检查项全部只读命令"
        return method

    ev_set = set(ev_lines)
    heads = [e[:48] for e in ev_lines if len(e) >= 16]
    # 证据被规则加工过（如加上「MySQL」前缀）时，用长特征词反查
    tokens = set()
    for e in ev_lines:
        for tok in re.split(r"[\s,;=|]+", e):
            t = tok.strip("'\"()[]{}<>")
            if len(t) >= 8 and re.search(r"[A-Za-z0-9]", t) and not t.isdigit():
                tokens.add(t)
    scores = {}
    for key, _cmd in pairs:
        out_lines = _norm_lines(o(outputs, key), 6)
        if not out_lines:
            continue
        oset = set(out_lines)
        score = len(ev_set & oset)
        if not score and heads:
            # hits() 会把证据行截断到 220 字符，做前缀包含匹配兜底
            score = sum(1 for h in heads if any(h in x for x in oset))
        if not score and tokens:
            blob = "\n".join(oset)
            score = sum(1 for t in tokens if t in blob)
        if score:
            scores[key] = score

    if scores:
        best = max(scores.values())
        keys = [k for k, _ in pairs
                if scores.get(k, 0) >= max(1, best * 0.34)][:6]
        method["cmds"] = [cmd for k, cmd in pairs if k in keys]
        method["evidence_keys"] = keys
        method["inferred"] = True
        method["source_note"] = "以下命令的输出即下方「关键证据」，已自动关联证据来源"
    else:
        method["source_note"] = "证据为规则组合结果，列出本检查项全部只读命令供复核"
    return method


# 新增检查项按模块归位（稳定排序，保持原有检查项相对顺序不变）
_MOD_ORDER = {m["id"]: i for i, m in enumerate(MODULES)}
CHECKS.sort(key=lambda c: _MOD_ORDER.get(c["module"], 99))


# ------------------------------------------------------------------ 对外接口
def parse_check(chk, outputs, session):
    h = HANDLERS.get(chk["id"])
    if not h:
        return res(note="该检查项仅采集信息")
    result = h(outputs, session)
    # 补全字段：每条发现都必须带「排查方法」，且命令优先取产出该证据的命令
    for f in result.get("findings", []):
        f.setdefault("id", chk["id"])
        f.setdefault("module", chk["module"])
        f.setdefault("check", chk["name"])
        f["method"] = finding_method(chk, outputs, f.get("evidence", ""))
    return result


def public_checks():
    return [{"id": c["id"], "module": c["module"], "name": c["name"],
             "desc": c["desc"], "method": check_method(c)}
            for c in CHECKS]
