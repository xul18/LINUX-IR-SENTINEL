# -*- coding: utf-8 -*-
"""
SENTINEL / Linux IR  --  SSH 执行引擎
负责：建立 SSH 连接 -> 第一时间 sudo -i 提权 -> 维持一个 root 会话执行只读排查命令。
所有命令均为只读，不会对目标主机做任何修改。
"""
import re
import time
import shlex
import uuid

def _get_paramiko():
    """延迟导入：允许服务启动后再自动安装依赖，无需重启。"""
    try:
        import paramiko
        return paramiko
    except ImportError:
        return None


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(text):
    """清洗终端输出：去 ANSI、去回车、去控制字符。"""
    if not text:
        return ""
    text = ANSI_RE.sub("", text)
    text = text.replace("\r", "")
    text = CTRL_RE.sub("", text)
    return text


class SSHSession:
    """一次 SSH 会话。优先使用持久 shell + sudo -i；失败时降级到 exec_command + sudo -S。"""

    def __init__(self, host, port, user, password, timeout=12, emit=None):
        self.host = host
        self.port = int(port or 22)
        self.user = user
        self.password = password
        self.timeout = timeout
        self.emit = emit or (lambda kind, data: None)
        self.client = None
        self.chan = None
        self.root = False
        self.mode = "shell"
        self.need_sudo = (user.strip().lower() != "root")
        self.os_family = "unknown"
        self.closed = False

    # ---------------------------------------------------------------- 日志
    def log(self, text, level="info"):
        self.emit("log", {"level": level, "text": text})

    # ---------------------------------------------------------------- 连接
    def connect(self):
        pm = _get_paramiko()
        if pm is None:
            raise RuntimeError(
                "缺少 paramiko 依赖，SSH 无法建立。请执行 pip install paramiko，"
                "或使用 start.bat / start.sh 一键启动（会自动安装依赖）。"
            )
        self.log("建立 SSH 加密通道  →  %s@%s:%s" % (self.user, self.host, self.port))
        self.client = pm.SSHClient()
        self.client.set_missing_host_key_policy(pm.AutoAddPolicy())
        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self.log("SSH 认证成功，会话已建立", "ok")

        # 建立交互式 pty 会话
        self.chan = self.client.invoke_shell(term="xterm-256color", width=240, height=60)
        self.chan.settimeout(0.2)
        self._settle(1.2)
        self._send("stty -echo 2>/dev/null; export HISTFILE=/dev/null; export HISTCONTROL=ignorespace; set +o history 2>/dev/null; export PS1=''\n")
        self._settle(0.6)

        if self.need_sudo:
            self._elevate()
        else:
            rc, out = self.run("id -u")
            self.root = (out.strip().splitlines()[-1].strip() == "0") if out.strip() else False
            if self.root:
                self.log("当前即为 root，无需提权", "ok")

        if not self.root:
            # 交互 shell 提权失败 -> 降级到 sudo -S 逐条执行
            self.log("交互提权未生效，切换 sudo -S 降级通道（部分检查可能受限）", "warn")
            self.mode = "exec"
            try:
                rc, out = self._exec("id -u")
                self.root = (out.strip().splitlines()[-1].strip() == "0")
                if self.root:
                    self.log("sudo 提权成功（降级通道），已获得 root 上下文", "ok")
            except Exception as e:
                self.log("sudo 提权失败：%s" % e, "err")

        if not self.root:
            self.log("未能取得 root：将继续以当前用户执行可读检查，结果仅供参考", "warn")

        # 识别发行版
        rc, out = self.run("cat /etc/os-release 2>/dev/null | head -8")
        low = out.lower()
        if "ubuntu" in low or "debian" in low:
            self.os_family = "debian"
        elif "centos" in low or "rhel" in low or "red hat" in low or "rocky" in low or "alma" in low:
            self.os_family = "redhat"
        else:
            self.os_family = "linux"
        self.log("目标系统识别：%s" % self.os_family.upper())
        return self.root

    # ------------------------------------------------------------ sudo -i
    def _elevate(self):
        self.log("检测到非 root 账号，立即执行  sudo -i  提升至 root …")
        self._send("sudo -i\n")
        buf = ""
        deadline = time.time() + 8
        while time.time() < deadline:
            buf = self._read_available(buf, 0.35)
            low = buf.lower()
            if "password" in low or "密码" in buf:
                self.log("sudo 要求密码，自动注入凭据")
                self._send(self.password + "\n")
                buf = ""
                break
            if re.search(r"root@|#\s*$", clean(buf)):
                break
            if "not in the sudoers" in low or "sorry" in low or "incorrect password" in low:
                break
        self._settle(1.0)
        self._send("stty -echo 2>/dev/null; export HISTFILE=/dev/null; set +o history 2>/dev/null; export PS1=''; clear 2>/dev/null\n")
        self._settle(0.5)
        rc, out = self.run("id -u; whoami")
        vals = [l.strip() for l in clean(out).splitlines() if l.strip()]
        if "0" in vals and "root" in vals:
            self.root = True
            self.log("提权成功：uid=0 / root，后续检查均在 root 上下文执行", "ok")
        else:
            self.root = False
            self.log("sudo -i 提权未确认（可能需要交互确认或 sudo 权限不足）", "warn")

    # ------------------------------------------------------------ 底层 IO
    def _settle(self, seconds):
        """等待终端输出安静。"""
        end = time.time() + seconds
        while time.time() < end:
            try:
                if self.chan.recv_ready():
                    self.chan.recv(65536)
                    end = time.time() + min(0.25, seconds)
                else:
                    time.sleep(0.03)
            except Exception:
                break

    def _read_available(self, buf, seconds):
        end = time.time() + seconds
        while time.time() < end:
            try:
                if self.chan.recv_ready():
                    buf += self.chan.recv(65536).decode("utf-8", "replace")
                    end = time.time() + 0.12
                else:
                    time.sleep(0.02)
            except Exception:
                break
        return buf

    def _send(self, text):
        if self.chan and not self.chan.closed:
            self.chan.send(text)

    # ------------------------------------------------------------ 执行命令
    def run(self, cmd, timeout=25):
        """返回 (exit_code, output)。只读命令。"""
        if self.mode == "exec":
            return self._exec(cmd, timeout)
        if not self.chan or self.chan.closed:
            self.mode = "exec"
            return self._exec(cmd, timeout)

        token = "__SNT_%s__" % uuid.uuid4().hex[:12]
        marker = token + "RC="
        try:
            self._settle(0.05)
            # 真实 shell 会把 $? 展开成上一条命令的退出码，输出形如 __SNT_x__RC=0
            self._send(cmd.rstrip() + "\n" + 'echo "%sRC=$?"\n' % token)
            buf = ""
            deadline = time.time() + timeout
            while time.time() < deadline:
                if self.chan.recv_ready():
                    buf += self.chan.recv(65536).decode("utf-8", "replace")
                    if marker in clean(buf):
                        break
                else:
                    time.sleep(0.02)
            txt = clean(buf)
            m = re.search(re.escape(marker) + r"(\d+)", txt)
            rc = int(m.group(1)) if m else -1
            body = txt.split(token)[0] if token in txt else txt

            # 去掉命令回显行（stty -echo 通常已关闭回显，这里是双保险）
            # 仅在首尾完全匹配命令本身时删除，避免误删以命令名开头的正常输出
            lines = body.split("\n")
            compact = re.sub(r"\s+", "", cmd)
            if lines and re.sub(r"\s+", "", lines[0]) == compact:
                lines.pop(0)
            if lines and 'echo "' + token in lines[0]:
                lines.pop(0)
            out = "\n".join(lines).strip("\n")
            # 去掉残留的提示符/回显碎片
            out = re.sub(r"(?m)^\s*(root|%s)@[^\s#\$]*[#\$]\s*$" % re.escape(self.user), "", out)
            if len(out) > 24000:
                out = out[:24000] + "\n…[输出已截断]"
            return rc, out
        except Exception as e:
            self.log("通道执行异常，切换降级通道：%s" % e, "warn")
            self.mode = "exec"
            return self._exec(cmd, timeout)

    def _exec(self, cmd, timeout=25):
        if self.need_sudo and not self.root:
            full = "sudo -S -p '' -i bash -c %s" % shlex.quote(cmd)
        elif self.need_sudo:
            full = "sudo -S -p '' -i bash -c %s" % shlex.quote(cmd)
        else:
            full = cmd
        try:
            stdin, stdout, stderr = self.client.exec_command(full, timeout=timeout)
            if self.need_sudo:
                stdin.write((getattr(self, "sudo_password", None) or self.password) + "\n")
                stdin.flush()
            out = stdout.read().decode("utf-8", "replace") + stderr.read().decode("utf-8", "replace")
            out = clean(out)
            # 去掉 sudo 的密码提示回显
            out = re.sub(r"(?m)^\[sudo\].*$", "", out)
            rc = stdout.channel.recv_exit_status()
            if len(out) > 24000:
                out = out[:24000] + "\n…[输出已截断]"
            return rc, out.strip()
        except Exception as e:
            return -1, "[命令执行失败] %s" % e

    # ------------------------------------------------------------ 收尾
    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.chan:
                self.chan.send("exit\nexit\n")
                self.chan.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass


def run_checks(session, emit, is_stopped, checks):
    """按检查项顺序执行，产出 finding / pass 事件。返回 (findings, passes, sysinfo)"""
    from checks import parse_check
    findings, passes = [], []
    sysinfo = {}
    total = len(checks)
    for idx, chk in enumerate(checks):
        if is_stopped():
            break
        emit("check_start", {
            "id": chk["id"], "module": chk["module"], "name": chk["name"],
            "index": idx + 1, "total": total,
        })
        emit("log", {"level": "cmd", "text": "[%02d/%02d] %s" % (idx + 1, total, chk["name"])})
        outputs = {}
        for key, cmd in chk.get("cmds", []):
            if is_stopped():
                break
            tmo = chk.get("timeout", 25)
            rc, out = session.run(cmd, timeout=tmo)
            outputs[key] = (rc, out)
        try:
            result = parse_check(chk, outputs, session)
        except Exception as e:
            result = {"findings": [], "note": "解析异常：%s" % e}
            emit("log", {"level": "warn", "text": "检查项 %s 解析异常：%s" % (chk["id"], e)})

        for f in result.get("findings", []):
            f.setdefault("id", chk["id"])
            f.setdefault("module", chk["module"])
            f.setdefault("check", chk["name"])
            findings.append(f)
            emit("finding", f)
        if not result.get("findings"):
            p = {"id": chk["id"], "module": chk["module"], "check": chk["name"],
                 "note": result.get("note", "未发现异常")}
            passes.append(p)
            emit("pass", p)
        emit("check_done", {"id": chk["id"], "count": len(result.get("findings", []))})
        emit("progress", {"done": idx + 1, "total": total,
                          "pct": round((idx + 1) * 100.0 / total, 1)})

        # 采集系统画像（供前端顶部信息条展示）
        if chk["id"] == "sys.info":
            def g(k):
                return outputs.get(k, (-1, ""))[1].strip()
            osline = (g("os").splitlines() or ["unknown"])[0]
            sysinfo = {
                "os": osline[:120],
                "os_full": g("os")[:900],
                "kernel": g("uname")[:200],
                "host": g("host")[:200],
                "identity": g("id")[:200],
                "clock": g("time")[:200],
            }
            emit("sysinfo", {
                "os": sysinfo["os"], "os_full": sysinfo["os_full"],
                "kernel": sysinfo["kernel"], "host": sysinfo["host"],
                "identity": sysinfo["identity"], "clock": sysinfo["clock"],
                "root": session.root, "family": session.os_family,
                "host_conn": session.host, "user": session.user, "port": session.port,
            })
    return findings, passes, sysinfo
