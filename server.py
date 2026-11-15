# -*- coding: utf-8 -*-
"""
SENTINEL / Linux IR  --  本地控制台服务
启动： python server.py [--port 8765]
浏览器打开 http://127.0.0.1:8765

设计要点：
* 服务仅监听回环地址，凭据只存在于内存，不写日志、不落盘、不随报告导出。
* 前端通过 /api/events 增量轮询获取实时日志与发现，兼容性优于 SSE。
* 所有排查命令均为只读；整改方案只输出建议，不自动改动目标主机。
"""
import os
import re
import io
import sys
import json
import time
import uuid
import queue
import threading
import traceback
import mimetypes
import subprocess
import webbrowser
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
WWW = os.path.join(BASE, "www")
REPORTS = os.path.join(BASE, "reports")
VERSION = "1.3.0"
# 前端据此判断后端是否具备结果存档能力，避免旧进程静默吞掉新接口请求
CAPABILITIES = ["checks", "method", "save", "saves", "load", "import", "delete"]
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")

# 旧版本 / 第三方报告缺少排查方法时的兜底（保证「排查方法」永远存在且含命令）
FALLBACK_METHOD = {
    "intro": "该检查项来自外部或旧版报告，当前版本未收录其命令定义；依据关键证据中的路径、账号或进程特征做只读复核。",
    "cmds": ["ps auxww; ss -tunap", "grep -Rni '<证据中的关键特征>' /etc /var/log /var/www 2>/dev/null | head -50"],
    "cmds_all": [],
    "judge": "输出与关键证据一致即命中；建议用当前版本重新执行一次排查以补齐取证命令。",
    "inferred": False,
    "source_note": "通用复核命令，原始取证命令未随报告保存",
}

import checks as checklib
import engine as enginelib
import demo as demolib

# ------------------------------------------------------------------ 依赖管理
DEP = {"state": "ok", "detail": "paramiko 已就绪"}


def dependency_ok():
    return enginelib._get_paramiko() is not None


def auto_install_paramiko():
    if dependency_ok():
        return
    DEP.update({"state": "installing", "detail": "正在自动安装 paramiko，请稍候…"})

    def _job():
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", "paramiko",
                 "--disable-pip-version-check", "-q"],
                capture_output=True, text=True, timeout=180,
            )
            if dependency_ok():
                DEP.update({"state": "ok", "detail": "paramiko 安装完成"})
            else:
                DEP.update({"state": "failed",
                            "detail": "自动安装未成功：" + ((r.stderr or r.stdout or "未知错误").strip()[:220])})
        except Exception as e:
            DEP.update({"state": "failed", "detail": "自动安装失败：%s" % e})
        print("[DEPENDENCY] %s" % DEP["detail"])

    threading.Thread(target=_job, daemon=True).start()


# ------------------------------------------------------------------ 任务模型
class Task:
    def __init__(self, mode, cfg):
        self.id = uuid.uuid4().hex[:12]
        self.mode = mode
        self.cfg = {k: v for k, v in cfg.items() if k not in ("password", "sudo_password")}
        self.credential = cfg.get("password", "")
        self.sudo_password = cfg.get("sudo_password") or cfg.get("password", "")
        self.events = []
        self.lock = threading.RLock()
        self.status = "running"
        self.started = time.time()
        self.finished = None
        self.findings = []
        self.passes = []
        self.sysinfo = {}
        self.summary = {}
        self.stop_flag = threading.Event()
        self.error = None
        self.seq = 0

    def emit(self, kind, data):
        with self.lock:
            self.seq += 1
            evt = {"n": self.seq, "type": kind, "data": data,
                   "t": round(time.time() - self.started, 2)}
            self.events.append(evt)
            if kind == "finding":
                self.findings.append(data)
            elif kind == "pass":
                self.passes.append(data)
            elif kind == "sysinfo":
                self.sysinfo = data
            elif kind == "done":
                self.summary = data or {}

    def events_after(self, cursor):
        with self.lock:
            return [e for e in self.events if e["n"] > cursor]

    def finish(self, status, payload=None, error=None):
        self.status = status
        self.finished = round(time.time() - self.started, 1)
        self.error = error
        if payload:
            self.summary = payload

    def is_stopped(self):
        return self.stop_flag.is_set()


TASKS = {}
TASKS_LOCK = threading.RLock()


def get_task(tid):
    with TASKS_LOCK:
        return TASKS.get(tid)


def new_task(mode, cfg):
    t = Task(mode, cfg)
    with TASKS_LOCK:
        # 仅保留最近 12 个任务
        if len(TASKS) > 12:
            for k in sorted(TASKS, key=lambda x: TASKS[x].started)[:len(TASKS) - 12]:
                TASKS.pop(k, None)
        TASKS[t.id] = t
    return t


# ------------------------------------------------------------------ 结果存档
def _safe_name(name):
    """存档名仅允许字母数字下划线点横线，阻断路径穿越。"""
    fn = str(name or "").strip()
    if fn and not fn.endswith(".json"):
        fn += ".json"
    if not fn or ".." in fn or "/" in fn or "\\" in fn or not SAFE_NAME.match(fn):
        return None
    return fn


def _report_dir():
    try:
        os.makedirs(REPORTS, exist_ok=True)
    except Exception:
        pass
    return REPORTS


def list_saved_reports():
    d = _report_dir()
    out = []
    for fn in sorted(os.listdir(d), reverse=True):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(d, fn)
        if not os.path.isfile(path):
            continue
        item = {"name": fn, "size": os.path.getsize(path),
                "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(path))),
                "target": "-", "findings": 0, "critical": 0, "mode": "-"}
        try:
            with open(path, "r", encoding="utf-8") as fp:
                r = json.load(fp)
            item["target"] = "%s@%s:%s" % (r.get("target", {}).get("user", "-"),
                                          r.get("target", {}).get("host", "-"),
                                          r.get("target", {}).get("port", "-"))
            item["findings"] = (r.get("stats") or {}).get("total", len(r.get("findings") or []))
            item["critical"] = ((r.get("stats") or {}).get("by_severity") or {}).get("critical", 0)
            item["mode"] = r.get("mode", "-")
            item["generated"] = r.get("generated", item["mtime"])
        except Exception:
            item["broken"] = True
        out.append(item)
    return out


def save_report(task, name=None):
    r = build_report(task)
    d = _report_dir()
    if not name:
        stamp = time.strftime("%Y%m%d_%H%M%S")
        host = re.sub(r"[^\w.\-]", "_", str(r["target"].get("host", "target")))[:32]
        name = "SENTINEL_%s_%s_%s.json" % (stamp, host, task.id[:6])
    fn = _safe_name(name)
    if not fn:
        raise ValueError("存档名称不合法（仅允许字母、数字、_ - . 与 .json 后缀）")
    path = os.path.join(d, fn)
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(r, fp, ensure_ascii=False, indent=2)
    return fn, path, r


def load_report_file(name):
    fn = _safe_name(name)
    if not fn:
        return None
    path = os.path.join(REPORTS, fn)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def delete_report(name):
    fn = _safe_name(name)
    if not fn:
        return False
    path = os.path.join(REPORTS, fn)
    if not os.path.isfile(path):
        return False
    os.remove(path)
    return True


def register_import(report):
    """把本地文件/存档报告注册为已完成任务，之后可统一走 /api/report 再次导出。"""
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError("报告格式不正确：缺少 findings 数组")
    target = {k: v for k, v in (report.get("target") or {}).items()
              if k in ("host", "port", "user")}
    t = new_task(report.get("mode") or "loaded", target)
    t.findings = [f for f in report["findings"] if isinstance(f, dict)]
    t.passes = [p for p in (report.get("passed") or []) if isinstance(p, dict)]
    t.sysinfo = report.get("sysinfo") or {}
    t.status = "done"
    t.summary = report.get("stats") or {}
    t.finished = report.get("duration") or 0
    t.error = report.get("error")
    try:
        t.started = time.time() - float(t.finished or 0)
    except (TypeError, ValueError):
        pass
    return t


# ------------------------------------------------------------------ 扫描线程
def worker(task):
    session = None
    try:
        task.emit("phase", {"text": "初始化作战会话"})
        if task.mode == "demo":
            task.emit("log", {"level": "info", "text": "演示模式：使用内置靶机数据重放完整排查流程"})
            demolib.run_demo(task.emit, task.is_stopped)
            payload = {"findings": len(task.findings), "checks": len(checklib.CHECKS),
                       "passes": len(task.passes), "duration": round(time.time() - task.started, 1),
                       "root": True, "mode": "demo", "stopped": task.is_stopped()}
        else:
            if not dependency_ok():
                raise RuntimeError("paramiko 未就绪（%s）。演示模式可正常使用。" % DEP["detail"])
            session = enginelib.SSHSession(
                host=task.cfg["host"], port=task.cfg.get("port", 22),
                user=task.cfg["user"], password=task.credential,
                emit=task.emit,
            )
            # 若用户单独填写了 sudo 口令，覆盖使用
            if task.sudo_password and task.sudo_password != task.credential:
                session.password = task.credential  # 登录口令保持不变
                session.sudo_password = task.sudo_password
            session.connect()
            task.emit("log", {"level": "ok",
                              "text": "已取得 root 上下文，开始执行 %d 项只读检查" % len(checklib.CHECKS)})
            _, _, _ = enginelib.run_checks(session, task.emit, task.is_stopped, checklib.CHECKS)
            payload = {"findings": len(task.findings), "checks": len(checklib.CHECKS),
                       "passes": len(task.passes), "duration": round(time.time() - task.started, 1),
                       "root": session.root, "mode": "live", "stopped": task.is_stopped()}
        task.emit("log", {"level": "ok", "text": "排查任务结束，报告已生成"})
        task.emit("done", payload)
        task.finish("done", payload)
    except Exception as e:
        msg = "%s: %s" % (type(e).__name__, e)
        task.emit("log", {"level": "err", "text": "任务中断 → " + msg})
        task.emit("log", {"level": "warn", "text": "请检查 IP/端口/账号口令、网络可达性与 sudo 权限；演示模式可直接预览完整效果"})
        traceback.print_exc()
        task.emit("done", {"error": msg, "findings": len(task.findings),
                           "duration": round(time.time() - task.started, 1), "mode": task.mode})
        task.finish("error", {"error": msg}, error=msg)
    finally:
        if session:
            try:
                session.close()
            except Exception:
                pass
        with TASKS_LOCK:
            pass


# 注意：SSHSession 的 sudo 口令默认复用登录口令；若单独提供，下面做兼容处理
_orig_elevate = enginelib.SSHSession._elevate


def _elevate_with_sudo_password(self):
    pwd = getattr(self, "sudo_password", None) or self.password
    old = self.password
    self.password = pwd
    try:
        return _orig_elevate(self)
    finally:
        self.password = old


enginelib.SSHSession._elevate = _elevate_with_sudo_password


def start_worker(task):
    th = threading.Thread(target=worker, args=(task,), daemon=True)
    th.start()
    return th


# ------------------------------------------------------------------ 报告
SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}


def build_report(task):
    counts = {k: 0 for k in SEV_CN}
    for f in task.findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    module_map = {m["id"]: m for m in checklib.MODULES}
    methods = {c["id"]: checklib.finding_method(c) for c in checklib.CHECKS}
    findings = []
    for f in sorted(task.findings, key=lambda f: checklib.SEV_ORDER.get(f.get("severity", "info"), 9)):
        item = dict(f)
        m = item.get("method")
        # 「排查方法」必须提供：缺失、空命令、旧格式一律回补为可执行的只读命令清单
        if not isinstance(m, dict) or not m.get("cmds"):
            item["method"] = dict(methods.get(item.get("id")) or FALLBACK_METHOD)
        else:
            item["method"] = dict(m)
            item["method"].setdefault("cmds_all", item["method"].get("cmds", []))
            item["method"].setdefault("judge", "对照命令输出与基线核验，命中异常特征即为风险项。")
        findings.append(item)
    return {
        "version": VERSION,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": task.mode,
        "target": task.cfg,
        "sysinfo": task.sysinfo,
        "status": task.status,
        "duration": task.finished or round(time.time() - task.started, 1),
        "error": task.error,
        "stats": {"total": len(findings), "by_severity": counts,
                  "checks": len(checklib.CHECKS), "passed": len(task.passes)},
        "modules": checklib.MODULES,
        "module_map": module_map,
        "findings": findings,
        "passed": task.passes,
    }


def report_markdown(task):
    r = build_report(task)
    si = r["sysinfo"] or {}
    lines = [
        "# SENTINEL · Linux 应急响应排查报告",
        "",
        "- 生成时间：%s" % r["generated"],
        "- 排查模式：%s" % ("演示数据" if r["mode"] == "demo" else "远程实机"),
        "- 目标：%s@%s:%s" % (r["target"].get("user", "-"), r["target"].get("host", "-"), r["target"].get("port", 22)),
        "- 系统：%s" % si.get("os", "未知"),
        "- 提权：%s" % ("root 已获取" if si.get("root") else "未获取 root（结果有盲区）"),
        "- 检查项：%d 项 / 通过 %d 项 / 发现 %d 项" % (r["stats"]["checks"], r["stats"]["passed"], r["stats"]["total"]),
        "- 严重度分布：" + " / ".join("%s %d" % (SEV_CN[k], v) for k, v in r["stats"]["by_severity"].items()),
        "", "> 本报告由只读排查生成，整改命令需人工评估后在变更窗口内执行。", "",
        "## 发现清单", "",
    ]
    for i, f in enumerate(r["findings"], 1):
        lines += [
            "### %02d. [%s] %s" % (i, SEV_CN.get(f.get("severity"), "提示"), f.get("title", "")),
            "",
            "- 分类：%s ｜ 检查项：%s ｜ 标签：%s" % (
                next((m["name"] for m in checklib.MODULES if m["id"] == f.get("module")), f.get("module", "-")),
                f.get("check", "-"), f.get("tag", "-")),
            "- 说明：%s" % f.get("summary", ""),
        ]
        m = f.get("method") or FALLBACK_METHOD
        # 排查方法保持简洁：只列产出关键证据的只读命令，格式与整改方案一致
        lines += ["", "排查方法：", ""]
        for c in (m.get("cmds") or FALLBACK_METHOD["cmds"]):
            lines.append("1. `%s`" % c)
        lines.append("")
        if f.get("evidence"):
            lines += ["", "关键证据：", "```text", f["evidence"], "```"]
        lines += ["", "整改方案："]
        for step in f.get("fix", []):
            lines.append("1. %s" % step)
        lines.append("")
    lines += ["## 已通过检查项", ""]
    for p in r["passed"]:
        lines.append("- [%s] %s — %s" % (
            next((m["name"] for m in checklib.MODULES if m["id"] == p.get("module")), p.get("module", "-")),
            p.get("check", "-"), p.get("note", "未发现异常")))
    return "\n".join(lines)


# ------------------------------------------------------------------ HTTP
MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "SENTINEL/%s" % VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if os.environ.get("SENTINEL_VERBOSE"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ------------------------------------------------------------ helpers
    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text, code=200, ctype="text/plain; charset=utf-8"):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self, maxlen=65536):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > maxlen:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _static(self, path):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        rel = rel.split("?")[0]
        full = os.path.normpath(os.path.join(WWW, rel))
        try:
            inside = os.path.commonpath([WWW, full]) == WWW
        except ValueError:
            inside = False
        if not inside or not os.path.isfile(full):
            self._text("404 Not Found", 404)
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = MIME.get(ext) or mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as fp:
            data = fp.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(data)

    # ------------------------------------------------------------ routes
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = (u.path.rstrip("/") or "/")
        try:
            if p == "/api/status":
                return self._json({
                    "version": VERSION,
                    "capabilities": CAPABILITIES,
                    "paramiko": dependency_ok(),
                    "dependency": DEP,
                    "checks": len(checklib.CHECKS),
                    "modules": len(checklib.MODULES),
                    "tasks": len(TASKS),
                })
            # 兼容把 POST 转成 GET 的代理/预览容器：GET 也能触发保存
            if p == "/api/save":
                t = get_task((q.get("id") or [""])[0])
                if not t:
                    return self._json({"error": "任务不存在或已过期，请先执行一次排查"}, 404)
                try:
                    fn, path, r = save_report(t, (q.get("name") or [None])[0])
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                return self._json({"ok": True, "name": fn, "path": path,
                                   "findings": r["stats"]["total"]})
            if p == "/api/checks":
                return self._json({"modules": checklib.MODULES, "checks": checklib.public_checks()})
            if p == "/api/saves":
                return self._json({"reports": list_saved_reports(), "dir": REPORTS})
            if p == "/api/load":
                name = (q.get("name") or [""])[0]
                r = load_report_file(name)
                if r is None:
                    return self._json({"error": "存档不存在或名称不合法"}, 404)
                t = register_import(r)
                return self._json({"task_id": t.id, "name": _safe_name(name), "report": build_report(t)})
            if p == "/api/events":
                t = get_task((q.get("id") or [""])[0])
                if not t:
                    return self._json({"error": "任务不存在"}, 404)
                cursor = int((q.get("cursor") or ["0"])[0] or 0)
                evts = t.events_after(cursor)
                return self._json({
                    "events": evts,
                    "cursor": t.seq,
                    "status": t.status,
                    "elapsed": round(time.time() - t.started, 1),
                    "dependency": DEP if not dependency_ok() else None,
                })
            if p == "/api/report":
                t = get_task((q.get("id") or [""])[0])
                if not t:
                    return self._json({"error": "任务不存在"}, 404)
                fmt = (q.get("format") or ["json"])[0]
                if fmt == "md":
                    return self._text(report_markdown(t), 200, "text/markdown; charset=utf-8")
                return self._json(build_report(t))
            if p.startswith("/api/"):
                return self._json({"error": "unknown endpoint"}, 404)
            return self._static(p)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as e:
            traceback.print_exc()
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass

    def do_POST(self):
        u = urlparse(self.path)
        p = (u.path.rstrip("/") or "/")
        body = self._body(8 * 1024 * 1024 if p == "/api/import" else 65536)
        try:
            if p == "/api/demo":
                t = new_task("demo", {"host": "10.20.14.37", "port": 22, "user": "opsadmin"})
                start_worker(t)
                return self._json({"task_id": t.id, "mode": "demo"})
            if p == "/api/scan":
                host = str(body.get("host", "")).strip()
                user = str(body.get("user", "")).strip()
                password = str(body.get("password", ""))
                try:
                    port = int(body.get("port", 22) or 22)
                except (TypeError, ValueError):
                    port = 22
                if not host or not user or not password:
                    return self._json({"error": "IP、账号、密码均为必填项"}, 400)
                if not dependency_ok():
                    if DEP["state"] == "failed":
                        return self._json({"error": "SSH 依赖未就绪：" + DEP["detail"]}, 503)
                    return self._json({"error": "SSH 依赖正在自动安装，请稍候重试（或先使用演示模式）"}, 503)
                cfg = {"host": host, "port": port, "user": user,
                       "password": password, "sudo_password": str(body.get("sudo_password", "") or "")}
                t = new_task("live", cfg)
                start_worker(t)
                return self._json({"task_id": t.id, "mode": "live"})
            if p == "/api/stop":
                t = get_task(str(body.get("id", "")))
                if t:
                    t.stop_flag.set()
                    t.emit("log", {"level": "warn", "text": "收到终止指令，将在当前检查项结束后安全停止"})
                return self._json({"ok": True})
            # ---- 结果保存 / 加载 ----
            if p == "/api/save":
                t = get_task(str(body.get("id", "")))
                if not t:
                    return self._json({"error": "任务不存在或已过期，请先执行一次排查"}, 404)
                try:
                    fn, path, r = save_report(t, body.get("name"))
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                return self._json({"ok": True, "name": fn, "path": path,
                                   "findings": r["stats"]["total"]})
            if p == "/api/import":
                try:
                    t = register_import(body)
                except ValueError as e:
                    return self._json({"error": str(e)}, 400)
                return self._json({"task_id": t.id, "report": build_report(t)})
            if p == "/api/save/delete":
                name = str(body.get("name", ""))
                if not delete_report(name):
                    return self._json({"error": "存档不存在或名称不合法"}, 404)
                return self._json({"ok": True})
            return self._json({"error": "unknown endpoint"}, 404)
        except Exception as e:
            traceback.print_exc()
            return self._json({"error": str(e)}, 500)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # Windows 上 SO_REUSEADDR 允许两个进程绑定同一端口，请求可能被旧的
    # server.py 进程接走并回 "unknown endpoint"。关掉复用，改为显式换端口。
    allow_reuse_address = False


def main():
    # Windows 控制台（chcp 65001）与重定向到文件时都保持 UTF-8，避免中文横幅编码异常
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="SENTINEL Linux 应急响应控制台")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    DEP["state"] = "ok" if dependency_ok() else "missing"
    if not dependency_ok():
        auto_install_paramiko()

    srv, port = None, args.port
    for cand in range(args.port, args.port + 6):
        try:
            srv = Server((args.host, cand), Handler)
            port = cand
            break
        except OSError:
            continue
    if srv is None:
        print("[X] 端口 %d-%d 均被占用。请关闭所有旧的 SENTINEL 控制台窗口后重试。" %
              (args.port, args.port + 5))
        return
    url = "http://127.0.0.1:%d" % port
    if port != args.port:
        print("[!] 端口 %d 已被占用（通常是旧版 SENTINEL 窗口仍在运行），自动改用 %d。"
              "建议关闭旧窗口后重新启动以固定端口。" % (args.port, port))
    print("=" * 62)
    print("  SENTINEL  //  LINUX INCIDENT RESPONSE CONSOLE   v%s" % VERSION)
    print("=" * 62)
    print("  控制台     : %s" % url)
    print("  检查项     : %d 项 / %d 个模块" % (len(checklib.CHECKS), len(checklib.MODULES)))
    print("  SSH 依赖   : %s" % ("已就绪" if dependency_ok() else "自动安装中（演示模式不受影响）"))
    print("  凭据安全   : 仅内存保存，不写日志 / 不落盘 / 不导出")
    print("  目标操作   : 全部只读，不自动执行任何整改动作")
    print("  结果存档   : %s" % REPORTS)
    print("  停止服务   : Ctrl + C")
    print("=" * 62)
    if not args.no_browser:
        try:
            threading.Timer(0.8, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    try:
        srv.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\n[+] 控制台已关闭")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
