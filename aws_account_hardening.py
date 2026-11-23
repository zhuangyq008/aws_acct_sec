#!/usr/bin/env python3
"""AWS 账号安全加固工具（CloudShell 引导式）

依据《AWS 账号安全与访问管理最佳实践》，逐项检查账号安全配置，
在用户逐项确认后对低风险项执行修复，并输出 Markdown / JSON 报告。

用法（CloudShell）:
    python3 aws_account_hardening.py               # 引导模式：检查 + 逐项确认修复
    python3 aws_account_hardening.py --check-only  # 只读检查
    python3 aws_account_hardening.py --triage      # 疑似泄露排查（只读）
    python3 aws_account_hardening.py --rollback    # 撤销本工具创建的资源

仅依赖 Python 标准库 + boto3（CloudShell 预装）。
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fnmatch
import functools
import io
import ipaddress
import json
import os
import re
import shlex
import statistics
import sys
import time
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from collections.abc import Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

# ═══════════════════════════════════════════════════════════════════════════
# 常量与配置
# ═══════════════════════════════════════════════════════════════════════════
VERSION = "0.1.0"
TOOL = "aws-account-hardening"
PREFIX = "acct-sec"
TAG_KEY, TAG_VALUE = "ManagedBy", TOOL
STATE_ROOT = Path(os.environ.get("ACCT_SEC_HOME", str(Path.home() / ".aws-account-hardening")))
STATE_VERSION = 1

KEY_UNUSED_DAYS = 90
ROOT_RECENT_DAYS = 30
DEFAULT_TRIAGE_DAYS = 30
DEFAULT_LOG_RETENTION_DAYS = 365
NONCURRENT_RETENTION_DAYS = 30
GD_HIGH_SEVERITY = 7
TRIAGE_EVENT_CAP = 2000
ROLE_PROPAGATION_SECONDS = float(os.environ.get("ACCT_SEC_ROLE_WAIT", "8"))
CRED_REPORT_POLL_SECONDS = float(os.environ.get("ACCT_SEC_POLL", "2"))

TRAIL_NAME = f"{PREFIX}-trail"
ORG_TRAIL_NAME = f"{PREFIX}-org-trail"
TOPIC_NAME = f"{PREFIX}-alerts"
FWD_ROLE_NAME = f"{PREFIX}-eventbridge-forwarder"
IPSET_NAME = f"{PREFIX}-trusted-ips"
IPSET_KEY = "guardduty/trusted-ips.txt"
CONFIG_RECORDER = f"{PREFIX}-recorder"
CONFIG_CHANNEL = f"{PREFIX}-channel"
ANALYZER_NAME = f"{PREFIX}-analyzer"
UNUSED_ANALYZER_NAME = f"{PREFIX}-unused-access"
ROOT_USER = "<root_account>"

BOTO_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 10},
    user_agent_extra=f"{TOOL}/{VERSION}",
    connect_timeout=10,
    read_timeout=60,
)

PASS, FAIL, WARN, MANUAL, NA, ERROR = "PASS", "FAIL", "WARN", "MANUAL", "N/A", "ERROR"
STATUS_ORDER = {FAIL: 0, ERROR: 1, WARN: 2, MANUAL: 3, PASS: 4, NA: 5}
ACCESS_DENIED = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "UnauthorizedException",
}
NOT_FOUND = {
    "NoSuchEntity",
    "ResourceNotFoundException",
    "NotFound",
    "NoSuchBucket",
    "NoSuchKey",
    "TrailNotFoundException",
    "NoSuchConfigurationRecorderException",
    "NoSuchDeliveryChannelException",
    "NoSuchBucketPolicy",
    "NoSuchPublicAccessBlockConfiguration",
    "NoSuchTagSet",
    "404",
}
# 可信 IP 列表的最小前缀：防止误填超大网段导致 GuardDuty 对大量来源静默
MIN_PREFIX_V4, MIN_PREFIX_V6 = 20, 48

# ═══════════════════════════════════════════════════════════════════════════
# 通用工具
# ═══════════════════════════════════════════════════════════════════════════


class UserQuit(Exception):
    """用户选择保存并退出。"""


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str | None) -> dt.datetime | None:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        ts = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=dt.timezone.utc)


def days_ago(ts: dt.datetime, now: dt.datetime | None = None) -> int:
    return ((now or now_utc()) - ts).days


def err_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "ClientError")
    return type(exc).__name__


def is_not_found(exc: Exception) -> bool:
    """精确判断“资源不存在”；GuardDuty 对不存在的 detector 返回 BadRequestException + not found 文案。"""
    if not isinstance(exc, ClientError):
        return False
    code = err_code(exc)
    msg = exc.response.get("Error", {}).get("Message", "").lower()
    return code in NOT_FOUND or (code == "BadRequestException" and ("not found" in msg or "does not exist" in msg))


def short_err(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        code = err_code(exc)
        msg = exc.response.get("Error", {}).get("Message", "")
        prefix = "权限不足" if code in ACCESS_DENIED else code
        return f"{prefix}: {msg}"[:300]
    return f"{type(exc).__name__}: {exc}"[:300]


_UNSAFE_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Cs", "Co"}


def clean(text: Any, keep_newlines: bool = True) -> str:
    """剔除控制字符、零宽字符、双向覆盖等，防止终端转义注入与视觉欺骗（外部数据输出前统一调用）。"""
    out = []
    for ch in str(text):
        if keep_newlines and ch in "\n\t":
            out.append(ch)
        elif unicodedata.category(ch) not in _UNSAFE_CATEGORIES:
            out.append(ch)
    return "".join(out)


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:2]}***@{domain}" if domain else "***"


def tag_list() -> list[dict]:
    return [{"Key": TAG_KEY, "Value": TAG_VALUE}, {"Key": "CreatedAt", "Value": iso_now()}]


def tag_map() -> dict:
    return {t["Key"]: t["Value"] for t in tag_list()}


def as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# ── 输入校验 ────────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()\-]{5,23}$")
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")


def validate_email(value: str) -> str | None:
    if len(value) > 254 or not EMAIL_RE.match(value):
        return "邮箱格式不正确，例如 aws-security@example.com"
    return None


def validate_emails(value: str) -> str | None:
    items = [v.strip() for v in value.split(",") if v.strip()]
    if not items:
        return "至少输入一个邮箱"
    for item in items:
        err = validate_email(item)
        if err:
            return f"{item}: {err}"
    return None


def validate_phone(value: str) -> str | None:
    return None if PHONE_RE.match(value) else "电话格式不正确，建议 E.164 格式，例如 +8613800000000"


def validate_text(max_len: int) -> Callable[[str], str | None]:
    def _check(value: str) -> str | None:
        if not value:
            return "不能为空"
        if len(value) > max_len:
            return f"长度不能超过 {max_len}"
        if any(unicodedata.category(ch) in _UNSAFE_CATEGORIES for ch in value):
            return "不能包含控制字符或不可见字符"
        return None

    return _check


def validate_account_id(value: str) -> str | None:
    return None if ACCOUNT_RE.match(value) else "账号 ID 应为 12 位数字"


def validate_int_range(lo: int, hi: int) -> Callable[[str], str | None]:
    def _check(value: str) -> str | None:
        if not value.isdigit() or not lo <= int(value) <= hi:
            return f"请输入 {lo}–{hi} 之间的整数"
        return None

    return _check


_SPECIAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)
_GLOBAL_V6 = ipaddress.IPv6Network("2000::/3")


def parse_cidr(item: str) -> str:
    """单个公网 CIDR：拒绝主机位、超大网段与任何私有/保留地址段（不依赖随 Python 版本变化的 is_global）。"""
    try:
        net = ipaddress.ip_network(item, strict=True)
    except ValueError as exc:
        raise ValueError(f"{item}: 不是合法 CIDR（主机位必须为 0，例如 203.0.113.0/24）") from exc
    min_prefix = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
    if net.prefixlen < min_prefix:
        raise ValueError(f"{item}: 网段过大（IPv{net.version} 前缀至少 /{min_prefix}）")
    if isinstance(net, ipaddress.IPv6Network) and not net.subnet_of(_GLOBAL_V6):
        raise ValueError(f"{item}: 不是 IPv6 全球单播地址")
    if any(net.version == s.version and net.overlaps(s) for s in _SPECIAL_NETS):
        raise ValueError(f"{item}: 包含私有/保留地址（可信 IP 列表只接受企业公网出口）")
    return str(net)


def parse_cidrs(value: str) -> list[str]:
    """解析逗号分隔的公网 CIDR，返回规范化列表；非法时抛 ValueError。"""
    items = [v.strip() for v in value.split(",") if v.strip()]
    if not items:
        raise ValueError("至少输入一个 CIDR")
    out = [parse_cidr(item) for item in items]
    if len(out) > 2000:
        raise ValueError("最多 2000 条")
    return sorted(set(out))


def validate_cidrs(value: str) -> str | None:
    try:
        parse_cidrs(value)
    except ValueError as exc:
        return str(exc)
    return None


# ═══════════════════════════════════════════════════════════════════════════
# UI
# ═══════════════════════════════════════════════════════════════════════════


def display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


def pad(text: str, width: int) -> str:
    return text + " " * max(0, width - display_width(text))


class UI:
    COLORS = {
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "dim": "2",
        "bold": "1",
    }
    STATUS_COLOR = {PASS: "green", FAIL: "red", WARN: "yellow", MANUAL: "cyan", NA: "dim", ERROR: "magenta"}

    def __init__(self, out=None, input_fn: Callable[[str], str] = input, color: bool | None = None):
        self.out = out or sys.stdout
        self.input_fn = input_fn
        if color is None:
            color = hasattr(self.out, "isatty") and self.out.isatty() and "NO_COLOR" not in os.environ
        self.color = color

    def c(self, text: str, color: str) -> str:
        return f"\033[{self.COLORS[color]}m{text}\033[0m" if self.color else text

    def say(self, msg: str = "") -> None:
        print(clean(msg).replace("\033", ""), file=self.out, flush=True)

    def _emit(self, msg: str) -> None:
        """输出已着色的文本（颜色码由本类生成，内容已经过 clean）。"""
        print(msg, file=self.out, flush=True)

    def title(self, msg: str) -> None:
        self.say()
        self._emit(self.c(f"━━ {clean(msg)} ━━", "bold"))

    def info(self, msg: str) -> None:
        self.say(f"  {msg}")

    def ok(self, msg: str) -> None:
        self._emit(f"  {self.c('✔', 'green')} {clean(msg)}")

    def warn(self, msg: str) -> None:
        self._emit(f"  {self.c('!', 'yellow')} {clean(msg)}")

    def error(self, msg: str) -> None:
        self._emit(f"  {self.c('✘', 'red')} {clean(msg)}")

    def label(self, name: str, value: str) -> None:
        self._emit(f"  {self.c(name, 'bold')}{clean(value)}")

    def status(self, status: str) -> str:
        return self.c(pad(status, 6), self.STATUS_COLOR.get(status, "dim"))

    def block(self, text: str, indent: str = "    ") -> None:
        for line in text.splitlines():
            self.say(f"{indent}{line}")

    def _read(self, prompt: str) -> str:
        try:
            return self.input_fn(prompt).strip()
        except EOFError as exc:
            raise UserQuit() from exc

    def confirm(self, question: str, default: bool = False) -> bool:
        hint = "[Y/n]" if default else "[y/N]"
        while True:
            ans = self._read(f"  {question} {hint}: ").lower()
            if not ans:
                return default
            if ans in ("y", "yes"):
                return True
            if ans in ("n", "no"):
                return False
            if ans == "q":
                raise UserQuit()

    def ask(
        self, question: str, validator: Callable[[str], str | None] | None = None, default: str | None = None
    ) -> str:
        validator = validator or validate_text(256)
        suffix = f" [{default}]" if default else ""
        while True:
            ans = self._read(f"  {question}{suffix}（输入 :q 保存退出）: ") or (default or "")
            if ans == ":q":
                raise UserQuit()
            err = validator(ans)
            if err is None:
                return ans
            self.warn(err)

    def choice(self, question: str, options: dict[str, str], default: str) -> str:
        opts = " ".join(f"[{k}]{v}" for k, v in options.items())
        while True:
            ans = self._read(f"  {question} {opts}（默认 {default}）: ").lower() or default
            if ans in options:
                return ans

    def table(self, headers: list[str], rows: list[list[str]], status_col: int | None = None) -> None:
        rows = [[clean(cell, keep_newlines=False) for cell in row] for row in rows]
        widths = [display_width(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = min(max(widths[i], display_width(cell)), 60)
        self._emit("  " + "  ".join(pad(h, widths[i]) for i, h in enumerate(headers)))
        self._emit("  " + "  ".join("─" * w for w in widths))
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                text = cell if display_width(cell) <= 60 else cell[:28] + "…"
                cells.append(self.status(text) if i == status_col else pad(text, widths[i]))
            self._emit("  " + "  ".join(cells))


# ═══════════════════════════════════════════════════════════════════════════
# 状态与变更日志
# ═══════════════════════════════════════════════════════════════════════════


def new_state(account_id: str, mode: str, inputs: dict | None = None) -> dict:
    return {
        "version": STATE_VERSION,
        "account_id": account_id,
        "mode": mode,
        "created": iso_now(),
        "updated": iso_now(),
        "checks": {},
        "decisions": {},
        "inputs": dict(inputs or {}),
        "triage": {},
    }


class StateStore:
    """~/.aws-account-hardening/<account>/ 下的进度、变更日志与报告。"""

    def __init__(self, base: Path, account_id: str):
        self.dir = Path(base) / account_id
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for d in (Path(base), self.dir):
            if d.stat().st_uid != os.getuid():
                raise RuntimeError(f"状态目录 {d} 不属于当前用户，已停止")
            os.chmod(d, 0o700)
        self.state_path = self.dir / "state.json"
        self.changes_path = self.dir / "changes.jsonl"

    def use_mode(self, mode: str) -> None:
        """不同模式（guided/check/triage）各自保存进度，互不覆盖。"""
        self.state_path = self.dir / f"state-{mode}.json"

    def load(self) -> dict | None:
        if not self.state_path.exists():
            return None
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            backup = self.state_path.with_suffix(f".corrupt-{int(time.time())}")
            self.state_path.replace(backup)
            return None
        return data if data.get("version") == STATE_VERSION else None

    def save(self, state: dict) -> None:
        tmp = self.state_path.with_name(f".{self.state_path.name}.{uuid.uuid4().hex[:8]}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2, default=str)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)

    def append_change(self, record: dict) -> None:
        fd = os.open(self.changes_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def changes(self) -> list[dict]:
        """按 id 合并追加日志，后写覆盖先写，保持首次出现顺序。"""
        if not self.changes_path.exists():
            return []
        merged: dict[str, dict] = {}
        for line in self.changes_path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = rec.get("id")
            if rid:
                merged[rid] = {**merged.get(rid, {}), **rec}
        return list(merged.values())

    def write_file(self, name: str, content: str) -> Path:
        path = self.dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(clean(content))
        return path


# ═══════════════════════════════════════════════════════════════════════════
# 数据模型与上下文
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Finding:
    id: str
    module: str
    title: str
    status: str
    detail: str = ""
    fix: str | None = None
    guidance: str = ""
    evidence: tuple = ()

    def to_dict(self) -> dict:
        return {**asdict(self), "evidence": list(self.evidence)}

    @staticmethod
    def from_dict(data: dict) -> Finding:
        return Finding(
            **{**data, "evidence": tuple(tuple(e) if isinstance(e, list) else e for e in data.get("evidence", ()))}
        )


@dataclass(frozen=True)
class FixPlan:
    title: str
    actions: tuple[str, ...]
    cli: tuple[str, ...]
    cost: str
    risk: str
    rollback: str
    params: dict = field(default_factory=dict)


@dataclass
class Ctx:
    session: Any
    ui: UI
    store: StateStore
    state: dict
    account_id: str
    partition: str
    caller_arn: str
    identity_type: str
    home_region: str
    regions: list[str] = field(default_factory=list)
    org_form: str = "unknown"  # standalone | management | member | unknown
    org_id: str | None = None
    mgmt_account_id: str | None = None
    feature_set: str | None = None
    control_tower: bool = False
    _clients: dict = field(default_factory=dict, repr=False)
    _cache: dict = field(default_factory=dict, repr=False)

    def client(self, service: str, region: str | None = None):
        key = (service, region or self.home_region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=key[1], config=BOTO_CONFIG)
        return self._clients[key]

    def arn(self, service: str, region: str, resource: str) -> str:
        return f"arn:{self.partition}:{service}:{region}:{self.account_id}:{resource}"

    @property
    def is_mgmt(self) -> bool:
        return self.org_form == "management"

    def cached(self, key: str, fn: Callable[[], Any]) -> Any:
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def invalidate(self, *keys: str) -> None:
        for key in keys:
            self._cache.pop(key, None)

    def put_state(self, section: str, key: str, value: Any) -> None:
        sec = {**self.state.get(section, {}), key: value}
        self.state = {**self.state, section: sec, "updated": iso_now()}
        self.store.save(self.state)

    def input_value(self, key: str, default: Any = None) -> Any:
        return self.state.get("inputs", {}).get(key, default)

    @contextmanager
    def change(self, module: str, action: str, region: str, resource: str, **params) -> Iterator[dict]:
        """记录一次写操作：先写 pending，成功写 done，失败写 failed。yield 的 dict 可补充回滚参数。"""
        rec = {
            "id": uuid.uuid4().hex[:12],
            "ts": iso_now(),
            "module": module,
            "action": action,
            "region": region,
            "resource": resource,
            "params": dict(params),
            "status": "pending",
        }
        self.store.append_change(rec)
        extra: dict = dict(params)
        try:
            yield extra
        except Exception as exc:
            self.store.append_change(
                {"id": rec["id"], "ts": iso_now(), "params": extra, "status": "failed", "error": short_err(exc)}
            )
            raise
        self.store.append_change({"id": rec["id"], "ts": iso_now(), "params": extra, "status": "done"})

    def cred_report(self) -> list[dict]:
        return self.cached("cred_report", lambda: fetch_credential_report(self.client("iam")))


def fetch_credential_report(iam) -> list[dict]:
    for _ in range(30):
        if iam.generate_credential_report().get("State") == "COMPLETE":
            break
        time.sleep(CRED_REPORT_POLL_SECONDS)
    for _ in range(10):
        try:
            content = iam.get_credential_report()["Content"]
            break
        except ClientError as exc:
            if err_code(exc) not in ("ReportInProgress", "ReportNotPresent"):
                raise
            time.sleep(CRED_REPORT_POLL_SECONDS)
    else:
        raise RuntimeError("IAM 凭证报告生成超时，请稍后重试")
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return list(csv.DictReader(io.StringIO(text)))


def for_regions(ctx: Ctx, fn: Callable[[str], Any], regions: list[str] | None = None) -> tuple[dict, dict]:
    results, errors = {}, {}
    for region in regions or ctx.regions:
        try:
            results[region] = fn(region)
        except (ClientError, BotoCoreError) as exc:
            errors[region] = short_err(exc)
    return results, errors


def exists_or_none(fn: Callable[[], Any]) -> Any:
    """调用 fn，资源不存在时返回 None。"""
    try:
        return fn()
    except ClientError as exc:
        if is_not_found(exc):
            return None
        raise


def raise_if_failed(failures: dict[str, str]) -> None:
    """分区域操作：有失败就抛错，使该项标记为 failed，可在下次运行重试。"""
    if failures:
        raise RuntimeError("部分区域失败: " + "; ".join(f"{r}: {e}" for r, e in failures.items()))


# ═══════════════════════════════════════════════════════════════════════════
# 指引文案
# ═══════════════════════════════════════════════════════════════════════════
G_ROOT_MFA = """root MFA 无法通过 API 启用，请在控制台操作：
1. 以 root 登录控制台 → 右上角账号名 → 安全凭证（Security credentials）
2. 多重身份验证（MFA）→ 分配 MFA 设备，建议注册至少 2 个（硬件安全密钥或通行密钥）
3. 将 root 凭据纳入保险柜或双人保管流程"""

G_ROOT_KEY = """root 不应持有任何长期 Access Key（v1 工具不自动删除，请人工确认无业务依赖后处理）：
1. 以 root 登录控制台 → 安全凭证 → 访问密钥：先“停用”，观察 1–3 天业务无异常后“删除”
2. 或以 root 身份在 CloudShell 执行：
   aws iam list-access-keys
   aws iam update-access-key --access-key-id <ID> --status Inactive
   aws iam delete-access-key --access-key-id <ID>
3. 组织成员账号且已启用集中式 root 管理：由管理账号执行
   aws sts assume-root --target-principal <成员账号ID> \\
     --task-policy-arn arn=arn:aws:iam::aws:policy/root-task/IAMDeleteRootUserCredentials
   再用返回的临时凭证删除 root 凭证"""

G_ROOT_RECENT = """root 近期被使用过。请核实使用人、时间和目的：
- 查 CloudTrail 事件历史：用户名 root / 事件 ConsoleLogin
- 日常操作改用 IAM Identity Center 或 IAM 角色，root 仅用于必须由 root 执行的任务"""

G_ROOT_IDENTITY = "当前以 root 身份运行本工具。完成加固后请退出 root，日常改用 IAM Identity Center / IAM 角色。"

G_ROOT_EMAIL = """root 邮箱无法通过 API 读取，请人工确认：
- 使用企业群组邮箱（如 aws-root-prod@example.com），至少 2 名负责人可收件，不使用个人邮箱
- 修改：root 登录 → 账号（Account）→ 账号设置 → 编辑电子邮件"""

G_TRAIL_VALIDATION = """已有 Trail 未开启日志文件完整性验证（工具不修改客户已有 Trail）：
  aws cloudtrail update-trail --name <trail> --enable-log-file-validation"""

G_TRAIL_MEMBER = "成员账号未看到组织级 Trail。请联系管理账号负责人创建组织级 Trail（覆盖所有账号、所有区域）。"

G_TRAIL_RETENTION = """请确认 Trail 日志桶的保留期超过 90 天，并开启版本控制、限制删除权限；
更强的防篡改可考虑：专用日志归档账号 + S3 Object Lock。"""

G_TRAIL_CT = "该账号由 Control Tower 管理 CloudTrail，请通过 Control Tower 调整，工具不做修改。"

G_IDC = """建议人员统一经 IAM Identity Center 登录：
1. 在管理账号控制台开启 IAM Identity Center（选择主区域）
2. 对接企业身份源（Microsoft Entra ID / Okta 等 SAML + SCIM），入职开通、离职回收自动生效
3. 按权限集分配最小权限，强制 MFA
4. 除破窗（break-glass）账号外，不再为人员创建 IAM 用户"""

G_IDC_MEMBER = (
    "成员账号通常使用管理账号中的组织级 Identity Center，请与管理账号负责人确认人员是否经由 Identity Center 登录。"
)

G_CONSOLE_USERS = """以下 IAM 用户拥有控制台密码。建议迁移到 IAM Identity Center，仅保留破窗账号：
  aws iam delete-login-profile --user-name <用户名>   # 迁移完成后删除控制台密码"""

G_CONSOLE_MFA = """以下 IAM 控制台用户未启用 MFA，请立即启用，或迁移到 Identity Center：
  控制台 → IAM → 用户 → <用户名> → 安全凭证 → 分配 MFA 设备"""

G_KEYS_UNUSED = """以下长期 Access Key 超过 90 天未使用（v1 工具不自动停用，请确认无业务依赖后处理）：
  aws iam list-access-keys --user-name <用户名>
  aws iam update-access-key --user-name <用户名> --access-key-id <ID> --status Inactive
观察无影响后删除：aws iam delete-access-key --user-name <用户名> --access-key-id <ID>
程序访问请改用 IAM 角色 / 实例配置文件 / EKS Pod Identity / OIDC 联合身份。"""

G_KEYS_ROTATE = """以下活跃 Access Key 超过 90 天未轮换。确有必要保留的长期密钥应定期轮换：
  aws iam create-access-key --user-name <用户名>     # 新建 → 更新应用配置 → 停用旧 Key → 删除旧 Key"""

G_NETWORK = """访问来源控制（v1 工具不生成、不挂载策略，请人工评估后灰度实施）：
1. 推荐在企业身份源侧配置条件访问（网络位置、设备合规、MFA 强度）
2. AWS 侧可用 IAM 策略 / SCP 拒绝非企业出口 IP 的 API 调用，示例：
   {"Version":"2012-10-17","Statement":[{"Sid":"DenyOutsideCorpIP","Effect":"Deny",
     "Action":"*","Resource":"*","Condition":{
       "NotIpAddress":{"aws:SourceIp":["192.0.2.0/24"]},
       "Bool":{"aws:ViaAWSService":"false"}}}]}
3. 注意：经 VPC 终端节点的请求不带公网源 IP，需用 aws:SourceVpc / aws:SourceVpce 放行；
   IAM 身份策略不限制 root（SCP 可限制成员账号 root）；保留破窗账号；先在测试账号灰度"""

G_SCP_FEATURES = """组织未启用“所有功能”，无法使用 SCP。管理账号执行：
  aws organizations enable-all-features   # 需要所有成员账号接受邀请"""

G_SCP_ENABLE = """组织未启用 SCP 策略类型。管理账号执行：
  aws organizations enable-policy-type --root-id <r-xxxx> --policy-type SERVICE_CONTROL_POLICY"""

SCP_SAMPLES = {
    "cloudtrail": '{"Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail",'
    '"cloudtrail:UpdateTrail","cloudtrail:PutEventSelectors"],"Resource":"*"}',
    "guardduty": '{"Effect":"Deny","Action":["guardduty:DeleteDetector","guardduty:UpdateDetector",'
    '"guardduty:DisassociateFromAdministratorAccount"],"Resource":"*"}',
    "leave_org": '{"Effect":"Deny","Action":"organizations:LeaveOrganization","Resource":"*"}',
    "region": '{"Effect":"Deny","NotAction":["iam:*","organizations:*","sts:*","support:*",'
    '"cloudfront:*","route53:*","budgets:*","ce:*","health:*"],"Resource":"*",'
    '"Condition":{"StringNotEquals":{"aws:RequestedRegion":["us-east-1","ap-southeast-1"]}}}',
    "iam_key": '{"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*"}',
}

G_SCP_TEMPLATE = """v1 工具不创建、不挂载 SCP。建议在 Statement 中加入以下语句，先挂到测试 OU 验证，再推广：
  {sample}
破窗/安全运维角色可通过 Condition 中 aws:PrincipalArn 排除。"""

G_ACCOUNT_STRUCT = """请确认多账号结构：生产、测试、日志归档、安全工具分属不同账号/OU，生产与实验隔离。
希望快速建立标准化多账号环境，可评估 AWS Control Tower。"""

G_ROOT_MGMT_MEMBER = """集中式 root 管理启用后，可删除成员账号 root 凭证（v1 工具不自动执行）：
  aws sts assume-root --target-principal <成员账号ID> \\
    --task-policy-arn arn=arn:aws:iam::aws:policy/root-task/IAMDeleteRootUserCredentials
  # 使用返回的临时凭证：
  aws iam delete-login-profile ; aws iam list-access-keys / delete-access-key ; aws iam deactivate-mfa-device
需要 root 才能完成的任务改由管理账号发起特权任务（短期 root 会话），并留存审批记录。"""

G_REVIEW = """定期审计与演练：
- 每月：IAM 凭证报告、Access Analyzer 未使用访问发现，回收闲置权限（可重跑本工具 --check-only 对比）
- 每季度：复核备用联系人、破窗账号、root 保管流程
- 每半年：账号安全事件桌面演练（收到 AWS 安全通知 → 判定 → 处置 → 开 case → 复盘）"""

G_SH_REGIONS = "Security Hub / Config 仅在主区域开启。需要全区域覆盖时，请在各区域分别开启并配置跨区域聚合。"

# ═══════════════════════════════════════════════════════════════════════════
# 账号识别与共享资源
# ═══════════════════════════════════════════════════════════════════════════


def identity_type(arn: str) -> str:
    if arn.endswith(":root"):
        return "root"
    if ":user/" in arn:
        return "iam_user"
    if ":assumed-role/" in arn:
        return "role"
    return "other"


def detect_org(ctx: Ctx) -> None:
    try:
        org = ctx.client("organizations").describe_organization()["Organization"]
    except ClientError as exc:
        ctx.org_form = "standalone" if err_code(exc) == "AWSOrganizationsNotInUseException" else "unknown"
        return
    ctx.org_id = org.get("Id")
    ctx.mgmt_account_id = org.get("MasterAccountId")
    ctx.feature_set = org.get("FeatureSet")
    ctx.org_form = "management" if ctx.mgmt_account_id == ctx.account_id else "member"


def detect_control_tower(ctx: Ctx) -> bool:
    """无法确认时按“是 Control Tower”处理（fail-closed）：Trail / Config 只检查不修改。"""
    iam = ctx.client("iam")
    for role in ("AWSControlTowerExecution", "AWSControlTowerAdmin"):
        try:
            iam.get_role(RoleName=role)
            return True
        except ClientError as exc:
            if err_code(exc) != "NoSuchEntity":
                ctx.ui.warn(f"无法确认是否部署 Control Tower（{short_err(exc)}），按 Control Tower 账号处理")
                return True
    try:
        trails = ctx.client("cloudtrail").describe_trails(includeShadowTrails=True)["trailList"]
    except ClientError as exc:
        ctx.ui.warn(f"无法确认是否部署 Control Tower（{short_err(exc)}），按 Control Tower 账号处理")
        return True
    return any(t.get("Name", "").startswith("aws-controltower-") for t in trails)


def alert_regions(ctx: Ctx) -> list[str]:
    """告警转发覆盖的区域：始终包含 us-east-1（IAM 等全局服务事件只在这里产生）。"""
    return sorted(set(ctx.regions) | {"us-east-1"})


def resolve_regions(ctx: Ctx, include: str | None, exclude: str | None) -> list[str]:
    resp = ctx.client("ec2", ctx.session.region_name or "us-east-1").describe_regions(
        AllRegions=False, Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    enabled = sorted(r["RegionName"] for r in resp["Regions"])
    regions = enabled
    if include:
        wanted = [r.strip() for r in include.split(",") if r.strip()]
        unknown = [r for r in wanted if r not in enabled]
        if unknown:
            raise ValueError(f"以下区域未启用或不存在: {', '.join(unknown)}")
        regions = wanted
    if exclude:
        drop = {r.strip() for r in exclude.split(",")}
        regions = [r for r in regions if r not in drop]
    if not REGION_RE.match(ctx.home_region) or ctx.home_region not in enabled:
        raise ValueError(f"主区域 {ctx.home_region} 不存在或未启用")
    if not regions:
        raise ValueError("区域列表为空")
    return regions


def log_bucket_name(ctx: Ctx) -> str:
    return f"{PREFIX}-trail-{ctx.account_id}-{ctx.home_region}"


def build_log_bucket_policy(bucket: str, account_id: str, partition: str, org_id: str | None) -> dict:
    """日志桶策略：CloudTrail（含组织 Trail）+ AWS Config 写入，强制 HTTPS。"""
    bucket_arn = f"arn:{partition}:s3:::{bucket}"
    trail_arn = f"arn:{partition}:cloudtrail:*:{account_id}:trail/{PREFIX}-*"
    trail_paths = [f"{bucket_arn}/AWSLogs/{account_id}/*"]
    if org_id:
        trail_paths.append(f"{bucket_arn}/AWSLogs/{org_id}/*")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": bucket_arn,
                "Condition": {"ArnLike": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": trail_paths,
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"},
                    "ArnLike": {"aws:SourceArn": trail_arn},
                },
            },
            {
                "Sid": "AWSConfigBucketCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": ["s3:GetBucketAcl", "s3:ListBucket"],
                "Resource": bucket_arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSConfigBucketDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{bucket_arn}/config/AWSLogs/{account_id}/Config/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceAccount": account_id}
                },
            },
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }


def bucket_state(s3, bucket: str) -> str:
    """返回 missing | owned | foreign。"""
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        code = err_code(exc)
        if code in ("404", "NoSuchBucket", "NotFound"):
            return "missing"
        if code in ("403", "AccessDenied"):
            return "foreign"
        raise
    return "owned"


def has_tool_tag(s3, bucket: str) -> bool:
    """仅凭标签判断归属（回滚时使用，不回退到变更日志）。"""
    try:
        tags = s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
    except ClientError:
        return False
    return any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE for t in tags)


def is_tool_bucket(ctx: Ctx, s3, bucket: str) -> bool:
    try:
        tags = s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
        if any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE for t in tags):
            return True
    except ClientError:
        pass
    return any(c.get("action") == "s3:create_bucket" and c.get("resource") == bucket for c in ctx.store.changes())


def ensure_log_bucket(ctx: Ctx, module: str) -> str:
    """创建（或复用本工具创建的）日志桶并加固。幂等。"""
    bucket = log_bucket_name(ctx)
    s3 = ctx.client("s3")
    state = bucket_state(s3, bucket)
    if state == "foreign":
        raise RuntimeError(f"S3 桶名 {bucket} 已被其他账号占用")
    if state == "owned" and not is_tool_bucket(ctx, s3, bucket):
        raise RuntimeError(f"S3 桶 {bucket} 已存在但不是本工具创建的，为避免覆盖其配置已停止")
    if state == "missing":
        with ctx.change(module, "s3:create_bucket", ctx.home_region, bucket, bucket=bucket):
            kwargs: dict = {"Bucket": bucket, "ObjectOwnership": "BucketOwnerEnforced"}
            if ctx.home_region != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.home_region}
            s3.create_bucket(**kwargs)
    harden_log_bucket(ctx, s3, bucket)
    return bucket


def build_lifecycle_rules(retention: int) -> list[dict]:
    """仅对日志前缀过期；guardduty/（可信 IP 列表）永不过期，否则 IPSet 会失效。"""
    return [
        {
            "ID": f"{PREFIX}-retention-{name}",
            "Status": "Enabled",
            "Filter": {"Prefix": prefix},
            "Expiration": {"Days": retention},
            "NoncurrentVersionExpiration": {"NoncurrentDays": NONCURRENT_RETENTION_DAYS},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
        }
        for name, prefix in (("cloudtrail", "AWSLogs/"), ("config", "config/"))
    ]


def harden_log_bucket(ctx: Ctx, s3, bucket: str) -> None:
    retention = int(ctx.input_value("log_retention_days", DEFAULT_LOG_RETENTION_DAYS))
    owner = {"Bucket": bucket, "ExpectedBucketOwner": ctx.account_id}
    s3.put_bucket_tagging(**owner, Tagging={"TagSet": tag_list()})
    s3.put_public_access_block(
        **owner,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(**owner, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_encryption(
        **owner,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_lifecycle_configuration(**owner, LifecycleConfiguration={"Rules": build_lifecycle_rules(retention)})
    policy = build_log_bucket_policy(bucket, ctx.account_id, ctx.partition, ctx.org_id if ctx.is_mgmt else None)
    s3.put_bucket_policy(**owner, Policy=json.dumps(policy))


def ensure_service_access(ctx: Ctx, principal: str, module: str) -> None:
    org = ctx.client("organizations")
    enabled: set[str] = set()
    for page in org.get_paginator("list_aws_service_access_for_organization").paginate():
        enabled.update(s["ServicePrincipal"] for s in page.get("EnabledServicePrincipals", []))
    if principal in enabled:
        return
    with ctx.change(module, "organizations:enable_aws_service_access", "global", principal):
        org.enable_aws_service_access(ServicePrincipal=principal)


# ═══════════════════════════════════════════════════════════════════════════
# 模块基类
# ═══════════════════════════════════════════════════════════════════════════


class Module:
    id = "M0"
    name = ""
    practice = ""

    def not_applicable(self, ctx: Ctx) -> str | None:
        return None

    def check(self, ctx: Ctx) -> list[Finding]:
        raise NotImplementedError

    def plan(self, ctx: Ctx, finding: Finding) -> FixPlan | None:
        fn = getattr(self, f"plan_{finding.fix}", None)
        return fn(ctx, finding) if fn else None

    def apply(self, ctx: Ctx, finding: Finding, plan: FixPlan) -> None:
        getattr(self, f"apply_{finding.fix}")(ctx, plan)

    def f(
        self,
        key: str,
        title: str,
        status: str,
        detail: str = "",
        fix: str | None = None,
        guidance: str = "",
        evidence: tuple | list = (),
    ) -> Finding:
        return Finding(
            id=f"{self.id}.{key}",
            module=self.id,
            title=title,
            status=status,
            detail=detail,
            fix=fix,
            guidance=guidance,
            evidence=tuple(evidence),
        )


def run_check(ctx: Ctx, module: Module) -> list[Finding]:
    reason = module.not_applicable(ctx)
    if reason:
        return [Finding(id=f"{module.id}.na", module=module.id, title=module.name, status=NA, detail=reason)]
    try:
        return module.check(ctx)
    except (ClientError, BotoCoreError, RuntimeError) as exc:
        detail = short_err(exc)
    except Exception as exc:  # 单个模块的意外错误不应中断整个检查
        detail = f"内部错误 {type(exc).__name__}: {exc}"[:300]
    return [Finding(id=f"{module.id}.error", module=module.id, title=module.name, status=ERROR, detail=detail)]


# ═══════════════════════════════════════════════════════════════════════════
# M1 root 用户保护
# ═══════════════════════════════════════════════════════════════════════════


class RootModule(Module):
    id, name, practice = "M1", "root 用户保护", "实践 1"

    def check(self, ctx: Ctx) -> list[Finding]:
        summary = ctx.client("iam").get_account_summary()["SummaryMap"]
        try:
            root = next((r for r in ctx.cred_report() if r.get("user") == ROOT_USER), {})
            recent = self._recent(root)
        except (ClientError, RuntimeError) as exc:
            root = {}
            recent = self.f("recent", f"root 近 {ROOT_RECENT_DAYS} 天未被使用", ERROR, f"凭证报告: {short_err(exc)}")
        return [
            self._mfa(ctx, summary, root),
            self._keys(summary, root),
            recent,
            self._identity(ctx),
            self.f("email", "root 邮箱为企业群组邮箱", MANUAL, "无 API，需人工确认", guidance=G_ROOT_EMAIL),
        ]

    def _mfa(self, ctx: Ctx, summary: dict, root: dict) -> Finding:
        if summary.get("AccountMFAEnabled") == 1:
            return self.f("mfa", "root 已启用 MFA", PASS)
        no_creds = root.get("password_enabled") == "false" and summary.get("AccountAccessKeysPresent") != 1
        if no_creds and ctx.org_form == "member":
            return self.f(
                "mfa",
                "root 已启用 MFA",
                MANUAL,
                "成员账号 root 无密码与密钥",
                guidance="若管理账号已启用集中式 root 管理并删除了该账号 root 凭证，则无需 MFA；"
                "否则（例如通过 CreateAccount 新建的账号）仍可经 root 邮箱找回密码，必须启用 MFA。\n" + G_ROOT_MFA,
            )
        detail = "root 未启用 MFA"
        if no_creds:
            detail += "；root 当前无密码，但仍可通过 root 邮箱找回密码登录，必须启用 MFA"
        return self.f("mfa", "root 已启用 MFA", FAIL, detail, guidance=G_ROOT_MFA)

    def _keys(self, summary: dict, root: dict) -> Finding:
        if summary.get("AccountAccessKeysPresent") != 1:
            return self.f("keys", "root 无 Access Key", PASS)
        ev = [(f"key{n}_last_used", root.get(f"access_key_{n}_last_used_date", "N/A")) for n in (1, 2)]
        return self.f("keys", "root 无 Access Key", FAIL, "root 存在 Access Key", guidance=G_ROOT_KEY, evidence=ev)

    def _recent(self, root: dict) -> Finding:
        used = [
            parse_ts(root.get(k))
            for k in ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date")
        ]
        recent = [d for d in used if d and days_ago(d) <= ROOT_RECENT_DAYS]
        if not recent:
            return self.f("recent", f"root 近 {ROOT_RECENT_DAYS} 天未被使用", PASS)
        last = max(recent).strftime("%Y-%m-%d %H:%M UTC")
        return self.f(
            "recent", f"root 近 {ROOT_RECENT_DAYS} 天未被使用", WARN, f"最近使用: {last}", guidance=G_ROOT_RECENT
        )

    def _identity(self, ctx: Ctx) -> Finding:
        if ctx.identity_type == "root":
            return self.f("identity", "未使用 root 执行日常操作", WARN, "当前以 root 运行", guidance=G_ROOT_IDENTITY)
        return self.f("identity", "未使用 root 执行日常操作", PASS, f"当前身份: {ctx.identity_type}")


# ═══════════════════════════════════════════════════════════════════════════
# M2 备用联系人
# ═══════════════════════════════════════════════════════════════════════════
CONTACT_TYPES = (("SECURITY", "安全"), ("BILLING", "账单"), ("OPERATIONS", "运维"))


class ContactsModule(Module):
    id, name, practice = "M2", "备用联系人", "实践 2"

    def check(self, ctx: Ctx) -> list[Finding]:
        acct = ctx.client("account")
        out = []
        for ctype, label in CONTACT_TYPES:
            title = f"{label}联系人已配置"
            try:
                c = acct.get_alternate_contact(AlternateContactType=ctype)["AlternateContact"]
                out.append(self.f(ctype, title, PASS, f"{c.get('Name')} / {mask_email(c.get('EmailAddress', ''))}"))
            except ClientError as exc:
                if err_code(exc) != "ResourceNotFoundException":
                    raise
                out.append(self.f(ctype, title, FAIL, "未配置", fix="contact", evidence=[("type", ctype)]))
        return out

    def plan_contact(self, ctx: Ctx, finding: Finding) -> FixPlan:
        ctype = dict(finding.evidence)["type"]
        label = dict(CONTACT_TYPES)[ctype]
        saved = ctx.input_value("contacts", {})
        reuse = next((v for k, v in saved.items() if k != ctype), None)
        if reuse and ctx.ui.confirm(f"沿用已录入的联系人 {reuse['name']} / {reuse['email']}？", default=False):
            data = dict(reuse)
        else:
            ctx.ui.info(f"请录入{label}联系人（建议使用群组邮箱与值班电话）")
            data = {
                "name": ctx.ui.ask("姓名/团队名", validate_text(64)),
                "title": ctx.ui.ask("职务", validate_text(50), default="Security Team"),
                "email": ctx.ui.ask("邮箱", validate_email),
                "phone": ctx.ui.ask("电话", validate_phone),
            }
        ctx.put_state("inputs", "contacts", {**saved, ctype: data})
        return FixPlan(
            title=f"配置{label}备用联系人",
            actions=(f"写入 {ctype} 联系人：{data['name']} / {data['email']} / {data['phone']}",),
            cli=(
                f"aws account put-alternate-contact --alternate-contact-type {ctype} "
                f"--name {shlex.quote(data['name'])} --title {shlex.quote(data['title'])} "
                f"--email-address {shlex.quote(data['email'])} --phone-number {shlex.quote(data['phone'])}",
            ),
            cost="免费",
            risk="低：仅新增联系人",
            rollback=f"aws account delete-alternate-contact --alternate-contact-type {ctype}",
            params={"type": ctype, **data},
        )

    def apply_contact(self, ctx: Ctx, plan: FixPlan) -> None:
        p = plan.params
        acct = ctx.client("account")
        if exists_or_none(lambda: acct.get_alternate_contact(AlternateContactType=p["type"])):
            ctx.ui.warn(f"{p['type']} 联系人已在此期间被配置，为避免覆盖已跳过")
            return
        with ctx.change(self.id, "account:put_alternate_contact", "global", p["type"], type=p["type"]):
            ctx.client("account").put_alternate_contact(
                AlternateContactType=p["type"],
                Name=p["name"],
                Title=p["title"],
                EmailAddress=p["email"],
                PhoneNumber=p["phone"],
            )


# ═══════════════════════════════════════════════════════════════════════════
# M3 CloudTrail
# ═══════════════════════════════════════════════════════════════════════════


def trail_has_mgmt_events(selectors: dict) -> bool:
    for sel in selectors.get("EventSelectors") or []:
        if sel.get("IncludeManagementEvents", True) and sel.get("ReadWriteType", "All") in ("All", "WriteOnly"):
            return True
    for adv in selectors.get("AdvancedEventSelectors") or []:
        for fs in adv.get("FieldSelectors", []):
            if fs.get("Field") == "eventCategory" and "Management" in fs.get("Equals", []):
                return True
    return False


def survey_trails(ctx: Ctx) -> list[dict]:
    trails = ctx.client("cloudtrail").describe_trails(includeShadowTrails=True)["trailList"]
    out = []
    for t in trails:
        home = t.get("HomeRegion", ctx.home_region)
        ct = ctx.client("cloudtrail", home)
        try:
            logging = ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging")
            # 未自定义 selector = 默认记录全部管理事件
            mgmt = not t.get("HasCustomEventSelectors", True) or trail_has_mgmt_events(
                ct.get_event_selectors(TrailName=t["TrailARN"])
            )
        except ClientError:
            if not (t.get("IsOrganizationTrail") and ctx.org_form == "member"):
                raise
            logging, mgmt = None, None  # 成员账号查看组织 Trail 无权限，状态未知
        out.append(
            {
                "name": t["Name"],
                "arn": t["TrailARN"],
                "home": home,
                "multi": t.get("IsMultiRegionTrail", False),
                "org": t.get("IsOrganizationTrail", False),
                "validation": t.get("LogFileValidationEnabled", False),
                "bucket": t.get("S3BucketName"),
                "logging": logging,
                "mgmt": mgmt,
            }
        )
    return out


def is_good_trail(t: dict) -> bool:
    """多区域 + 记录管理事件 + 正在记录；成员账号看组织 Trail 时状态未知（None）视为有效。"""
    if not t["multi"] or t["mgmt"] is False:
        return False
    return t["logging"] is True or (t["logging"] is None and t["org"])


class TrailModule(Module):
    id, name, practice = "M3", "CloudTrail 日志审计", "实践 3"

    def check(self, ctx: Ctx) -> list[Finding]:
        ctx.invalidate("trails")
        trails = ctx.cached("trails", lambda: survey_trails(ctx))
        good = [t for t in trails if is_good_trail(t)]
        fix = None if ctx.control_tower else "trail"
        guide = G_TRAIL_CT if ctx.control_tower else ""
        out = []
        if good:
            out.append(self.f("trail", "存在多区域且正在记录的 Trail", PASS, ", ".join(t["name"] for t in good)))
        else:
            detail = f"现有 Trail: {', '.join(t['name'] for t in trails)}" if trails else "没有任何 Trail"
            out.append(self.f("trail", "存在多区域且正在记录的 Trail", FAIL, detail, fix=fix, guidance=guide))
        if good:
            no_val = [t["name"] for t in good if not t["validation"]]
            out.append(
                self.f(
                    "validation",
                    "Trail 开启日志文件完整性验证",
                    WARN if no_val else PASS,
                    ", ".join(no_val),
                    guidance=G_TRAIL_VALIDATION if no_val else "",
                )
            )
        out.append(self._org_finding(ctx, good, fix, guide))
        ours = any(t["bucket"] == log_bucket_name(ctx) for t in good)
        if ours:
            days = ctx.input_value("log_retention_days", DEFAULT_LOG_RETENTION_DAYS)
            out.append(self.f("retention", "日志保留超过 90 天", PASS, f"日志桶生命周期 {days} 天"))
        else:
            out.append(
                self.f("retention", "日志保留超过 90 天", MANUAL, "请确认日志桶保留策略", guidance=G_TRAIL_RETENTION)
            )
        return out

    def _org_finding(self, ctx: Ctx, good: list[dict], fix: str | None, guide: str) -> Finding:
        title = "组织级 Trail 覆盖所有账号"
        has_org = any(t["org"] for t in good)
        if ctx.is_mgmt:
            return self.f(
                "org",
                title,
                PASS if has_org else FAIL,
                "" if has_org else "未创建组织级 Trail",
                fix=None if has_org else fix,
                guidance="" if has_org else guide,
            )
        if ctx.org_form == "member":
            return self.f("org", title, PASS if has_org else WARN, "", guidance="" if has_org else G_TRAIL_MEMBER)
        return self.f("org", title, NA, "非 Organizations 账号")

    def plan_trail(self, ctx: Ctx, finding: Finding) -> FixPlan:
        org = ctx.is_mgmt
        days = int(
            ctx.ui.ask(
                "日志保留天数",
                validate_int_range(90, 3650),
                default=str(ctx.input_value("log_retention_days", DEFAULT_LOG_RETENTION_DAYS)),
            )
        )
        ctx.put_state("inputs", "log_retention_days", days)
        bucket, name = log_bucket_name(ctx), ORG_TRAIL_NAME if org else TRAIL_NAME
        actions = [
            f"创建/复用 S3 日志桶 {bucket}：阻止公共访问、SSE-S3、版本控制、仅 HTTPS、保留 {days} 天",
            f"创建{'组织级' if org else ''}多区域 Trail {name}：管理事件读写、日志文件完整性验证",
            "开始记录",
        ]
        if org:
            actions.insert(1, "启用 CloudTrail 对 Organizations 的可信访问")
        flag = " --is-organization-trail" if org else ""
        return FixPlan(
            title="创建多区域 CloudTrail",
            actions=tuple(actions),
            cli=(
                f"aws s3api create-bucket --bucket {bucket} ...（加固配置略）",
                f"aws cloudtrail create-trail --name {name} --s3-bucket-name {bucket} "
                f"--is-multi-region-trail --enable-log-file-validation{flag}",
                f"aws cloudtrail start-logging --name {name}",
            ),
            cost="第一份管理事件 Trail 免费；S3 存储按量计费（通常每月几美元以内）",
            risk="低：仅新增资源，不修改已有 Trail",
            rollback="删除 Trail；日志桶默认保留（审计证据）",
            params={"org": org, "name": name},
        )

    def apply_trail(self, ctx: Ctx, plan: FixPlan) -> None:
        org, name = plan.params["org"], plan.params["name"]
        bucket = ensure_log_bucket(ctx, self.id)
        if org:
            ensure_service_access(ctx, "cloudtrail.amazonaws.com", self.id)
        ct = ctx.client("cloudtrail")
        arn = ctx.arn("cloudtrail", ctx.home_region, f"trail/{name}")
        existing = ct.describe_trails(trailNameList=[name], includeShadowTrails=False)["trailList"]
        if not existing:
            with ctx.change(self.id, "cloudtrail:create_trail", ctx.home_region, arn, name=name):
                ct.create_trail(
                    Name=name,
                    S3BucketName=bucket,
                    IsMultiRegionTrail=True,
                    IncludeGlobalServiceEvents=True,
                    EnableLogFileValidation=True,
                    IsOrganizationTrail=org,
                    TagsList=tag_list(),
                )
        ct.start_logging(Name=name)
        ctx.invalidate("trails")


# ═══════════════════════════════════════════════════════════════════════════
# M4 GuardDuty
# ═══════════════════════════════════════════════════════════════════════════
COST_GD = (
    "每个区域 30 天免费试用；之后按分析的 CloudTrail 事件 / VPC 流日志 / DNS 日志量计费，试用期可在控制台查看费用预估"
)


def total_addresses(cidrs: list[str]) -> int:
    return sum(ipaddress.ip_network(c).num_addresses for c in cidrs)


def gd_region_info(ctx: Ctx, region: str) -> dict:
    gd = ctx.client("guardduty", region)
    ids = gd.list_detectors().get("DetectorIds", [])
    if not ids:
        return {"detector": None, "enabled": False, "ipsets": 0, "admin": None}
    did = ids[0]
    enabled = gd.get_detector(DetectorId=did).get("Status") == "ENABLED"
    try:
        ids_ = gd.list_ip_sets(DetectorId=did).get("IpSetIds", [])
        statuses_ = [gd.get_ip_set(DetectorId=did, IpSetId=i).get("Status") for i in ids_]
        ipsets: int | None = sum(1 for st in statuses_ if st == "ACTIVE")
    except ClientError:
        ipsets = None  # 无法确认，不提示配置
    try:
        admin = (gd.get_administrator_account(DetectorId=did).get("Administrator") or {}).get("AccountId")
    except ClientError:
        admin = None
    return {"detector": did, "enabled": enabled, "ipsets": ipsets, "admin": admin}


class GuardDutyModule(Module):
    id, name, practice = "M4", "GuardDuty 威胁检测", "实践 4"

    def _detectors(self, ctx: Ctx, regions: list[str]) -> dict[str, str | None]:
        """apply 时现场查询 detector（续跑时检查缓存为空，不能依赖 check 的副作用）。"""
        out = {}
        for region in regions:
            ids = ctx.client("guardduty", region).list_detectors().get("DetectorIds", [])
            out[region] = ids[0] if ids else None
        return out

    def check(self, ctx: Ctx) -> list[Finding]:
        info, errors = for_regions(ctx, lambda r: gd_region_info(ctx, r))
        missing = sorted(r for r, i in info.items() if not i["enabled"])
        detail = f"未启用: {', '.join(missing)}" if missing else f"{len(info)} 个区域已启用"
        if errors:
            detail += f"；检查失败: {', '.join(errors)}"
        gd_admins = sorted({i["admin"] for i in info.values() if i.get("admin")})
        if gd_admins:
            detail += f"；由委派管理员 {', '.join(gd_admins)} 统一管理"
        status = FAIL if missing else (ERROR if errors and not info else WARN if errors else PASS)
        out = [
            self.f(
                "enabled",
                "所有区域已启用 GuardDuty",
                status,
                detail,
                fix="gd_enable" if missing else None,
                evidence=[("regions", missing)],
            )
        ]
        with_det = sorted(r for r, i in info.items() if i["detector"])
        no_ipset = [r for r in with_det if info[r]["ipsets"] == 0]
        unknown = [r for r in with_det if info[r]["ipsets"] is None]
        if with_det:
            detail = f"未配置: {', '.join(no_ipset)}" if no_ipset else ""
            if unknown:
                detail += f"{'；' if detail else ''}无法确认: {', '.join(unknown)}"
            out.append(
                self.f(
                    "ipset",
                    "GuardDuty 已配置可信 IP 列表（可选）",
                    WARN if (no_ipset or unknown) else PASS,
                    detail,
                    fix="gd_ipset" if no_ipset else None,
                    evidence=[("regions", no_ipset)],
                )
            )
        admins: list[dict] = []
        if ctx.is_mgmt:
            admins = (
                ctx.client("organizations")
                .list_delegated_administrators(ServicePrincipal="guardduty.amazonaws.com")
                .get("DelegatedAdministrators", [])
            )
            out.append(self._org_admin(admins))
        # 管理账号也能调用 DescribeOrganizationConfiguration，只有自身是委派管理员时才检查自动启用
        if not ctx.is_mgmt or any(a["Id"] == ctx.account_id for a in admins):
            auto = self._auto_enable(ctx, info)
            if auto:
                out.append(auto)
        return out

    def _org_admin(self, admins: list[dict]) -> Finding:
        title = "GuardDuty 由安全账号（委派管理员）统一管理"
        if admins:
            return self.f("org_admin", title, PASS, ", ".join(a["Id"] for a in admins))
        return self.f("org_admin", title, FAIL, "未设置委派管理员", fix="gd_org_admin")

    def _auto_enable(self, ctx: Ctx, info: dict) -> Finding | None:
        not_all, is_admin = [], False
        for region, i in info.items():
            if not i["detector"]:
                continue
            try:
                conf = ctx.client("guardduty", region).describe_organization_configuration(DetectorId=i["detector"])
            except ClientError:
                continue
            is_admin = True
            if conf.get("AutoEnableOrganizationMembers") != "ALL":
                not_all.append(region)
        if not is_admin:
            return None
        return self.f(
            "auto",
            "委派管理员已对组织成员自动启用 GuardDuty",
            FAIL if not_all else PASS,
            f"未设为 ALL: {', '.join(not_all)}" if not_all else "",
            fix="gd_auto" if not_all else None,
            evidence=[("regions", not_all)],
        )

    def plan_gd_enable(self, ctx: Ctx, finding: Finding) -> FixPlan:
        regions = list(dict(finding.evidence)["regions"])
        return FixPlan(
            title="在所有区域启用 GuardDuty",
            actions=tuple(f"{r}: 创建/启用 detector（发现发布频率 15 分钟）" for r in regions),
            cli=tuple(f"aws guardduty create-detector --enable --region {r}" for r in regions[:3])
            + (("...",) if len(regions) > 3 else ()),
            cost=COST_GD,
            risk="低：只读分析，不影响业务",
            rollback="删除本工具创建的 detector（会删除其发现记录）",
            params={"regions": regions},
        )

    def apply_gd_enable(self, ctx: Ctx, plan: FixPlan) -> None:
        failures: dict[str, str] = {}
        for region in plan.params["regions"]:
            gd = ctx.client("guardduty", region)
            try:
                did = self._detectors(ctx, [region])[region]
                if did:
                    with ctx.change(self.id, "guardduty:enable_detector", region, did, detector_id=did):
                        gd.update_detector(DetectorId=did, Enable=True)
                else:
                    with ctx.change(self.id, "guardduty:create_detector", region, "detector") as extra:
                        extra["detector_id"] = gd.create_detector(
                            Enable=True, FindingPublishingFrequency="FIFTEEN_MINUTES", Tags=tag_map()
                        )["DetectorId"]
                ctx.ui.ok(f"{region} 已启用")
            except (ClientError, BotoCoreError) as exc:
                failures[region] = short_err(exc)
                ctx.ui.error(f"{region}: {short_err(exc)}")
        raise_if_failed(failures)

    def plan_gd_ipset(self, ctx: Ctx, finding: Finding) -> FixPlan:
        regions = list(dict(finding.evidence)["regions"])
        default = ",".join(ctx.input_value("trusted_cidrs", [])) or None
        cidrs = parse_cidrs(ctx.ui.ask("企业公网出口 CIDR（逗号分隔）", validate_cidrs, default=default))
        ctx.put_state("inputs", "trusted_cidrs", cidrs)
        bucket = log_bucket_name(ctx)
        return FixPlan(
            title="配置 GuardDuty 可信 IP 列表",
            actions=(
                f"写入 s3://{bucket}/{IPSET_KEY}（{len(cidrs)} 条，共 {total_addresses(cidrs):,} 个地址）：",
                *[f"    {c}" for c in cidrs],
                f"在 {len(regions)} 个区域创建并激活 IPSet {IPSET_NAME}",
            ),
            cli=(
                f"aws s3 cp trusted-ips.txt s3://{bucket}/{IPSET_KEY}",
                f"aws guardduty create-ip-set --detector-id <id> --name {IPSET_NAME} --format TXT "
                f"--location https://s3.amazonaws.com/{bucket}/{IPSET_KEY} --activate",
            ),
            cost="免费",
            risk="中：来自可信 IP 的活动不再产生发现，请只填写企业受控出口",
            rollback="删除 IPSet 与 S3 对象",
            params={"regions": regions, "cidrs": cidrs},
        )

    def apply_gd_ipset(self, ctx: Ctx, plan: FixPlan) -> None:
        bucket = ensure_log_bucket(ctx, self.id)
        with ctx.change(
            self.id, "s3:put_object", ctx.home_region, f"{bucket}/{IPSET_KEY}", bucket=bucket, key=IPSET_KEY
        ) as extra:
            extra_v = ctx.client("s3").put_object(
                Bucket=bucket,
                Key=IPSET_KEY,
                Body="\n".join(plan.params["cidrs"]) + "\n",
                ServerSideEncryption="AES256",
                ExpectedBucketOwner=ctx.account_id,
            )
            extra["version_id"] = extra_v.get("VersionId")
        location = f"https://s3.amazonaws.com/{bucket}/{IPSET_KEY}"
        failures: dict[str, str] = {}
        for region in plan.params["regions"]:
            try:
                did = self._detectors(ctx, [region])[region]
                if not did:
                    raise RuntimeError("该区域没有 GuardDuty detector")
                with ctx.change(self.id, "guardduty:create_ip_set", region, IPSET_NAME, detector_id=did) as extra:
                    extra["ip_set_id"] = ctx.client("guardduty", region).create_ip_set(
                        DetectorId=did, Name=IPSET_NAME, Format="TXT", Location=location, Activate=True, Tags=tag_map()
                    )["IpSetId"]
                ctx.ui.ok(f"{region} 已创建")
            except (ClientError, BotoCoreError, RuntimeError) as exc:
                failures[region] = short_err(exc)
                ctx.ui.error(f"{region}: {short_err(exc)}")
        raise_if_failed(failures)

    def plan_gd_org_admin(self, ctx: Ctx, finding: Finding) -> FixPlan:
        acct = ctx.ui.ask(
            "安全工具账号 ID（作为 GuardDuty 委派管理员）",
            validate_account_id,
            default=ctx.input_value("security_account_id"),
        )
        if acct == ctx.account_id:
            ctx.ui.warn("AWS 建议不要把管理账号设为委派管理员，请优先使用独立的安全工具账号")
        ctx.put_state("inputs", "security_account_id", acct)
        return FixPlan(
            title="设置 GuardDuty 委派管理员",
            actions=(
                f"在 {len(ctx.regions)} 个区域将 {acct} 设为 GuardDuty 委派管理员",
                "之后在该账号中重跑本工具，开启“自动启用组织成员”",
            ),
            cli=(f"aws guardduty enable-organization-admin-account --admin-account-id {acct} --region <region>",),
            cost="设置本身免费；成员账号开启 GuardDuty 后按量计费",
            risk="低：不改变成员账号现有配置",
            rollback="aws guardduty disable-organization-admin-account",
            params={"admin": acct},
        )

    def apply_gd_org_admin(self, ctx: Ctx, plan: FixPlan) -> None:
        acct = plan.params["admin"]
        failures: dict[str, str] = {}
        for region in ctx.regions:
            gd = ctx.client("guardduty", region)
            try:
                current = gd.list_organization_admin_accounts().get("AdminAccounts", [])
                if any(a.get("AdminAccountId") == acct for a in current):
                    continue
                with ctx.change(self.id, "guardduty:enable_org_admin", region, acct, admin=acct):
                    gd.enable_organization_admin_account(AdminAccountId=acct)
                ctx.ui.ok(f"{region} 已设置")
            except (ClientError, BotoCoreError) as exc:
                failures[region] = short_err(exc)
                ctx.ui.error(f"{region}: {short_err(exc)}")
        raise_if_failed(failures)

    def plan_gd_auto(self, ctx: Ctx, finding: Finding) -> FixPlan:
        regions = list(dict(finding.evidence)["regions"])
        return FixPlan(
            title="对组织成员自动启用 GuardDuty",
            actions=tuple(f"{r}: AutoEnableOrganizationMembers=ALL（含现有成员账号）" for r in regions),
            cli=(
                "aws guardduty update-organization-configuration --detector-id <id> "
                "--auto-enable-organization-members ALL",
            ),
            cost="组织内所有成员账号开始计费（各自享 30 天试用）",
            risk="低：只读分析",
            rollback="恢复为原配置",
            params={"regions": regions},
        )

    def apply_gd_auto(self, ctx: Ctx, plan: FixPlan) -> None:
        failures: dict[str, str] = {}
        for region in plan.params["regions"]:
            gd = ctx.client("guardduty", region)
            try:
                did = self._detectors(ctx, [region])[region]
                if not did:
                    raise RuntimeError("该区域没有 GuardDuty detector")
                prev = gd.describe_organization_configuration(DetectorId=did).get("AutoEnableOrganizationMembers")
                with ctx.change(self.id, "guardduty:update_org_config", region, did, detector_id=did, previous=prev):
                    gd.update_organization_configuration(DetectorId=did, AutoEnableOrganizationMembers="ALL")
                ctx.ui.ok(f"{region} 已设置")
            except (ClientError, BotoCoreError, RuntimeError) as exc:
                failures[region] = short_err(exc)
                ctx.ui.error(f"{region}: {short_err(exc)}")
        raise_if_failed(failures)


# ═══════════════════════════════════════════════════════════════════════════
# M4A EventBridge + SNS 告警
# ═══════════════════════════════════════════════════════════════════════════
CT_API = "AWS API Call via CloudTrail"
CT_SIGNIN = "AWS Console Sign In via CloudTrail"
GD_TAMPER_EVENTS = [
    "DeleteDetector",
    "UpdateDetector",
    "DisassociateFromMasterAccount",
    "DisassociateFromAdministratorAccount",
    "CreateIPSet",
    "UpdateIPSet",
    "DeleteIPSet",
    "CreateFilter",
    "UpdateFilter",
    "DeleteMembers",
    "DisassociateMembers",
    "StopMonitoringMembers",
    "DisableOrganizationAdminAccount",
    "ArchiveFindings",
]


def build_alert_rules(ctx: Ctx) -> dict[str, tuple[str, dict]]:
    """主区域告警规则：安全事件 + 告警链路自身被篡改。"""
    topic = ctx.arn("sns", ctx.home_region, TOPIC_NAME)
    api = {"detail-type": [CT_API]}
    return {
        f"{PREFIX}-alert-root": (
            "root 登录或 API 调用",
            {
                "source": [{"prefix": "aws."}],
                "detail-type": [CT_SIGNIN, CT_API],
                "detail": {"userIdentity": {"type": ["Root"]}},
            },
        ),
        f"{PREFIX}-alert-trail": (
            "CloudTrail 被关闭或修改",
            {
                "source": ["aws.cloudtrail"],
                **api,
                "detail": {"eventName": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]},
            },
        ),
        f"{PREFIX}-alert-guardduty-change": (
            "GuardDuty 被关闭、修改或添加抑制规则",
            {"source": ["aws.guardduty"], **api, "detail": {"eventName": GD_TAMPER_EVENTS}},
        ),
        f"{PREFIX}-alert-iam": (
            "创建 Access Key / IAM 用户 / 控制台密码",
            {
                "source": ["aws.iam"],
                **api,
                "detail": {"eventName": ["CreateAccessKey", "CreateUser", "CreateLoginProfile"]},
            },
        ),
        f"{PREFIX}-alert-account": (
            "修改账号联系人或开通/关闭区域",
            {
                "source": ["aws.account"],
                **api,
                "detail": {
                    "eventName": [
                        "PutAlternateContact",
                        "DeleteAlternateContact",
                        "PutContactInformation",
                        "EnableRegion",
                        "DisableRegion",
                    ]
                },
            },
        ),
        f"{PREFIX}-alert-guardduty": (
            f"GuardDuty 高危发现（severity ≥ {GD_HIGH_SEVERITY}）",
            {
                "source": ["aws.guardduty"],
                "detail-type": ["GuardDuty Finding"],
                "detail": {"severity": [{"numeric": [">=", GD_HIGH_SEVERITY]}]},
            },
        ),
        f"{PREFIX}-alert-health": ("AWS Health 事件", {"source": ["aws.health"], "detail-type": ["AWS Health Event"]}),
        # ── 告警链路防篡改 ──
        f"{PREFIX}-alert-tamper-rules": (
            "告警规则被修改/禁用/删除",
            {
                "source": ["aws.events"],
                **api,
                "detail": {
                    "eventName": ["PutRule", "DeleteRule", "DisableRule"],
                    "requestParameters": {"name": [{"prefix": f"{PREFIX}-"}]},
                },
            },
        ),
        f"{PREFIX}-alert-tamper-targets": (
            "告警规则目标被修改",
            {
                "source": ["aws.events"],
                **api,
                "detail": {
                    "eventName": ["PutTargets", "RemoveTargets"],
                    "requestParameters": {"rule": [{"prefix": f"{PREFIX}-"}]},
                },
            },
        ),
        f"{PREFIX}-alert-tamper-topic": (
            "告警 SNS topic 被修改/删除",
            {
                "source": ["aws.sns"],
                **api,
                "detail": {
                    "eventName": [
                        "DeleteTopic",
                        "SetTopicAttributes",
                        "AddPermission",
                        "RemovePermission",
                        "Subscribe",
                    ],
                    "requestParameters": {"topicArn": [topic]},
                },
            },
        ),
        f"{PREFIX}-alert-tamper-subscription": (
            "告警订阅被取消或修改",
            {
                "source": ["aws.sns"],
                **api,
                "detail": {
                    "eventName": ["Unsubscribe", "SetSubscriptionAttributes"],
                    "requestParameters": {"subscriptionArn": [{"prefix": f"{topic}:"}]},
                },
            },
        ),
        f"{PREFIX}-alert-tamper-role": (
            "告警转发角色被修改/删除",
            {
                "source": ["aws.iam"],
                **api,
                "detail": {
                    "eventName": [
                        "DeleteRole",
                        "DeleteRolePolicy",
                        "PutRolePolicy",
                        "UpdateAssumeRolePolicy",
                        "AttachRolePolicy",
                        "DetachRolePolicy",
                    ],
                    "requestParameters": {"roleName": [FWD_ROLE_NAME]},
                },
            },
        ),
        f"{PREFIX}-alert-tamper-bucket": (
            "日志桶策略/生命周期/版本控制被修改或删除",
            {
                "source": ["aws.s3"],
                **api,
                "detail": {
                    "eventName": [
                        "DeleteBucket",
                        "DeleteBucketPolicy",
                        "PutBucketPolicy",
                        "PutBucketLifecycle",
                        "DeleteBucketLifecycle",
                        "PutBucketVersioning",
                        "PutBucketAcl",
                    ],
                    "requestParameters": {"bucketName": [log_bucket_name(ctx)]},
                },
            },
        ),
    }


# 各区域转发到主区域的事件源（日志桶、SNS topic 均在主区域，无需转发 aws.s3 / aws.sns）
FORWARD_SOURCES = ["aws.cloudtrail", "aws.guardduty", "aws.iam", "aws.account", "aws.health", "aws.events"]
FORWARD_RULES: dict[str, tuple[str, dict]] = {
    # root 活动中来自 FORWARD_SOURCES 的事件已由 fwd-security 转发，这里排除以免重复告警
    f"{PREFIX}-fwd-root": (
        "转发 root 活动到主区域",
        {
            "source": [{"anything-but": FORWARD_SOURCES}],
            "detail-type": [CT_SIGNIN, CT_API],
            "detail": {"userIdentity": {"type": ["Root"]}},
        },
    ),
    f"{PREFIX}-fwd-security": ("转发安全相关事件到主区域", {"source": FORWARD_SOURCES}),
}


def build_topic_policy(topic_arn: str, ctx: Ctx) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeRules",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic_arn,
                "Condition": {"ArnLike": {"aws:SourceArn": ctx.arn("events", ctx.home_region, f"rule/{PREFIX}-*")}},
            },
            {
                "Sid": "AllowAccountOwner",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:{ctx.partition}:iam::{ctx.account_id}:root"},
                "Action": [
                    "sns:GetTopicAttributes",
                    "sns:SetTopicAttributes",
                    "sns:Subscribe",
                    "sns:Publish",
                    "sns:ListSubscriptionsByTopic",
                    "sns:DeleteTopic",
                    "sns:Receive",
                ],
                "Resource": topic_arn,
            },
        ],
    }


def build_forward_role_policies(ctx: Ctx) -> tuple[dict, dict]:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": ctx.account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:{ctx.partition}:events:*:{ctx.account_id}:rule/{PREFIX}-fwd-*"},
                },
            }
        ],
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "events:PutEvents",
                "Resource": ctx.arn("events", ctx.home_region, "event-bus/default"),
            }
        ],
    }
    return trust, policy


def rule_ok(events, name: str, pattern: dict, target_arn: str) -> bool:
    """规则存在、已启用、事件模式未被改动、且目标指向预期资源。"""
    rule = exists_or_none(lambda: events.describe_rule(Name=name))
    if not rule or rule.get("State") != "ENABLED":
        return False
    try:
        if json.loads(rule.get("EventPattern") or "{}") != pattern:
            return False
    except json.JSONDecodeError:
        return False
    targets = events.list_targets_by_rule(Rule=name).get("Targets", [])
    return any(t.get("Arn") == target_arn for t in targets)


class AlertsModule(Module):
    id, name, practice = "M4A", "EventBridge + SNS 实时告警", "实践 2/4"

    def topic_arn(self, ctx: Ctx) -> str:
        return ctx.arn("sns", ctx.home_region, TOPIC_NAME)

    def home_bus(self, ctx: Ctx) -> str:
        return ctx.arn("events", ctx.home_region, "event-bus/default")

    def forward_regions(self, ctx: Ctx) -> list[str]:
        return [r for r in alert_regions(ctx) if r != ctx.home_region]

    def _rule_gaps(self, ctx: Ctx) -> tuple[list[str], dict[str, list[str]], dict[str, str]]:
        topic, events = self.topic_arn(ctx), ctx.client("events")
        home_bad = [n for n, (_, pat) in build_alert_rules(ctx).items() if not rule_ok(events, n, pat, topic)]
        bus = self.home_bus(ctx)
        fwd, errors = for_regions(
            ctx,
            lambda r: [n for n, (_, pat) in FORWARD_RULES.items() if not rule_ok(ctx.client("events", r), n, pat, bus)],
            self.forward_regions(ctx),
        )
        return home_bad, {r: v for r, v in fwd.items() if v}, errors

    def check(self, ctx: Ctx) -> list[Finding]:
        sns, topic = ctx.client("sns"), self.topic_arn(ctx)
        topic_ok = exists_or_none(lambda: sns.get_topic_attributes(TopicArn=topic)) is not None
        out = [
            self.f(
                "topic",
                f"告警 SNS topic {TOPIC_NAME}",
                PASS if topic_ok else FAIL,
                ctx.home_region,
                fix=None if topic_ok else "alerts",
            )
        ]
        if topic_ok:
            out.append(self._sub_finding(sns, topic))
        home_bad, fwd_bad, errors = self._rule_gaps(ctx)
        bad = bool(home_bad or fwd_bad)
        n_rules = len(build_alert_rules(ctx))
        detail = (
            f"主区域 {len(home_bad)} 条规则缺失或被改动，{len(fwd_bad)} 个区域转发规则缺失或被改动"
            if bad
            else f"{n_rules} 条告警规则 + {len(self.forward_regions(ctx))} 个区域转发"
        )
        if errors:
            detail += f"；检查失败: {', '.join(errors)}"
        out.append(
            self.f(
                "rules",
                "关键事件与告警链路防篡改规则",
                FAIL if bad else (ERROR if errors else PASS),
                detail,
                fix="alerts" if bad else None,
                evidence=[("home", home_bad), ("forward", sorted(fwd_bad))],
            )
        )
        trails = ctx.cached("trails", lambda: survey_trails(ctx))
        if not any(is_good_trail(t) for t in trails):
            out.append(
                self.f(
                    "prereq",
                    "告警前提：存在正在记录的 Trail",
                    WARN,
                    "基于 CloudTrail 的告警需要至少一条正在记录的 Trail",
                    guidance="请先完成 M3",
                )
            )
        return out

    def _sub_finding(self, sns, topic: str) -> Finding:
        subs = sns.list_subscriptions_by_topic(TopicArn=topic).get("Subscriptions", [])
        confirmed = [s for s in subs if s.get("SubscriptionArn", "").startswith("arn:")]
        endpoints = ", ".join(
            f"{s.get('Protocol')}:{mask_email(s.get('Endpoint', ''))}"
            if s.get("Protocol") == "email"
            else f"{s.get('Protocol')}:{s.get('Endpoint', '')[:40]}"
            for s in confirmed
        )
        if confirmed:
            return self.f(
                "sub",
                "告警已有确认的订阅",
                PASS,
                f"{len(confirmed)} 个已确认: {endpoints}",
                guidance="请人工确认以上订阅端点均为企业受控的值班地址",
            )
        pending = len(subs) - len(confirmed)
        detail = f"{pending} 个订阅等待邮件确认" if pending else "无订阅"
        return self.f(
            "sub",
            "告警已有确认的订阅",
            WARN,
            detail,
            fix="alerts_sub",
            guidance="请收件人点击 AWS Notification 邮件中的 Confirm subscription 链接",
        )

    def _ask_emails(self, ctx: Ctx) -> list[str]:
        default = ",".join(ctx.input_value("alert_emails", [])) or None
        raw = ctx.ui.ask("告警接收邮箱（值班群组邮箱，逗号分隔）", validate_emails, default=default)
        emails = sorted({e.strip() for e in raw.split(",") if e.strip()})
        ctx.put_state("inputs", "alert_emails", emails)
        return emails

    def plan_alerts(self, ctx: Ctx, finding: Finding) -> FixPlan:
        sns, topic = ctx.client("sns"), self.topic_arn(ctx)
        has_subs = exists_or_none(lambda: sns.list_subscriptions_by_topic(TopicArn=topic).get("Subscriptions"))
        emails = [] if has_subs else self._ask_emails(ctx)
        others = self.forward_regions(ctx)
        actions = [f"{ctx.home_region}: 创建/校验 SNS topic {TOPIC_NAME}（仅允许本工具的 EventBridge 规则发布）"]
        actions += [f"订阅邮箱 {e}（需收件人点击确认）" for e in emails]
        actions += [f"{ctx.home_region}: 规则 {n} — {desc}" for n, (desc, _) in build_alert_rules(ctx).items()]
        if others:
            actions += [
                f"创建/校验 IAM 角色 {FWD_ROLE_NAME}（仅允许本工具转发规则 PutEvents 到主区域 default bus）",
                f"{len(others)} 个区域: 创建/修复转发规则 {', '.join(FORWARD_RULES)} → {ctx.home_region}",
            ]
        actions.append("说明：配置过程中本工具自身的操作可能触发几条防篡改告警，属正常现象")
        return FixPlan(
            title="配置实时告警",
            actions=tuple(actions),
            cli=(
                f"aws sns create-topic --name {TOPIC_NAME}",
                f"aws sns subscribe --topic-arn {topic} --protocol email --notification-endpoint <email>",
                "aws events put-rule --name <rule> --event-pattern <json>",
                "aws events put-targets --rule <rule> --targets Id=sns,Arn=<topic>",
            ),
            cost="SNS 邮件每月前 1000 封免费；AWS 服务事件进入默认总线免费；跨区域转发约 $1/百万事件",
            risk="低：仅新增或修复本工具的资源",
            rollback="删除规则、topic、IAM 角色",
            params={"emails": emails},
        )

    def apply_alerts(self, ctx: Ctx, plan: FixPlan) -> None:
        topic = self._ensure_topic(ctx)
        self._subscribe(ctx, topic, plan.params.get("emails", []))
        events = ctx.client("events")
        for name, (desc, pattern) in build_alert_rules(ctx).items():
            if not rule_ok(events, name, pattern, topic):
                self._put_rule(ctx, ctx.home_region, name, desc, pattern, {"Id": "sns", "Arn": topic})
        others = self.forward_regions(ctx)
        failures: dict[str, str] = {}
        if others:
            role, bus = self._ensure_forward_role(ctx), self.home_bus(ctx)
            for region in others:
                try:
                    for name, (desc, pattern) in FORWARD_RULES.items():
                        if not rule_ok(ctx.client("events", region), name, pattern, bus):
                            self._put_rule(
                                ctx, region, name, desc, pattern, {"Id": "home-bus", "Arn": bus, "RoleArn": role}
                            )
                except (ClientError, BotoCoreError, RuntimeError) as exc:
                    failures[region] = short_err(exc)
                    ctx.ui.error(f"{region}: {short_err(exc)}")
        raise_if_failed(failures)
        ctx.ui.ok("告警规则已就绪")
        self._offer_test(ctx, topic)

    def plan_alerts_sub(self, ctx: Ctx, finding: Finding) -> FixPlan:
        emails = self._ask_emails(ctx)
        return FixPlan(
            title="添加告警邮件订阅",
            actions=tuple(f"订阅 {e}" for e in emails),
            cli=(
                f"aws sns subscribe --topic-arn {self.topic_arn(ctx)} --protocol email --notification-endpoint <email>",
            ),
            cost="免费",
            risk="低",
            rollback="删除订阅",
            params={"emails": emails},
        )

    def apply_alerts_sub(self, ctx: Ctx, plan: FixPlan) -> None:
        self._subscribe(ctx, self.topic_arn(ctx), plan.params["emails"])

    def _ensure_topic(self, ctx: Ctx) -> str:
        sns, topic = ctx.client("sns"), self.topic_arn(ctx)
        policy = json.dumps(build_topic_policy(topic, ctx))
        if exists_or_none(lambda: sns.get_topic_attributes(TopicArn=topic)) is None:
            with ctx.change(self.id, "sns:create_topic", ctx.home_region, topic, topic_arn=topic):
                sns.create_topic(Name=TOPIC_NAME, Tags=tag_list(), Attributes={"Policy": policy})
        else:
            if not self._owned_topic(sns, topic):
                raise RuntimeError(f"SNS topic {TOPIC_NAME} 已存在但不是本工具创建的，已停止")
            sns.set_topic_attributes(TopicArn=topic, AttributeName="Policy", AttributeValue=policy)
        return topic

    @staticmethod
    def _owned_topic(sns, topic: str) -> bool:
        tags = sns.list_tags_for_resource(ResourceArn=topic).get("Tags", [])
        return any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE for t in tags)

    def _subscribe(self, ctx: Ctx, topic: str, emails: list[str]) -> None:
        sns = ctx.client("sns")
        for email in emails:
            with ctx.change(self.id, "sns:subscribe", ctx.home_region, mask_email(email)) as extra:
                extra["subscription_arn"] = sns.subscribe(
                    TopicArn=topic, Protocol="email", Endpoint=email, ReturnSubscriptionArn=True
                ).get("SubscriptionArn")
        if emails:
            ctx.ui.warn("请收件人在邮箱中点击 Confirm subscription，确认前收不到告警")

    def _put_rule(self, ctx: Ctx, region: str, name: str, desc: str, pattern: dict, target: dict) -> None:
        events = ctx.client("events", region)
        existing = exists_or_none(lambda: events.describe_rule(Name=name))
        if existing and not owned_rule(events, existing["Arn"]):
            raise RuntimeError(f"{region} 的规则 {name} 已存在但不是本工具创建的，已停止")
        with ctx.change(
            self.id, "events:put_rule", region, name, name=name, target_ids=[target["Id"]], existed=bool(existing)
        ):
            events.put_rule(
                Name=name,
                EventPattern=json.dumps(pattern),
                State="ENABLED",
                Description=f"[{TOOL}] {desc}",
                Tags=tag_list(),
            )
            resp = events.put_targets(Rule=name, Targets=[target])
            if resp.get("FailedEntryCount"):
                raise RuntimeError(f"{name} 设置目标失败: {resp.get('FailedEntries')}")

    def _ensure_forward_role(self, ctx: Ctx) -> str:
        iam = ctx.client("iam")
        trust, policy = build_forward_role_policies(ctx)
        role = exists_or_none(lambda: iam.get_role(RoleName=FWD_ROLE_NAME))
        if role:
            tags = iam.list_role_tags(RoleName=FWD_ROLE_NAME).get("Tags", [])
            if not any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE for t in tags):
                raise RuntimeError(f"IAM 角色 {FWD_ROLE_NAME} 已存在但不是本工具创建的，已停止")
            # 修复可能被改动或未写全的策略（例如上次在 create_role 与 put_role_policy 之间中断）
            iam.update_assume_role_policy(RoleName=FWD_ROLE_NAME, PolicyDocument=json.dumps(trust))
            iam.put_role_policy(
                RoleName=FWD_ROLE_NAME, PolicyName="put-events-home-bus", PolicyDocument=json.dumps(policy)
            )
            return role["Role"]["Arn"]
        with ctx.change(self.id, "iam:create_role", "global", FWD_ROLE_NAME, role=FWD_ROLE_NAME):
            arn = iam.create_role(
                RoleName=FWD_ROLE_NAME,
                AssumeRolePolicyDocument=json.dumps(trust),
                Description=f"[{TOOL}] forward security events to home region",
                Tags=tag_list(),
            )["Role"]["Arn"]
            iam.put_role_policy(
                RoleName=FWD_ROLE_NAME, PolicyName="put-events-home-bus", PolicyDocument=json.dumps(policy)
            )
        time.sleep(ROLE_PROPAGATION_SECONDS)
        return arn

    def _offer_test(self, ctx: Ctx, topic: str) -> None:
        if ctx.ui.confirm("发送一条测试消息到告警 topic？", default=False):
            ctx.client("sns").publish(
                TopicArn=topic,
                Subject=f"[{PREFIX}] 告警通道测试",
                Message=f"账号 {ctx.account_id} 的安全告警通道测试消息（{iso_now()}）",
            )
            ctx.ui.ok("已发送；如未收到请检查订阅是否已确认、是否进入垃圾邮件")
        ctx.ui.info(
            "验收建议：用 root 登录一次控制台，确认值班人员 5 分钟内收到告警；并定期重跑 --check-only 校验告警链路完整"
        )


def owned_rule(events, rule_arn: str) -> bool:
    tags = events.list_tags_for_resource(ResourceARN=rule_arn).get("Tags", [])
    return any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE for t in tags)


# ═══════════════════════════════════════════════════════════════════════════
# M4S Security Hub CSPM + AWS Config
# ═══════════════════════════════════════════════════════════════════════════
FSBP_FRAGMENT = "aws-foundational-security-best-practices"


class SecurityHubModule(Module):
    id, name, practice = "M4S", "Security Hub CSPM 合规汇总（可选）", "实践 4"

    def _hub_state(self, ctx: Ctx) -> tuple[bool, bool]:
        sh = ctx.client("securityhub")
        try:
            sh.describe_hub()
        except ClientError as exc:
            if err_code(exc) in ("InvalidAccessException", "ResourceNotFoundException"):
                return False, False
            raise
        subs = sh.get_enabled_standards().get("StandardsSubscriptions", [])
        return True, any(FSBP_FRAGMENT in s.get("StandardsArn", "") for s in subs)

    def check(self, ctx: Ctx) -> list[Finding]:
        enabled, fsbp = self._hub_state(ctx)
        cfg = ctx.client("config")
        statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        recording = any(s.get("recording") for s in statuses)
        hub_ok = enabled and fsbp
        detail = "已启用 + FSBP" if hub_ok else ("已启用，未订阅 FSBP 标准" if enabled else "未启用")
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        customer = bool(recorders) and recorders[0]["name"] != CONFIG_RECORDER
        cfg_fix = None if recording or customer else "securityhub"
        cfg_detail = ctx.home_region + (
            f"（客户记录器 {recorders[0]['name']} 未在记录，工具不修改）" if customer and not recording else ""
        )
        return [
            self.f(
                "hub",
                "Security Hub CSPM 已启用 AWS FSBP 标准",
                PASS if hub_ok else WARN,
                f"{ctx.home_region}: {detail}",
                fix=None if hub_ok else "securityhub",
                guidance=G_SH_REGIONS,
            ),
            self.f(
                "config",
                "AWS Config 正在记录（Security Hub 检查依赖）",
                PASS if recording else WARN,
                cfg_detail,
                fix=cfg_fix,
                guidance="请检查现有 Config 记录器与投递通道配置" if customer and not recording else "",
            ),
        ]

    def plan_securityhub(self, ctx: Ctx, finding: Finding) -> FixPlan:
        bucket = log_bucket_name(ctx)
        return FixPlan(
            title=f"开启 Security Hub CSPM + AWS Config（{ctx.home_region}）",
            actions=(
                "如无 Config 记录器：创建 AWSServiceRoleForConfig、记录器（DAILY 频率）、投递通道 → "
                f"s3://{bucket}/config/",
                "启用 Security Hub CSPM（不启用默认标准）",
                "订阅 AWS Foundational Security Best Practices 标准",
            ),
            cli=(
                "aws configservice put-configuration-recorder ... --recording-mode recordingFrequency=DAILY",
                "aws securityhub enable-security-hub --no-enable-default-standards",
                "aws securityhub batch-enable-standards --standards-subscription-requests StandardsArn=<FSBP>",
            ),
            cost="⚠ 持续收费：Security Hub 按安全检查次数计费，Config 按记录的配置项计费（DAILY 已降成本）；"
            "均有 30 天免费试用。小型账号通常每月数十美元，资源多的账号会更高，请先评估",
            risk="低：只读检查",
            rollback="停用 Security Hub；停止并删除本工具创建的 Config 记录器与投递通道",
        )

    def apply_securityhub(self, ctx: Ctx, plan: FixPlan) -> None:
        bucket = ensure_log_bucket(ctx, self.id)
        self._ensure_config(ctx, bucket)
        sh = ctx.client("securityhub")
        enabled, fsbp = self._hub_state(ctx)
        if not enabled:
            with ctx.change(self.id, "securityhub:enable", ctx.home_region, "hub"):
                sh.enable_security_hub(
                    EnableDefaultStandards=False, ControlFindingGenerator="SECURITY_CONTROL", Tags=tag_map()
                )
        if not fsbp:
            arn = f"arn:{ctx.partition}:securityhub:{ctx.home_region}::standards/{FSBP_FRAGMENT}/v/1.0.0"
            with ctx.change(self.id, "securityhub:enable_standard", ctx.home_region, arn):
                sh.batch_enable_standards(StandardsSubscriptionRequests=[{"StandardsArn": arn}])

    def _ensure_config(self, ctx: Ctx, bucket: str) -> None:
        cfg = ctx.client("config")
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if recorders and recorders[0]["name"] != CONFIG_RECORDER:
            ctx.ui.warn(f"已存在客户自己的 Config 记录器 {recorders[0]['name']}，工具不修改（不启动、不加投递通道）")
            return
        if recorders:
            name = CONFIG_RECORDER
        else:
            role_arn = self._ensure_config_slr(ctx)
            name = CONFIG_RECORDER
            with ctx.change(self.id, "config:put_recorder", ctx.home_region, name, name=name):
                cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": name,
                        "roleARN": role_arn,
                        "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
                        "recordingMode": {"recordingFrequency": "DAILY"},
                    }
                )
        if not cfg.describe_delivery_channels().get("DeliveryChannels"):
            with ctx.change(
                self.id,
                "config:put_delivery_channel",
                ctx.home_region,
                CONFIG_CHANNEL,
                name=CONFIG_CHANNEL,
                recorder=name,
            ):
                cfg.put_delivery_channel(
                    DeliveryChannel={"name": CONFIG_CHANNEL, "s3BucketName": bucket, "s3KeyPrefix": "config"}
                )
        status = cfg.describe_configuration_recorder_status(ConfigurationRecorderNames=[name])
        if not any(s.get("recording") for s in status.get("ConfigurationRecordersStatus", [])):
            with ctx.change(self.id, "config:start_recorder", ctx.home_region, name, name=name):
                cfg.start_configuration_recorder(ConfigurationRecorderName=name)

    def _ensure_config_slr(self, ctx: Ctx) -> str:
        try:
            with ctx.change(self.id, "iam:create_service_linked_role", "global", "AWSServiceRoleForConfig"):
                ctx.client("iam").create_service_linked_role(AWSServiceName="config.amazonaws.com")
        except ClientError as exc:
            if err_code(exc) != "InvalidInput":  # 已存在
                raise
        return (
            f"arn:{ctx.partition}:iam::{ctx.account_id}:role/aws-service-role/"
            "config.amazonaws.com/AWSServiceRoleForConfig"
        )


# ═══════════════════════════════════════════════════════════════════════════
# M5 IAM Identity Center   M6 长期访问密钥   M7 访问来源控制
# ═══════════════════════════════════════════════════════════════════════════


class IdentityCenterModule(Module):
    id, name, practice = "M5", "IAM Identity Center", "实践 5"

    def check(self, ctx: Ctx) -> list[Finding]:
        found, errors = for_regions(ctx, lambda r: ctx.client("sso-admin", r).list_instances().get("Instances", []))
        regions = sorted(r for r, v in found.items() if v)
        denied = [r for r, e in errors.items() if e.startswith("权限不足")]
        if regions:
            idc = self.f("instance", "已启用 IAM Identity Center", PASS, ", ".join(regions))
        elif ctx.org_form == "member":
            idc = self.f(
                "instance", "已启用 IAM Identity Center", MANUAL, "成员账号看不到组织级实例", guidance=G_IDC_MEMBER
            )
        elif denied and not found:
            idc = self.f("instance", "已启用 IAM Identity Center", ERROR, f"权限不足: {', '.join(denied[:5])}")
        else:
            idc = self.f("instance", "已启用 IAM Identity Center", FAIL, "未发现实例", guidance=G_IDC)
        users = [r for r in ctx.cred_report() if r.get("user") != ROOT_USER and r.get("password_enabled") == "true"]
        no_mfa = [u["user"] for u in users if u.get("mfa_active") != "true"]
        names = [u["user"] for u in users]
        return [
            idc,
            self.f(
                "console_users",
                "人员不使用 IAM 用户登录控制台（破窗账号除外）",
                WARN if users else PASS,
                f"{len(users)} 个: {', '.join(names[:10])}" if users else "",
                guidance=G_CONSOLE_USERS if users else "",
                evidence=[("users", names)],
            ),
            self.f(
                "console_mfa",
                "IAM 控制台用户均启用 MFA",
                FAIL if no_mfa else PASS,
                ", ".join(no_mfa[:10]),
                guidance=G_CONSOLE_MFA if no_mfa else "",
                evidence=[("users", no_mfa)],
            ),
        ]


def analyze_access_keys(rows: list[dict], now: dt.datetime, days: int = KEY_UNUSED_DAYS) -> tuple[list, list, int]:
    """返回 (长期未使用, 长期未轮换, 活跃 Key 总数)。"""
    unused, stale, active = [], [], 0
    for row in rows:
        if row.get("user") == ROOT_USER:
            continue
        for n in (1, 2):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            active += 1
            rotated = parse_ts(row.get(f"access_key_{n}_last_rotated"))
            used = parse_ts(row.get(f"access_key_{n}_last_used_date"))
            ref = used or rotated
            label = f"{row['user']}#key{n}"
            if ref and days_ago(ref, now) >= days:
                unused.append(f"{label}（{'从未使用' if not used else f'{days_ago(used, now)} 天未用'}）")
            if rotated and days_ago(rotated, now) >= days:
                stale.append(f"{label}（{days_ago(rotated, now)} 天）")
    return unused, stale, active


class AccessKeyModule(Module):
    id, name, practice = "M6", "长期访问密钥", "实践 6"

    def check(self, ctx: Ctx) -> list[Finding]:
        unused, stale, active = analyze_access_keys(ctx.cred_report(), now_utc())
        return [
            self.f(
                "count",
                "IAM 用户活跃长期 Access Key 数量",
                PASS if active == 0 else WARN,
                f"{active} 个",
                guidance="" if active == 0 else "程序访问改用 IAM 角色与临时凭证，逐月降低长期 Key 数量",
            ),
            self.f(
                "unused",
                f"无超过 {KEY_UNUSED_DAYS} 天未使用的 Access Key",
                FAIL if unused else PASS,
                "; ".join(unused[:10]),
                guidance=G_KEYS_UNUSED if unused else "",
                evidence=[("keys", unused)],
            ),
            self.f(
                "rotation",
                f"活跃 Access Key {KEY_UNUSED_DAYS} 天内轮换",
                WARN if stale else PASS,
                "; ".join(stale[:10]),
                guidance=G_KEYS_ROTATE if stale else "",
                evidence=[("keys", stale)],
            ),
        ]


class NetworkModule(Module):
    id, name, practice = "M7", "访问来源控制", "实践 7"

    def check(self, ctx: Ctx) -> list[Finding]:
        return [
            self.f(
                "source",
                "已在身份源或 AWS 侧限制访问来源，并保留破窗账号",
                MANUAL,
                "需结合企业网络与身份源评估",
                guidance=G_NETWORK,
            )
        ]


# ═══════════════════════════════════════════════════════════════════════════
# M8 SCP 护栏   M9 集中式 root 管理   M10 Access Analyzer
# ═══════════════════════════════════════════════════════════════════════════
GUARDRAILS = (
    ("cloudtrail", "SCP：禁止关闭/删除 CloudTrail", ("cloudtrail:StopLogging", "cloudtrail:DeleteTrail"), None),
    ("guardduty", "SCP：禁止关闭 GuardDuty", ("guardduty:DeleteDetector",), None),
    ("leave_org", "SCP：禁止成员账号退出组织", ("organizations:LeaveOrganization",), None),
    ("region", "SCP：限制可用区域", (), "aws:RequestedRegion"),
    ("iam_key", "SCP：禁止为 IAM 用户创建 Access Key", ("iam:CreateAccessKey",), None),
)


def scp_covers(doc: dict, actions: tuple[str, ...], cond_key: str | None) -> str | None:
    """返回 full（无条件拒绝）/ conditional（拒绝语句带 Condition，仅部分覆盖）/ None。"""
    best = None
    for stmt in as_list(doc.get("Statement")):
        if stmt.get("Effect") != "Deny":
            continue
        if cond_key:
            if cond_key.lower() in json.dumps(stmt.get("Condition", {})).lower():
                return "full"
            continue
        patterns = [p.lower() for p in as_list(stmt.get("Action"))]
        if patterns and all(any(fnmatch.fnmatchcase(a.lower(), p) for p in patterns) for a in actions):
            if not stmt.get("Condition"):
                return "full"
            best = "conditional"
    return best


def not_mgmt_reason(ctx: Ctx) -> str | None:
    if ctx.is_mgmt:
        return None
    return {"standalone": "独立账号，未使用 Organizations", "member": "成员账号，请在管理账号运行"}.get(
        ctx.org_form, "无法识别 Organizations 状态"
    ) + "（仅适用于管理账号）"


class ScpModule(Module):
    id, name, practice = "M8", "多账号结构与 SCP 护栏", "实践 8"

    def not_applicable(self, ctx: Ctx) -> str | None:
        return not_mgmt_reason(ctx)

    def check(self, ctx: Ctx) -> list[Finding]:
        org = ctx.client("organizations")
        out = [
            self.f(
                "features",
                "组织启用“所有功能”",
                PASS if ctx.feature_set == "ALL" else FAIL,
                ctx.feature_set or "",
                guidance="" if ctx.feature_set == "ALL" else G_SCP_FEATURES,
            )
        ]
        root = org.list_roots()["Roots"][0]
        enabled = any(
            p["Type"] == "SERVICE_CONTROL_POLICY" and p["Status"] == "ENABLED" for p in root.get("PolicyTypes", [])
        )
        out.append(
            self.f(
                "scp",
                "SCP 策略类型已启用",
                PASS if enabled else FAIL,
                root["Id"],
                guidance="" if enabled else G_SCP_ENABLE,
            )
        )
        if enabled:
            out += self._guardrails(org)
        count = sum(len(p.get("Accounts", [])) for p in org.get_paginator("list_accounts").paginate())
        out.append(
            self.f(
                "structure", "生产/测试/日志/安全分账号", MANUAL, f"组织共 {count} 个账号", guidance=G_ACCOUNT_STRUCT
            )
        )
        return out

    def _guardrails(self, org) -> list[Finding]:
        policies = []
        for page in org.get_paginator("list_policies").paginate(Filter="SERVICE_CONTROL_POLICY"):
            for p in page.get("Policies", []):
                if p.get("AwsManaged"):
                    continue
                content = json.loads(org.describe_policy(PolicyId=p["Id"])["Policy"]["Content"])
                targets = {t.get("Type") for t in org.list_targets_for_policy(PolicyId=p["Id"]).get("Targets", [])}
                policies.append((p["Name"], content, targets))
        return [self._guardrail(policies, *g) for g in GUARDRAILS]

    def _guardrail(self, policies: list, key: str, title: str, actions: tuple, cond: str | None) -> Finding:
        guide = G_SCP_TEMPLATE.format(sample=SCP_SAMPLES[key])
        hits = [(name, scp_covers(doc, actions, cond), targets) for name, doc, targets in policies]
        hits = [h for h in hits if h[1]]
        at_root = [n for n, cov, t in hits if cov == "full" and "ROOT" in t]
        if at_root:
            return self.f(key, title, PASS, f"已挂载到组织根: {', '.join(at_root)}")
        partial = [
            f"{n}（{'带条件' if cov == 'conditional' else ''}{'仅部分 OU/账号' if t else '未挂载'}）"
            for n, cov, t in hits
        ]
        if partial:
            return self.f(
                key,
                title,
                WARN,
                "; ".join(partial),
                guidance="护栏仅部分生效（带 Condition 或未挂载到组织根），请确认覆盖范围是否符合预期。\n" + guide,
            )
        return self.f(key, title, FAIL, "未发现对应 SCP", guidance=guide)


class RootMgmtModule(Module):
    id, name, practice = "M9", "集中式 root 访问管理", "实践 9"

    def not_applicable(self, ctx: Ctx) -> str | None:
        return not_mgmt_reason(ctx)

    def _features(self, ctx: Ctx) -> list[str]:
        try:
            return ctx.client("iam").list_organizations_features().get("EnabledFeatures", [])
        except ClientError as exc:
            if err_code(exc) in ACCESS_DENIED:
                raise
            return []

    def check(self, ctx: Ctx) -> list[Finding]:
        feats = self._features(ctx)
        fixable = ctx.feature_set == "ALL"
        guide = "" if fixable else G_SCP_FEATURES
        out = []
        for key, feat, title in (
            ("creds", "RootCredentialsManagement", "集中管理成员账号 root 凭证"),
            ("sessions", "RootSessions", "允许特权 root 会话（短期 root 任务）"),
        ):
            ok = feat in feats
            out.append(
                self.f(
                    key,
                    title,
                    PASS if ok else FAIL,
                    "" if ok else "未启用",
                    fix=None if ok or not fixable else "root_mgmt",
                    guidance="" if ok else guide,
                )
            )
        out.append(
            self.f(
                "member_root",
                "成员账号无可用 root 登录凭证",
                MANUAL,
                "v1 不自动删除成员 root 凭证",
                guidance=G_ROOT_MGMT_MEMBER,
            )
        )
        return out

    def plan_root_mgmt(self, ctx: Ctx, finding: Finding) -> FixPlan:
        return FixPlan(
            title="启用集中式 root 访问管理",
            actions=(
                "启用 IAM 对 Organizations 的可信访问（iam.amazonaws.com）",
                "启用 RootCredentialsManagement 与 RootSessions",
                "之后组织内新建账号默认无 root 凭证；已有成员账号 root 凭证不会被自动删除",
            ),
            cli=(
                "aws organizations enable-aws-service-access --service-principal iam.amazonaws.com",
                "aws iam enable-organizations-root-credentials-management",
                "aws iam enable-organizations-root-sessions",
            ),
            cost="免费",
            risk="低：仅开启管理能力，不删除任何凭证",
            rollback="aws iam disable-organizations-root-credentials-management / disable-organizations-root-sessions",
        )

    def apply_root_mgmt(self, ctx: Ctx, plan: FixPlan) -> None:
        ensure_service_access(ctx, "iam.amazonaws.com", self.id)
        iam, feats = ctx.client("iam"), self._features(ctx)
        if "RootCredentialsManagement" not in feats:
            with ctx.change(self.id, "iam:enable_root_credentials_management", "global", "org"):
                iam.enable_organizations_root_credentials_management()
        if "RootSessions" not in feats:
            with ctx.change(self.id, "iam:enable_root_sessions", "global", "org"):
                iam.enable_organizations_root_sessions()


class AnalyzerModule(Module):
    id, name, practice = "M10", "IAM Access Analyzer 与定期审计", "实践 10"

    def _analyzers(self, ctx: Ctx, region: str) -> list[dict]:
        aa = ctx.client("accessanalyzer", region)
        out = []
        for page in aa.get_paginator("list_analyzers").paginate():
            out += [a for a in page.get("analyzers", []) if a.get("status") in ("ACTIVE", "CREATING")]
        return out

    def check(self, ctx: Ctx) -> list[Finding]:
        found, errors = for_regions(ctx, lambda r: [a["type"] for a in self._analyzers(ctx, r)])
        missing = sorted(r for r, types in found.items() if not {"ACCOUNT", "ORGANIZATION"} & set(types))
        detail = f"未创建: {', '.join(missing)}" if missing else f"{len(found)} 个区域已创建"
        if errors:
            detail += f"；检查失败: {', '.join(errors)}"
        home_types = set(found.get(ctx.home_region, []))
        unused_ok = bool({"ACCOUNT_UNUSED_ACCESS", "ORGANIZATION_UNUSED_ACCESS"} & home_types)
        status = FAIL if missing else (ERROR if errors and not found else WARN if errors else PASS)
        return [
            self.f(
                "external",
                "所有区域已创建外部访问分析器",
                status,
                detail,
                fix="analyzer" if missing else None,
                evidence=[("regions", missing)],
            ),
            self.f(
                "unused",
                "已创建未使用访问分析器（可选，收费）",
                PASS if unused_ok else WARN,
                ctx.home_region,
                fix=None if unused_ok else "analyzer_unused",
            ),
            self.f("review", "定期审计与应急演练机制", MANUAL, "", guidance=G_REVIEW),
        ]

    def _type(self, ctx: Ctx, unused: bool) -> str:
        scope = "ORGANIZATION" if ctx.is_mgmt else "ACCOUNT"
        return f"{scope}_UNUSED_ACCESS" if unused else scope

    def plan_analyzer(self, ctx: Ctx, finding: Finding) -> FixPlan:
        regions = list(dict(finding.evidence)["regions"])
        atype = self._type(ctx, False)
        return FixPlan(
            title="创建外部访问分析器",
            actions=tuple(f"{r}: 创建 {ANALYZER_NAME}（{atype}）" for r in regions),
            cli=(f"aws accessanalyzer create-analyzer --analyzer-name {ANALYZER_NAME} --type {atype} --region <r>",),
            cost="外部访问分析免费",
            risk="低：只读分析",
            rollback="删除分析器",
            params={"regions": regions, "type": atype},
        )

    def apply_analyzer(self, ctx: Ctx, plan: FixPlan) -> None:
        failures: dict[str, str] = {}
        for region in plan.params["regions"]:
            try:
                with ctx.change(self.id, "accessanalyzer:create_analyzer", region, ANALYZER_NAME, name=ANALYZER_NAME):
                    ctx.client("accessanalyzer", region).create_analyzer(
                        analyzerName=ANALYZER_NAME, type=plan.params["type"], tags=tag_map()
                    )
                ctx.ui.ok(f"{region} 已创建")
            except (ClientError, BotoCoreError) as exc:
                failures[region] = short_err(exc)
                ctx.ui.error(f"{region}: {short_err(exc)}")
        raise_if_failed(failures)

    def plan_analyzer_unused(self, ctx: Ctx, finding: Finding) -> FixPlan:
        atype = self._type(ctx, True)
        return FixPlan(
            title="创建未使用访问分析器",
            actions=(f"{ctx.home_region}: 创建 {UNUSED_ANALYZER_NAME}（{atype}，{KEY_UNUSED_DAYS} 天阈值）",),
            cli=(
                f"aws accessanalyzer create-analyzer --analyzer-name {UNUSED_ANALYZER_NAME} --type {atype} "
                f"--configuration unusedAccess={{unusedAccessAge={KEY_UNUSED_DAYS}}}",
            ),
            cost="⚠ 按每月分析的 IAM 角色/用户数量计费",
            risk="低：只读分析",
            rollback="删除分析器",
            params={"type": atype},
        )

    def apply_analyzer_unused(self, ctx: Ctx, plan: FixPlan) -> None:
        with ctx.change(
            self.id, "accessanalyzer:create_analyzer", ctx.home_region, UNUSED_ANALYZER_NAME, name=UNUSED_ANALYZER_NAME
        ):
            ctx.client("accessanalyzer").create_analyzer(
                analyzerName=UNUSED_ANALYZER_NAME,
                type=plan.params["type"],
                tags=tag_map(),
                configuration={"unusedAccess": {"unusedAccessAge": KEY_UNUSED_DAYS}},
            )


MODULES: tuple[Module, ...] = (
    RootModule(),
    ContactsModule(),
    TrailModule(),
    GuardDutyModule(),
    AlertsModule(),
    SecurityHubModule(),
    IdentityCenterModule(),
    AccessKeyModule(),
    NetworkModule(),
    ScpModule(),
    RootMgmtModule(),
    AnalyzerModule(),
)
MODULE_BY_ID = {m.id: m for m in MODULES}

# ═══════════════════════════════════════════════════════════════════════════
# Triage：疑似泄露排查（只读）
# ═══════════════════════════════════════════════════════════════════════════
SENSITIVE_GLOBAL_EVENTS = (
    "CreateUser",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AttachUserPolicy",
    "PutUserPolicy",
    "AttachRolePolicy",
    "UpdateAssumeRolePolicy",
    "DeactivateMFADevice",
    "PutAlternateContact",
)
SENSITIVE_REGIONAL_EVENTS = ("StopLogging", "DeleteTrail", "DeleteDetector", "ImportKeyPair", "CreateKeyPair")
ACCEL_PREFIXES = ("inf", "trn", "dl", "f1", "f2", "vt1")


def is_accelerated(instance_type: str) -> bool:
    family = instance_type.split(".")[0]
    if family.startswith(ACCEL_PREFIXES):
        return True
    return len(family) > 1 and family[0] in "pg" and family[1].isdigit()


def summarize_event(ev: dict) -> dict:
    raw = json.loads(ev.get("CloudTrailEvent") or "{}")
    uid = raw.get("userIdentity", {})
    return {
        "time": str(ev.get("EventTime")),
        "name": ev.get("EventName"),
        "user": uid.get("arn") or uid.get("type"),
        "type": uid.get("type"),
        "ip": raw.get("sourceIPAddress"),
        "region": raw.get("awsRegion"),
        "result": (raw.get("responseElements") or {}).get("ConsoleLogin"),
        "mfa": (raw.get("additionalEventData") or {}).get("MFAUsed"),
        "error": raw.get("errorCode"),
    }


def lookup_events(ctx: Ctx, region: str, event_name: str, start: dt.datetime) -> list[dict]:
    pager = ctx.client("cloudtrail", region).get_paginator("lookup_events")
    out = []
    for page in pager.paginate(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
        StartTime=start,
        EndTime=now_utc(),
    ):
        for ev in page.get("Events", []):
            out.append(summarize_event(ev))
            if len(out) >= TRIAGE_EVENT_CAP:
                return out
    return out


def aggregate_logins(events: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for ev in events:
        key = (ev.get("user"), ev.get("ip"), ev.get("result") or ev.get("error") or "-")
        g = groups.get(key) or {
            "user": key[0],
            "ip": key[1],
            "result": key[2],
            "count": 0,
            "first": ev["time"],
            "last": ev["time"],
            "mfa": set(),
        }
        g = {
            **g,
            "count": g["count"] + 1,
            "first": min(g["first"], ev["time"]),
            "last": max(g["last"], ev["time"]),
            "mfa": g["mfa"] | {ev.get("mfa") or "-"},
        }
        groups[key] = g
    return sorted(
        ({**g, "mfa": ",".join(sorted(g["mfa"]))} for g in groups.values()), key=lambda g: (-g["count"], str(g["user"]))
    )


def detect_spikes(daily: list[tuple[str, float]], factor: float = 2.0, min_amount: float = 1.0) -> list[dict]:
    spikes = []
    for i, (day, amount) in enumerate(daily):
        prior = [a for _, a in daily[max(0, i - 7) : i]]
        if len(prior) < 3:
            continue
        base = statistics.median(prior)
        if amount >= min_amount and amount > factor * max(base, 0.01):
            spikes.append({"date": day, "amount": round(amount, 2), "baseline": round(base, 2)})
    return spikes


def triage_iam(ctx: Ctx, days: int) -> dict:
    now = now_utc()
    rows = ctx.cred_report()
    recent_users, recent_keys = [], []
    for r in rows:
        if r.get("user") == ROOT_USER:
            continue
        created = parse_ts(r.get("user_creation_time"))
        if created and days_ago(created, now) <= days:
            recent_users.append({"user": r["user"], "created": str(created), "console": r.get("password_enabled")})
        for n in (1, 2):
            rot = parse_ts(r.get(f"access_key_{n}_last_rotated"))
            if r.get(f"access_key_{n}_active") == "true" and rot and days_ago(rot, now) <= days:
                recent_keys.append({"user": r["user"], "key": n, "created": str(rot)})
    roles = []
    for page in ctx.client("iam").get_paginator("list_roles").paginate():
        for role in page.get("Roles", []):
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            if days_ago(role["CreateDate"], now) <= days:
                roles.append({"role": role["RoleName"], "created": str(role["CreateDate"])})
    return {"users": recent_users, "keys": recent_keys, "roles": roles}


def triage_compute(ctx: Ctx, region: str, days: int) -> dict:
    now, instances, accel = now_utc(), 0, []
    ec2 = ctx.client("ec2", region)
    for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]
    ):
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                instances += 1
                launched = inst.get("LaunchTime")
                if is_accelerated(inst["InstanceType"]) or (launched and days_ago(launched, now) <= days):
                    accel.append(
                        {
                            "id": inst["InstanceId"],
                            "type": inst["InstanceType"],
                            "launched": str(launched),
                            "state": inst["State"]["Name"],
                            "accelerated": is_accelerated(inst["InstanceType"]),
                        }
                    )
    lambdas = []
    for page in ctx.client("lambda", region).get_paginator("list_functions").paginate():
        for fn in page.get("Functions", []):
            modified = parse_ts(fn.get("LastModified", "").replace("+0000", "+00:00"))
            if modified and days_ago(modified, now) <= days:
                lambdas.append({"name": fn["FunctionName"], "modified": str(modified)})
    return {"instances": instances, "flagged": accel, "lambdas": lambdas}


def triage_s3(ctx: Ctx, days: int) -> dict:
    s3, now = ctx.client("s3"), now_utc()
    buckets = s3.list_buckets().get("Buckets", [])
    recent = []
    for b in buckets:
        if days_ago(b["CreationDate"], now) > days:
            continue
        status = exists_or_none(functools.partial(s3.get_bucket_policy_status, Bucket=b["Name"]))
        public = bool(status and status.get("PolicyStatus", {}).get("IsPublic"))
        recent.append({"bucket": b["Name"], "created": str(b["CreationDate"]), "public": public})
    try:
        conf = ctx.client("s3control").get_public_access_block(AccountId=ctx.account_id)
        account_bpa: bool | str = all(conf.get("PublicAccessBlockConfiguration", {}).values())
    except ClientError as exc:
        account_bpa = False if err_code(exc) == "NoSuchPublicAccessBlockConfiguration" else f"未知（{short_err(exc)}）"
    return {"total": len(buckets), "recent": recent, "account_block_public_access": account_bpa}


def triage_events(ctx: Ctx, region: str, days: int) -> dict:
    start = now_utc() - dt.timedelta(days=days)
    logins = lookup_events(ctx, region, "ConsoleLogin", now_utc() - dt.timedelta(days=90))
    names = SENSITIVE_REGIONAL_EVENTS + (SENSITIVE_GLOBAL_EVENTS if region == "us-east-1" else ())
    sensitive, truncated = [], ["ConsoleLogin"] if len(logins) >= TRIAGE_EVENT_CAP else []
    for name in names:
        found = lookup_events(ctx, region, name, start)
        if len(found) >= TRIAGE_EVENT_CAP:
            truncated.append(name)
        sensitive += found
    return {"logins": logins, "sensitive": sensitive, "truncated": truncated}


def triage_cost(ctx: Ctx, days: int) -> dict:
    ce = ctx.client("ce", "us-east-1")
    end = dt.date.today()
    start = end - dt.timedelta(days=days)
    by_service: dict[str, float] = {}
    daily: dict[str, float] = {}
    token = None
    while True:
        kwargs = {
            "TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
        }
        if token:
            kwargs["NextPageToken"] = token
        resp = ce.get_cost_and_usage(**kwargs)
        for period in resp.get("ResultsByTime", []):
            day = period["TimePeriod"]["Start"]
            for g in period.get("Groups", []):
                amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
                by_service[g["Keys"][0]] = by_service.get(g["Keys"][0], 0.0) + amt
                daily[day] = daily.get(day, 0.0) + amt
        token = resp.get("NextPageToken")
        if not token:
            break
    top = sorted(by_service.items(), key=lambda kv: -kv[1])[:15]
    series = sorted(daily.items())
    return {
        "top_services": [{"service": s, "amount": round(a, 2)} for s, a in top],
        "total": round(sum(daily.values()), 2),
        "spikes": detect_spikes(series),
    }


TRIAGE_SECTIONS: tuple[tuple[str, str, bool], ...] = (
    ("iam", "IAM 用户 / Access Key / 角色（近期新建）", False),
    ("compute", "EC2（GPU/加速实例、近期启动）与 Lambda（近期修改）", True),
    ("s3", "S3 桶（近期新建、公开状态）", False),
    ("events", "CloudTrail：ConsoleLogin（90 天）与敏感操作", True),
)


def run_triage_section(ctx: Ctx, key: str, regional: bool, days: int) -> None:
    done = ctx.state.get("triage", {}).get(key, {})
    targets = ctx.regions if regional else ["global"]
    for idx, region in enumerate(targets, 1):
        if region in done and "error" not in done[region]:
            continue
        ctx.ui.info(f"  [{idx}/{len(targets)}] {region}")
        try:
            if key == "iam":
                data = triage_iam(ctx, days)
            elif key == "s3":
                data = triage_s3(ctx, days)
            elif key == "compute":
                data = triage_compute(ctx, region, days)
            else:
                data = triage_events(ctx, region, days)
        except (ClientError, BotoCoreError) as exc:
            data = {"error": short_err(exc)}
        done = {**done, region: data}
        ctx.put_state("triage", key, done)


def run_triage(ctx: Ctx, days: int) -> int:
    ctx.ui.title(f"疑似泄露排查（只读，近 {days} 天）")
    for key, label, regional in TRIAGE_SECTIONS:
        ctx.ui.info(f"▶ {label}")
        run_triage_section(ctx, key, regional, days)
    if "cost" not in ctx.state.get("triage", {}):
        if ctx.ui.confirm("查询 Cost Explorer 费用明细？（每次 API 请求 $0.01）", default=True):
            try:
                ctx.put_state("triage", "cost", triage_cost(ctx, days))
            except (ClientError, BotoCoreError) as exc:
                ctx.put_state("triage", "cost", {"error": short_err(exc)})
    print_triage_highlights(ctx)
    md = render_triage_md(ctx.state.get("triage", {}), days)
    stamp = now_utc().strftime("%Y%m%d-%H%M%S")
    path = ctx.store.write_file(f"triage-{stamp}.md", report_header(ctx, "疑似泄露排查报告") + md)
    ctx.store.write_file(
        f"triage-{stamp}.json", json.dumps(ctx.state.get("triage", {}), ensure_ascii=False, indent=2, default=str)
    )
    ctx.ui.ok(f"排查报告：{path}")
    ctx.ui.info("可将报告作为 Support case 附件；处置建议见《最佳实践》1.4")
    return 0


def triage_flags(triage: dict) -> list[str]:
    flags = []
    iam = (triage.get("iam") or {}).get("global") or {}
    for label, key in (("新建 IAM 用户", "users"), ("新建 Access Key", "keys"), ("新建 IAM 角色", "roles")):
        if iam.get(key):
            flags.append(f"{label} {len(iam[key])} 个")
    for region, data in (triage.get("compute") or {}).items():
        accel = [i for i in data.get("flagged", []) if i.get("accelerated")]
        if accel:
            flags.append(f"{region}: GPU/加速实例 {len(accel)} 台")
    for region, data in (triage.get("events") or {}).items():
        root = [e for e in data.get("logins", []) if e.get("type") == "Root"]
        failed = [e for e in data.get("logins", []) if e.get("result") == "Failure"]
        if root:
            flags.append(f"{region}: root 登录 {len(root)} 次")
        if failed:
            flags.append(f"{region}: 登录失败 {len(failed)} 次")
        if data.get("sensitive"):
            flags.append(f"{region}: 敏感操作 {len(data['sensitive'])} 条")
        if data.get("truncated"):
            flags.append(
                f"{region}: 事件超过 {TRIAGE_EVENT_CAP} 条已截断（{', '.join(data['truncated'])}），"
                "请在 CloudTrail 控制台或 Athena 中完整排查"
            )
    for spike in (triage.get("cost") or {}).get("spikes", []):
        flags.append(f"费用突增 {spike['date']}: ${spike['amount']}（基线 ${spike['baseline']}）")
    return flags


def print_triage_highlights(ctx: Ctx) -> None:
    ctx.ui.title("排查要点")
    flags = triage_flags(ctx.state.get("triage", {}))
    if not flags:
        ctx.ui.ok("未发现明显异常（仍请人工复核报告）")
    for flag in flags:
        ctx.ui.warn(flag)


# ═══════════════════════════════════════════════════════════════════════════
# 报告
# ═══════════════════════════════════════════════════════════════════════════


def md_cell(text: Any) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", "<br>")


ORG_FORM_LABEL = {
    "standalone": "独立账号",
    "management": "Organizations 管理账号",
    "member": "Organizations 成员账号",
    "unknown": "未知（无 Organizations 读取权限）",
}


def report_header(ctx: Ctx, title: str) -> str:
    return "\n".join(
        [
            f"# {title}",
            "",
            f"- 账号：{ctx.account_id}（{ORG_FORM_LABEL[ctx.org_form]}{'，Control Tower' if ctx.control_tower else ''}）",
            f"- 执行身份：{ctx.caller_arn}",
            f"- 主区域：{ctx.home_region}；覆盖区域：{len(ctx.regions)} 个",
            f"- 生成时间：{iso_now()}；工具版本：{VERSION}",
            "",
            "",
        ]
    )


def load_findings(state: dict) -> list[Finding]:
    out = []
    for module in MODULES:
        out += [Finding.from_dict(d) for d in state.get("checks", {}).get(module.id, [])]
    return out


def render_report_md(ctx: Ctx, findings: list[Finding], changes: list[dict]) -> str:
    counts = {s: sum(1 for f in findings if f.status == s) for s in (PASS, FAIL, WARN, MANUAL, ERROR, NA)}
    lines = [
        report_header(ctx, "AWS 账号安全检查报告"),
        "## 结果汇总",
        "",
        " / ".join(f"{k} {v}" for k, v in counts.items()),
        "",
        "## 检查明细",
        "",
        "| 编号 | 实践 | 检查项 | 状态 | 说明 | 处理 |",
        "|---|---|---|---|---|---|",
    ]
    decisions = ctx.state.get("decisions", {})
    for f in findings:
        mod = MODULE_BY_ID[f.module]
        lines.append(
            f"| {f.id} | {md_cell(mod.practice)} | {md_cell(f.title)} | {f.status} | "
            f"{md_cell(f.detail)} | {md_cell(decisions.get(f.id, ''))} |"
        )
    todo = [f for f in findings if f.status in (FAIL, WARN, MANUAL, ERROR) and (f.guidance or f.fix)]
    if todo:
        lines += ["", "## 待处理与指引", ""]
        for f in todo:
            lines += [f"### {f.id} {f.title}（{f.status}）", "", f.detail, ""]
            if f.fix and decisions.get(f.id) != "done":
                lines += ["> 可由工具自动修复：运行 `python3 aws_account_hardening.py` 进入引导模式", ""]
            if f.guidance:
                lines += ["```text", f.guidance, "```", ""]
    if changes:
        lines += ["", "## 变更记录", "", "| 时间 | 模块 | 操作 | 区域 | 资源 | 状态 |", "|---|---|---|---|---|---|"]
        for c in changes:
            lines.append(
                f"| {c.get('ts')} | {c.get('module')} | {c.get('action')} | {c.get('region')} | "
                f"{md_cell(c.get('resource'))} | {c.get('status')} |"
            )
    return "\n".join(lines) + "\n"


def render_triage_md(triage: dict, days: int) -> str:
    lines = ["## 排查要点", ""] + [f"- {f}" for f in triage_flags(triage)] + [""]
    iam = (triage.get("iam") or {}).get("global") or {}
    lines += [f"## IAM（近 {days} 天）", ""]
    for label, key in (("新建用户", "users"), ("新建 Access Key", "keys"), ("新建角色", "roles")):
        items = iam.get(key) or []
        lines.append(f"- {label}：{len(items)}")
        lines += [f"  - `{json.dumps(i, ensure_ascii=False)}`" for i in items[:50]]
    if "us-east-1" not in (triage.get("events") or {}):
        lines += ["", "> ⚠ 未覆盖 us-east-1：IAM 等全局服务的敏感操作只记录在 us-east-1，本次未排查"]
    lines += ["", "## 计算资源", "", "| 区域 | 实例总数 | 标记实例 | 近期修改 Lambda |", "|---|---|---|---|"]
    for region, d in sorted((triage.get("compute") or {}).items()):
        flagged = ", ".join(f"{i['id']}({i['type']})" for i in d.get("flagged", [])[:10])
        lines.append(
            f"| {region} | {d.get('instances', d.get('error', ''))} | {md_cell(flagged)} | "
            f"{len(d.get('lambdas', []))} |"
        )
    s3 = (triage.get("s3") or {}).get("global") or {}
    bpa = s3.get("account_block_public_access")
    bpa_text = bpa if isinstance(bpa, str) else ("已全部开启" if bpa else "未配置或未全部开启")
    lines += ["", "## S3", "", f"- 桶总数：{s3.get('total', s3.get('error'))}；账号级 Block Public Access：{bpa_text}"]
    lines += [f"  - 近期新建：{b['bucket']}（{b['created']}，公开：{b['public']}）" for b in s3.get("recent", [])]
    lines += [
        "",
        "## 控制台登录（ConsoleLogin，90 天）",
        "",
        "| 区域 | 身份 | 来源 IP | 结果 | MFA | 次数 | 首次 | 最近 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for region, d in sorted((triage.get("events") or {}).items()):
        for g in aggregate_logins(d.get("logins", [])):
            lines.append(
                f"| {region} | {md_cell(g['user'])} | {g['ip']} | {g['result']} | {g['mfa']} | "
                f"{g['count']} | {g['first']} | {g['last']} |"
            )
    lines += [
        "",
        f"## 敏感操作（近 {days} 天）",
        "",
        "| 时间 | 区域 | 事件 | 身份 | 来源 IP | 错误 |",
        "|---|---|---|---|---|---|",
    ]
    for _, d in sorted((triage.get("events") or {}).items()):
        for e in sorted(d.get("sensitive", []), key=lambda e: e["time"], reverse=True)[:200]:
            lines.append(
                f"| {e['time']} | {e['region']} | {e['name']} | {md_cell(e['user'])} | {e['ip']} | "
                f"{e.get('error') or ''} |"
            )
    cost = triage.get("cost") or {}
    if cost:
        lines += ["", f"## 费用（近 {days} 天，合计 ${cost.get('total', '-')}）", ""]
        lines += [f"- {c['service']}: ${c['amount']}" for c in cost.get("top_services", [])]
        lines += [f"- ⚠ 突增 {s['date']}: ${s['amount']}（基线 ${s['baseline']}）" for s in cost.get("spikes", [])]
        if cost.get("error"):
            lines.append(f"- 查询失败：{cost['error']}")
    return "\n".join(lines) + "\n"


def write_reports(ctx: Ctx) -> Path:
    findings = load_findings(ctx.state)
    changes = ctx.store.changes()
    stamp = now_utc().strftime("%Y%m%d-%H%M%S")
    path = ctx.store.write_file(f"report-{stamp}.md", render_report_md(ctx, findings, changes))
    ctx.store.write_file(
        f"report-{stamp}.json",
        json.dumps(
            {
                "account_id": ctx.account_id,
                "org_form": ctx.org_form,
                "generated": iso_now(),
                "version": VERSION,
                "findings": [f.to_dict() for f in findings],
                "decisions": ctx.state.get("decisions", {}),
                "changes": changes,
            },
            ensure_ascii=False,
            indent=2,
            default=str,
        ),
    )
    return path


# ═══════════════════════════════════════════════════════════════════════════
# 引导流程
# ═══════════════════════════════════════════════════════════════════════════


def print_summary(ctx: Ctx) -> None:
    ctx.ui.title("检查结果")
    findings = sorted(
        load_findings(ctx.state), key=lambda f: (MODULES.index(MODULE_BY_ID[f.module]), STATUS_ORDER.get(f.status, 9))
    )
    rows = [[f.id, f.status, f.title, f.detail] for f in findings]
    ctx.ui.table(["编号", "状态", "检查项", "说明"], rows, status_col=1)
    counts = {s: sum(1 for f in findings if f.status == s) for s in (FAIL, WARN, MANUAL, PASS)}
    fixable = sum(1 for f in findings if f.fix and f.status in (FAIL, WARN))
    ctx.ui.say()
    ctx.ui.info(" / ".join(f"{k} {v}" for k, v in counts.items()) + f"；其中可由工具修复 {fixable} 项")


def run_checks(ctx: Ctx, reuse: bool) -> None:
    ctx.ui.title("检查阶段")
    for module in MODULES:
        if reuse and module.id in ctx.state.get("checks", {}):
            ctx.ui.info(f"{module.id} {module.name}：沿用上次结果")
            continue
        ctx.ui.info(f"{module.id} {module.name} ...")
        findings = run_check(ctx, module)
        ctx.put_state("checks", module.id, [f.to_dict() for f in findings])


def next_fixable(ctx: Ctx) -> tuple[Module, Finding] | None:
    decisions = ctx.state.get("decisions", {})
    for module in MODULES:
        for data in ctx.state.get("checks", {}).get(module.id, []):
            f = Finding.from_dict(data)
            if f.fix and f.status in (FAIL, WARN) and f.id not in decisions:
                return module, f
    return None


def show_plan(ui: UI, plan: FixPlan) -> None:
    ui.label("将执行：", "")
    for i, action in enumerate(plan.actions, 1):
        ui.say(f"    {i}. {action}")
    ui.label("等价 CLI：", "")
    for cmd in plan.cli:
        ui.say(f"    $ {cmd}")
    ui.label("费用：", plan.cost)
    ui.label("风险：", plan.risk)
    ui.label("回滚：", plan.rollback)


def handle_fix(ctx: Ctx, module: Module, finding: Finding) -> None:
    ui = ctx.ui
    ui.title(f"[{finding.id}] {finding.title}（{module.practice}）")
    ui._emit(f"  状态：{ui.status(finding.status)} {clean(finding.detail)}")
    while True:
        ans = ui.choice("处理此项？", {"y": "处理", "n": "跳过", "d": "详情", "q": "保存退出"}, "n")
        if ans == "d":
            ui.block(finding.guidance or "（无额外说明）")
            for key, value in finding.evidence:
                ui.info(f"{key}: {value}")
            continue
        break
    if ans == "q":
        raise UserQuit()
    if ans == "n":
        ctx.put_state("decisions", finding.id, "skipped")
        return
    try:
        plan = module.plan(ctx, finding)
    except (ClientError, BotoCoreError, RuntimeError, ValueError) as exc:
        ctx.put_state("decisions", finding.id, "failed")
        ui.error(f"准备修复失败：{short_err(exc)}")
        return
    if plan is None:
        ctx.put_state("decisions", finding.id, "skipped")
        return
    show_plan(ui, plan)
    if not ui.confirm("确认执行？", default=False):
        ctx.put_state("decisions", finding.id, "skipped")
        return
    try:
        module.apply(ctx, finding, plan)
        ctx.put_state("decisions", finding.id, "done")
        ui.ok("完成")
    except (ClientError, BotoCoreError, RuntimeError, ValueError) as exc:
        ctx.put_state("decisions", finding.id, "failed")
        ui.error(f"执行失败：{short_err(exc)}")
        ui.info("已记录为失败；修复原因后用 --restart 重新运行可再次尝试")
    ctx.invalidate("trails")
    ctx.put_state("checks", module.id, [f.to_dict() for f in run_check(ctx, module)])


def run_fixes(ctx: Ctx) -> None:
    ctx.ui.title("修复阶段（每项均需确认，默认跳过）")
    while True:
        nxt = next_fixable(ctx)
        if nxt is None:
            break
        handle_fix(ctx, *nxt)


def print_manual(ctx: Ctx) -> None:
    todo = [f for f in load_findings(ctx.state) if f.status in (FAIL, WARN, MANUAL, ERROR)]
    if not todo:
        return
    ctx.ui.title("仍需人工处理（详细指引见报告）")
    for f in todo:
        ctx.ui._emit(f"  {ctx.ui.status(f.status)} {f.id} {clean(f.title)}")


def choose_state(ctx: Ctx, mode: str, restart: bool) -> bool:
    """返回是否沿用上次检查结果。各模式独立保存进度。"""
    ctx.store.use_mode(mode)
    old = ctx.store.load()
    inputs = (old or {}).get("inputs", {})
    if old and not restart and (old.get("checks") or old.get("triage")):
        ans = ctx.ui.choice(f"发现 {old.get('updated')} 的未完成进度", {"c": "继续", "r": "重新检查"}, "c")
        if ans == "c":
            ctx.state = old
            return True
    ctx.state = new_state(ctx.account_id, mode, inputs)
    ctx.store.save(ctx.state)
    return False


def run_guided(ctx: Ctx, check_only: bool, restart: bool) -> int:
    reuse = choose_state(ctx, "check" if check_only else "guided", restart)
    run_checks(ctx, reuse)
    print_summary(ctx)
    if not check_only:
        run_fixes(ctx)
    print_manual(ctx)
    path = write_reports(ctx)
    ctx.ui.ok(f"报告：{path}（同目录有 JSON 版本）")
    return 0


# ═══════════════════════════════════════════════════════════════════════════
# 回滚
# ═══════════════════════════════════════════════════════════════════════════


def _delete_versions(s3, bucket: str, prefix: str | None = None) -> None:
    kwargs = {"Bucket": bucket, **({"Prefix": prefix} if prefix else {})}
    for page in s3.get_paginator("list_object_versions").paginate(**kwargs):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            if prefix is None or v["Key"] == prefix
        ]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _rb_object(ctx: Ctx, rec: dict) -> bool:
    _delete_versions(ctx.client("s3", rec["region"]), rec["params"]["bucket"], rec["params"]["key"])
    return True


def _rb_bucket(ctx: Ctx, rec: dict) -> bool:
    bucket = rec["resource"]
    if not ctx.ui.confirm(f"删除日志桶 {bucket} 及其中全部日志？（审计证据，建议保留）", default=False):
        return False
    s3 = ctx.client("s3", rec["region"])
    if not has_tool_tag(s3, bucket):
        ctx.ui.warn(f"{bucket} 缺少本工具标签，跳过")
        return False
    _delete_versions(s3, bucket)
    s3.delete_bucket(Bucket=bucket, ExpectedBucketOwner=ctx.account_id)
    return True


def _rb_detector(ctx: Ctx, rec: dict) -> bool:
    if not ctx.ui.confirm(f"删除 {rec['region']} 的 GuardDuty detector（会删除其发现记录）？", default=False):
        return False
    ctx.client("guardduty", rec["region"]).delete_detector(DetectorId=rec["params"]["detector_id"])
    return True


def _rb_events_rule(ctx: Ctx, rec: dict) -> bool:
    events = ctx.client("events", rec["region"])
    rule = exists_or_none(lambda: events.describe_rule(Name=rec["resource"]))
    if rule is None:
        return True
    if not owned_rule(events, rule["Arn"]):
        ctx.ui.warn(f"规则 {rec['resource']} 缺少本工具标签，跳过")
        return False
    exists_or_none(lambda: events.remove_targets(Rule=rec["resource"], Ids=rec["params"].get("target_ids", [])))
    events.delete_rule(Name=rec["resource"])
    return True


def _rb_role(ctx: Ctx, rec: dict) -> bool:
    iam = ctx.client("iam")
    tags = iam.list_role_tags(RoleName=rec["resource"]).get("Tags", [])
    if not any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE for t in tags):
        ctx.ui.warn(f"角色 {rec['resource']} 缺少本工具标签，跳过")
        return False
    for name in iam.list_role_policies(RoleName=rec["resource"]).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=rec["resource"], PolicyName=name)
    iam.delete_role(RoleName=rec["resource"])
    return True


def _rb_delivery_channel(ctx: Ctx, rec: dict) -> bool:
    cfg = ctx.client("config", rec["region"])
    exists_or_none(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=rec["params"]["recorder"]))
    cfg.delete_delivery_channel(DeliveryChannelName=rec["resource"])
    return True


def _rb_topic(ctx: Ctx, rec: dict) -> bool:
    sns, topic = ctx.client("sns", rec["region"]), rec["params"]["topic_arn"]
    if exists_or_none(lambda: sns.get_topic_attributes(TopicArn=topic)) is None:
        return True
    if not AlertsModule._owned_topic(sns, topic):
        ctx.ui.warn(f"topic {topic} 缺少本工具标签，跳过")
        return False
    subs = sns.list_subscriptions_by_topic(TopicArn=topic).get("Subscriptions", [])
    if subs and not ctx.ui.confirm(f"topic 上还有 {len(subs)} 个订阅（可能含后来添加的），仍删除？", default=False):
        return False
    sns.delete_topic(TopicArn=topic)
    return True


def _rb_trail(ctx: Ctx, rec: dict) -> bool:
    ct = ctx.client("cloudtrail", rec["region"])
    arn = rec["resource"]
    tags = exists_or_none(lambda: ct.list_tags(ResourceIdList=[arn]))
    if tags is None:
        return True
    tag_list_ = (tags.get("ResourceTagList") or [{}])[0].get("TagsList", [])
    if not any(t["Key"] == TAG_KEY and t["Value"] == TAG_VALUE for t in tag_list_):
        ctx.ui.warn(f"Trail {arn} 缺少本工具标签，跳过")
        return False
    ct.delete_trail(Name=rec["params"].get("name") or arn)
    return True


def _rb_recorder(ctx: Ctx, rec: dict) -> bool:
    cfg = ctx.client("config", rec["region"])
    exists_or_none(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=rec["resource"]))
    cfg.delete_configuration_recorder(ConfigurationRecorderName=rec["resource"])
    return True


def _skip(reason: str) -> Callable[[Ctx, dict], bool]:
    def _fn(ctx: Ctx, rec: dict) -> bool:
        ctx.ui.info(f"跳过 {rec['action']} {rec['resource']}：{reason}")
        return False

    return _fn


def _call(service: str, method: str, build: Callable[[dict], dict], global_region: bool = False):
    def _fn(ctx: Ctx, rec: dict) -> bool:
        region = None if global_region or rec.get("region") == "global" else rec.get("region")
        getattr(ctx.client(service, region), method)(**build(rec))
        return True

    return _fn


ROLLBACK_HANDLERS: dict[str, Callable[[Ctx, dict], bool]] = {
    "s3:create_bucket": _rb_bucket,
    "s3:put_object": _rb_object,
    "cloudtrail:create_trail": _rb_trail,
    "guardduty:create_detector": _rb_detector,
    "guardduty:enable_detector": _call(
        "guardduty", "update_detector", lambda r: {"DetectorId": r["params"]["detector_id"], "Enable": False}
    ),
    "guardduty:create_ip_set": _call(
        "guardduty",
        "delete_ip_set",
        lambda r: {"DetectorId": r["params"]["detector_id"], "IpSetId": r["params"]["ip_set_id"]},
    ),
    "guardduty:enable_org_admin": _call(
        "guardduty", "disable_organization_admin_account", lambda r: {"AdminAccountId": r["params"]["admin"]}
    ),
    "guardduty:update_org_config": _call(
        "guardduty",
        "update_organization_configuration",
        lambda r: {
            "DetectorId": r["params"]["detector_id"],
            "AutoEnableOrganizationMembers": r["params"].get("previous") or "NONE",
        },
    ),
    "sns:create_topic": _rb_topic,
    "sns:subscribe": _skip("随 topic 删除；未确认的订阅会自动过期"),
    "iam:create_role": _rb_role,
    "events:put_rule": _rb_events_rule,
    "account:put_alternate_contact": _call(
        "account", "delete_alternate_contact", lambda r: {"AlternateContactType": r["params"]["type"]}, True
    ),
    "config:put_recorder": _rb_recorder,
    "config:put_delivery_channel": _rb_delivery_channel,
    "config:start_recorder": _skip("随记录器删除"),
    "securityhub:enable": _call("securityhub", "disable_security_hub", lambda r: {}),
    "securityhub:enable_standard": _skip("随 Security Hub 停用"),
    "iam:create_service_linked_role": _skip("服务关联角色可能被其他功能使用，请人工评估"),
    "organizations:enable_aws_service_access": _skip("禁用可信访问可能影响组织其他功能，请人工评估"),
    "iam:enable_root_credentials_management": _call(
        "iam", "disable_organizations_root_credentials_management", lambda r: {}, True
    ),
    "iam:enable_root_sessions": _call("iam", "disable_organizations_root_sessions", lambda r: {}, True),
    "accessanalyzer:create_analyzer": _call(
        "accessanalyzer", "delete_analyzer", lambda r: {"analyzerName": r["params"]["name"]}
    ),
}


WEAKENS_DETECTION = {
    "cloudtrail:create_trail",
    "guardduty:create_detector",
    "guardduty:enable_detector",
    "securityhub:enable",
    "config:put_recorder",
    "events:put_rule",
    "sns:create_topic",
    "accessanalyzer:create_analyzer",
    "guardduty:update_org_config",
    "guardduty:enable_org_admin",
}


def run_rollback(ctx: Ctx) -> int:
    changes = [
        c
        for c in ctx.store.changes()
        if c.get("status") in ("done", "pending") and not c.get("params", {}).get("existed")
    ]
    ctx.ui.title("回滚本工具创建的资源")
    if not changes:
        ctx.ui.info("没有可回滚的变更记录")
        return 0
    ctx.ui.table(
        ["时间", "模块", "操作", "区域", "资源"],
        [[c["ts"], c["module"], c["action"], c["region"], str(c["resource"])] for c in changes],
    )
    weak = sorted({c["action"] for c in changes if c["action"] in WEAKENS_DETECTION})
    if weak:
        ctx.ui.warn("⚠ 以下回滚会削弱账号的检测与告警能力：" + ", ".join(weak))
    if not ctx.ui.confirm(f"按逆序回滚以上 {len(changes)} 项？", default=False):
        return 0
    failed = 0
    for rec in reversed(changes):
        handler = ROLLBACK_HANDLERS.get(rec["action"])
        if handler is None:
            ctx.ui.warn(f"未知操作 {rec['action']}，跳过")
            continue
        try:
            done = handler(ctx, rec)
        except ClientError as exc:
            if is_not_found(exc):
                done = True
            else:
                failed += 1
                ctx.ui.error(f"{rec['action']} {rec['resource']}: {short_err(exc)}")
                continue
        except (BotoCoreError, KeyError) as exc:
            failed += 1
            ctx.ui.error(f"{rec['action']} {rec['resource']}: {short_err(exc)}")
            continue
        status = "rolled_back" if done else "kept"
        ctx.store.append_change({"id": rec["id"], "ts": iso_now(), "status": status})
        if done:
            ctx.ui.ok(f"已回滚 {rec['action']} {rec['resource']}")
    return 1 if failed else 0


# ═══════════════════════════════════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════════════════════════════════


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AWS 账号安全加固工具（CloudShell 引导式）")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--check-only", action="store_true", help="只读检查，不做任何修改")
    mode.add_argument("--triage", action="store_true", help="疑似泄露排查（只读）")
    mode.add_argument("--rollback", action="store_true", help="撤销本工具创建的资源")
    p.add_argument("--regions", help="只检查这些区域（逗号分隔）")
    p.add_argument("--exclude-regions", help="排除这些区域（逗号分隔）")
    p.add_argument("--home-region", help="告警/日志汇聚区域，默认 CloudShell 当前区域")
    p.add_argument("--days", type=int, default=DEFAULT_TRIAGE_DAYS, help="triage 回溯天数（1–90）")
    p.add_argument("--restart", action="store_true", help="忽略上次进度，重新开始")
    p.add_argument("--version", action="version", version=VERSION)
    args = p.parse_args(argv)
    if not 1 <= args.days <= 90:
        p.error("--days 需在 1–90 之间")
    return args


def bootstrap(args: argparse.Namespace, ui: UI, session=None) -> Ctx:
    session = session or boto3.Session()
    home = args.home_region or session.region_name or os.environ.get("AWS_REGION") or "us-east-1"
    if not REGION_RE.match(home):
        raise ValueError(f"主区域 {home} 格式不正确")
    sts_region = session.region_name or os.environ.get("AWS_REGION") or "us-east-1"
    ident = session.client("sts", region_name=sts_region, config=BOTO_CONFIG).get_caller_identity()
    arn = ident["Arn"]
    partition = arn.split(":")[1]
    if partition != "aws":
        raise RuntimeError(f"当前仅支持 AWS 全球区域（aws 分区），检测到 {partition}")
    store = StateStore(STATE_ROOT, ident["Account"])
    ctx = Ctx(
        session=session,
        ui=ui,
        store=store,
        state=new_state(ident["Account"], "init"),
        account_id=ident["Account"],
        partition=partition,
        caller_arn=arn,
        identity_type=identity_type(arn),
        home_region=home,
    )
    ctx.regions = resolve_regions(ctx, args.regions, args.exclude_regions)
    if "us-east-1" not in ctx.regions:
        ui.warn(
            "未覆盖 us-east-1：IAM 等全局服务事件只记录在 us-east-1，告警转发仍会覆盖该区域，"
            "但 GuardDuty / triage 不会检查它"
        )
    detect_org(ctx)
    ctx.control_tower = detect_control_tower(ctx)
    return ctx


def print_banner(ctx: Ctx, mode: str) -> None:
    ui = ctx.ui
    ui.title(f"AWS 账号安全加固工具 v{VERSION} — {mode}")
    form = ORG_FORM_LABEL[ctx.org_form]
    ui.info(f"账号      : {ctx.account_id}（{form}{'，检测到 Control Tower' if ctx.control_tower else ''}）")
    ui.info(f"执行身份  : {ctx.caller_arn}")
    ui.info(f"主区域    : {ctx.home_region}；覆盖 {len(ctx.regions)} 个区域")
    ui.info(f"进度目录  : {ctx.store.dir}")
    if ctx.identity_type == "root":
        ui.warn("当前以 root 运行。日常不应使用 root，完成后请退出。")
    if os.environ.get("AWS_EXECUTION_ENV", "").startswith("CloudShell"):
        ui.warn("CloudShell 闲置 20–30 分钟会断开：进度已自动保存，断开后在同一区域重新运行同一命令即可继续")
        ui.warn("CloudShell 持久存储按区域隔离；VPC 环境无持久存储，无法续跑")


def main(argv: list[str] | None = None, session=None, ui: UI | None = None) -> int:
    args = parse_args(argv)
    ui = ui or UI()
    try:
        ctx = bootstrap(args, ui, session)
        mode = (
            "回滚"
            if args.rollback
            else "疑似泄露排查"
            if args.triage
            else "只读检查"
            if args.check_only
            else "引导加固"
        )
        print_banner(ctx, mode)
        if args.rollback:
            return run_rollback(ctx)
        if args.triage:
            reuse = choose_state(ctx, "triage", args.restart)
            if not reuse:
                ctx.put_state("inputs", "triage_days", args.days)
            return run_triage(ctx, ctx.input_value("triage_days", args.days))
        if not args.check_only and not ui.confirm("开始检查？（检查阶段只读）", default=True):
            return 0
        return run_guided(ctx, args.check_only, args.restart)
    except (UserQuit, KeyboardInterrupt):
        ui.say()
        ui.warn("已保存进度并退出。重新运行同一命令即可继续。")
        return 130
    except NoCredentialsError:
        ui.error("未找到 AWS 凭证。请在 CloudShell 中运行，或先配置凭证。")
        return 2
    except (ClientError, BotoCoreError, RuntimeError, ValueError) as exc:
        ui.error(short_err(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
