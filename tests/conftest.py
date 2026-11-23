"""公共 fixture：moto 环境、脚本化输入、Ctx 构造。"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import aws_account_hardening as h

REGIONS = "us-east-1,eu-west-1"


class Script:
    """按提示词子串匹配应答；未匹配返回空串（即采用默认值，默认均为“否/跳过”）。"""

    def __init__(self, rules: list[tuple[str, object]] | None = None):
        self.rules = list(rules or [])
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        for sub, ans in self.rules:
            if sub in prompt:
                return ans() if callable(ans) else str(ans)
        return ""


def make_ui(script: Script | None = None) -> tuple[h.UI, io.StringIO]:
    out = io.StringIO()
    return h.UI(out=out, input_fn=script or Script(), color=False), out


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    for key in (
        "AWS_PROFILE",
        "AWS_SESSION_TOKEN",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_EXECUTION_ENV",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setattr(h, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(h, "ROLE_PROPAGATION_SECONDS", 0)
    monkeypatch.setattr(h, "CRED_REPORT_POLL_SECONDS", 0)
    yield


@pytest.fixture
def aws():
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


def build_ctx(session, script: Script | None = None, regions: str = REGIONS) -> h.Ctx:
    ui, _ = make_ui(script)
    args = h.parse_args(["--regions", regions])
    ctx = h.bootstrap(args, ui, session)
    ctx.state = h.new_state(ctx.account_id, "guided")
    return ctx


@pytest.fixture
def ctx(aws):
    return build_ctx(aws)


def statuses(findings: list[h.Finding]) -> dict[str, str]:
    return {f.id: f.status for f in findings}


def get_finding(findings: list[h.Finding], fid: str) -> h.Finding:
    return next(f for f in findings if f.id == fid)


def apply_fix(ctx: h.Ctx, module: h.Module, fid: str, script: Script | None = None) -> h.FixPlan:
    if script is not None:
        ctx.ui.input_fn = script
    finding = get_finding(module.check(ctx), fid)
    plan = module.plan(ctx, finding)
    module.apply(ctx, finding, plan)
    return plan


__all__ = ["REGIONS", "Script", "apply_fix", "build_ctx", "get_finding", "h", "make_ui", "os", "statuses"]
