"""moto 集成测试：修复 → 复检 → 回滚，以及引导流程、续跑、组织、triage。"""

from __future__ import annotations

import json

import pytest
from botocore.stub import ANY, Stubber
from conftest import REGIONS, Script, apply_fix, build_ctx, get_finding, h, make_ui, statuses

CONTACT_ANSWERS = [
    ("沿用", "n"),
    ("姓名", "SecOps"),
    ("职务", "Security"),
    ("邮箱", "sec@example.com"),
    ("电话", "+8613800000000"),
]


# ── 识别 ────────────────────────────────────────────────────────────────────
def test_bootstrap_standalone(ctx):
    assert ctx.org_form == "standalone" and not ctx.control_tower
    assert ctx.regions == ["us-east-1", "eu-west-1"] and ctx.identity_type == "iam_user"


def test_bootstrap_rejects_unknown_region(aws):
    ui, _ = make_ui()
    with pytest.raises(ValueError, match="未启用"):
        h.bootstrap(h.parse_args(["--regions", "us-east-1,xx-fake-1"]), ui, aws)


def test_detect_control_tower(aws):
    aws.client("iam").create_role(RoleName="AWSControlTowerExecution", AssumeRolePolicyDocument="{}")
    assert build_ctx(aws).control_tower is True


def test_detect_org_management_and_member(aws):
    aws.client("organizations").create_organization(FeatureSet="ALL")
    ctx = build_ctx(aws)
    assert ctx.org_form == "management" and ctx.feature_set == "ALL" and ctx.org_id


# ── M1 / M5 / M6 / M7 只读模块 ─────────────────────────────────────────────
def test_root_and_identity_modules(ctx):
    res = statuses(h.RootModule().check(ctx))
    assert res["M1.mfa"] == h.FAIL and res["M1.keys"] == h.PASS and res["M1.email"] == h.MANUAL
    ctx.identity_type = "root"
    assert statuses(h.RootModule().check(ctx))["M1.identity"] == h.WARN


def test_root_findings_variants(ctx):
    mod = h.RootModule()
    assert mod._mfa(ctx, {"AccountMFAEnabled": 1}, {}).status == h.PASS
    standalone = mod._mfa(ctx, {}, {"password_enabled": "false"})
    assert standalone.status == h.FAIL and "找回密码" in standalone.detail
    ctx.org_form = "member"
    member = mod._mfa(ctx, {}, {"password_enabled": "false"})
    assert member.status == h.MANUAL and "CreateAccount" in member.guidance
    assert mod._keys({"AccountAccessKeysPresent": 1}, {}).status == h.FAIL
    recent = mod._recent({"password_last_used": h.iso_now()})
    assert recent.status == h.WARN and "最近使用" in recent.detail


def test_console_users_and_keys(aws):
    iam = aws.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Xx1!xxxxxxxxxx")
    iam.create_access_key(UserName="alice")
    ctx = build_ctx(aws)
    idc = statuses(h.IdentityCenterModule().check(ctx))
    assert idc["M5.console_users"] == h.WARN and idc["M5.console_mfa"] == h.FAIL
    keys = statuses(h.AccessKeyModule().check(ctx))
    assert keys["M6.count"] == h.WARN and keys["M6.unused"] == h.PASS
    assert statuses(h.NetworkModule().check(ctx))["M7.source"] == h.MANUAL


# ── M2 备用联系人 ───────────────────────────────────────────────────────────
def test_contacts_fix_and_reuse(ctx):
    mod = h.ContactsModule()
    assert statuses(mod.check(ctx))["M2.SECURITY"] == h.FAIL
    plan = apply_fix(ctx, mod, "M2.SECURITY", Script(CONTACT_ANSWERS))
    assert "put-alternate-contact" in plan.cli[0]
    apply_fix(ctx, mod, "M2.BILLING", Script([("沿用", "y")]))
    res = statuses(mod.check(ctx))
    assert res["M2.SECURITY"] == h.PASS and res["M2.BILLING"] == h.PASS and res["M2.OPERATIONS"] == h.FAIL
    assert set(ctx.input_value("contacts")) == {"SECURITY", "BILLING"}


# ── M3 CloudTrail ───────────────────────────────────────────────────────────
def test_trail_fix_creates_hardened_bucket(ctx, aws):
    mod = h.TrailModule()
    assert statuses(mod.check(ctx))["M3.trail"] == h.FAIL
    apply_fix(ctx, mod, "M3.trail", Script([("保留天数", "400")]))
    res = statuses(mod.check(ctx))
    assert res["M3.trail"] == h.PASS and res["M3.validation"] == h.PASS and res["M3.retention"] == h.PASS
    s3, bucket = aws.client("s3"), h.log_bucket_name(ctx)
    assert s3.get_bucket_versioning(Bucket=bucket)["Status"] == "Enabled"
    assert s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]["BlockPublicPolicy"]
    rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    assert rules[0]["Expiration"]["Days"] == 400
    assert "DenyInsecureTransport" in s3.get_bucket_policy(Bucket=bucket)["Policy"]
    # 幂等：再次执行不报错、不重复创建
    plan = h.TrailModule().plan_trail(ctx, get_finding(mod.check(ctx), "M3.trail"))
    mod.apply_trail(ctx, plan)
    assert sum(1 for c in ctx.store.changes() if c["action"] == "cloudtrail:create_trail") == 1


def test_trail_refuses_foreign_bucket(ctx, aws):
    aws.client("s3").create_bucket(Bucket=h.log_bucket_name(ctx))
    with pytest.raises(RuntimeError, match="不是本工具创建"):
        h.ensure_log_bucket(ctx, "M3")


def test_trail_control_tower_is_read_only(ctx):
    ctx.control_tower = True
    f = get_finding(h.TrailModule().check(ctx), "M3.trail")
    assert f.status == h.FAIL and f.fix is None and "Control Tower" in f.guidance


def test_trail_existing_without_validation(ctx, aws):
    s3 = aws.client("s3")
    s3.create_bucket(Bucket="customer-trail")
    ct = aws.client("cloudtrail")
    ct.create_trail(Name="customer", S3BucketName="customer-trail", IsMultiRegionTrail=True)
    ct.start_logging(Name="customer")
    res = statuses(h.TrailModule().check(ctx))
    assert res["M3.trail"] == h.PASS and res["M3.validation"] == h.WARN and res["M3.retention"] == h.MANUAL


# ── M4 GuardDuty ────────────────────────────────────────────────────────────
def test_guardduty_enable_and_ipset(ctx, aws, monkeypatch):
    mod = h.GuardDutyModule()
    f = get_finding(mod.check(ctx), "M4.enabled")
    assert f.status == h.FAIL and dict(f.evidence)["regions"] == ["eu-west-1", "us-east-1"]
    apply_fix(ctx, mod, "M4.enabled")
    assert statuses(mod.check(ctx))["M4.enabled"] == h.PASS
    # moto 未实现 ListIPSets / CreateIPSet：打补丁模拟
    created = []
    for region in ctx.regions:
        client = ctx.client("guardduty", region)
        monkeypatch.setattr(client, "list_ip_sets", lambda **kw: {"IpSetIds": ["x"] if created else []})
        monkeypatch.setattr(client, "get_ip_set", lambda **kw: {"Status": "ACTIVE"})
        monkeypatch.setattr(client, "create_ip_set", lambda **kw: created.append(kw) or {"IpSetId": "ip-1"})
    res = mod.check(ctx)
    assert statuses(res)["M4.ipset"] == h.WARN
    # moto 对 aws:SecureTransport 条件的处理与真实 S3 不同，这里截获 PutObject 校验内容
    puts = []
    monkeypatch.setattr(ctx.client("s3"), "put_object", lambda **kw: puts.append(kw) or {})
    apply_fix(ctx, mod, "M4.ipset", Script([("CIDR", "8.8.8.8,1.1.1.0/24")]))
    assert puts[0]["Key"] == h.IPSET_KEY and puts[0]["Body"].split() == ["1.1.1.0/24", "8.8.8.8/32"]
    assert len(created) == 2 and created[0]["Location"].endswith(h.IPSET_KEY) and created[0]["Activate"]
    assert statuses(mod.check(ctx))["M4.ipset"] == h.PASS


def test_guardduty_ipset_unknown(ctx):
    apply_fix(ctx, h.GuardDutyModule(), "M4.enabled")
    f = get_finding(h.GuardDutyModule().check(ctx), "M4.ipset")
    assert f.status == h.WARN and "无法确认" in f.detail and f.fix is None


def test_guardduty_reenables_disabled_detector(ctx, aws):
    gd = aws.client("guardduty")
    did = gd.create_detector(Enable=False)["DetectorId"]
    mod = h.GuardDutyModule()
    apply_fix(ctx, mod, "M4.enabled")
    assert gd.get_detector(DetectorId=did)["Status"] == "ENABLED"
    assert any(c["action"] == "guardduty:enable_detector" for c in ctx.store.changes())


def test_guardduty_region_error_is_reported(ctx):
    plan = h.FixPlan("t", (), (), "", "", "", {"regions": ["us-east-1"]})
    gd = ctx.client("guardduty", "us-east-1")
    with Stubber(gd) as stub:
        stub.add_response("list_detectors", {"DetectorIds": []})
        stub.add_client_error("create_detector", "AccessDeniedException", "denied")
        with pytest.raises(RuntimeError, match="部分区域失败"):
            h.GuardDutyModule().apply_gd_enable(ctx, plan)
    assert "权限不足" in ctx.ui.out.getvalue()
    assert any(c["status"] == "failed" for c in ctx.store.changes())


# ── M4A 告警 ────────────────────────────────────────────────────────────────
def test_alerts_fix_creates_rules_everywhere(ctx, aws):
    mod = h.AlertsModule()
    res = statuses(mod.check(ctx))
    assert res["M4A.topic"] == h.FAIL and res["M4A.rules"] == h.FAIL and res["M4A.prereq"] == h.WARN
    plan = apply_fix(ctx, mod, "M4A.topic", Script([("告警接收邮箱", "oncall@example.com"), ("测试消息", "y")]))
    assert any("oncall@example.com" in a for a in plan.actions)
    res = statuses(mod.check(ctx))
    assert res["M4A.topic"] == h.PASS and res["M4A.rules"] == h.PASS
    home = aws.client("events")
    rules = h.build_alert_rules(ctx)
    assert any("tamper" in n for n in rules)
    for name, (_, pattern) in rules.items():
        rule = home.describe_rule(Name=name)
        assert json.loads(rule["EventPattern"]) == pattern
        assert home.list_targets_by_rule(Rule=name)["Targets"][0]["Arn"].endswith(h.TOPIC_NAME)
    eu = aws.client("events", region_name="eu-west-1")
    target = eu.list_targets_by_rule(Rule=f"{h.PREFIX}-fwd-root")["Targets"][0]
    assert target["Arn"].endswith(":event-bus/default") and ":us-east-1:" in target["Arn"]
    assert target["RoleArn"].endswith(h.FWD_ROLE_NAME)
    policy = json.loads(aws.client("sns").get_topic_attributes(TopicArn=mod.topic_arn(ctx))["Attributes"]["Policy"])
    assert policy["Statement"][0]["Principal"] == {"Service": "events.amazonaws.com"}


def test_alerts_sub_plan(ctx):
    mod = h.AlertsModule()
    apply_fix(ctx, mod, "M4A.topic", Script([("告警接收邮箱", "a@example.com")]))
    plan = mod.plan_alerts_sub(ctx, h.Finding("M4A.sub", "M4A", "t", h.WARN, fix="alerts_sub"))
    mod.apply_alerts_sub(ctx, plan)
    assert sum(1 for c in ctx.store.changes() if c["action"] == "sns:subscribe") == 2


# ── M4S Security Hub + Config ───────────────────────────────────────────────
def test_securityhub_and_config(ctx, aws, monkeypatch):
    sh, subs = ctx.client("securityhub"), []
    monkeypatch.setattr(
        sh, "batch_enable_standards", lambda **kw: subs.extend(kw["StandardsSubscriptionRequests"]) or {}
    )
    monkeypatch.setattr(sh, "get_enabled_standards", lambda **kw: {"StandardsSubscriptions": list(subs)})
    mod = h.SecurityHubModule()
    res = statuses(mod.check(ctx))
    assert res["M4S.hub"] == h.WARN and res["M4S.config"] == h.WARN
    apply_fix(ctx, mod, "M4S.hub")
    cfg = aws.client("config")
    assert cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"][0]["recording"]
    assert cfg.describe_delivery_channels()["DeliveryChannels"][0]["s3KeyPrefix"] == "config"
    res = statuses(mod.check(ctx))
    assert res["M4S.config"] == h.PASS and res["M4S.hub"] == h.PASS
    assert h.FSBP_FRAGMENT in subs[0]["StandardsArn"]
    actions = [c["action"] for c in ctx.store.changes()]
    assert "securityhub:enable" in actions and "config:put_recorder" in actions


# ── M10 Access Analyzer（moto 不支持，用 Stubber）────────────────────────────
def _stub_analyzers(ctx, regions, analyzers):
    stubs = []
    for region in regions:
        client = ctx.client("accessanalyzer", region)
        stub = Stubber(client)
        stub.add_response("list_analyzers", {"analyzers": analyzers})
        stub.activate()
        stubs.append(stub)
    return stubs


def test_analyzer_check_and_fix(ctx):
    _stub_analyzers(ctx, ["us-east-1", "eu-west-1"], [])
    findings = h.AnalyzerModule().check(ctx)
    f = get_finding(findings, "M10.external")
    assert f.status == h.FAIL and dict(f.evidence)["regions"] == ["eu-west-1", "us-east-1"]
    assert get_finding(findings, "M10.unused").status == h.WARN
    ctx._clients.clear()
    mod = h.AnalyzerModule()
    plan = mod.plan_analyzer(ctx, f)
    assert plan.params["type"] == "ACCOUNT"
    for region in plan.params["regions"]:
        stub = Stubber(ctx.client("accessanalyzer", region))
        stub.add_response(
            "create_analyzer",
            {"arn": "arn:aws:access-analyzer:x:1:analyzer/a"},
            {"analyzerName": h.ANALYZER_NAME, "type": "ACCOUNT", "tags": ANY},
        )
        stub.activate()
    mod.apply_analyzer(ctx, plan)
    assert sum(1 for c in ctx.store.changes() if c["status"] == "done") == 2


def test_analyzer_all_regions_error(ctx):
    for region in ("us-east-1", "eu-west-1"):
        stub = Stubber(ctx.client("accessanalyzer", region))
        stub.add_client_error("list_analyzers", "AccessDeniedException", "denied")
        stub.activate()
    assert get_finding(h.AnalyzerModule().check(ctx), "M10.external").status == h.ERROR


def test_analyzer_unused_fix(ctx):
    mod = h.AnalyzerModule()
    plan = mod.plan_analyzer_unused(ctx, h.Finding("M10.unused", "M10", "t", h.WARN, fix="analyzer_unused"))
    stub = Stubber(ctx.client("accessanalyzer"))
    stub.add_response("create_analyzer", {"arn": "arn:aws:access-analyzer:x:1:analyzer/u"})
    stub.activate()
    mod.apply_analyzer_unused(ctx, plan)
    assert plan.params["type"] == "ACCOUNT_UNUSED_ACCESS"


# ── 组织管理账号：M3 组织 Trail / M4 委派管理员 / M8 SCP / M9 root 管理 ────────
@pytest.fixture
def org_ctx(aws):
    aws.client("organizations").create_organization(FeatureSet="ALL")
    return build_ctx(aws)


def test_org_trail(org_ctx, aws):
    mod = h.TrailModule()
    res = statuses(mod.check(org_ctx))
    assert res["M3.org"] == h.FAIL
    apply_fix(org_ctx, mod, "M3.org", Script([("保留天数", "")]))
    trail = aws.client("cloudtrail").describe_trails(trailNameList=[h.ORG_TRAIL_NAME])["trailList"][0]
    assert trail["IsOrganizationTrail"] is True
    assert statuses(mod.check(org_ctx))["M3.org"] == h.PASS
    policy = aws.client("s3").get_bucket_policy(Bucket=h.log_bucket_name(org_ctx))["Policy"]
    assert f"AWSLogs/{org_ctx.org_id}/" in policy


def test_scp_guardrails(org_ctx, aws):
    org = aws.client("organizations")
    root_id = org.list_roots()["Roots"][0]["Id"]
    org.enable_policy_type(RootId=root_id, PolicyType="SERVICE_CONTROL_POLICY")
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"}],
    }
    pid = org.create_policy(Name="deny-leave", Description="d", Type="SERVICE_CONTROL_POLICY", Content=json.dumps(doc))[
        "Policy"
    ]["PolicySummary"]["Id"]
    org.create_policy(
        Name="deny-key",
        Description="d",
        Type="SERVICE_CONTROL_POLICY",
        Content=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "iam:CreateAccessKey", "Resource": "*"}],
            }
        ),
    )
    ou = org.create_organizational_unit(ParentId=root_id, Name="prod")["OrganizationalUnit"]["Id"]
    org.attach_policy(PolicyId=pid, TargetId=ou)
    res = statuses(h.ScpModule().check(org_ctx))
    assert res["M8.features"] == h.PASS and res["M8.scp"] == h.PASS
    assert res["M8.leave_org"] == h.WARN and res["M8.iam_key"] == h.WARN and res["M8.cloudtrail"] == h.FAIL
    org.attach_policy(PolicyId=pid, TargetId=root_id)
    assert statuses(h.ScpModule().check(org_ctx))["M8.leave_org"] == h.PASS
    assert res["M8.structure"] == h.MANUAL


def test_scp_not_applicable_for_standalone(ctx):
    assert h.run_check(ctx, h.ScpModule())[0].status == h.NA
    ctx.org_form = "member"
    assert "成员账号" in h.run_check(ctx, h.RootMgmtModule())[0].detail


def test_root_mgmt(org_ctx, monkeypatch):
    monkeypatch.setattr(org_ctx.client("organizations"), "enable_aws_service_access", lambda **kw: {})
    iam = org_ctx.client("iam")
    stub = Stubber(iam)
    stub.add_response("list_organizations_features", {"EnabledFeatures": []})
    stub.add_response("list_organizations_features", {"EnabledFeatures": []})
    stub.add_response("enable_organizations_root_credentials_management", {})
    stub.add_response("enable_organizations_root_sessions", {})
    stub.activate()
    mod = h.RootMgmtModule()
    findings = mod.check(org_ctx)
    assert statuses(findings)["M9.creds"] == h.FAIL and get_finding(findings, "M9.creds").fix == "root_mgmt"
    mod.apply(org_ctx, get_finding(findings, "M9.creds"), mod.plan_root_mgmt(org_ctx, findings[0]))
    stub.assert_no_pending_responses()
    actions = [c["action"] for c in org_ctx.store.changes()]
    assert "organizations:enable_aws_service_access" in actions and "iam:enable_root_sessions" in actions


def test_guardduty_org_admin_and_auto(org_ctx):
    mod = h.GuardDutyModule()
    f = h.Finding("M4.org_admin", "M4", "t", h.FAIL, fix="gd_org_admin")
    org_ctx.ui.input_fn = Script([("安全工具账号", "222233334444")])
    plan = mod.plan_gd_org_admin(org_ctx, f)
    for region in org_ctx.regions:
        stub = Stubber(org_ctx.client("guardduty", region))
        stub.add_response("list_organization_admin_accounts", {"AdminAccounts": []})
        stub.add_response("enable_organization_admin_account", {}, {"AdminAccountId": "222233334444"})
        stub.activate()
    mod.apply_gd_org_admin(org_ctx, plan)
    assert org_ctx.input_value("security_account_id") == "222233334444"
    org_ctx._clients.clear()
    stub = Stubber(org_ctx.client("guardduty", "us-east-1"))
    stub.add_response("list_detectors", {"DetectorIds": ["d1"]})
    stub.add_response(
        "describe_organization_configuration",
        {"AutoEnable": False, "MemberAccountLimitReached": False, "AutoEnableOrganizationMembers": "NEW"},
    )
    stub.add_response("update_organization_configuration", {})
    stub.activate()
    auto_plan = mod.plan_gd_auto(
        org_ctx, h.Finding("M4.auto", "M4", "t", h.FAIL, fix="gd_auto", evidence=(("regions", ["us-east-1"]),))
    )
    mod.apply_gd_auto(org_ctx, auto_plan)
    rec = next(c for c in org_ctx.store.changes() if c["action"] == "guardduty:update_org_config")
    assert rec["params"]["previous"] == "NEW" and rec["status"] == "done"


# ── 回滚 ────────────────────────────────────────────────────────────────────
def test_rollback_removes_created_resources(ctx, aws):
    apply_fix(ctx, h.TrailModule(), "M3.trail", Script([("保留天数", "")]))
    apply_fix(ctx, h.GuardDutyModule(), "M4.enabled")
    apply_fix(ctx, h.AlertsModule(), "M4A.topic", Script([("告警接收邮箱", "a@example.com")]))
    apply_fix(ctx, h.ContactsModule(), "M2.SECURITY", Script(CONTACT_ANSWERS))
    ctx.ui.input_fn = Script([("按逆序回滚", "y"), ("GuardDuty detector", "y"), ("删除日志桶", "y"), ("仍删除", "y")])
    assert h.run_rollback(ctx) == 0
    assert "削弱账号的检测" in ctx.ui.out.getvalue()
    assert aws.client("cloudtrail").describe_trails()["trailList"] == [], ctx.ui.out.getvalue()[-1500:]
    assert aws.client("guardduty").list_detectors()["DetectorIds"] == []
    assert not aws.client("sns").list_topics()["Topics"]
    assert not [r for r in aws.client("events").list_rules()["Rules"] if r["Name"].startswith(h.PREFIX)]
    assert h.log_bucket_name(ctx) not in [b["Name"] for b in aws.client("s3").list_buckets()["Buckets"]]
    assert statuses(h.ContactsModule().check(ctx))["M2.SECURITY"] == h.FAIL
    assert all(c["status"] == "rolled_back" for c in ctx.store.changes() if c["action"] not in ("sns:subscribe",))
    assert next(c for c in ctx.store.changes() if c["action"] == "sns:subscribe")["status"] == "kept"
    ctx.ui.input_fn = Script()
    assert h.run_rollback(ctx) == 0  # 再次回滚：无可回滚项或用户默认拒绝


def test_rollback_keeps_bucket_by_default(ctx, aws):
    apply_fix(ctx, h.TrailModule(), "M3.trail", Script([("保留天数", "")]))
    ctx.ui.input_fn = Script([("按逆序回滚", "y")])
    h.run_rollback(ctx)
    assert h.log_bucket_name(ctx) in [b["Name"] for b in aws.client("s3").list_buckets()["Buckets"]]


def test_rollback_nothing(ctx):
    assert h.run_rollback(ctx) == 0 and "没有可回滚" in ctx.ui.out.getvalue()


# ── 端到端：main() ──────────────────────────────────────────────────────────
def run_main(aws, argv, script):
    ui, out = make_ui(script)
    rc = h.main(argv + ["--regions", REGIONS], session=aws, ui=ui)
    return rc, out.getvalue()


def test_main_check_only_writes_report(aws):
    rc, out = run_main(aws, ["--check-only"], Script())
    assert rc == 0 and "报告：" in out
    state_dir = next(h.STATE_ROOT.iterdir())
    md = next(state_dir.glob("report-*.md")).read_text()
    assert "## 检查明细" in md and "M3.trail" in md and "待处理与指引" in md and "独立账号" in md
    assert "可由工具自动修复" in md
    data = json.loads(next(state_dir.glob("report-*.json")).read_text())
    assert data["findings"] and data["account_id"] == state_dir.name


def test_main_guided_fix_all_then_resume(aws):
    script = Script(
        [
            ("开始检查", "y"),
            ("处理此项", "y"),
            ("确认执行", "y"),
            ("保留天数", ""),
            ("告警接收邮箱", "oncall@example.com"),
            ("CIDR", "8.8.8.8"),
        ]
        + CONTACT_ANSWERS
    )
    # Access Analyzer 在 moto 中不可用 → 该项检查为 ERROR，不提供修复
    rc, out = run_main(aws, [], script)
    assert rc == 0, out
    state = json.loads(next(h.STATE_ROOT.iterdir()).joinpath("state-guided.json").read_text())
    done = {k for k, v in state["decisions"].items() if v == "done"}
    assert {"M2.SECURITY", "M3.trail", "M4.enabled", "M4A.topic"} <= done
    findings = {f["id"]: f["status"] for mod in state["checks"].values() for f in mod}
    assert findings["M3.trail"] == h.PASS and findings["M4.enabled"] == h.PASS and findings["M4A.rules"] == h.PASS
    rc, out = run_main(aws, [], Script([("开始检查", "y"), ("未完成进度", "c")]))
    assert rc == 0 and "沿用上次结果" in out


def test_main_quit_and_resume(aws):
    rc, out = run_main(aws, [], Script([("开始检查", "y"), ("处理此项", "q")]))
    assert rc == 130 and "已保存进度" in out
    script = Script([("开始检查", "y"), ("未完成进度", "c")])
    rc, out = run_main(aws, [], script)
    assert rc == 0 and "沿用上次结果" in out
    assert any("未完成进度" in p for p in script.prompts)


def test_main_skip_and_detail(aws):
    script = Script([("开始检查", "y"), ("处理此项", lambda: next(answers))])
    answers = iter(["d"] + ["n"] * 100)
    rc, out = run_main(aws, [], script)
    assert rc == 0 and "root" in out


def test_main_guided_with_securityhub(aws):
    """引导流程中的 failed 分支：Security Hub 在 moto 中 BatchEnableStandards 未实现。"""
    script = Script([("开始检查", "y"), ("处理此项", lambda: next(answers)), ("确认执行", "y")])
    answers = iter(["n"] * 7 + ["y"] + ["n"] * 100)
    rc, out = run_main(aws, [], script)
    assert rc == 0 and "执行失败" in out


def test_main_decline_start(aws):
    rc, _ = run_main(aws, [], Script([("开始检查", "n")]))
    assert rc == 0


def test_main_triage(aws, monkeypatch):
    login = {
        "time": "2026-11-20T00:00:00",
        "name": "ConsoleLogin",
        "user": "arn:aws:iam::1:root",
        "type": "Root",
        "ip": "203.0.113.9",
        "region": "us-east-1",
        "result": "Success",
        "mfa": "No",
        "error": None,
    }
    monkeypatch.setattr(h, "lookup_events", lambda ctx, region, name, start: [login] if name == "ConsoleLogin" else [])
    ec2 = aws.client("ec2")
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, InstanceType="p3.2xlarge", MinCount=1, MaxCount=1)
    aws.client("iam").create_user(UserName="intruder")
    aws.client("s3").create_bucket(Bucket="fresh-bucket")
    rc, out = run_main(aws, ["--triage", "--days", "7"], Script([("Cost Explorer", "y")]))
    assert rc == 0, out
    assert "GPU/加速实例" in out and "新建 IAM 用户" in out and "root 登录" in out
    state_dir = next(h.STATE_ROOT.iterdir())
    md = next(state_dir.glob("triage-*.md")).read_text()
    assert "p3.2xlarge" in md and "fresh-bucket" in md
    rc, out = run_main(aws, ["--triage"], Script([("未完成进度", "c")]))
    assert rc == 0


def test_main_rollback_mode(aws):
    rc, out = run_main(aws, ["--rollback"], Script())
    assert rc == 0 and "没有可回滚" in out


def test_main_no_credentials(monkeypatch):
    import boto3

    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    ui, out = make_ui()
    assert h.main(["--check-only"], session=boto3.Session(region_name="us-east-1"), ui=ui) == 2
    assert "未找到 AWS 凭证" in out.getvalue()


def test_banner_cloudshell_and_root(ctx, monkeypatch):
    monkeypatch.setenv("AWS_EXECUTION_ENV", "CloudShell")
    ctx.identity_type = "root"
    h.print_banner(ctx, "x")
    out = ctx.ui.out.getvalue()
    assert "闲置 20–30 分钟" in out and "root" in out


# ── 审查后补充的回归测试 ────────────────────────────────────────────────────
def test_resume_guardduty_fix_without_check_cache(ctx):
    """续跑时检查缓存为空，修复仍应现场查询 detector 并成功（而非静默跳过）。"""
    gd = ctx.client("guardduty")
    did = gd.create_detector(Enable=False)["DetectorId"]
    ctx._cache.clear()
    plan = h.FixPlan("t", (), (), "", "", "", {"regions": ["us-east-1"]})
    h.GuardDutyModule().apply_gd_enable(ctx, plan)
    assert gd.get_detector(DetectorId=did)["Status"] == "ENABLED"


def test_alert_rule_disabled_is_detected_and_repaired(ctx, aws):
    mod = h.AlertsModule()
    apply_fix(ctx, mod, "M4A.topic", Script([("告警接收邮箱", "a@example.com")]))
    aws.client("events").disable_rule(Name=f"{h.PREFIX}-alert-root")
    aws.client("events", region_name="eu-west-1").remove_targets(Rule=f"{h.PREFIX}-fwd-security", Ids=["home-bus"])
    f = get_finding(mod.check(ctx), "M4A.rules")
    assert f.status == h.FAIL
    assert dict(f.evidence)["home"] == [f"{h.PREFIX}-alert-root"] and dict(f.evidence)["forward"] == ["eu-west-1"]
    mod.apply(ctx, f, mod.plan(ctx, f))
    assert statuses(mod.check(ctx))["M4A.rules"] == h.PASS


def test_alerts_forward_always_covers_us_east_1(aws):
    ui, _ = make_ui()
    ctx = h.bootstrap(h.parse_args(["--regions", "eu-west-1", "--home-region", "eu-west-1"]), ui, aws)
    ctx.state = h.new_state(ctx.account_id, "guided")
    assert h.AlertsModule().forward_regions(ctx) == ["us-east-1"]
    assert "未覆盖 us-east-1" in ui.out.getvalue()


def test_put_targets_failure_marks_failed(ctx, monkeypatch):
    events = ctx.client("events")
    monkeypatch.setattr(events, "put_targets", lambda **kw: {"FailedEntryCount": 1, "FailedEntries": [{"x": 1}]})
    with pytest.raises(RuntimeError, match="设置目标失败"):
        h.AlertsModule()._put_rule(
            ctx,
            "us-east-1",
            f"{h.PREFIX}-alert-x",
            "d",
            {"source": ["aws.x"]},
            {"Id": "sns", "Arn": "arn:aws:sns:us-east-1:123456789012:t"},
        )
    assert ctx.store.changes()[-1]["status"] == "failed"


def test_foreign_resources_are_not_taken_over(ctx, aws):
    aws.client("iam").create_role(RoleName=h.FWD_ROLE_NAME, AssumeRolePolicyDocument="{}")
    with pytest.raises(RuntimeError, match="不是本工具创建"):
        h.AlertsModule()._ensure_forward_role(ctx)
    aws.client("sns").create_topic(Name=h.TOPIC_NAME)
    with pytest.raises(RuntimeError, match="不是本工具创建"):
        h.AlertsModule()._ensure_topic(ctx)
    aws.client("events").put_rule(Name=f"{h.PREFIX}-alert-root", EventPattern='{"source":["x"]}')
    with pytest.raises(RuntimeError, match="不是本工具创建"):
        h.AlertsModule()._put_rule(ctx, "us-east-1", f"{h.PREFIX}-alert-root", "d", {}, {"Id": "a", "Arn": "b"})


def test_customer_config_recorder_untouched(ctx, aws, monkeypatch):
    cfg = aws.client("config")
    cfg.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/x",
            "recordingGroup": {"allSupported": True},
        }
    )
    res = h.SecurityHubModule().check(ctx)
    f = get_finding(res, "M4S.config")
    assert f.status == h.WARN and f.fix is None and "客户记录器" in f.detail
    h.SecurityHubModule()._ensure_config(ctx, "bucket")
    assert not cfg.describe_delivery_channels()["DeliveryChannels"]
    assert not cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"][0].get("recording")


def test_lifecycle_never_expires_ipset(ctx, aws):
    apply_fix(ctx, h.TrailModule(), "M3.trail", Script([("保留天数", "")]))
    rules = aws.client("s3").get_bucket_lifecycle_configuration(Bucket=h.log_bucket_name(ctx))["Rules"]
    prefixes = {r["Filter"]["Prefix"] for r in rules}
    assert prefixes == {"AWSLogs/", "config/"}


def test_rollback_skips_untagged_and_marks_kept(ctx, aws):
    aws.client("events").put_rule(Name="acct-sec-alert-x", EventPattern='{"source":["x"]}')
    ctx.store.append_change(
        {
            "id": "r1",
            "ts": h.iso_now(),
            "module": "M4A",
            "action": "events:put_rule",
            "region": "us-east-1",
            "resource": "acct-sec-alert-x",
            "params": {"name": "acct-sec-alert-x", "target_ids": []},
            "status": "done",
        }
    )
    ctx.ui.input_fn = Script([("按逆序回滚", "y")])
    h.run_rollback(ctx)
    assert aws.client("events").describe_rule(Name="acct-sec-alert-x")
    assert ctx.store.changes()[0]["status"] == "kept"
    assert h.run_rollback(ctx) == 0 and "没有可回滚" in ctx.ui.out.getvalue()


def test_check_unexpected_exception_becomes_error(ctx, monkeypatch):
    monkeypatch.setattr(h.NetworkModule, "check", lambda self, c: {}["boom"])
    f = h.run_check(ctx, h.NetworkModule())[0]
    assert f.status == h.ERROR and "KeyError" in f.detail


def test_plan_failure_does_not_crash(ctx, monkeypatch):
    mod = h.AlertsModule()
    monkeypatch.setattr(mod, "plan_alerts", lambda c, f: (_ for _ in ()).throw(RuntimeError("x")))
    ctx.ui.input_fn = Script([("处理此项", "y")])
    h.handle_fix(ctx, mod, h.Finding("M4A.topic", "M4A", "t", h.FAIL, fix="alerts"))
    assert ctx.state["decisions"]["M4A.topic"] == "failed"


def test_modes_do_not_overwrite_each_other(aws):
    run_main(aws, [], Script([("开始检查", "y"), ("处理此项", "q")]))
    run_main(aws, ["--check-only"], Script())
    state_dir = next(h.STATE_ROOT.iterdir())
    assert (state_dir / "state-guided.json").exists() and (state_dir / "state-check.json").exists()


def test_home_region_validated(aws):
    ui, _ = make_ui()
    with pytest.raises(ValueError, match="主区域"):
        h.bootstrap(h.parse_args(["--regions", "us-east-1", "--home-region", "xx-fake-9"]), ui, aws)


def test_control_tower_fail_closed(aws, monkeypatch):
    from botocore.exceptions import ClientError

    ctx = build_ctx(aws)
    iam = ctx.client("iam")
    monkeypatch.setattr(
        iam,
        "get_role",
        lambda **kw: (_ for _ in ()).throw(
            ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetRole")
        ),
    )
    assert h.detect_control_tower(ctx) is True


def test_terminal_injection_is_stripped(ctx):
    ctx.ui.say("evil\x1b[2J\u202eTXT")
    ctx.ui.table(["a"], [["x\x1b]0;title\x07y"]])
    out = ctx.ui.out.getvalue()
    assert "\x1b" not in out and "\u202e" not in out and "\x07" not in out
