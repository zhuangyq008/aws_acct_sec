"""纯函数单元测试。"""

from __future__ import annotations

import datetime as dt
import json

import pytest
from conftest import Script, h, make_ui

NOW = dt.datetime(2026, 11, 23, tzinfo=dt.timezone.utc)


def iso(days_before: int) -> str:
    return (NOW - dt.timedelta(days=days_before)).isoformat()


# ── 校验 ────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "value,ok",
    [("sec@example.com", True), ("a.b+c@x.co", True), ("bad", False), ("a@b", False), ("x" * 250 + "@a.com", False)],
)
def test_validate_email(value, ok):
    assert (h.validate_email(value) is None) is ok


def test_validate_emails_reports_bad_item():
    assert h.validate_emails("a@example.com, b@example.com") is None
    assert "bad" in h.validate_emails("a@example.com,bad")
    assert h.validate_emails(" , ") is not None


@pytest.mark.parametrize(
    "value,ok", [("+8613800000000", True), ("+1 (206) 555-0100", True), ("abc", False), ("12", False)]
)
def test_validate_phone(value, ok):
    assert (h.validate_phone(value) is None) is ok


def test_validate_text_and_ints_and_account():
    check = h.validate_text(5)
    assert check("") and check("123456") and check("a\x07") and check("ok") is None
    rng = h.validate_int_range(90, 3650)
    assert rng("365") is None and rng("30") and rng("x")
    assert h.validate_account_id("123456789012") is None and h.validate_account_id("1234")


def test_parse_cidrs():
    assert h.parse_cidrs("8.8.8.8, 1.1.1.0/24,8.8.8.8") == ["1.1.1.0/24", "8.8.8.8/32"]
    assert h.parse_cidrs("2600:1f18::/48") == ["2600:1f18::/48"]
    assert h.parse_cidrs("8.8.0.0/20") == ["8.8.0.0/20"]
    assert h.total_addresses(["1.1.1.0/24", "8.8.8.8/32"]) == 257


@pytest.mark.parametrize(
    "bad,msg",
    [
        ("0.0.0.0/0", "网段过大"),
        ("128.0.0.0/1", "网段过大"),
        ("::/0", "网段过大"),
        ("2000::/3", "网段过大"),
        ("1.0.0.0/8", "网段过大"),
        ("1.2.3.4/24", "主机位"),
        ("10.0.0.0/24", "私有"),
        ("8.8.0.0/16", "网段过大"),
        ("10.1.2.3", "私有"),
        ("192.168.1.0/24", "私有"),
        ("203.0.113.5", "私有"),
        ("100.64.0.1", "私有"),
        ("fd00::/64", "全球单播"),
        ("2001:db8::/48", "私有"),
        ("not-an-ip", "合法"),
        ("", "至少"),
    ],
)
def test_parse_cidrs_rejects(bad, msg):
    with pytest.raises(ValueError, match=msg):
        h.parse_cidrs(bad)
    assert h.validate_cidrs(bad)


def test_clean_and_validators_reject_invisible():
    assert h.clean("a\x1b[31mb\u202ec\u200bd\ne") == "a[31mbcd\ne"
    assert h.clean("x\ny", keep_newlines=False) == "xy"
    assert h.validate_text(20)("ab\u202ecd") and h.validate_text(20)("a\u2028b")
    assert h.validate_account_id("١٢٣٤٥٦٧٨٩٠١٢")


def test_is_not_found():
    from botocore.exceptions import ClientError

    def ce(code, msg=""):
        return ClientError({"Error": {"Code": code, "Message": msg}}, "Op")

    assert h.is_not_found(ce("NoSuchEntity")) and h.is_not_found(ce("BadRequestException", "detector not found"))
    assert not h.is_not_found(ce("BadRequestException", "invalid input"))
    assert not h.is_not_found(ce("InvalidAccessException")) and not h.is_not_found(ValueError())


def test_lifecycle_rules():
    rules = h.build_lifecycle_rules(400)
    assert {r["Filter"]["Prefix"] for r in rules} == {"AWSLogs/", "config/"}
    assert all(r["Expiration"]["Days"] == 400 for r in rules)


# ── 时间与格式 ──────────────────────────────────────────────────────────────
def test_parse_ts_and_days_ago():
    assert h.parse_ts("N/A") is None and h.parse_ts("garbage") is None and h.parse_ts(None) is None
    ts = h.parse_ts("2026-11-01T00:00:00Z")
    assert ts.tzinfo is not None and h.days_ago(ts, NOW) == 22
    assert h.parse_ts("2026-11-01T00:00:00").tzinfo is not None
    assert h.parse_ts("2024-01-01T00:00:00.000+00:00") is not None


def test_mask_email_tags_as_list_md_cell():
    assert h.mask_email("security@example.com") == "se***@example.com"
    assert h.mask_email("nope") == "***"
    assert {t["Key"] for t in h.tag_list()} == {"ManagedBy", "CreatedAt"}
    assert h.tag_map()["ManagedBy"] == h.TOOL
    assert h.as_list(None) == [] and h.as_list("a") == ["a"] and h.as_list(["a"]) == ["a"]
    assert h.md_cell("a|b\nc") == "a\\|b<br>c" and h.md_cell(None) == ""


def test_display_width_and_pad():
    assert h.display_width("ab") == 2 and h.display_width("中文") == 4
    assert h.pad("中", 4) == "中  "


def test_identity_type():
    assert h.identity_type("arn:aws:iam::1:root") == "root"
    assert h.identity_type("arn:aws:iam::1:user/a") == "iam_user"
    assert h.identity_type("arn:aws:sts::1:assumed-role/r/s") == "role"
    assert h.identity_type("arn:aws:sts::1:federated-user/x") == "other"


def test_short_err_and_code():
    from botocore.exceptions import ClientError

    exc = ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "Op")
    assert h.err_code(exc) == "AccessDenied" and h.short_err(exc).startswith("权限不足")
    assert h.err_code(ValueError("x")) == "ValueError" and "ValueError" in h.short_err(ValueError("x"))


# ── 分析函数 ────────────────────────────────────────────────────────────────
def test_analyze_access_keys():
    rows = [
        {"user": h.ROOT_USER, "access_key_1_active": "true", "access_key_1_last_rotated": iso(400)},
        {
            "user": "old",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": iso(200),
            "access_key_1_last_used_date": iso(120),
            "access_key_2_active": "false",
        },
        {
            "user": "never",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": iso(100),
            "access_key_1_last_used_date": "N/A",
        },
        {
            "user": "fresh",
            "access_key_1_active": "true",
            "access_key_1_last_rotated": iso(10),
            "access_key_1_last_used_date": iso(1),
        },
    ]
    unused, stale, active = h.analyze_access_keys(rows, NOW)
    assert active == 3
    assert any("old#key1" in u and "120" in u for u in unused)
    assert any("never#key1" in u and "从未使用" in u for u in unused)
    assert not any("fresh" in u for u in unused + stale)
    assert {s.split("（")[0] for s in stale} == {"old#key1", "never#key1"}


def test_scp_covers():
    doc = {
        "Statement": [
            {"Effect": "Allow", "Action": "*"},
            {"Effect": "Deny", "Action": ["cloudtrail:*"]},
            {
                "Effect": "Deny",
                "NotAction": ["iam:*"],
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["x"]}},
            },
            {"Effect": "Deny", "Action": "*", "Condition": {"NotIpAddress": {"aws:SourceIp": ["1.1.1.0/24"]}}},
        ]
    }
    assert h.scp_covers(doc, ("cloudtrail:StopLogging", "cloudtrail:DeleteTrail"), None) == "full"
    assert h.scp_covers(doc, (), "aws:RequestedRegion") == "full"
    assert h.scp_covers(doc, ("iam:CreateAccessKey",), None) == "conditional"
    assert h.scp_covers({"Statement": []}, ("iam:CreateAccessKey",), None) is None
    single = {"Statement": {"Effect": "Deny", "Action": "iam:CreateAccessKey"}}
    assert h.scp_covers(single, ("iam:CreateAccessKey",), None) == "full"


def test_detect_spikes():
    daily = [(f"d{i}", 10.0) for i in range(7)] + [("d7", 50.0), ("d8", 0.5)]
    spikes = h.detect_spikes(daily)
    assert [s["date"] for s in spikes] == ["d7"] and spikes[0]["baseline"] == 10.0
    assert h.detect_spikes([("a", 0), ("b", 0), ("c", 0), ("d", 0.5)]) == []


@pytest.mark.parametrize(
    "itype,expected",
    [
        ("p5.48xlarge", True),
        ("g6.xlarge", True),
        ("inf2.xlarge", True),
        ("trn1.32xlarge", True),
        ("m5.large", False),
        ("gr6.large", False),
        ("t3.micro", False),
    ],
)
def test_is_accelerated(itype, expected):
    assert h.is_accelerated(itype) is expected


def test_summarize_and_aggregate_logins():
    raw = {
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::1:root"},
        "sourceIPAddress": "1.2.3.4",
        "awsRegion": "us-east-1",
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
    }
    evs = [
        h.summarize_event(
            {"EventTime": f"2026-11-0{i}", "EventName": "ConsoleLogin", "CloudTrailEvent": json.dumps(raw)}
        )
        for i in (1, 3, 2)
    ]
    assert evs[0]["type"] == "Root" and evs[0]["ip"] == "1.2.3.4" and evs[0]["mfa"] == "No"
    agg = h.aggregate_logins(evs + [{**evs[0], "ip": "5.6.7.8"}])
    assert agg[0]["count"] == 3 and agg[0]["first"] == "2026-11-01" and agg[0]["last"] == "2026-11-03"
    assert len(agg) == 2 and agg[0]["mfa"] == "No"


def test_trail_selectors_and_good_trail():
    assert h.trail_has_mgmt_events({"EventSelectors": [{"ReadWriteType": "All", "IncludeManagementEvents": True}]})
    assert not h.trail_has_mgmt_events({"EventSelectors": [{"ReadWriteType": "ReadOnly"}]})
    assert h.trail_has_mgmt_events(
        {"AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}]}
    )
    assert not h.trail_has_mgmt_events({})
    base = {"multi": True, "mgmt": True, "logging": True, "org": False}
    assert h.is_good_trail(base)
    assert not h.is_good_trail({**base, "multi": False})
    assert not h.is_good_trail({**base, "logging": False})
    assert not h.is_good_trail({**base, "mgmt": False})
    assert h.is_good_trail({**base, "logging": None, "mgmt": None, "org": True})
    assert not h.is_good_trail({**base, "logging": None, "org": False})


def test_build_log_bucket_policy():
    pol = h.build_log_bucket_policy("b", "111122223333", "aws", "o-abc")
    sids = {s["Sid"]: s for s in pol["Statement"]}
    assert "arn:aws:s3:::b/AWSLogs/o-abc/*" in sids["AWSCloudTrailWrite"]["Resource"]
    assert sids["DenyInsecureTransport"]["Effect"] == "Deny"
    assert sids["AWSCloudTrailAclCheck"]["Condition"]["ArnLike"]["aws:SourceArn"].endswith(f"trail/{h.PREFIX}-*")
    no_org = h.build_log_bucket_policy("b", "111122223333", "aws", None)
    assert len(next(s for s in no_org["Statement"] if s["Sid"] == "AWSCloudTrailWrite")["Resource"]) == 1


def test_triage_flags_and_render():
    triage = {
        "iam": {"global": {"users": [{"user": "x"}], "keys": [], "roles": [{"role": "r"}]}},
        "compute": {
            "us-east-1": {
                "instances": 2,
                "lambdas": [],
                "flagged": [{"id": "i-1", "type": "p5.48xlarge", "accelerated": True}],
            }
        },
        "events": {
            "us-east-1": {
                "logins": [
                    {"type": "Root", "result": "Success", "user": "root", "ip": "1.1.1.1", "time": "t", "mfa": "No"},
                    {"type": "IAMUser", "result": "Failure", "user": "u", "ip": "2.2.2.2", "time": "t", "mfa": "No"},
                ],
                "sensitive": [{"time": "t", "region": "us-east-1", "name": "CreateUser", "user": "u", "ip": "2.2.2.2"}],
            }
        },
        "s3": {
            "global": {
                "total": 1,
                "recent": [{"bucket": "b", "created": "t", "public": True}],
                "account_block_public_access": False,
            }
        },
        "cost": {
            "total": 100,
            "top_services": [{"service": "EC2", "amount": 90}],
            "spikes": [{"date": "d", "amount": 50, "baseline": 5}],
        },
    }
    flags = h.triage_flags(triage)
    assert any("新建 IAM 用户 1" in f for f in flags) and any("GPU" in f for f in flags)
    assert any("root 登录 1" in f for f in flags) and any("登录失败 1" in f for f in flags)
    assert any("费用突增" in f for f in flags)
    md = h.render_triage_md(triage, 30)
    assert "p5.48xlarge" in md and "CreateUser" in md and "突增" in md and "未配置" in md
    truncated = {**triage, "events": {"eu-west-1": {"logins": [], "sensitive": [], "truncated": ["ConsoleLogin"]}}}
    assert any("已截断" in f for f in h.triage_flags(truncated))
    assert "未覆盖 us-east-1" in h.render_triage_md(truncated, 30)


# ── 状态存储 ────────────────────────────────────────────────────────────────
def test_state_store_roundtrip_and_changes(tmp_path):
    store = h.StateStore(tmp_path, "111122223333")
    assert store.load() is None and store.changes() == []
    state = h.new_state("111122223333", "guided", {"k": 1})
    store.save(state)
    assert store.load()["inputs"] == {"k": 1}
    assert oct(store.state_path.stat().st_mode & 0o777) == "0o600"
    store.append_change({"id": "a", "action": "x", "status": "pending"})
    store.append_change({"id": "b", "action": "y", "status": "pending"})
    store.append_change({"id": "a", "status": "done"})
    store.changes_path.open("a").write("not json\n")
    merged = store.changes()
    assert [c["id"] for c in merged] == ["a", "b"] and merged[0] == {"id": "a", "action": "x", "status": "done"}


def test_state_store_corrupt_and_version(tmp_path):
    store = h.StateStore(tmp_path, "1")
    store.state_path.write_text("{broken")
    assert store.load() is None and list(store.dir.glob("state.corrupt-*"))
    store.state_path.write_text(json.dumps({"version": 999}))
    assert store.load() is None


def test_finding_roundtrip():
    f = h.Finding(id="M1.x", module="M1", title="t", status=h.FAIL, evidence=(("regions", ["a"]),))
    back = h.Finding.from_dict(json.loads(json.dumps(f.to_dict())))
    assert back == h.Finding(id="M1.x", module="M1", title="t", status=h.FAIL, evidence=(("regions", ["a"]),))
    assert dict(back.evidence)["regions"] == ["a"]


# ── UI ──────────────────────────────────────────────────────────────────────
def test_ui_confirm_choice_ask():
    ui, out = make_ui(Script([("Q1", "maybe"), ("Q1", "y")]))
    answers = iter(["maybe", "y"])
    ui.input_fn = lambda p: next(answers)
    assert ui.confirm("Q1") is True
    ui.input_fn = lambda p: ""
    assert ui.confirm("Q2", default=True) is True and ui.choice("Q3", {"a": "A", "b": "B"}, "b") == "b"
    answers = iter(["bad", "ok@example.com"])
    ui.input_fn = lambda p: next(answers)
    assert ui.ask("邮箱", h.validate_email) == "ok@example.com"
    assert "邮箱格式不正确" in out.getvalue()
    ui.input_fn = lambda p: ""
    assert ui.ask("x", default="dflt") == "dflt"


def test_ui_quit_paths():
    ui, _ = make_ui()
    ui.input_fn = lambda p: ":q"
    with pytest.raises(h.UserQuit):
        ui.ask("x")
    ui.input_fn = lambda p: "q"
    with pytest.raises(h.UserQuit):
        ui.confirm("x")

    def eof(_):
        raise EOFError

    ui.input_fn = eof
    with pytest.raises(h.UserQuit):
        ui.choice("x", {"a": "A"}, "a")


def test_ui_table_and_color():
    ui, out = make_ui()
    ui.table(["A", "状态"], [["很长" * 40, h.PASS]], status_col=1)
    assert "…" in out.getvalue() and "PASS" in out.getvalue()
    colored = h.UI(out=out, input_fn=lambda p: "", color=True)
    assert colored.c("x", "red").startswith("\033[31m")


def test_parse_args_validation():
    assert h.parse_args([]).days == h.DEFAULT_TRIAGE_DAYS
    with pytest.raises(SystemExit):
        h.parse_args(["--days", "0"])
    with pytest.raises(SystemExit):
        h.parse_args(["--triage", "--rollback"])
