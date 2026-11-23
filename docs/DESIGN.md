# AWS 账号安全加固工具 — 设计文档 (v0.3)

> **v1 范围决定（2026-11-23）**：十项实践 + triage 全部覆盖；**高风险写操作不做**（Access Key 停用/删除、IP 白名单策略、SCP 挂载、成员账号 root 凭证删除），这些项只检查 + 给出指引。

> 依据：[AWS-account-security-best-practices.md](AWS-account-security-best-practices.md)
> 运行环境：AWS CloudShell（Python 3 + boto3 预装，无需 pip install）
> 交付形态：单文件 `aws_account_hardening.py`，仅依赖标准库 + boto3

---

## 1. 目标与非目标

**目标**
- 引导式：逐项 **检查 → 展示差距 → 确认后修复**，客户在 CloudShell 中一条命令启动
- 覆盖文档十项实践中**可用 API 完成**的部分；不能 API 化的给出控制台操作指引并在报告中标记
- 断点续跑：应对 CloudShell 20–30 分钟闲置断开
- 输出可作为 Support case 附件 / 内部验收的报告（Markdown + JSON）

**非目标**
- 不替代 Security Hub / Config 做持续合规
- 不处理账号暂停恢复流程本身（暂停期间 CloudShell 通常不可用）
- 不做 IdP（Entra ID / Okta）对接、不改 root 邮箱/密码/MFA（无 API）

---

## 2. 运行方式

```bash
# 在 CloudShell 中
curl -fsSLO <分发地址>/aws_account_hardening.py
sha256sum aws_account_hardening.py      # 与发布页校验值比对
python3 aws_account_hardening.py        # 默认：引导模式（检查 + 可选修复）
```

| 参数 | 说明 |
|---|---|
| (无) | 引导模式：先全量检查，再逐项询问是否修复 |
| `--check-only` | 只读，仅出报告，不做任何写操作 |
| `--triage` | 疑似泄露排查（只读，对应文档 1.4） |
| `--regions a,b` / `--exclude-regions a,b` | 区域范围，默认所有已启用区域 |
| `--home-region` | 告警/日志汇聚区域，默认 CloudShell 当前区域 |
| `--rollback` | 按变更日志撤销本工具创建的资源 |
| `--restart` | 忽略已有进度，重新开始 |

> **没有 `--yes`**：所有写操作必须逐项人工确认，防止误用。

---

## 3. 总体流程

```
启动
 ├─ 0. 预检：sts get-caller-identity / 身份类型(root|IAM user|role) / 账号形态识别 / 权限试探
 ├─ 1. 加载进度（同账号存在 state.json → 询问 继续 / 重来）
 ├─ 2. 检查阶段：按模块执行 check()，每完成一个模块即落盘
 ├─ 3. 汇总：打印差距表（PASS / FAIL / WARN / MANUAL / N/A）
 ├─ 4. 修复阶段：对每个 FAIL 项
 │      展示 → 原因(文档章节) / 将执行的操作 / 等价 CLI / 费用 / 风险 / 回滚方式
 │      选择 → [y] 执行  [n] 跳过  [d] 查看详情  [q] 保存并退出
 │      执行前写 changes.jsonl(pending) → 执行 → 写(done|failed) → 复检
 └─ 5. 生成报告 report-<ts>.md / .json
```

### 3.1 账号形态识别

| 判定 | 方式 | 影响 |
|---|---|---|
| 独立账号 | `organizations:DescribeOrganization` 抛 `AWSOrganizationsNotInUseException` | 账号级 Trail / GuardDuty |
| 管理账号 | `MasterAccountId == 当前账号` | 额外开放：组织级 Trail、SCP、集中式 root 管理 |
| 成员账号 | 属于组织但非管理账号 | 组织级项标记 `N/A — 请联系管理账号` |
| Control Tower | 存在 `AWSControlTowerExecution` 角色或 `aws-controltower-*` Trail | **不创建/修改** CloudTrail、Config、CT 管理的 SCP，仅检查 |

### 3.2 身份类型

- **root**：可删除 root 自身 Access Key；启动时提示"日常不应使用 root，完成后请退出"
- **IAM user / role**：root Access Key 只能检查；修复给出指引（root 登录后执行 或 管理账号 `sts:AssumeRoot`）

---

## 4. 模块设计（与文档对照）

状态：`AUTO` 可自动修复 / `GUIDE` 只出指引 / `GEN` 只生成配置不挂载

### M1 root 保护（实践 1）
| 检查项 | 数据来源 | 修复 |
|---|---|---|
| root MFA 已启用 | `iam:GetAccountSummary.AccountMFAEnabled` + 凭证报告 | GUIDE（控制台步骤，建议注册 ≥2 个设备） |
| root 无 Access Key | `AccountAccessKeysPresent` + 凭证报告 | GUIDE（v1 不做 Key 写操作；给出 root 登录后删除步骤 / 管理账号 `sts:AssumeRoot` 命令） |
| root 近期使用 | 凭证报告 `password_last_used` | 仅告警 |
| root 邮箱为群组邮箱 | 无 API | MANUAL（报告中列为人工确认项） |

### M2 备用联系人与通知（实践 2）
| 检查项 | 修复 |
|---|---|
| SECURITY / BILLING / OPERATIONS 三类联系人 | AUTO：交互录入 姓名/职务/邮箱/电话，`account:PutAlternateContact`（校验邮箱、电话格式） |
| AWS Health 事件通知 | AUTO：EventBridge 规则 `source=aws.health` → 告警 SNS |

### M3 日志审计（实践 3）
| 检查项 | 修复 |
|---|---|
| 存在多区域、正在记录的 Trail（含管理事件读写） | AUTO：创建 Trail `acct-sec-trail`，多区域、日志完整性验证 |
| 日志桶加固 | 新建 `acct-sec-trail-<acct>-<home-region>`：Block Public Access、SSE-S3、版本控制、BucketOwnerEnforced、仅 HTTPS、CloudTrail 写入策略带 `aws:SourceArn` 条件、生命周期**仅作用于 `AWSLogs/` 与 `config/` 前缀**（默认 365 天；`guardduty/` 可信 IP 列表永不过期） |
| 管理账号：组织级 Trail | AUTO（仅管理账号、非 CT）：`IsOrganizationTrail=true` |
| 已有 Trail 但未开启完整性验证 / 非多区域 | 提示，**不修改客户已有 Trail**（只建议） |

### M4 威胁检测与告警（实践 4）
| 检查项 | 修复 |
|---|---|
| GuardDuty 各区域 detector 已启用 | AUTO：逐区域 `CreateDetector`（展示 30 天免费试用与费用说明） |
| 管理账号：GuardDuty 委派管理员 | AUTO：录入安全账号 ID → 逐区域 `EnableOrganizationAdminAccount` |
| 当前账号为 GuardDuty 委派管理员：自动启用成员 | AUTO：`UpdateOrganizationConfiguration(AutoEnableOrganizationMembers=ALL)`（提示全组织费用） |
| 可信 IP 列表 | AUTO（可选）：录入出口 CIDR（`strict` 解析、IPv4 ≥ /20、IPv6 ≥ /48、拒绝任何私有/保留/文档段；确认页逐条列出与地址总数）→ 写入日志桶 `guardduty/trusted-ips.txt` → 逐区域 `CreateIPSet`；检查时只把 `ACTIVE` 的 IPSet 计为已配置 |
| 告警 SNS | AUTO：home region 创建 `acct-sec-alerts` topic（topic 策略只允许本工具的 EventBridge 规则发布；未启用 SSE：EventBridge 不能用 `alias/aws/sns`，需客户自管 CMK，v1 不做），订阅值班邮箱（**需收件人点击确认**，工具会提示并可复检订阅状态） |
| 关键事件实时告警 | AUTO：见 §5 |
| Security Hub CSPM + AWS FSBP 标准 | AUTO（**默认 No**，仅 home region）：无 Config 记录器时创建（DAILY 记录频率，投递到日志桶 `config/`）；**客户已有记录器时完全不碰**（不启动、不加投递通道、回滚也不停止） |

### M5 IAM Identity Center（实践 5）
| 检查项 | 修复 |
|---|---|
| Identity Center 实例是否存在 | GUIDE |
| 有控制台密码的 IAM 用户数量 / 是否启用 MFA | 列出清单，GUIDE |

### M6 长期访问密钥（实践 6）
| 检查项 | 修复 |
|---|---|
| 超过 90 天未使用 / 从未使用的 Access Key | GUIDE：列出清单 + 停用命令（v1 不自动停用） |
| 超过 90 天未轮换的活跃 Key | 仅列出，GUIDE |
| 无 MFA 的控制台 IAM 用户 | 仅列出 |

### M7 访问来源控制（实践 7）
| 检查项 | 修复 |
|---|---|
| — | GUIDE：报告中给出示例策略与灰度步骤（v1 不生成、不挂载） |

### M8 多账号与 SCP（实践 8，仅管理账号）
| 检查项 | 修复 |
|---|---|
| SCP 功能是否启用、OU 结构、已挂载 SCP | 检查 |
| 四类护栏：禁关 CloudTrail/GuardDuty、禁退出组织、限制区域、禁建 IAM 用户 Key | 检查：扫描现有 SCP 内容是否覆盖并已挂载；GUIDE（v1 不创建、不挂载 SCP） |

### M9 集中式 root 访问管理（实践 9，仅管理账号）
| 检查项 | 修复 |
|---|---|
| `RootCredentialsManagement` / `RootSessions` 是否启用 | AUTO：`iam:EnableOrganizationsRootCredentialsManagement` / `EnableOrganizationsRootSessions` |
| 成员账号 root 凭证 | 仅检查 + GUIDE（删除成员 root 凭证属高危批量操作，v1 不自动做） |

### M10 定期审计（实践 10）
| 检查项 | 修复 |
|---|---|
| IAM Access Analyzer（外部访问） | AUTO：home region 创建 ACCOUNT 级 analyzer（免费） |
| 未使用访问 analyzer | AUTO（默认不勾选，收费） |
| — | 报告中给出"每月/季度/半年"复查清单；支持定期重跑对比上次报告 |

### Triage 模式（文档 1.4，只读）
| 内容 | API |
|---|---|
| IAM 用户 / Access Key / Role 近 N 天新建（默认 30） | 凭证报告、`iam:ListRoles` |
| 各区域 EC2（高亮 p/g/inf/trn/dl 等 GPU/加速实例）、Lambda（近期修改） | `ec2:DescribeInstances`、`lambda:ListFunctions` |
| S3 桶创建时间、公开访问状态 | `s3:ListBuckets`、`GetPublicAccessBlock` |
| CloudTrail 90 天 `ConsoleLogin`（按用户/来源 IP/成败聚合） | `cloudtrail:LookupEvents`（2 TPS 限流，按区域落盘） |
| 敏感事件：CreateUser / CreateAccessKey / CreateLoginProfile / AttachUserPolicy / StopLogging / DeleteTrail 等 | `cloudtrail:LookupEvents` |
| 近 30 天费用按服务 + 日费用突增 | `ce:GetCostAndUsage`（每次请求 $0.01，会提示） |

---

## 5. 告警设计（SNS）

```
各区域 default event bus                     home region
┌──────────────────────────┐   跨区域转发    ┌────────────────────────────────┐
│ rule: acct-sec-forward    │ ─────────────▶ │ default bus                     │
│  (root 登录 / StopLogging │  (IAM role     │  rule: acct-sec-alert-*         │
│   / GuardDuty 高危 …)     │   events:Put)  │   → SNS acct-sec-alerts → 邮件  │
└──────────────────────────┘                └────────────────────────────────┘
```

- EventBridge 的 SNS target 必须同区域，所以非 home region 先转发到 home region 的 default bus，再统一投递到一个 SNS
- 告警事件：

| 事件 | 匹配 |
|---|---|
| root 登录 | `aws.signin` `ConsoleLogin` 且 `userIdentity.type=Root` |
| root API 调用 | CloudTrail API `userIdentity.type=Root` |
| 关闭/修改 CloudTrail | `StopLogging` / `DeleteTrail` / `UpdateTrail` / `PutEventSelectors` |
| 关闭 GuardDuty | `DeleteDetector` / `UpdateDetector` / `DisassociateFromMasterAccount` |
| 创建 Access Key | `iam:CreateAccessKey` |
| 修改联系人 | `account:PutAlternateContact` / `PutContactInformation` / `DeleteAlternateContact` |
| GuardDuty 高危发现 | `aws.guardduty` `GuardDuty Finding` severity ≥ 7 |
| AWS Health | `aws.health` |

| 告警链路防篡改 | 告警规则/目标被改删、SNS topic 或订阅被改删、转发角色被改删、日志桶策略/生命周期/版本控制被改删 |
| GuardDuty 抑制 | `CreateFilter` / `UpdateFilter` / `ArchiveFindings` / 成员解除关联等 |
| 区域开通 | `account:EnableRegion` / `DisableRegion`（新开通区域没有转发规则和 GuardDuty） |

- 前提：基于 CloudTrail 的事件规则需要至少一条正在记录的 Trail（M3 先于 M4 执行，工具会校验）
- 复检不仅看规则是否存在，还比对 `State=ENABLED`、事件模式与目标 ARN 是否与预期一致；不一致即 FAIL 并可一键修复
- 转发区域始终包含 us-east-1（IAM 等全局服务事件只在这里产生），即使 `--regions` 排除了它
- 转发规则被删除时，删除事件本身无法被已删除的规则转发 → 依赖定期重跑 `--check-only` 校验链路完整性
- 验收：修复完成后可选发送一条 SNS 测试消息；并提示"用 root 登录一次验证 5 分钟内收到告警"

---

## 6. 断点续跑与状态

**目录**：`~/.aws-account-hardening/<account_id>/`

| 文件 | 内容 |
|---|---|
| `state-<mode>.json` | 按模式（guided / check / triage）分别保存：检查结果、已选/已跳过项、已录入参数，互不覆盖 |
| `changes.jsonl` | 追加写；每次写操作一条：`ts / module / action / resource_arn / status(pending→done/failed) / rollback 参数` |
| `report-<ts>.md` / `.json` | 报告 |

- 每个模块（以及 triage 中的每个区域）完成即落盘，写入采用 tmp 文件 + `os.replace` 原子替换
- 修复执行时现场查询资源状态（不依赖检查阶段的缓存），续跑与首次运行行为一致
- 分区域操作有任一区域失败即标记该项为 failed（可 `--restart` 重试），不会误标完成
- 所有修复**幂等**：执行前重新检查，已满足则跳过
- 长扫描期间持续打印进度；启动提示"断开后重新打开 CloudShell 并运行同一命令即可继续"
- **注意**：CloudShell 持久存储按区域隔离 → 必须在同一区域重开 CloudShell 才能续跑（启动时打印提示）；**VPC 环境无持久存储**，检测到后警告

---

## 7. 安全与可回滚

- 默认选择为 **No**；每个写操作单独确认
- 所有创建的资源：名称前缀 `acct-sec-`，标签 `ManagedBy=aws-account-hardening`、`CreatedAt`
- `--rollback` 仅处理 `changes.jsonl` 中记录、且**实时核对仍带上述标签**的资源，按逆序撤销；缺标签的跳过并标记 kept
- 回滚前列出会削弱检测能力的项单独警示；topic 上有订阅、删除日志桶、删除 detector 均需二次确认；日志桶默认**保留不删**（审计证据）
- 同名资源已存在但不是本工具创建的（topic / 规则 / 转发角色 / 日志桶）→ 停止，不接管
- Control Tower 识别失败（如无权限）按 CT 账号处理（fail-closed）
- 不修改、不删除客户已有资源；v1 不对任何 Access Key、IAM 策略、SCP 做写操作
- 日志/报告中不输出任何 secret；Access Key 只显示后 4 位
- 输入校验：邮箱、电话、CIDR、账号 ID（ASCII 数字）、区域名；文本拒绝控制字符/零宽/双向覆盖字符
- 输出清洗：终端与报告中所有外部数据（AWS 返回值、用户输入）剔除控制与不可见字符，防终端转义注入；示例 CLI 用 `shlex.quote`
- 本地文件：目录 700 并校验属主，文件 600，`O_NOFOLLOW`，临时文件 `O_EXCL`
- 所需权限：
  - `--check-only` / `--triage`：`SecurityAudit` + `ViewOnlyAccess` 托管策略 + `account:GetAlternateContact` + `ce:GetCostAndUsage`
  - 修复：建议 `AdministratorAccess`；另附一份最小权限自定义策略 `docs/fix-policy.json`

---

## 8. 代码结构（单文件内分区）

```
aws_account_hardening.py
├─ 常量与配置（名称前缀、默认值、费用说明文案）
├─ ui        : 彩色输出、表格、prompt/confirm、输入校验
├─ state     : StateStore（原子读写）、ChangeLog
├─ aws       : Session/client 工厂（重试配置 adaptive）、区域枚举、身份/形态识别
├─ model     : Finding(dataclass, frozen)、FixPlan(frozen)
├─ checks/fixes : M1–M10 各一个类，统一接口
│                 check(ctx) -> list[Finding]
│                 plan(ctx, finding) -> FixPlan     # 展示用：操作/CLI/费用/风险/回滚
│                 apply(ctx, plan) -> ChangeRecord
│                 rollback(ctx, record)
├─ triage    : 只读排查
├─ report    : Markdown / JSON
└─ main      : argparse、流程编排
```

预计 1500–2000 行。

---

## 9. 测试

| 层级 | 方式 |
|---|---|
| 单元 | pytest + `botocore.stub.Stubber`（每个 check/fix 的正常、已满足、异常、无权限分支） |
| 集成 | pytest + moto（开发依赖，不随工具分发）：fix → 复检 → rollback |
| E2E | 沙箱账号的 CloudShell 中真实运行：check-only → 引导修复 → 中途断开续跑 → rollback |

---

## 10. 待确认 / 需实测

1. `aws.signin` 事件在非 us-east-1 区域的投递行为（决定转发规则的区域覆盖）
2. GuardDuty IPSet 的 S3 Location 在跨区域（桶在 home region、detector 在其他区域）时是否可用
3. 修复模式需在沙箱账号的 CloudShell 中端到端实测（v1 已在真实账号完成只读检查验证，修复路径仅 moto 验证）
4. 文档 1.1 中"关闭 60 天后永久关闭"与 AWS 账号关闭文档中 90 天 post-closure period 不一致，需核对知识中心原文
5. 文档 7.3 中"IAM 策略不能限制 root"：SCP 可以限制成员账号 root，表述需补充
