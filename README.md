# AWS 账号安全加固工具（CloudShell 引导式）

依据《AWS 账号安全与访问管理最佳实践》（[docs/AWS-account-security-best-practices.md](docs/AWS-account-security-best-practices.md)），在 AWS CloudShell 中逐项**检查**账号安全配置，并在**逐项确认**后修复低风险项，最后输出 Markdown / JSON 报告。

- 单文件 `aws_account_hardening.py`，仅依赖 Python 标准库 + boto3（CloudShell 预装），兼容 Python 3.9+
- 支持独立账号、Organizations 管理账号、成员账号，自动识别 Control Tower（CT 管理的部分只检查不修改）
- 进度自动保存：CloudShell 闲置断开后，重新运行同一命令即可继续

## 快速开始

```bash
# 在 CloudShell 中（建议先切到你希望作为“主区域”的区域，告警和日志会汇聚到这里）
curl -fsSLO <分发地址>/aws_account_hardening.py
sha256sum aws_account_hardening.py          # 与发布页的校验值比对

python3 aws_account_hardening.py --check-only   # 1. 先只读检查，看报告
python3 aws_account_hardening.py                # 2. 引导加固：逐项确认后修复
```

| 命令 | 说明 |
|---|---|
| `python3 aws_account_hardening.py` | 引导模式：全量检查 → 逐项询问是否修复（默认跳过） |
| `--check-only` | 只读检查，只出报告 |
| `--triage [--days N]` | 疑似泄露排查（只读）：近期新建的用户/Key/角色、GPU 实例、Lambda、S3 桶、90 天 ConsoleLogin、敏感操作、费用突增 |
| `--rollback` | 按变更日志逆序撤销本工具创建的资源 |
| `--regions a,b` / `--exclude-regions a,b` | 区域范围，默认所有已启用区域 |
| `--home-region r` | 主区域，默认 CloudShell 当前区域 |
| `--restart` | 忽略上次进度，重新检查 |

## 检查与修复范围

状态说明：**AUTO** 工具可自动修复 · **GUIDE** 只给出操作指引 · **MANUAL** 需人工确认

| 模块 | 对应实践 | 检查 | 修复 |
|---|---|---|---|
| M1 root 保护 | 1 | MFA、root Access Key、近 30 天使用、root 邮箱 | GUIDE（root MFA 和邮箱没有 API；root Key 在 v1 中不自动删除） |
| M2 备用联系人 | 2 | 安全 / 账单 / 运维三类联系人 | AUTO |
| M3 CloudTrail | 3 | 多区域且在记录的 Trail、完整性验证、组织级 Trail、保留期 | AUTO：新建加固日志桶 + 多区域 Trail（管理账号创建组织级 Trail） |
| M4 GuardDuty | 4 | 各区域 detector、可信 IP 列表、委派管理员、成员自动启用 | AUTO |
| M4A 实时告警 | 2 / 4 | SNS topic、订阅确认、EventBridge 规则（含各区域转发） | AUTO |
| M4S Security Hub | 4 | Security Hub CSPM + FSBP、AWS Config 记录 | AUTO（仅主区域，**收费**） |
| M5 Identity Center | 5 | 实例、IAM 控制台用户、MFA | GUIDE |
| M6 长期密钥 | 6 | 90 天未使用 / 未轮换的 Access Key | GUIDE（v1 不停用 Key） |
| M7 访问来源 | 7 | — | GUIDE（v1 不生成、不挂载 IP 策略） |
| M8 SCP 护栏 | 8 | 全部功能、SCP 启用、五类护栏是否存在并已挂载 | GUIDE（v1 不创建、不挂载 SCP） |
| M9 集中式 root | 9 | RootCredentialsManagement / RootSessions | AUTO（只开启能力，不删除成员 root 凭证） |
| M10 审计 | 10 | 各区域外部访问分析器、未使用访问分析器 | AUTO（未使用访问分析器**收费**） |

实时告警覆盖以下事件：root 登录或 API 调用、CloudTrail 被关闭或修改、GuardDuty 被关闭/修改/添加抑制规则、创建 Access Key / IAM 用户 / 控制台密码、修改账号联系人或开通区域、GuardDuty 高危发现（severity ≥ 7）、AWS Health 事件，以及**告警链路自身被篡改**（规则、SNS topic/订阅、转发角色、日志桶策略被改删）。复检会比对规则的启用状态、事件模式和目标，被禁用或改动即判 FAIL。非主区域的事件先转发到主区域 default bus，再统一投递到一个 SNS topic。

## 安全边界

- **所有写操作都要逐项确认，默认选“跳过”**，没有 `--yes` 参数
- v1 **不对**以下对象做任何写操作：Access Key、IAM 策略、SCP、成员账号 root 凭证、客户已有的 Trail / Config 记录器 / 规则
- 创建的资源统一使用 `acct-sec-` 前缀，并打上标签 `ManagedBy=aws-account-hardening`
- 同名资源（日志桶、SNS topic、EventBridge 规则、转发角色）已存在但不是本工具创建的 → 停止，不接管
- 客户已有的 AWS Config 记录器完全不碰
- 可信 IP 列表只接受企业公网出口：IPv4 至少 /20、IPv6 至少 /48，拒绝任何私有/保留网段
- 回滚只处理变更日志里记录、且实时核对仍带本工具标签的资源；会削弱检测能力的项单独警示；日志桶默认保留（审计证据）

## 费用提示

| 资源 | 费用 |
|---|---|
| CloudTrail 第一份管理事件 Trail | 免费；S3 存储按量计费 |
| GuardDuty | 每个区域 30 天试用，之后按事件量计费 |
| SNS 邮件 / EventBridge | 基本免费（跨区域转发约 $1 / 百万事件） |
| Security Hub CSPM + AWS Config | **持续收费**，引导时默认跳过 |
| Access Analyzer 未使用访问 | **按分析的角色/用户数量收费** |
| `--triage` 查询 Cost Explorer | $0.01 / 次请求（执行前会询问） |

## 所需权限

- `--check-only` / `--triage`：AWS 托管策略 `SecurityAudit` + `ViewOnlyAccess`，另加 `account:GetAlternateContact`、`ce:GetCostAndUsage`
- 引导修复：建议使用 `AdministratorAccess`；组织级功能需要在**管理账号**中运行

## 本地文件

保存在 `~/.aws-account-hardening/<账号ID>/`（目录权限 700，文件权限 600）：

| 文件 | 内容 |
|---|---|
| `state-<模式>.json` | 各模式（guided / check / triage）独立的进度、检查结果、已录入的参数 |
| `changes.jsonl` | 追加写的变更日志（用于续跑和回滚） |
| `report-*.md/json` | 检查报告 |
| `triage-*.md/json` | 排查报告，可作为 Support case 附件 |

> CloudShell 的持久存储**按区域隔离**：必须在同一区域重新打开 CloudShell 才能续跑。CloudShell VPC 环境没有持久存储。

## 仓库结构

```
aws_account_hardening.py   # 工具本体（单文件分发，CloudShell 中直接运行）
docs/
  AWS-account-security-best-practices.md   # 依据的最佳实践文档
  DESIGN.md                                # 设计文档（模块、告警架构、状态与回滚、待实测项）
tests/
  test_unit.py         # 纯函数：校验、分析、策略生成、状态存储、UI
  test_integration.py  # moto：修复 → 复检 → 回滚、引导流程、断点续跑、组织管理账号、triage
requirements-dev.txt   # 开发/测试依赖
pyproject.toml         # pytest / ruff 配置
```

## 开发与测试

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q --cov=aws_account_hardening   # 当前 110 个用例，覆盖率 91%
ruff check . && ruff format --check .
```

- 需同时在 Python 3.9（CloudShell）与 3.12 下通过
- moto 未实现的 API（如 GuardDuty IPSet、Security Hub 标准、Access Analyzer、CloudTrail LookupEvents）用 Stubber / monkeypatch 补齐

## 已知限制 / 待实测

- 修复模式目前仅在 moto 中验证；真实账号只完成了只读检查验证，请先在沙箱账号的 CloudShell 中端到端实测
- GuardDuty IPSet 的 S3 文件位于主区域，跨区域 detector 能否读取需实测确认
- 防篡改告警存在自指缺口：`acct-sec-alert-tamper-*` 规则自身、非主区域的转发规则或转发角色被禁用/删除时，该事件无法再被告警链路捕获，只能通过定期重跑 `--check-only` 发现（复检会比对规则状态、模式与目标）
- 复检目前不比对 topic 策略、转发角色策略与日志桶策略的内容；日志桶未启用 Object Lock，有足够权限的主体仍可删除日志
- 告警 SNS topic 未启用 KMS 加密（EventBridge 不支持 `alias/aws/sns`，需客户自管 CMK）
