# AWS 账号安全与访问管理最佳实践

> 适用对象：企业 IT / 云平台负责人、安全负责人、财务与账号管理员
> 文档目的：说明 AWS 账号被暂停后如何恢复，并给出防止此类事件再次发生的账号管理最佳实践。
> 说明：具体的暂停原因与恢复要求，以 AWS 发送的通知邮件和 AWS Support 的回复为准。

---

## 一、账号被暂停后的恢复流程

### 1.1 时限：必须尽快处理

根据 AWS 知识中心的说明：

- 账号被暂停后需在 **30 天内**恢复，否则 AWS 会关闭该账号。
- 账号关闭 **60 天后**关闭即为永久，无法重新开启，账号内容会被删除。
- 暂停期间**无法删除账号中的资源**，AWS Support 也不能代为删除。

### 1.2 恢复步骤

1. **查邮件**：检查 root 邮箱和备用联系人邮箱（包括垃圾邮件），找到 AWS 的通知，确认原因和要求补充的信息。
2. **按要求回复**：如果 AWS 要求补充信息（例如身份验证、登录情况说明），直接回复邮件或在 Support case 中提供。
3. **开 Support case**：用 root 用户登录 → Support Center → 创建 *Account and billing* 类 case（类别选择账号恢复 / Account reinstatement）。所有支持计划都可以开此类 case。
4. **成员账号**：如果被暂停的账号属于 AWS Organizations，同时联系管理账号（Management Account）的负责人。
5. **无法登录时**：通过 AWS 账号支持表单联系账号验证团队。

### 1.3 在 case 中建议说明的内容

- 异常登录是否为本单位人员所为：时间、地点、网络环境（例如出差、家庭网络、VPN）。
- 已完成的安全处置（见 1.4），附截图。
- 业务影响范围与期望的恢复时间。

### 1.4 无论是否误报，都先按"凭证可能泄露"处置

| 动作 | 说明 |
|---|---|
| 修改 root 密码，确认 root 邮箱可控 | root 邮箱应为企业群组邮箱 |
| root 启用 MFA | 建议至少注册 2 个 MFA 设备（硬件密钥或通行密钥） |
| 删除 root 的 Access Key | root 不应持有任何长期密钥 |
| 审查 IAM 用户与 Access Key | 停用不认识的用户和密钥，轮换所有长期密钥 |
| 审查所有区域的资源 | 重点关注 EC2/GPU 实例、Lambda、新建的 IAM 角色和 S3 存储桶 |
| 查 CloudTrail 事件历史 | 默认保留 90 天；按 `ConsoleLogin` 事件和来源 IP 排查异常操作 |
| 检查账单 | 确认是否有异常费用；如因未授权使用产生费用，可在 case 中说明 |

---

## 二、账号管理十项最佳实践

| # | 实践 | 解决的问题 | 优先级 |
|---|---|---|---|
| 1 | 保护 root 用户 | 最高权限凭证泄露 | 立即 |
| 2 | 配置备用联系人与通知 | AWS 安全通知无人接收 | 立即 |
| 3 | 开启日志审计 | 出事后无法溯源 | 立即 |
| 4 | 开启威胁检测与告警 | 异常登录无人知晓 | 立即 |
| 5 | 人员统一使用 IAM Identity Center 登录 | 账号分散、离职回收难 | 短期 |
| 6 | 淘汰长期访问密钥 | 密钥泄露风险 | 短期 |
| 7 | 控制访问来源（网络与设备） | 从非受控网络登录 | 短期 |
| 8 | 多账号结构与 SCP 护栏 | 一个账号出事影响全部业务 | 中期 |
| 9 | 集中式 root 访问管理（多账号） | 成员账号 root 难以统一管控 | 中期 |
| 10 | 定期审计与应急演练 | 权限蔓延、出事时手忙脚乱 | 持续 |

### 实践 1：保护 root 用户

- **日常不使用 root**，仅用于必须由 root 执行的少数任务。
- **不创建 root Access Key**；已有的立即删除。
- root 邮箱使用**企业群组邮箱**（例如 `aws-root-prod@example.com`），至少 2 名负责人可收到邮件，不使用个人邮箱。
- root 启用 **MFA**，凭据纳入保险柜或双人保管流程。

**验收标准**：IAM 凭证报告中 root 的 `mfa_active = true`，`access_key_1_active = false`。

### 实践 2：配置备用联系人与通知

- 在 **账号 → 备用联系人（Alternate contacts）** 中分别填写**安全、账单、运维**三类联系人，使用群组邮箱和值班电话。
- 订阅 **AWS Health** 事件通知，转发到企业 IM 或工单系统。

> AWS 的安全通知默认发给 root 邮箱和安全联系人。通知无人接收或无人响应，是账号被进一步限制的常见原因之一。

**验收标准**：三类备用联系人均已配置；用测试事件确认通知能到达值班人员。

### 实践 3：开启日志审计

- 创建 **CloudTrail 组织级 Trail**（覆盖所有区域、所有账号），日志写入专用日志账号的 S3 存储桶，并开启日志文件完整性验证。
- 日志存储桶开启版本控制，限制删除权限。

**验收标准**：任一账号、任一区域的管理事件都能在日志账号中查到，且保留超过 90 天。

### 实践 4：开启威胁检测与告警

- **Amazon GuardDuty** 在所有账号、所有区域开启，由安全账号统一管理。与账号登录相关的检测包括：

| GuardDuty 发现类型 | 含义 |
|---|---|
| `Policy:IAMUser/RootCredentialUsage` | root 凭证被使用 |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | 异常的控制台登录 |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | 来自已知恶意 IP 的调用 |
| `UnauthorizedAccess:IAMUser/TorIPCaller` | 来自 Tor 出口节点的调用 |
| `InitialAccess:IAMUser/AnomalousBehavior` | 与初始访问相关的异常 API 行为 |

- 将企业出口 IP 加入 GuardDuty **可信 IP 列表**，减少误报。
- 用 **EventBridge** 对关键事件实时告警：root 登录、关闭 CloudTrail、创建 Access Key、修改账单联系人。
- 用 **AWS Security Hub** 汇总合规检查结果（如 root MFA、密钥轮换）。

**验收标准**：模拟一次 root 登录，值班人员 5 分钟内收到告警。

### 实践 5：人员统一使用 IAM Identity Center 登录

- 员工通过 **IAM Identity Center（单点登录）** 访问各账号，按**权限集**分配最小权限，强制 MFA。
- 对接企业现有身份源（如 Microsoft Entra ID、Okta 等 SAML/SCIM 身份源），**入职开通、离职回收自动生效**。
- 不再为人员创建 IAM 用户。

**验收标准**：除破窗（break-glass）账号外，人员访问全部经由 Identity Center。

### 实践 6：淘汰长期访问密钥

- 程序访问使用 **IAM 角色与临时凭证**：EC2 用实例配置文件，EKS 用 Pod Identity / IRSA，CI/CD 用 OIDC 联合身份。
- 确有必要保留的长期密钥：定期轮换，并用 IAM 凭证报告监控最后使用时间。
- 禁止在代码、配置文件和镜像中硬编码密钥。

**验收标准**：长期 Access Key 数量逐月下降；90 天未使用的密钥全部停用。

### 实践 7：控制访问来源（网络与设备）

**在身份源一侧控制登录（推荐）**：在企业身份源上配置条件访问策略，限制可登录的网络位置、设备合规状态和 MFA 强度。这是控制"谁能从哪里登录"最有效的位置。

**在 AWS 一侧限制 API 调用来源**：用 IAM 策略或 SCP 拒绝来自非企业出口 IP 的调用，示例如下：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideCorpIP",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "NotIpAddress": { "aws:SourceIp": ["192.0.2.0/24", "203.0.113.0/24"] },
        "Bool": { "aws:ViaAWSService": "false" }
      }
    }
  ]
}
```

实施前需注意：

1. **`aws:ViaAWSService` 条件**用于放行 AWS 服务代表您发起的调用（例如 CloudFormation 创建资源），否则这些调用也会被拒绝。
2. **通过 VPC 终端节点的请求不携带公网来源 IP**，会被上述策略拒绝；此类场景需结合 `aws:SourceVpc` / `aws:SourceVpce` 单独放行。
3. **IAM 策略不能限制 root 用户**，也不阻止登录动作本身，只限制登录后的操作。
4. 出差和远程办公需统一经企业 VPN 访问，固定出口 IP 后再加入白名单。
5. **保留破窗账号**，并先在测试账号或单个权限集上灰度验证，避免把管理员自己锁在外面。

**验收标准**：从非白名单网络发起的 API 调用被拒绝，正常业务和 AWS 服务调用不受影响。

### 实践 8：多账号结构与 SCP 护栏

- 使用 **AWS Organizations** 按环境和职能拆分账号：生产、测试、日志归档、安全工具等，生产与实验隔离。
- 常用 **SCP（服务控制策略）** 护栏：
  - 禁止关闭或修改 CloudTrail、GuardDuty
  - 禁止成员账号退出组织
  - 限制可使用的区域
  - 禁止为 IAM 用户创建 Access Key
- 希望快速建立标准化多账号环境的，可评估 **AWS Control Tower**。

**验收标准**：生产工作负载不与开发测试共用账号；关键护栏 SCP 已挂载到对应 OU。

### 实践 9：集中式 root 访问管理（适用于多账号）

- 在 Organizations 中启用 **集中式 root 访问管理**后，可以删除成员账号的 root 密码、访问密钥和 MFA；在组织中新建的账号默认没有 root 凭证。
- 需要执行必须由 root 完成的任务时，由管理账号或 IAM 委派管理员发起**特权任务**（短期 root 会话），任务完成后再删除凭证。

**验收标准**：成员账号无可用 root 登录凭证；特权任务有审批与记录。

### 实践 10：定期审计与应急演练

- **每月**：审查 IAM 凭证报告、IAM Access Analyzer 的未使用访问发现，回收闲置权限。
- **每季度**：复核备用联系人、破窗账号、root 保管流程是否仍然有效。
- **每半年**：做一次账号安全事件桌面演练，演练内容包括：收到 AWS 安全通知 → 判定 → 处置 → 开 case → 复盘。

---

## 三、自查清单

- [ ] root 已启用 MFA，且没有 Access Key
- [ ] root 邮箱为企业群组邮箱，至少 2 人可收件
- [ ] 安全、账单、运维三类备用联系人已配置
- [ ] CloudTrail 组织级 Trail 已覆盖所有账号和区域
- [ ] GuardDuty 已在所有账号和区域开启，告警能到达值班人员
- [ ] root 登录有实时告警
- [ ] 人员通过 IAM Identity Center 登录，并强制 MFA
- [ ] 已制定长期 Access Key 的淘汰计划
- [ ] 已在身份源或 AWS 侧设置访问来源控制，并保留破窗账号
- [ ] 生产与测试分属不同账号，关键 SCP 护栏已生效
- [ ] 有书面的账号安全事件应急流程，且演练过

---

## 四、实施路线图

| 阶段 | 时间 | 重点工作 |
|---|---|---|
| 止血 | 当天 | 恢复账号；完成 1.4 的安全处置 |
| 加固 | 1 周内 | 实践 1–4：root 保护、备用联系人、日志审计、威胁检测与告警 |
| 收口 | 2–4 周 | 实践 5–7：IAM Identity Center、淘汰长期密钥、访问来源控制 |
| 体系化 | 1–2 个月 | 实践 8–10：多账号结构与 SCP、集中式 root 管理、定期审计与演练 |

建议在"体系化"阶段，结合 **AWS Well-Architected 框架安全支柱**做一次正式评审。

---

## 五、参考文档

- AWS 知识中心：如何恢复被暂停的 AWS 账号 — https://repost.aws/knowledge-center/reactivate-suspended-account
- AWS 知识中心：发现账号中存在未授权活动怎么办 — https://repost.aws/knowledge-center/potential-account-compromise
- root 用户最佳实践 — https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
- 集中式 root 访问管理 — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html
- IAM 安全最佳实践 — https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- 按来源 IP 拒绝访问的策略示例 — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-ip.html
- 配置备用联系人 — https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html
- GuardDuty IAM 发现类型 — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html
- GuardDuty 可信 IP 列表与威胁列表 — https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload-lists.html
- 修复可能泄露的 AWS 凭证 — https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html
- 为组织创建 CloudTrail Trail — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html
- SCP 示例 — https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html
- IAM Identity Center — https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html
- 多账号环境组织白皮书 — https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/organizing-your-aws-environment.html
- AWS 安全参考架构（SRA） — https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html
