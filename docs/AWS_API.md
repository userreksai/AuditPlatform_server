# AWS IAM 审计实现依据

核验日期：2026-11-09。下列内容根据 AWS 官方文档整理；字段解释和 IP 判读属于本项目的审计展示规则。

## 采集 API 与字段

| 官方 API | 本平台用途 |
| --- | --- |
| [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) | 获取凭证实际所属的 AWS 账号 ID；官方说明该调用不需要显式授予权限。 |
| [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) | 使用 User、Group 过滤，取得 IAM 用户、组、直接/继承关系和内联策略。每次检查 IsTruncated 并沿 Marker 翻页。 |
| [UserDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UserDetail.html) | 获取用户稳定 ID、ARN、创建时间、组、托管策略关联及权限边界。本项目负责人来自账号配置或平台备注；需求检查也是平台记录。 |
| [GetPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html) / [GetPolicyVersion](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html) | 对所有直接、组继承和边界策略读取当前 DefaultVersionId 的文档；按 ARN 在一次采集中缓存。政策文档可能使用 RFC 3986 URL 编码，先尝试 JSON，再解码一次；不能双重解码或把字面加号改成空格。 |
| [ListAccountAliases](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccountAliases.html) | 获取账号别名；平台账号名称优先来自配置文件。 |
| [GetLoginProfile](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetLoginProfile.html) | 是否存在控制台密码。成功表示存在登录配置，NoSuchEntity 表示无该配置；AccessDenied、网络错误不能当作禁用。存在配置不等于所有其他策略都允许控制台访问。 |
| [ListMFADevices](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListMFADevices.html) | 获取用户已关联 MFA 设备，按 Marker 翻页；查询错误显示未知。已启用设备不等于每次 API 调用都强制 MFA。 |
| [ListAccessKeys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html) | 读取每把 Key ID、状态和创建时间，仍需处理分页；AWS 不会再次返回 Secret Access Key。 |
| [GetAccessKeyLastUsed](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html) | 获取每把 Key 最后使用时间、服务和区域。 |

## 凭证报告时效

[AWS 凭证报告说明](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)：GenerateCredentialReport 后需等待 COMPLETE，再读取 GetCredentialReport。AWS 最多每四小时重新生成一次，期间请求会返回已有报告。因此平台“获取全部”会重新调用 AWS，但密码最后使用时间可能来自四小时内已有报告，必须标注报告生成时间。password_last_used 的 no_information 与 N/A 含义不同，不能伪造时间或断言绝对从未登录。报告包含 root 行，本平台以 IAM 用户为维度，不将该行冒充普通用户。

## IP 条件判读

1. 保留每条 Statement 的 Sid、Effect、Action/NotAction、Resource/NotResource、完整 Condition，展示策略名和直接/组继承来源。保留 IpAddress、NotIpAddress、IfExists 和集合运算符、单值/数组、IPv4/IPv6。[条件运算符官方说明](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)。
2. 截图 sp7969 的 Deny + NotIpAddress + aws:SourceIp 表示：在该条语句的操作、资源及其他条件覆盖范围内，来自给定范围以外的请求会触发显式拒绝。它自身不授予权限；结合 SecurityAudit 等允许策略理解。[AWS 官方示例](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-ip.html)。
3. Allow + IpAddress 只限制该 Allow 语句；其他允许语句可能仍授予权限，不能单凭它标记为全局强制白名单。Deny + IpAddress 是拒绝名单，不应称为白名单。[AWS 条件运算符](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)。
4. aws:SourceIp 针对公网来源，经过 VPC endpoint 的请求不带这个键；aws:VpcSourceIp 是私网来源，需结合 SourceVpc/SourceVpce 识别网络。其他 Condition 项和键是否存在都会影响结果。[AWS 全局条件键](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)。
5. 权限边界只约束权限，不单独授予权限。最终授权还受资源策略、SCP、会话策略及请求上下文等影响；本平台展示 IAM 用户和组的策略证据，不是完整授权模拟器。[AWS 权限边界说明](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)。

## 采集身份所需权限

按当前 API 实现授予以下动作即可，无需 AdministratorAccess。Resource 可先使用 `*` 确保账号级清单 API 可调用，再按组织规范收紧可限定资源的动作。唯一生成操作为凭证报告，不更改用户、策略或密钥。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AuditPlatformReadIAM",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:ListAccountAliases",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport"
      ],
      "Resource": "*"
    }
  ]
}
```

## 失败处理要求

账号身份确认失败或权限列表读取失败，不覆盖该账号已有完整快照。单项采集失败保留该字段未知状态与错误证据，账号显示部分成功；不把 AccessDenied 等错误解释成“无 Key / MFA 未开 / 无 IP 限制”。凭证配置不进入前端 API、SQLite 快照或日志。所有时间为带时区 ISO 8601；调度器使用 Asia/Shanghai 09:00，不能依赖 Linux 主机默认时区。
