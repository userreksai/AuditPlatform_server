package audit

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Secrets Manager 读取权限：以 secretsmanager:GetSecretValue 为判定动作
// （BatchGetSecretValue 同样要求对每个 Secret 拥有 GetSecretValue）。
// 只分析已采集的用户直接/用户组身份策略和权限边界，不是 IAM 授权模拟器。
const secretsReadAction = "secretsmanager:GetSecretValue"

const (
	SecretsFull    = "full"    // 存在无条件、覆盖全部 Secret 的允许，且未发现针对性拒绝
	SecretsLimited = "limited" // 允许受资源范围、条件或拒绝语句约束
	SecretsDenied  = "denied"  // 允许被无条件拒绝或权限边界阻断
	SecretsNone    = "none"    // 未发现授予读取的允许语句
	SecretsUnknown = "unknown" // 策略采集不完整
)

func globMatch(pattern, value string, foldCase bool) bool {
	expr := "^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(pattern)) + "$"
	if foldCase {
		expr = "(?i)" + expr
	}
	ok, err := regexp.MatchString(expr, value)
	return err == nil && ok
}

func anyGlob(patterns []string, value string, foldCase bool) bool {
	for _, p := range patterns {
		if globMatch(p, value, foldCase) {
			return true
		}
	}
	return false
}

// statementActionMatches 判断语句的 Action/NotAction 是否覆盖指定动作。
func statementActionMatches(s map[string]json.RawMessage, action string) (bool, error) {
	if raw := s["Action"]; len(raw) > 0 {
		v, e := stringValues(raw)
		if e != nil {
			return false, e
		}
		return anyGlob(v, action, true), nil
	}
	if raw := s["NotAction"]; len(raw) > 0 {
		v, e := stringValues(raw)
		if e != nil {
			return false, e
		}
		return !anyGlob(v, action, true), nil
	}
	return false, nil
}

// resourceScope 返回语句对目标服务资源的覆盖：all=覆盖全部样例资源，some=可能覆盖部分资源。
func resourceScope(s map[string]json.RawMessage, service string, samples []string) (all, some bool, err error) {
	if raw := s["Resource"]; len(raw) > 0 {
		v, e := stringValues(raw)
		if e != nil {
			return false, false, e
		}
		all = true
		for _, sample := range samples {
			if !anyGlob(v, sample, false) {
				all = false
			}
		}
		for _, r := range v {
			parts := strings.SplitN(r, ":", 4)
			if r == "*" || (len(parts) >= 3 && globMatch(parts[2], service, true)) {
				some = true
			}
		}
		return all, some || all, nil
	}
	if raw := s["NotResource"]; len(raw) > 0 {
		v, e := stringValues(raw)
		if e != nil {
			return false, false, e
		}
		for _, sample := range samples {
			if !anyGlob(v, sample, false) {
				some = true
			}
		}
		return false, some, nil
	}
	return false, false, nil
}

func secretSamples(partition, account string) []string {
	return []string{
		"arn:" + partition + ":secretsmanager:us-east-1:" + account + ":secret:audit-sample-a1B2c3",
		"arn:" + partition + ":secretsmanager:ap-southeast-1:" + account + ":secret:prod/db/password-Zz9Yx8",
	}
}

func userPartitionAccount(u *AuditUser) (string, string) {
	partition, account := "aws", u.AccountID
	if parts := strings.SplitN(u.ARN, ":", 6); len(parts) == 6 && parts[1] != "" {
		partition = parts[1]
		if account == "" {
			account = parts[4]
		}
	}
	return partition, account
}

// accessCheck 描述一次针对单个 IAM 动作的策略证据评估。
type accessCheck struct {
	Action  string   // 例如 secretsmanager:GetSecretValue
	Service string   // ARN 中的服务名，例如 secretsmanager / rds
	Samples []string // 用于判断“全部资源”的样例 ARN
	Unit    string   // 证据中的资源称谓，例如 Secret / RDS 资源
}

// evaluateAccess 只分析已采集的用户直接/用户组身份策略和权限边界，返回 full/limited/denied/none/unknown。
func evaluateAccess(u *AuditUser, complete bool, c accessCheck) (string, []string) {
	allowFull, allowSome, denyFull, denySome := false, false, false, false
	evidence := []string{}
	label := func(p Policy, s map[string]json.RawMessage) string {
		name := p.Name
		if p.Source == "group" && p.GroupName != "" {
			name = p.GroupName + " → " + name
		}
		if sid := scalar(s["Sid"]); sid != "" {
			name += " / " + sid
		}
		return name
	}
	for _, p := range u.Policies {
		if len(p.Warnings) > 0 {
			complete = false
		}
		ss, e := statements(p.Document)
		if e != nil {
			complete = false
			continue
		}
		for _, s := range ss {
			match, e := statementActionMatches(s, c.Action)
			if e != nil {
				complete = false
				continue
			}
			if !match {
				continue
			}
			all, some, e := resourceScope(s, c.Service, c.Samples)
			if e != nil {
				complete = false
				continue
			}
			if !some {
				continue
			}
			conditional := len(s["Condition"]) > 0
			switch scalar(s["Effect"]) {
			case "Allow":
				if all && !conditional {
					allowFull = true
					evidence = append(evidence, "允许（全部 "+c.Unit+"）: "+label(p, s))
				} else {
					allowSome = true
					scope := "部分 " + c.Unit
					if all {
						scope = "全部 " + c.Unit + "，带条件"
					} else if conditional {
						scope = "部分 " + c.Unit + "，带条件"
					}
					evidence = append(evidence, "允许（"+scope+"）: "+label(p, s))
				}
			case "Deny":
				if all && !conditional {
					denyFull = true
					evidence = append(evidence, "拒绝（全部 "+c.Unit+"）: "+label(p, s))
				} else {
					denySome = true
					evidence = append(evidence, "拒绝（部分 "+c.Unit+" 或带条件，如来源 IP）: "+label(p, s))
				}
			}
		}
	}
	boundaryBlocks := false
	if b := u.PermissionsBoundary; b != nil {
		if len(b.Warnings) > 0 {
			complete = false
		} else if ss, e := statements(b.Document); e != nil {
			complete = false
		} else {
			allowed := false
			for _, s := range ss {
				match, e := statementActionMatches(s, c.Action)
				if e != nil || !match || scalar(s["Effect"]) != "Allow" {
					continue
				}
				if _, some, e := resourceScope(s, c.Service, c.Samples); e == nil && some {
					allowed = true
				}
			}
			if !allowed {
				boundaryBlocks = true
				evidence = append(evidence, "权限边界未允许 "+c.Action+": "+b.Name)
			}
		}
	}
	switch {
	case !complete:
		return SecretsUnknown, evidence
	case !allowFull && !allowSome:
		return SecretsNone, evidence
	case denyFull || boundaryBlocks:
		return SecretsDenied, evidence
	case allowFull && !denySome:
		return SecretsFull, evidence
	default:
		return SecretsLimited, evidence
	}
}

func SummarizeSecrets(u *AuditUser, complete bool) {
	partition, account := userPartitionAccount(u)
	state, evidence := evaluateAccess(u, complete, accessCheck{Action: secretsReadAction, Service: "secretsmanager", Samples: secretSamples(partition, account), Unit: "Secret"})
	u.SecretsAccess = state
	u.SecretsEvidence = evidence
	const scopeNote = "仅分析用户直接及用户组身份策略与权限边界；未评估 SCP、Secret 资源策略、KMS 密钥策略（客户托管密钥还需 kms:Decrypt）。"
	switch state {
	case SecretsUnknown:
		u.SecretsExplanation = "策略或关联信息采集不完整，无法确认 Secrets Manager 读取权限。" + scopeNote
	case SecretsNone:
		u.SecretsExplanation = "未发现授予 " + secretsReadAction + " 的允许语句。" + scopeNote
	case SecretsDenied:
		u.SecretsExplanation = "存在 " + secretsReadAction + " 的允许，但被无条件拒绝或权限边界阻断。" + scopeNote
	case SecretsFull:
		u.SecretsExplanation = "可读取账号内全部 Secret 的值（" + secretsReadAction + " 无条件允许于全部资源）。" + scopeNote
	default:
		u.SecretsExplanation = "可读取 Secret 的值，但受资源范围、条件或带条件的拒绝语句（如来源 IP）约束。" + scopeNote
	}
}
