package audit

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// DecodePolicy accepts the SDK's plain JSON or IAM's RFC 3986 encoded document.
// PathUnescape intentionally preserves literal '+' characters.
func DecodePolicy(raw string) (json.RawMessage, error) {
	b := []byte(raw)
	if !json.Valid(b) {
		s, e := url.PathUnescape(raw)
		if e != nil {
			return nil, e
		}
		b = []byte(s)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("policy is not a JSON object")
	}
	if _, ok := obj["Statement"]; !ok {
		return nil, fmt.Errorf("policy Statement missing")
	}
	return b, nil
}

func statements(doc json.RawMessage) ([]map[string]json.RawMessage, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(doc, &root); err != nil {
		return nil, err
	}
	raw := root["Statement"]
	var arr []map[string]json.RawMessage
	if len(raw) > 0 && raw[0] == '{' {
		var s map[string]json.RawMessage
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		return []map[string]json.RawMessage{s}, nil
	}
	if err := json.Unmarshal(raw, &arr); err != nil || arr == nil {
		return nil, fmt.Errorf("invalid Statement")
	}
	return arr, nil
}
func stringValues(raw json.RawMessage) ([]string, error) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil || many == nil {
		return nil, fmt.Errorf("expected string or string array")
	}
	return many, nil
}
func scalar(raw json.RawMessage) string { var s string; _ = json.Unmarshal(raw, &s); return s }
func star(raw json.RawMessage) bool {
	v, e := stringValues(raw)
	return e == nil && len(v) == 1 && v[0] == "*"
}
func validIP(v string) bool {
	if _, e := netip.ParsePrefix(v); e == nil {
		return true
	}
	_, e := netip.ParseAddr(v)
	return e == nil
}

// AnalyzePolicy extracts evidence, not an IAM authorization simulator.
func AnalyzePolicy(p *Policy) bool {
	p.IPConditions = []IPCondition{}
	if p.Warnings == nil {
		p.Warnings = []string{}
	}
	ss, err := statements(p.Document)
	if err != nil {
		p.Warnings = append(p.Warnings, "策略文档未能解析，无法判断 IP 条件")
		return false
	}
	for _, s := range ss {
		if len(s["Condition"]) == 0 {
			continue
		}
		var cond map[string]map[string]json.RawMessage
		if err = json.Unmarshal(s["Condition"], &cond); err != nil {
			p.Warnings = append(p.Warnings, "Condition 格式无法解析")
			continue
		}
		ops := make([]string, 0, len(cond))
		for op := range cond {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		for _, op := range ops {
			keys := make([]string, 0, len(cond[op]))
			for k := range cond[op] {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if !strings.EqualFold(key, "aws:SourceIp") && !strings.EqualFold(key, "aws:VpcSourceIp") {
					continue
				}
				vals, e := stringValues(cond[op][key])
				if e != nil {
					p.Warnings = append(p.Warnings, "IP 条件值格式无法解析")
					continue
				}
				effect := scalar(s["Effect"])
				base := strings.TrimPrefix(strings.TrimPrefix(op, "ForAllValues:"), "ForAnyValue:")
				base = strings.TrimSuffix(base, "IfExists")
				meaning := "IP 条件证据；需结合完整语句判断"
				switch {
				case effect == "Deny" && base == "NotIpAddress":
					meaning = "范围外请求匹配显式拒绝；仍须满足语句其他条件、Action 与 Resource"
				case effect == "Deny" && base == "IpAddress":
					meaning = "拒绝名单：范围内请求匹配拒绝，不是白名单"
				case effect == "Allow" && base == "IpAddress":
					meaning = "范围内请求可匹配此允许语句；其他策略仍可能允许范围外请求"
				case effect == "Allow" && base == "NotIpAddress":
					meaning = "范围外请求可匹配此允许语句，不是白名单"
				}
				if strings.Contains(op, "IfExists") {
					meaning += "；IfExists 在键缺失时仍可能匹配"
				}
				if strings.Contains(op, ":") {
					meaning += "；包含集合操作符，请检查多值上下文"
				}
				if strings.EqualFold(key, "aws:VpcSourceIp") {
					meaning += "；VPC 私网来源需结合 SourceVpc/SourceVpce"
				} else {
					meaning += "；SourceIp 在 VPC 端点请求中可能缺失"
				}
				for _, v := range vals {
					if !validIP(v) {
						p.Warnings = append(p.Warnings, "IP/CIDR 值无法校验: "+v)
					}
				}
				p.IPConditions = append(p.IPConditions, IPCondition{SID: scalar(s["Sid"]), Effect: effect, Operator: op, Key: key, Values: vals, Interpretation: meaning})
			}
		}
	}
	return len(p.Warnings) == 0
}

func SummarizeIP(u *AuditUser, complete bool) {
	ranges := map[string]bool{}
	found, strict := false, false
	policies := append([]Policy{}, u.Policies...)
	if u.PermissionsBoundary != nil {
		policies = append(policies, *u.PermissionsBoundary)
	}
	for _, p := range policies {
		if len(p.Warnings) > 0 {
			complete = false
		}
		for _, c := range p.IPConditions {
			found = true
			for _, v := range c.Values {
				ranges[v] = true
			}
		}
		ss, e := statements(p.Document)
		if e != nil {
			complete = false
			continue
		}
		for _, s := range ss {
			if scalar(s["Effect"]) != "Deny" || !star(s["Action"]) || !star(s["Resource"]) || len(s["NotAction"]) > 0 || len(s["NotResource"]) > 0 {
				continue
			}
			var co map[string]map[string]json.RawMessage
			if json.Unmarshal(s["Condition"], &co) != nil || len(co) != 1 {
				continue
			}
			ip := co["NotIpAddress"]
			if len(ip) != 1 {
				continue
			}
			for k, raw := range ip {
				if !strings.EqualFold(k, "aws:SourceIp") {
					continue
				}
				v, er := stringValues(raw)
				valid := er == nil && len(v) > 0
				for _, x := range v {
					if !validIP(x) {
						valid = false
					}
					if pr, er := netip.ParsePrefix(x); er == nil && pr.Bits() == 0 {
						valid = false
					}
				}
				if valid {
					strict = true
				}
			}
		}
	}
	u.IPRanges = []string{}
	for x := range ranges {
		u.IPRanges = append(u.IPRanges, x)
	}
	sort.Strings(u.IPRanges)
	switch {
	case !complete:
		u.IPStatus = "unknown"
		u.IPExplanation = "策略或关联信息采集不完整，无法确认 IP 限制；已发现的条件仅供核查。"
	case strict:
		u.IPStatus = "restricted"
		u.IPExplanation = "发现覆盖全部 Action/Resource 的 Deny + NotIpAddress 来源 IP 约束。仅为身份策略证据，未模拟最终权限；VPC 端点及服务转发场景需复核。"
	case found:
		u.IPStatus = "conditional"
		u.IPExplanation = "发现 IP 条件；可能只约束部分操作、允许语句或拒绝名单，不能认定全局白名单。"
	default:
		u.IPStatus = "unrestricted"
		u.IPExplanation = "已获取的用户及用户组身份策略中未发现来源 IP 条件；未评估 SCP、资源策略及会话策略。"
	}
}
