package audit

import (
	"encoding/json"
	"net/url"
	"slices"
	"testing"
)

func reviewPolicy(t *testing.T, document string) Policy {
	t.Helper()
	doc, err := DecodePolicy(document)
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{ID: "review-policy", Name: "review-policy", Source: "direct", Document: doc}
	AnalyzePolicy(&p)
	return p
}

func TestReviewDecodePolicyPreservesLiteralPlus(t *testing.T) {
	// RFC 3986 decoding must preserve '+' in resource names and JSON values.
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a+b/*"}}`
	for _, value := range []string{raw, url.PathEscape(raw)} {
		doc, err := DecodePolicy(value)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err := json.Unmarshal(doc, &object); err != nil {
			t.Fatal(err)
		}
		statement := object["Statement"].(map[string]any)
		if got := statement["Resource"]; got != "arn:aws:s3:::a+b/*" {
			t.Fatalf("resource was changed by decoding: %q", got)
		}
	}
}

func TestReviewIPConditionScope(t *testing.T) {
	tests := []struct {
		name, document, want string
	}{
		{
			name:     "screenshot explicit outside deny",
			document: `{"Statement":{"Sid":"DenyOutsideAllowedIPs","Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":["203.0.113.10/32","198.51.100.24/32"]}}}}`,
			want:     "restricted",
		},
		{
			name:     "allow condition is not global restriction",
			document: `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}}`,
			want:     "conditional",
		},
		{
			name:     "deny inside is blacklist",
			document: `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}}`,
			want:     "conditional",
		},
		{
			name:     "limited actions are not global",
			document: `{"Statement":{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}}`,
			want:     "conditional",
		},
		{
			name:     "other conditions limit the deny",
			document: `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"},"Bool":{"aws:MultiFactorAuthPresent":"false"}}}}`,
			want:     "conditional",
		},
		{
			name:     "if exists needs contextual review",
			document: `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddressIfExists":{"aws:SourceIp":"203.0.113.0/24"}}}}`,
			want:     "conditional",
		},
		{
			name:     "all public IPv4 is not a whitelist restriction",
			document: `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"0.0.0.0/0"}}}}`,
			want:     "conditional",
		},
		{
			name:     "ordinary policy has no observed IP condition",
			document: `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`,
			want:     "unrestricted",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u := AuditUser{Policies: []Policy{reviewPolicy(t, test.document)}}
			SummarizeIP(&u, true)
			if u.IPStatus != test.want {
				t.Fatalf("IPStatus = %s, want %s; %s", u.IPStatus, test.want, u.IPExplanation)
			}
		})
	}
}

func TestReviewExtractIPOperatorAndIPv6(t *testing.T) {
	p := reviewPolicy(t, `{"Statement":{"Sid":"VpcIPv6","Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"ForAnyValue:NotIpAddressIfExists":{"aws:VpcSourceIp":["2001:db8::/64","10.0.0.0/8"]}}}}`)
	if len(p.IPConditions) != 1 {
		t.Fatalf("conditions: %#v", p.IPConditions)
	}
	c := p.IPConditions[0]
	if c.SID != "VpcIPv6" || c.Effect != "Deny" || c.Operator != "ForAnyValue:NotIpAddressIfExists" || c.Key != "aws:VpcSourceIp" {
		t.Fatalf("condition evidence was changed: %#v", c)
	}
	if !slices.Equal(c.Values, []string{"2001:db8::/64", "10.0.0.0/8"}) {
		t.Fatalf("CIDR evidence changed: %#v", c.Values)
	}
}

func TestReviewBoundaryIPIsVisible(t *testing.T) {
	boundary := reviewPolicy(t, `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}}`)
	boundary.Source, boundary.Type = "boundary", "boundary"
	u := AuditUser{
		Policies:            []Policy{reviewPolicy(t, `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)},
		PermissionsBoundary: &boundary,
	}
	SummarizeIP(&u, true)
	if u.IPStatus != "conditional" {
		t.Fatalf("boundary IP condition ignored: IPStatus=%s", u.IPStatus)
	}
	if !slices.Contains(u.IPRanges, "203.0.113.0/24") {
		t.Fatalf("boundary CIDR missing from evidence: %#v", u.IPRanges)
	}
}

func TestReviewIncompletePolicyCannotLookUnrestricted(t *testing.T) {
	for _, boundary := range []bool{false, true} {
		p := Policy{ID: "unreadable", Document: json.RawMessage(`{}`), Warnings: []string{"GetPolicyVersion: AccessDenied"}}
		u := AuditUser{}
		if boundary {
			u.PermissionsBoundary = &p
		} else {
			u.Policies = []Policy{p}
		}
		SummarizeIP(&u, true)
		if u.IPStatus != "unknown" {
			t.Fatalf("incomplete boundary=%v: IPStatus=%s, want unknown", boundary, u.IPStatus)
		}
	}
}
