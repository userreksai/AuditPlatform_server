package audit

import (
	"strings"
	"testing"
	"time"
)

func TestSummarizeRDSSecretVisibility(t *testing.T) {
	cases := []struct {
		name string
		docs []string
		want string
	}{
		{"admin", []string{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}, SecretsFull},
		{"read only style", []string{`{"Statement":{"Effect":"Allow","Action":["rds:Describe*","secretsmanager:DescribeSecret"],"Resource":"*"}}`}, SecretsFull},
		{"rds only", []string{`{"Statement":{"Effect":"Allow","Action":"rds:Describe*","Resource":"*"}}`}, RDSVisibilityRDSOnly},
		{"clusters only still sees managed flag", []string{`{"Statement":{"Effect":"Allow","Action":["rds:DescribeDBClusters","secretsmanager:DescribeSecret"],"Resource":"*"}}`}, SecretsFull},
		{"secrets only", []string{`{"Statement":{"Effect":"Allow","Action":"secretsmanager:*","Resource":"*"}}`}, SecretsNone},
		{"single instance", []string{`{"Statement":{"Effect":"Allow","Action":["rds:DescribeDBInstances","secretsmanager:DescribeSecret"],"Resource":["arn:aws:rds:us-east-1:123456789012:db:prod","*"]}}`, `{"Statement":{"Effect":"Deny","Action":"rds:*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"1.2.3.4/32"}}}}`}, SecretsLimited},
		{"nothing", []string{`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`}, SecretsNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := secretsUser(t, "", c.docs...)
			SummarizeRDSSecretVisibility(&u, true)
			if u.RDSSecretAccess != c.want {
				t.Fatalf("got %s want %s (%v)", u.RDSSecretAccess, c.want, u.RDSSecretEvidence)
			}
		})
	}
	u := secretsUser(t, "", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	SummarizeRDSSecretVisibility(&u, false)
	if u.RDSSecretAccess != SecretsUnknown {
		t.Fatal("incomplete collection must be unknown")
	}
}

func TestApplyVerification(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-11-12T03:00:00Z")
	last, _ := time.Parse(time.RFC3339, "2026-11-08T02:00:00Z")
	next, _ := time.Parse(time.RFC3339, "2026-11-15T05:00:00Z")
	past, _ := time.Parse(time.RFC3339, "2026-11-10T00:00:00Z")

	item := RDSSecret{Migrated: "no"}
	ApplyVerification(&item, nil, now)
	if item.Verdict != "not_migrated" || item.RotationEnabled != "" {
		t.Fatalf("not migrated: %+v", item)
	}

	ok := func() *SecretMeta {
		return &SecretMeta{OwningService: "rds", RotationEnabled: true, AfterDays: 7, LastRotated: &last, NextRotation: &next}
	}
	item = RDSSecret{Migrated: "yes", SecretStatus: "active"}
	ApplyVerification(&item, ok(), now)
	if item.Verdict != "pass" || item.RotationPeriod != "每 7 天" || item.NextRotationSource != "aws" || item.LastRotatedAt != "2026-11-08T02:00:00Z" {
		t.Fatalf("pass: %+v", item)
	}

	m := ok()
	m.NextRotation = nil
	m.AfterDays = 0
	m.ScheduleExpr = "rate(4 days)"
	item = RDSSecret{Migrated: "yes", SecretStatus: "active"}
	ApplyVerification(&item, m, now)
	if item.NextRotationSource != "estimated" || item.NextRotationAt != "2026-11-12T02:00:00Z" || item.Verdict != "warn" || !strings.Contains(item.VerdictText, "逾期") {
		t.Fatalf("estimated/overdue: %+v", item)
	}

	m = ok()
	m.RotationEnabled = false
	item = RDSSecret{Migrated: "yes", SecretStatus: "active"}
	ApplyVerification(&item, m, now)
	if item.Verdict != "warn" || item.RotationEnabled != "disabled" {
		t.Fatalf("rotation off: %+v", item)
	}

	item = RDSSecret{Migrated: "yes", SecretStatus: "impaired"}
	ApplyVerification(&item, ok(), now)
	if item.Verdict != "fail" {
		t.Fatalf("impaired: %+v", item)
	}

	m = ok()
	m.NextRotation = &past
	item = RDSSecret{Migrated: "yes", SecretStatus: "active"}
	ApplyVerification(&item, m, now)
	if item.Verdict != "warn" {
		t.Fatalf("overdue aws date: %+v", item)
	}

	item = RDSSecret{Migrated: "yes", SecretStatus: "active"}
	ApplyVerification(&item, &SecretMeta{Error: "AccessDeniedException"}, now)
	if item.Verdict != "unknown" || item.RotationEnabled != "unknown" || !strings.Contains(item.VerdictText, "AccessDeniedException") {
		t.Fatalf("describe failed: %+v", item)
	}
}

func TestRotationPeriod(t *testing.T) {
	for in, want := range map[string]string{"rate(10 days)": "每 10 天", "rate(12 hours)": "每 12 小时", "cron(0 16 ? * SUN *)": "按计划 cron(0 16 ? * SUN *)", "": ""} {
		if got, _ := rotationPeriod(0, in); got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
	}
}
