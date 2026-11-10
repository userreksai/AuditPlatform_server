package audit

import "testing"

func secretsUser(t *testing.T, boundary string, docs ...string) AuditUser {
	t.Helper()
	u := AuditUser{AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/alice"}
	for _, d := range docs {
		u.Policies = append(u.Policies, reviewPolicy(t, d))
	}
	if boundary != "" {
		b := reviewPolicy(t, boundary)
		b.Source = "boundary"
		u.PermissionsBoundary = &b
	}
	return u
}

func TestSummarizeSecrets(t *testing.T) {
	const ipDeny = `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":"18.136.15.95/32"}}}}`
	cases := []struct {
		name     string
		boundary string
		docs     []string
		want     string
	}{
		{"admin", "", []string{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}, SecretsFull},
		{"service wildcard", "", []string{`{"Statement":[{"Effect":"Allow","Action":["secretsmanager:*"],"Resource":"*"}]}`}, SecretsFull},
		{"get wildcard lower case", "", []string{`{"Statement":{"Effect":"Allow","Action":"SecretsManager:get*","Resource":"arn:aws:secretsmanager:*:*:secret:*"}}`}, SecretsFull},
		{"list only", "", []string{`{"Statement":{"Effect":"Allow","Action":["secretsmanager:ListSecrets","secretsmanager:DescribeSecret"],"Resource":"*"}}`}, SecretsNone},
		{"other service", "", []string{`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`}, SecretsNone},
		{"single secret", "", []string{`{"Statement":{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-*"}}`}, SecretsLimited},
		{"s3 resource only", "", []string{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::bucket/*"}}`}, SecretsNone},
		{"ip deny", "", []string{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, ipDeny}, SecretsLimited},
		{"hard deny", "", []string{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"secretsmanager:*","Resource":"*"}]}`}, SecretsDenied},
		{"not action allow", "", []string{`{"Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}`}, SecretsFull},
		{"not action excludes", "", []string{`{"Statement":{"Effect":"Allow","NotAction":"secretsmanager:*","Resource":"*"}}`}, SecretsNone},
		{"boundary blocks", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`, []string{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}, SecretsDenied},
		{"boundary allows", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, []string{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}, SecretsFull},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := secretsUser(t, c.boundary, c.docs...)
			SummarizeSecrets(&u, true)
			if u.SecretsAccess != c.want {
				t.Fatalf("got %s want %s (%v)", u.SecretsAccess, c.want, u.SecretsEvidence)
			}
		})
	}
	u := secretsUser(t, "", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	SummarizeSecrets(&u, false)
	if u.SecretsAccess != SecretsUnknown {
		t.Fatal("incomplete collection must be unknown")
	}
}
