package audit

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type Collector interface {
	Collect(context.Context, AccountConfig) (Account, []AuditUser, error)
}
type AWSCollector struct{ HTTPClient *http.Client }

func stamp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
func safeError(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "采集超时"
	}
	if errors.Is(err, context.Canceled) {
		return "采集已取消"
	}
	return "AWS 请求或响应处理失败"
}

func (collector AWSCollector) Collect(ctx context.Context, c AccountConfig) (Account, []AuditUser, error) {
	a := Account{Name: c.Name, Owner: c.Owner, Status: "success"}
	users := []AuditUser{}
	clientHTTP := collector.HTTPClient
	if clientHTTP == nil {
		clientHTTP = &http.Client{Timeout: 45 * time.Second}
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.Region), awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)), awsconfig.WithHTTPClient(clientHTTP), awsconfig.WithRetryMaxAttempts(4))
	if err != nil {
		return a, nil, fmt.Errorf("初始化 AWS 客户端失败")
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return a, nil, fmt.Errorf("STS GetCallerIdentity: %s", safeError(err))
	}
	a.ID = aws.ToString(identity.Account)
	if c.ExpectedAccountID != "" && a.ID != c.ExpectedAccountID {
		return a, nil, fmt.Errorf("AWS 账号 ID 与 expected_account_id 不一致，已拒绝覆盖快照")
	}
	client := iam.NewFromConfig(cfg)
	issues := []string{}
	alias, err := client.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil {
		issues = append(issues, "ListAccountAliases: "+safeError(err))
	} else if len(alias.AccountAliases) > 0 {
		a.Alias = alias.AccountAliases[0]
	}
	// A failed page invalidates this account's entire authorization snapshot.
	details := []types.UserDetail{}
	groups := map[string]types.GroupDetail{}
	pager := iam.NewGetAccountAuthorizationDetailsPaginator(client, &iam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeUser, types.EntityTypeGroup}, MaxItems: aws.Int32(1000)})
	for pager.HasMorePages() {
		page, e := pager.NextPage(ctx)
		if e != nil {
			return a, nil, fmt.Errorf("GetAccountAuthorizationDetails: %s", safeError(e))
		}
		details = append(details, page.UserDetailList...)
		for _, g := range page.GroupDetailList {
			groups[aws.ToString(g.GroupName)] = g
		}
	}
	report, generated, reportErr := credentialReport(ctx, client)
	if reportErr != nil {
		issues = append(issues, "凭证报告: "+safeError(reportErr))
	}
	cache := map[string]Policy{}
	managed := func(arn, name, source, group string) Policy {
		p, exists := cache[arn]
		if !exists {
			kind := "customer_managed"
			if strings.Contains(arn, ":iam::aws:policy/") {
				kind = "aws_managed"
			}
			p = Policy{ID: arn, ARN: arn, Name: name, Type: kind, Document: []byte(`{}`), IPConditions: []IPCondition{}, Warnings: []string{}}
			meta, e := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
			if e != nil {
				p.Warnings = append(p.Warnings, "GetPolicy: "+safeError(e))
			} else if meta.Policy == nil || meta.Policy.DefaultVersionId == nil {
				p.Warnings = append(p.Warnings, "未返回默认策略版本")
			} else {
				p.Name = aws.ToString(meta.Policy.PolicyName)
				version, e := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: meta.Policy.DefaultVersionId})
				if e != nil {
					p.Warnings = append(p.Warnings, "GetPolicyVersion: "+safeError(e))
				} else if version.PolicyVersion == nil {
					p.Warnings = append(p.Warnings, "未返回策略文档")
				} else {
					doc, e := DecodePolicy(aws.ToString(version.PolicyVersion.Document))
					if e != nil {
						p.Warnings = append(p.Warnings, "策略文档解码失败")
					} else {
						p.Document = doc
						AnalyzePolicy(&p)
					}
				}
			}
			cache[arn] = p
		}
		p.Source = source
		p.GroupName = group
		if source == "boundary" {
			p.Type = "boundary"
		}
		return p
	}
	inline := func(name, raw, source, group, uid string) Policy {
		p := Policy{ID: uid + ":" + source + ":" + group + ":" + name, Name: name, Type: "inline", Source: source, GroupName: group, Document: []byte(`{}`), IPConditions: []IPCondition{}, Warnings: []string{}}
		doc, e := DecodePolicy(raw)
		if e != nil {
			p.Warnings = append(p.Warnings, "内联策略文档解码失败")
		} else {
			p.Document = doc
			AnalyzePolicy(&p)
		}
		return p
	}
	for _, d := range details {
		if ctx.Err() != nil {
			return a, nil, fmt.Errorf("%s", safeError(ctx.Err()))
		}
		name, uid := aws.ToString(d.UserName), aws.ToString(d.UserId)
		u := AuditUser{AccountID: a.ID, AccountName: a.Name, UserID: uid, Username: name, ARN: aws.ToString(d.Arn), Path: aws.ToString(d.Path), Owner: c.Owner, ReviewStatus: "pending", ConsoleAccess: "unknown", MFAEnabled: "unknown", CreatedAt: stamp(d.CreateDate), Groups: append([]string{}, d.GroupList...), AccessKeys: []AccessKey{}, Policies: []Policy{}, Warnings: []string{}, IPRanges: []string{}}
		complete := true
		_, e := client.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: aws.String(name)})
		if e == nil {
			u.ConsoleAccess = "enabled"
		} else {
			var no *types.NoSuchEntityException
			if errors.As(e, &no) {
				u.ConsoleAccess = "disabled"
			} else {
				u.Warnings = append(u.Warnings, "控制台权限 GetLoginProfile: "+safeError(e))
			}
		}
		mp := iam.NewListMFADevicesPaginator(client, &iam.ListMFADevicesInput{UserName: aws.String(name)})
		mfaCount := 0
		mfaOK := true
		for mp.HasMorePages() {
			page, e := mp.NextPage(ctx)
			if e != nil {
				u.Warnings = append(u.Warnings, "MFA ListMFADevices: "+safeError(e))
				mfaOK = false
				break
			}
			mfaCount += len(page.MFADevices)
		}
		if mfaOK {
			u.MFAEnabled = "disabled"
			if mfaCount > 0 {
				u.MFAEnabled = "enabled"
			}
		}
		if row, ok := report[name]; ok {
			last := row["password_last_used"]
			if _, e = time.Parse(time.RFC3339, last); e == nil {
				u.PasswordLastUsed = last
			} else if last != "N/A" && last != "no_information" && last != "" {
				u.Warnings = append(u.Warnings, "密码最后使用时间无法解析")
			}
			if last == "no_information" {
				u.Warnings = append(u.Warnings, "凭证报告无密码使用记录（从未使用或 AWS 未记录）")
			}
			if generated != "" {
				u.Warnings = append(u.Warnings, "密码使用时间来源于凭证报告，报告生成于 "+generated+"（AWS 最多每 4 小时生成一次）")
			}
		} else {
			u.Warnings = append(u.Warnings, "凭证报告未返回此用户，密码使用时间未知")
		}
		kp := iam.NewListAccessKeysPaginator(client, &iam.ListAccessKeysInput{UserName: aws.String(name)})
		for kp.HasMorePages() {
			page, e := kp.NextPage(ctx)
			if e != nil {
				u.Warnings = append(u.Warnings, "Access Key ListAccessKeys: "+safeError(e))
				break
			}
			for _, key := range page.AccessKeyMetadata {
				k := AccessKey{ID: aws.ToString(key.AccessKeyId), Status: string(key.Status), CreatedAt: stamp(key.CreateDate)}
				last, e := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKeyId})
				if e != nil {
					u.Warnings = append(u.Warnings, "Access Key GetAccessKeyLastUsed: "+safeError(e))
				} else if last.AccessKeyLastUsed != nil {
					k.LastUsedAt = stamp(last.AccessKeyLastUsed.LastUsedDate)
					k.LastUsedService = aws.ToString(last.AccessKeyLastUsed.ServiceName)
					k.LastUsedRegion = aws.ToString(last.AccessKeyLastUsed.Region)
				}
				u.AccessKeys = append(u.AccessKeys, k)
			}
		}
		for _, p := range d.UserPolicyList {
			u.Policies = append(u.Policies, inline(aws.ToString(p.PolicyName), aws.ToString(p.PolicyDocument), "direct", "", uid))
		}
		for _, p := range d.AttachedManagedPolicies {
			u.Policies = append(u.Policies, managed(aws.ToString(p.PolicyArn), aws.ToString(p.PolicyName), "direct", ""))
		}
		for _, gname := range d.GroupList {
			g, ok := groups[gname]
			if !ok {
				u.Warnings = append(u.Warnings, "用户组 "+gname+" 详情缺失，继承权限未知")
				complete = false
				continue
			}
			for _, p := range g.GroupPolicyList {
				u.Policies = append(u.Policies, inline(aws.ToString(p.PolicyName), aws.ToString(p.PolicyDocument), "group", gname, uid))
			}
			for _, p := range g.AttachedManagedPolicies {
				u.Policies = append(u.Policies, managed(aws.ToString(p.PolicyArn), aws.ToString(p.PolicyName), "group", gname))
			}
		}
		if d.PermissionsBoundary != nil && d.PermissionsBoundary.PermissionsBoundaryArn != nil {
			p := managed(aws.ToString(d.PermissionsBoundary.PermissionsBoundaryArn), "权限边界", "boundary", "")
			u.PermissionsBoundary = &p
			if len(p.Warnings) > 0 {
				u.Warnings = append(u.Warnings, "权限边界文档未完整获取")
				complete = false
			}
		}
		for _, p := range u.Policies {
			if len(p.Warnings) > 0 {
				complete = false
				u.Warnings = append(u.Warnings, "策略 "+p.Name+" 信息不完整")
			}
		}
		SummarizeIP(&u, complete)
		SummarizeSecrets(&u, complete)
		sort.Strings(u.Groups)
		users = append(users, u)
	}
	if reportErr != nil {
		a.Status = "partial"
	}
	// Routine report-age notes are evidence metadata, not collection failures.
	for _, u := range users {
		for _, w := range u.Warnings {
			if strings.Contains(w, "凭证报告，报告生成于") || strings.Contains(w, "无密码使用记录") {
				continue
			}
			a.Status = "partial"
			break
		}
	}
	if len(issues) > 0 {
		a.Status = "partial"
		a.Error = strings.Join(issues, "；")
	} else if a.Status == "partial" {
		a.Error = "部分信息未能完整获取，请查看用户和策略告警"
	}
	a.UserCount = len(users)
	a.LastSyncedAt = time.Now().UTC().Format(time.RFC3339)
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return a, users, nil
}

func credentialReport(ctx context.Context, c *iam.Client) (map[string]map[string]string, string, error) {
	for i := 0; i < 30; i++ {
		r, e := c.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if e != nil {
			return nil, "", e
		}
		if r.State == types.ReportStateTypeComplete {
			break
		}
		if i == 29 {
			return nil, "", fmt.Errorf("credential report timeout")
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	r, e := c.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if e != nil {
		return nil, "", e
	}
	rows, e := csv.NewReader(strings.NewReader(string(r.Content))).ReadAll()
	if e != nil || len(rows) == 0 {
		return nil, "", fmt.Errorf("invalid credentials CSV")
	}
	result := map[string]map[string]string{}
	for _, row := range rows[1:] {
		if len(row) != len(rows[0]) {
			return nil, "", fmt.Errorf("invalid CSV column count")
		}
		v := map[string]string{}
		for i, h := range rows[0] {
			v[h] = row[i]
		}
		if v["user"] != "<root_account>" {
			result[v["user"]] = v
		}
	}
	return result, stamp(r.GeneratedTime), nil
}
