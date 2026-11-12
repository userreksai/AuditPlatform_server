package audit

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// ---------- 每个 IAM 用户能否查询 RDS 主密码托管信息 ----------

// 查看“是否托管”：DescribeDBInstances / DescribeDBClusters 返回 MasterUserSecret。
// 查看轮换详情：secretsmanager:DescribeSecret（只返回元数据，不返回 Secret 值）。
const (
	rdsDescribeInstances = "rds:DescribeDBInstances"
	rdsDescribeClusters  = "rds:DescribeDBClusters"
	secretsDescribe      = "secretsmanager:DescribeSecret"
)

// RDS 托管信息可见性：full / limited / rds_only / none / unknown
const RDSVisibilityRDSOnly = "rds_only"

func rdsSamples(partition, account, kind string) []string {
	return []string{
		"arn:" + partition + ":rds:us-east-1:" + account + ":" + kind + ":audit-sample-a",
		"arn:" + partition + ":rds:ap-southeast-1:" + account + ":" + kind + ":prod-db-b",
	}
}

func rank(state string) int {
	switch state {
	case SecretsFull:
		return 2
	case SecretsLimited:
		return 1
	}
	return 0
}

// SummarizeRDSSecretVisibility 判断用户能否查询“RDS 主用户密码是否由 Secrets Manager 托管”及轮换详情。
func SummarizeRDSSecretVisibility(u *AuditUser, complete bool) {
	partition, account := userPartitionAccount(u)
	inst, instEv := evaluateAccess(u, complete, accessCheck{Action: rdsDescribeInstances, Service: "rds", Samples: rdsSamples(partition, account, "db"), Unit: "RDS 实例"})
	clus, clusEv := evaluateAccess(u, complete, accessCheck{Action: rdsDescribeClusters, Service: "rds", Samples: rdsSamples(partition, account, "cluster"), Unit: "RDS 集群"})
	sec, secEv := evaluateAccess(u, complete, accessCheck{Action: secretsDescribe, Service: "secretsmanager", Samples: secretSamples(partition, account), Unit: "Secret"})
	evidence := []string{}
	for _, group := range []struct {
		name string
		ev   []string
	}{{rdsDescribeInstances, instEv}, {rdsDescribeClusters, clusEv}, {secretsDescribe, secEv}} {
		for _, e := range group.ev {
			evidence = append(evidence, group.name+" · "+e)
		}
	}
	u.RDSSecretEvidence = evidence
	rdsState := inst
	if rank(clus) > rank(inst) {
		rdsState = clus
	}
	const scopeNote = "仅分析用户直接及用户组身份策略与权限边界；未评估 SCP、资源策略及请求上下文。"
	stateText := func(s string) string {
		switch s {
		case SecretsFull:
			return "全部资源可查"
		case SecretsLimited:
			return "受限/带条件"
		case SecretsDenied:
			return "被拒绝"
		case SecretsUnknown:
			return "未知"
		}
		return "无权限"
	}
	detail := fmt.Sprintf("%s：%s；%s：%s；%s：%s。", rdsDescribeInstances, stateText(inst), rdsDescribeClusters, stateText(clus), secretsDescribe, stateText(sec))
	switch {
	case inst == SecretsUnknown || clus == SecretsUnknown || sec == SecretsUnknown:
		u.RDSSecretAccess = SecretsUnknown
		u.RDSSecretExplanation = "策略或关联信息采集不完整，无法确认能否查询 RDS 托管信息。" + detail + scopeNote
	case rank(rdsState) == 0:
		u.RDSSecretAccess = SecretsNone
		u.RDSSecretExplanation = "无法查询 RDS 实例/集群，因此看不到主用户密码是否由 Secrets Manager 托管。" + detail + scopeNote
	case rank(sec) == 0:
		u.RDSSecretAccess = RDSVisibilityRDSOnly
		u.RDSSecretExplanation = "可查看 RDS 是否托管（MasterUserSecret），但缺少 " + secretsDescribe + "，看不到轮换周期与轮换时间。" + detail + scopeNote
	case rdsState == SecretsFull && sec == SecretsFull:
		u.RDSSecretAccess = SecretsFull
		u.RDSSecretExplanation = "可查询全部 RDS 的托管状态及对应 Secret 的轮换配置（不含 Secret 值）。" + detail + scopeNote
	default:
		u.RDSSecretAccess = SecretsLimited
		u.RDSSecretExplanation = "可查询 RDS 托管信息，但受资源范围、条件或带条件的拒绝语句约束。" + detail + scopeNote
	}
}

// ---------- RDS 主用户密码托管清单 ----------

type RDSSecret struct {
	AccountID          string   `json:"account_id"`
	AccountName        string   `json:"account_name"`
	Region             string   `json:"region"`
	Kind               string   `json:"kind"` // instance / cluster
	Identifier         string   `json:"identifier"`
	Engine             string   `json:"engine"`
	EngineVersion      string   `json:"engine_version"`
	MasterUsername     string   `json:"master_username"`
	Migrated           string   `json:"migrated"` // yes / no
	SecretARN          string   `json:"secret_arn"`
	SecretStatus       string   `json:"secret_status"` // RDS MasterUserSecret.SecretStatus
	KMSKeyID           string   `json:"kms_key_id"`
	Verdict            string   `json:"verdict"` // pass / warn / fail / not_migrated / unknown
	VerdictText        string   `json:"verdict_text"`
	RotationEnabled    string   `json:"rotation_enabled"` // enabled / disabled / unknown / ""
	RotationPeriod     string   `json:"rotation_period"`
	RotationSchedule   string   `json:"rotation_schedule"`
	RotationWindow     string   `json:"rotation_window"`
	LastRotatedAt      string   `json:"last_rotated_at"`
	NextRotationAt     string   `json:"next_rotation_at"`
	NextRotationSource string   `json:"next_rotation_source"` // aws / estimated / ""
	Warnings           []string `json:"warnings"`
}

type RDSInventory struct {
	ConfigID    string      `json:"config_id"`
	AccountID   string      `json:"account_id"`
	AccountName string      `json:"account_name"`
	Status      string      `json:"status"` // success / partial / error / pending
	Error       string      `json:"error"`
	SyncedAt    string      `json:"synced_at"`
	Regions     []string    `json:"regions"`
	Items       []RDSSecret `json:"items"`
}

type RDSAccountSummary struct {
	AccountID   string   `json:"account_id"`
	AccountName string   `json:"account_name"`
	Status      string   `json:"status"`
	Error       string   `json:"error"`
	SyncedAt    string   `json:"synced_at"`
	Regions     []string `json:"regions"`
	Count       int      `json:"count"`
}

type RDSSecretsView struct {
	Accounts []RDSAccountSummary `json:"accounts"`
	Items    []RDSSecret         `json:"items"`
}

// SecretMeta 是 DescribeSecret 中与核验相关的字段（不包含 Secret 值）。
type SecretMeta struct {
	OwningService     string
	RotationEnabled   bool
	AfterDays         int64
	ScheduleExpr      string
	Duration          string
	LastRotated       *time.Time
	NextRotation      *time.Time
	Deleted           *time.Time
	Error             string // DescribeSecret 失败时的错误码
	DescribeAttempted bool
}

var rateExpr = regexp.MustCompile(`^rate\((\d+)\s+(day|days|hour|hours)\)$`)

// rotationPeriod 返回轮换周期描述及换算出的周期（无法换算时为 0）。
func rotationPeriod(afterDays int64, schedule string) (string, time.Duration) {
	if afterDays > 0 {
		return fmt.Sprintf("每 %d 天", afterDays), time.Duration(afterDays) * 24 * time.Hour
	}
	s := strings.TrimSpace(schedule)
	if m := rateExpr.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		if strings.HasPrefix(m[2], "day") {
			return fmt.Sprintf("每 %d 天", n), time.Duration(n) * 24 * time.Hour
		}
		return fmt.Sprintf("每 %d 小时", n), time.Duration(n) * time.Hour
	}
	if s != "" {
		return "按计划 " + s, 0
	}
	return "", 0
}

// ApplyVerification 根据 RDS MasterUserSecret 与 DescribeSecret 元数据填写迁移核验结论与轮换字段。
func ApplyVerification(item *RDSSecret, meta *SecretMeta, now time.Time) {
	if item.Warnings == nil {
		item.Warnings = []string{}
	}
	if item.Migrated != "yes" {
		item.Verdict = "not_migrated"
		item.VerdictText = "未迁移：主用户密码未由 Secrets Manager 托管（未启用 ManageMasterUserPassword），仍为 RDS 本地密码。"
		return
	}
	issues := []string{}
	verdict := "pass"
	raise := func(v string) {
		order := map[string]int{"pass": 0, "warn": 1, "unknown": 2, "fail": 3}
		if order[v] > order[verdict] {
			verdict = v
		}
	}
	switch strings.ToLower(item.SecretStatus) {
	case "active":
	case "impaired":
		raise("fail")
		issues = append(issues, "RDS 显示 Secret 状态为 impaired（RDS 无法访问该 Secret 或其 KMS 密钥）")
	case "creating", "rotating":
		raise("warn")
		issues = append(issues, "Secret 状态为 "+item.SecretStatus+"，请稍后复核")
	default:
		raise("warn")
		issues = append(issues, "RDS 未返回可识别的 Secret 状态（"+item.SecretStatus+"）")
	}
	if meta == nil || meta.Error != "" {
		raise("unknown")
		code := "未调用"
		if meta != nil {
			code = meta.Error
		}
		issues = append(issues, "DescribeSecret 失败（"+code+"），无法核验轮换配置")
		item.RotationEnabled = "unknown"
	} else {
		if meta.Deleted != nil {
			raise("fail")
			issues = append(issues, "Secret 已计划删除（"+stamp(meta.Deleted)+"）")
		}
		if meta.OwningService != "" && meta.OwningService != "rds" {
			raise("warn")
			issues = append(issues, "Secret 的 OwningService 为 "+meta.OwningService+"，不是 rds")
		}
		item.RotationEnabled = "disabled"
		if meta.RotationEnabled {
			item.RotationEnabled = "enabled"
		} else {
			raise("warn")
			issues = append(issues, "自动轮换未开启")
		}
		period, every := rotationPeriod(meta.AfterDays, meta.ScheduleExpr)
		item.RotationPeriod = period
		item.RotationSchedule = meta.ScheduleExpr
		item.RotationWindow = meta.Duration
		item.LastRotatedAt = stamp(meta.LastRotated)
		if meta.NextRotation != nil {
			item.NextRotationAt = stamp(meta.NextRotation)
			item.NextRotationSource = "aws"
		} else if meta.RotationEnabled && meta.LastRotated != nil && every > 0 {
			next := meta.LastRotated.Add(every)
			item.NextRotationAt = stamp(&next)
			item.NextRotationSource = "estimated"
		}
		if meta.RotationEnabled {
			if meta.LastRotated == nil {
				raise("warn")
				issues = append(issues, "尚无轮换记录")
			}
			if item.NextRotationAt != "" {
				if t, e := time.Parse(time.RFC3339, item.NextRotationAt); e == nil && t.Before(now) {
					raise("warn")
					issues = append(issues, "已超过下次轮换最晚时间，轮换可能失败或逾期")
				}
			}
		}
	}
	item.Verdict = verdict
	if verdict == "pass" {
		item.VerdictText = "已迁移，核验通过：Secret 状态 active，由 RDS 托管，自动轮换已开启。"
		return
	}
	prefix := map[string]string{"warn": "已迁移，需关注：", "fail": "已迁移，存在问题：", "unknown": "RDS 显示已托管，未能完整核验："}[verdict]
	item.VerdictText = prefix + strings.Join(issues, "；") + "。"
}

// ---------- 采集 ----------

// RDSCollector 为可选能力：实现该接口的采集器在 IAM 采集成功后继续采集 RDS 托管清单。
type RDSCollector interface {
	CollectRDS(ctx context.Context, c AccountConfig, a Account) RDSInventory
}

func (c AccountConfig) rdsRegions() []string {
	if len(c.RDSRegions) == 0 {
		return []string{c.Region}
	}
	return c.RDSRegions
}

func secretRegion(arn, fallback string) string {
	if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 && parts[3] != "" {
		return parts[3]
	}
	return fallback
}

func (collector AWSCollector) CollectRDS(ctx context.Context, c AccountConfig, a Account) RDSInventory {
	inv := RDSInventory{ConfigID: c.ID, AccountID: a.ID, AccountName: c.Name, Status: "success", Regions: c.rdsRegions(), Items: []RDSSecret{}}
	inv.SyncedAt = time.Now().UTC().Format(time.RFC3339)
	cfg, err := collector.awsConfig(ctx, c)
	if err != nil {
		inv.Status, inv.Error = "error", err.Error()
		return inv
	}
	issues := []string{}
	failedRegions := 0
	secretClients := map[string]*secretsmanager.Client{}
	describe := func(arn, region string) *SecretMeta {
		r := secretRegion(arn, region)
		client, ok := secretClients[r]
		if !ok {
			client = secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) { o.Region = r })
			secretClients[r] = client
		}
		meta := &SecretMeta{DescribeAttempted: true}
		out, e := client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(arn)})
		if e != nil {
			meta.Error = safeError(e)
			return meta
		}
		meta.OwningService = aws.ToString(out.OwningService)
		meta.RotationEnabled = aws.ToBool(out.RotationEnabled)
		if out.RotationRules != nil {
			meta.AfterDays = aws.ToInt64(out.RotationRules.AutomaticallyAfterDays)
			meta.ScheduleExpr = aws.ToString(out.RotationRules.ScheduleExpression)
			meta.Duration = aws.ToString(out.RotationRules.Duration)
		}
		meta.LastRotated, meta.NextRotation, meta.Deleted = out.LastRotatedDate, out.NextRotationDate, out.DeletedDate
		return meta
	}
	build := func(region, kind, id, engine, version, user string, secret *rdstypes.MasterUserSecret) RDSSecret {
		item := RDSSecret{AccountID: a.ID, AccountName: c.Name, Region: region, Kind: kind, Identifier: id, Engine: engine, EngineVersion: version, MasterUsername: user, Migrated: "no", Warnings: []string{}}
		var meta *SecretMeta
		if secret != nil && aws.ToString(secret.SecretArn) != "" {
			item.Migrated = "yes"
			item.SecretARN = aws.ToString(secret.SecretArn)
			item.SecretStatus = aws.ToString(secret.SecretStatus)
			item.KMSKeyID = aws.ToString(secret.KmsKeyId)
			meta = describe(item.SecretARN, region)
		}
		ApplyVerification(&item, meta, time.Now())
		return item
	}
	for _, region := range inv.Regions {
		if ctx.Err() != nil {
			issues = append(issues, safeError(ctx.Err()))
			break
		}
		client := rds.NewFromConfig(cfg, func(o *rds.Options) { o.Region = region })
		regionOK := true
		ip := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
		for ip.HasMorePages() {
			page, e := ip.NextPage(ctx)
			if e != nil {
				issues = append(issues, region+" DescribeDBInstances: "+safeError(e))
				regionOK = false
				break
			}
			for _, d := range page.DBInstances {
				// 集群成员的主用户由集群管理，在集群行中展示。
				if aws.ToString(d.DBClusterIdentifier) != "" {
					continue
				}
				inv.Items = append(inv.Items, build(region, "instance", aws.ToString(d.DBInstanceIdentifier), aws.ToString(d.Engine), aws.ToString(d.EngineVersion), aws.ToString(d.MasterUsername), d.MasterUserSecret))
			}
		}
		cp := rds.NewDescribeDBClustersPaginator(client, &rds.DescribeDBClustersInput{})
		for cp.HasMorePages() {
			page, e := cp.NextPage(ctx)
			if e != nil {
				issues = append(issues, region+" DescribeDBClusters: "+safeError(e))
				regionOK = false
				break
			}
			for _, d := range page.DBClusters {
				inv.Items = append(inv.Items, build(region, "cluster", aws.ToString(d.DBClusterIdentifier), aws.ToString(d.Engine), aws.ToString(d.EngineVersion), aws.ToString(d.MasterUsername), d.MasterUserSecret))
			}
		}
		if !regionOK {
			failedRegions++
		}
	}
	sort.Slice(inv.Items, func(i, j int) bool {
		x, y := inv.Items[i], inv.Items[j]
		if x.Region != y.Region {
			return x.Region < y.Region
		}
		return x.Identifier < y.Identifier
	})
	if len(issues) > 0 {
		inv.Status = "partial"
		if failedRegions == len(inv.Regions) && len(inv.Items) == 0 {
			inv.Status = "error"
		}
		inv.Error = strings.Join(issues, "；")
	}
	for _, it := range inv.Items {
		if it.Verdict == "unknown" && inv.Status == "success" {
			inv.Status = "partial"
			inv.Error = "部分 Secret 详情读取失败，请查看迁移核验结论"
			break
		}
	}
	return inv
}
