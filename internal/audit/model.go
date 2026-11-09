package audit

import "encoding/json"

type Account struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Alias        string `json:"alias"`
	Owner        string `json:"owner"`
	Status       string `json:"status"`
	LastSyncedAt string `json:"last_synced_at"`
	Error        string `json:"error"`
	UserCount    int    `json:"user_count"`
}
type AccessKey struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	LastUsedAt      string `json:"last_used_at"`
	LastUsedService string `json:"last_used_service"`
	LastUsedRegion  string `json:"last_used_region"`
}
type IPCondition struct {
	SID            string   `json:"sid"`
	Effect         string   `json:"effect"`
	Operator       string   `json:"operator"`
	Key            string   `json:"key"`
	Values         []string `json:"values"`
	Interpretation string   `json:"interpretation"`
}
type Policy struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	ARN          string          `json:"arn"`
	Type         string          `json:"type"`
	Source       string          `json:"source"`
	GroupName    string          `json:"group_name"`
	Document     json.RawMessage `json:"document"`
	IPConditions []IPCondition   `json:"ip_conditions"`
	Warnings     []string        `json:"warnings"`
}
type AuditUser struct {
	AccountID           string      `json:"account_id"`
	AccountName         string      `json:"account_name"`
	UserID              string      `json:"user_id"`
	Username            string      `json:"username"`
	ARN                 string      `json:"arn"`
	Path                string      `json:"path"`
	Owner               string      `json:"owner"`
	ReviewStatus        string      `json:"review_status"`
	Note                string      `json:"note"`
	ConsoleAccess       string      `json:"console_access"`
	MFAEnabled          string      `json:"mfa_enabled"`
	CreatedAt           string      `json:"created_at"`
	PasswordLastUsed    string      `json:"password_last_used"`
	Groups              []string    `json:"groups"`
	AccessKeys          []AccessKey `json:"access_keys"`
	Policies            []Policy    `json:"policies"`
	PermissionsBoundary *Policy     `json:"permissions_boundary,omitempty"`
	IPStatus            string      `json:"ip_status"`
	IPExplanation       string      `json:"ip_explanation"`
	IPRanges            []string    `json:"ip_ranges"`
	Warnings            []string    `json:"warnings"`
}
type Annotation struct {
	Owner        string `json:"owner"`
	ReviewStatus string `json:"review_status"`
	Note         string `json:"note"`
}
type SyncLog struct {
	ID                int64  `json:"id"`
	StartedAt         string `json:"started_at"`
	FinishedAt        string `json:"finished_at"`
	Trigger           string `json:"trigger"`
	Status            string `json:"status"`
	AccountsTotal     int    `json:"accounts_total"`
	AccountsSucceeded int    `json:"accounts_succeeded"`
	Error             string `json:"error"`
}
type SyncStatus struct {
	Running        bool      `json:"running"`
	StartedAt      string    `json:"started_at"`
	LastFinishedAt string    `json:"last_finished_at"`
	NextRunAt      string    `json:"next_run_at"`
	Timezone       string    `json:"timezone"`
	Schedule       string    `json:"schedule"`
	LastResult     string    `json:"last_result"`
	Logs           []SyncLog `json:"logs"`
}
type Dashboard struct {
	Accounts []Account   `json:"accounts"`
	Users    []AuditUser `json:"users"`
	Sync     SyncStatus  `json:"sync"`
}
