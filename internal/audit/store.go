package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS snapshots (config_id TEXT PRIMARY KEY,account TEXT NOT NULL,users TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rds_snapshots (config_id TEXT PRIMARY KEY,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS annotations (account_id TEXT NOT NULL,user_id TEXT NOT NULL,owner TEXT NOT NULL,review_status TEXT NOT NULL,note TEXT NOT NULL,PRIMARY KEY(account_id,user_id));
CREATE TABLE IF NOT EXISTS sync_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,started_at TEXT NOT NULL,finished_at TEXT NOT NULL DEFAULT '',trigger TEXT NOT NULL,status TEXT NOT NULL,accounts_total INTEGER NOT NULL,accounts_succeeded INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '');
UPDATE sync_logs SET status='error',finished_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'),error='服务重启，上次同步中断' WHERE status='running';`)
	if err != nil {
		db.Close()
		return nil, err
	}
	if path != ":memory:" {
		_ = os.Chmod(path, 0600)
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) SaveSnapshot(id string, a Account, u []AuditUser) error {
	if u == nil {
		u = []AuditUser{}
	}
	ab, e := json.Marshal(a)
	if e != nil {
		return e
	}
	ub, e := json.Marshal(u)
	if e != nil {
		return e
	}
	_, e = s.db.Exec(`INSERT INTO snapshots(config_id,account,users) VALUES(?,?,?) ON CONFLICT(config_id) DO UPDATE SET account=excluded.account,users=excluded.users`, id, string(ab), string(ub))
	return e
}
func (s *Store) AccountSnapshot(id string) (Account, []AuditUser, bool, error) {
	var ab, ub string
	e := s.db.QueryRow(`SELECT account,users FROM snapshots WHERE config_id=?`, id).Scan(&ab, &ub)
	if e == sql.ErrNoRows {
		return Account{}, []AuditUser{}, false, nil
	}
	if e != nil {
		return Account{}, nil, false, e
	}
	var a Account
	u := []AuditUser{}
	if e = json.Unmarshal([]byte(ab), &a); e != nil {
		return a, nil, false, e
	}
	if e = json.Unmarshal([]byte(ub), &u); e != nil {
		return a, nil, false, e
	}
	return a, u, true, nil
}
func (s *Store) ReadDashboard(configs []AccountConfig) ([]Account, []AuditUser, error) {
	accounts := []Account{}
	users := []AuditUser{}
	for _, c := range configs {
		a, u, exists, e := s.AccountSnapshot(c.ID)
		if e != nil {
			return nil, nil, e
		}
		if !exists {
			a = Account{ID: c.ExpectedAccountID, Name: c.Name, Owner: c.Owner, Status: "pending"}
			if a.ID == "" {
				a.ID = c.ID
			}
		} else {
			a.Name = c.Name
			a.Owner = c.Owner
		}
		accounts = append(accounts, a)
		for i := range u {
			u[i].AccountName = c.Name
			// 升级前保存的快照没有该字段；策略文档已在快照中，直接补算，无需重新采集。
			if u[i].SecretsAccess == "" {
				complete := true
				for _, w := range u[i].Warnings {
					if strings.Contains(w, "详情缺失") {
						complete = false
					}
				}
				SummarizeSecrets(&u[i], complete)
			}
			if u[i].RDSSecretAccess == "" {
				complete := true
				for _, w := range u[i].Warnings {
					if strings.Contains(w, "详情缺失") {
						complete = false
					}
				}
				SummarizeRDSSecretVisibility(&u[i], complete)
			}
			var an Annotation
			e = s.db.QueryRow(`SELECT owner,review_status,note FROM annotations WHERE account_id=? AND user_id=?`, u[i].AccountID, u[i].UserID).Scan(&an.Owner, &an.ReviewStatus, &an.Note)
			if e == nil {
				u[i].Owner = an.Owner
				u[i].ReviewStatus = an.ReviewStatus
				u[i].Note = an.Note
			} else if e != sql.ErrNoRows {
				return nil, nil, e
			}
			users = append(users, u[i])
		}
	}
	return accounts, users, nil
}
func (s *Store) MarkFailure(c AccountConfig, message string) error {
	a, u, ok, e := s.AccountSnapshot(c.ID)
	if e != nil {
		return e
	}
	if !ok {
		a = Account{ID: c.ExpectedAccountID, Name: c.Name, Owner: c.Owner}
		if a.ID == "" {
			a.ID = c.ID
		}
	}
	a.Status = "error"
	a.Error = message
	return s.SaveSnapshot(c.ID, a, u)
}
func (s *Store) Annotate(accountID, userID string, an Annotation, configs []AccountConfig) error {
	_, users, e := s.ReadDashboard(configs)
	if e != nil {
		return e
	}
	exists := false
	for _, u := range users {
		if u.AccountID == accountID && u.UserID == userID {
			exists = true
			break
		}
	}
	if !exists {
		return sql.ErrNoRows
	}
	_, e = s.db.Exec(`INSERT INTO annotations(account_id,user_id,owner,review_status,note) VALUES(?,?,?,?,?) ON CONFLICT(account_id,user_id) DO UPDATE SET owner=excluded.owner,review_status=excluded.review_status,note=excluded.note`, accountID, userID, an.Owner, an.ReviewStatus, an.Note)
	return e
}
func (s *Store) BeginLog(trigger string, total int) (int64, error) {
	r, e := s.db.Exec(`INSERT INTO sync_logs(started_at,trigger,status,accounts_total) VALUES(?,?,'running',?)`, time.Now().UTC().Format(time.RFC3339), trigger, total)
	if e != nil {
		return 0, e
	}
	return r.LastInsertId()
}
func (s *Store) FinishLog(id int64, status string, success int, message string) error {
	_, e := s.db.Exec(`UPDATE sync_logs SET finished_at=?,status=?,accounts_succeeded=?,error=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), status, success, message, id)
	return e
}
func (s *Store) Logs() ([]SyncLog, error) {
	rows, e := s.db.Query(`SELECT id,started_at,finished_at,trigger,status,accounts_total,accounts_succeeded,error FROM sync_logs ORDER BY id DESC LIMIT 30`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	logs := []SyncLog{}
	for rows.Next() {
		var l SyncLog
		if e = rows.Scan(&l.ID, &l.StartedAt, &l.FinishedAt, &l.Trigger, &l.Status, &l.AccountsTotal, &l.AccountsSucceeded, &l.Error); e != nil {
			return nil, e
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}
func (s *Store) PruneLogs() error {
	_, e := s.db.Exec(`DELETE FROM sync_logs WHERE id NOT IN (SELECT id FROM sync_logs ORDER BY id DESC LIMIT 300)`)
	if e != nil {
		return fmt.Errorf("prune logs: %w", e)
	}
	return nil
}

func (s *Store) rdsSnapshot(id string) (RDSInventory, bool, error) {
	var raw string
	e := s.db.QueryRow(`SELECT data FROM rds_snapshots WHERE config_id=?`, id).Scan(&raw)
	if e == sql.ErrNoRows {
		return RDSInventory{}, false, nil
	}
	if e != nil {
		return RDSInventory{}, false, e
	}
	var inv RDSInventory
	if e = json.Unmarshal([]byte(raw), &inv); e != nil {
		return inv, false, e
	}
	return inv, true, nil
}

// SaveRDS 保存 RDS 托管清单；整体失败时保留上次成功采集的条目，只更新状态与错误。
func (s *Store) SaveRDS(id string, inv RDSInventory) error {
	if inv.Status == "error" {
		if old, ok, e := s.rdsSnapshot(id); e == nil && ok {
			old.Status, old.Error = inv.Status, inv.Error
			if inv.AccountID != "" {
				old.AccountID = inv.AccountID
			}
			inv = old
		}
	}
	if inv.Items == nil {
		inv.Items = []RDSSecret{}
	}
	b, e := json.Marshal(inv)
	if e != nil {
		return e
	}
	_, e = s.db.Exec(`INSERT INTO rds_snapshots(config_id,data) VALUES(?,?) ON CONFLICT(config_id) DO UPDATE SET data=excluded.data`, id, string(b))
	return e
}

func (s *Store) ReadRDS(configs []AccountConfig) (RDSSecretsView, error) {
	v := RDSSecretsView{Accounts: []RDSAccountSummary{}, Items: []RDSSecret{}}
	for _, c := range configs {
		inv, ok, e := s.rdsSnapshot(c.ID)
		if e != nil {
			return v, e
		}
		if !ok {
			id := c.ExpectedAccountID
			if a, _, exists, er := s.AccountSnapshot(c.ID); er == nil && exists && a.ID != "" {
				id = a.ID
			}
			if id == "" {
				id = c.ID
			}
			inv = RDSInventory{AccountID: id, Status: "pending", Regions: c.rdsRegions()}
		}
		v.Accounts = append(v.Accounts, RDSAccountSummary{AccountID: inv.AccountID, AccountName: c.Name, Status: inv.Status, Error: inv.Error, SyncedAt: inv.SyncedAt, Regions: inv.Regions, Count: len(inv.Items)})
		for _, it := range inv.Items {
			it.AccountName = c.Name
			if it.Warnings == nil {
				it.Warnings = []string{}
			}
			v.Items = append(v.Items, it)
		}
	}
	return v, nil
}
