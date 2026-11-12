package audit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

var ErrRunning = errors.New("已有同步任务正在运行")
var ErrNoAccounts = errors.New("尚未配置 AWS 账号，请填写配置文件并重启服务")

type Service struct {
	Config    *Config
	Store     *Store
	Collector Collector
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	running   bool
	started   string
	wg        sync.WaitGroup
}

func NewService(c *Config, s *Store, collector Collector) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{Config: c, Store: s, Collector: collector, ctx: ctx, cancel: cancel}
}
func (s *Service) StartSync(trigger string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return ErrRunning
	}
	if len(s.Config.Accounts) == 0 {
		return ErrNoAccounts
	}
	id, e := s.Store.BeginLog(trigger, len(s.Config.Accounts))
	if e != nil {
		return e
	}
	s.running = true
	s.started = time.Now().UTC().Format(time.RFC3339)
	s.wg.Add(1)
	go s.runSync(id)
	return nil
}
func (s *Service) runSync(id int64) {
	defer s.wg.Done()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(s.ctx, time.Duration(s.Config.Sync.TimeoutMinutes)*time.Minute)
	defer cancel()
	success, partial := 0, 0
	messages := []string{}
	for _, c := range s.Config.Accounts {
		a, u, e := s.Collector.Collect(ctx, c)
		if e != nil {
			message := e.Error()
			if er := s.Store.MarkFailure(c, message); er != nil {
				log.Printf("failed to persist account error: %v", er)
			}
			messages = append(messages, c.Name+": "+message)
			continue
		}
		if e = s.Store.SaveSnapshot(c.ID, a, u); e != nil {
			messages = append(messages, c.Name+": 数据库存储失败")
			log.Printf("snapshot write failed: %v", e)
			continue
		}
		rdsOK := true
		if rc, ok := s.Collector.(RDSCollector); ok {
			inv := rc.CollectRDS(ctx, c, a)
			if e = s.Store.SaveRDS(c.ID, inv); e != nil {
				log.Printf("rds snapshot write failed: %v", e)
				inv.Status, inv.Error = "error", "数据库存储失败"
			}
			if inv.Status != "success" {
				rdsOK = false
				messages = append(messages, c.Name+": RDS 托管信息 "+inv.Error)
			}
		}
		if a.Status == "partial" || !rdsOK {
			partial++
			if a.Status == "partial" {
				messages = append(messages, c.Name+": "+a.Error)
			}
		} else {
			success++
		}
	}
	status := "error"
	if success == len(s.Config.Accounts) {
		status = "success"
	} else if success > 0 || partial > 0 {
		status = "partial"
	}
	if e := s.Store.FinishLog(id, status, success, strings.Join(messages, "；")); e != nil {
		log.Printf("sync log write failed: %v", e)
	}
	_ = s.Store.PruneLogs()
}
func (s *Service) Status() (SyncStatus, error) {
	s.mu.Lock()
	running, started := s.running, s.started
	s.mu.Unlock()
	logs, e := s.Store.Logs()
	if e != nil {
		return SyncStatus{}, e
	}
	v := SyncStatus{Running: running, StartedAt: started, NextRunAt: NextRun(time.Now(), s.Config.Sync.Time, s.Config.Sync.Timezone).Format(time.RFC3339), Timezone: s.Config.Sync.Timezone, Schedule: s.Config.Sync.Time, LastResult: "never", Logs: logs}
	if len(logs) > 0 {
		v.LastResult = logs[0].Status
		if v.StartedAt == "" {
			v.StartedAt = logs[0].StartedAt
		}
		for _, l := range logs {
			if l.FinishedAt != "" {
				v.LastFinishedAt = l.FinishedAt
				break
			}
		}
	}
	if running {
		v.LastResult = "running"
	}
	return v, nil
}
func (s *Service) Dashboard() (Dashboard, error) {
	a, u, e := s.Store.ReadDashboard(s.Config.Accounts)
	if e != nil {
		return Dashboard{}, e
	}
	status, e := s.Status()
	return Dashboard{Accounts: a, Users: u, Sync: status}, e
}
func (s *Service) RDSSecrets() (RDSSecretsView, error) {
	return s.Store.ReadRDS(s.Config.Accounts)
}
func (s *Service) RunScheduler() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			next := NextRun(time.Now(), s.Config.Sync.Time, s.Config.Sync.Timezone)
			timer := time.NewTimer(time.Until(next))
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				if e := s.StartSync("scheduled"); e != nil && !errors.Is(e, ErrRunning) && !errors.Is(e, ErrNoAccounts) {
					log.Printf("scheduled sync could not start: %v", e)
				}
			}
		}
	}()
}
func (s *Service) Close() { s.cancel(); s.wg.Wait() }
func (s *Service) Check() error {
	if s.Config == nil || s.Store == nil || s.Collector == nil {
		return fmt.Errorf("incomplete service")
	}
	return nil
}
