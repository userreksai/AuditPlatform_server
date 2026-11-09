package audit

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	_ "time/tzdata"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Address      string `yaml:"address"`
		WebDirectory string `yaml:"web_directory"`
		SecureCookie bool   `yaml:"secure_cookie"`
		SessionHours int    `yaml:"session_hours"`
	} `yaml:"server"`
	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
	Auth struct {
		Username     string `yaml:"username"`
		Password     string `yaml:"password"`
		PasswordHash string `yaml:"password_hash"`
	} `yaml:"auth"`
	Sync struct {
		Time           string `yaml:"time"`
		Timezone       string `yaml:"timezone"`
		TimeoutMinutes int    `yaml:"timeout_minutes"`
	} `yaml:"sync"`
	Accounts []AccountConfig `yaml:"accounts"`
}
type AccountConfig struct {
	ID                string `yaml:"id"`
	Name              string `yaml:"name"`
	Owner             string `yaml:"owner"`
	Region            string `yaml:"region"`
	ExpectedAccountID string `yaml:"expected_account_id"`
	AccessKeyID       string `yaml:"access_key_id"`
	SecretAccessKey   string `yaml:"secret_access_key"`
	SessionToken      string `yaml:"session_token"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	c.Server.Address = "127.0.0.1:8080"
	c.Server.WebDirectory = "./web"
	c.Server.SessionHours = 12
	c.Database.Path = "./data/audit.db"
	c.Auth.Username = "auditroot"
	c.Auth.Password = "a181818."
	c.Sync.Time = "09:00"
	c.Sync.Timezone = "Asia/Shanghai"
	c.Sync.TimeoutMinutes = 30
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	d.KnownFields(true)
	if err = d.Decode(c); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if _, _, err = net.SplitHostPort(c.Server.Address); err != nil {
		return nil, fmt.Errorf("invalid server.address")
	}
	if c.Auth.Username == "" || (c.Auth.Password == "" && c.Auth.PasswordHash == "") {
		return nil, fmt.Errorf("auth username and password/hash required")
	}
	if c.Auth.PasswordHash == "" {
		h, e := bcrypt.GenerateFromPassword([]byte(c.Auth.Password), bcrypt.DefaultCost)
		if e != nil {
			return nil, e
		}
		c.Auth.PasswordHash = string(h)
	} else if _, err = bcrypt.Cost([]byte(c.Auth.PasswordHash)); err != nil {
		return nil, fmt.Errorf("invalid bcrypt password_hash")
	}
	c.Auth.Password = ""
	if c.Server.SessionHours < 1 || c.Server.SessionHours > 168 {
		return nil, fmt.Errorf("session_hours must be 1..168")
	}
	if c.Sync.TimeoutMinutes < 1 || c.Sync.TimeoutMinutes > 1440 {
		return nil, fmt.Errorf("timeout_minutes must be 1..1440")
	}
	if _, err = time.Parse("15:04", c.Sync.Time); err != nil {
		return nil, fmt.Errorf("sync.time must be HH:MM")
	}
	if _, err = time.LoadLocation(c.Sync.Timezone); err != nil {
		return nil, fmt.Errorf("invalid sync.timezone")
	}
	seen := map[string]bool{}
	for i := range c.Accounts {
		a := &c.Accounts[i]
		if a.ID == "" || seen[a.ID] {
			return nil, fmt.Errorf("each accounts.id must be nonempty and unique")
		}
		seen[a.ID] = true
		if a.AccessKeyID == "" || a.SecretAccessKey == "" {
			return nil, fmt.Errorf("account %s requires access_key_id and secret_access_key", a.ID)
		}
		if a.Region == "" {
			a.Region = "us-east-1"
		}
		if a.Name == "" {
			a.Name = a.ID
		}
		if a.ExpectedAccountID != "" {
			if len(a.ExpectedAccountID) != 12 || strings.IndexFunc(a.ExpectedAccountID, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return nil, fmt.Errorf("invalid expected_account_id for %s", a.ID)
			}
		}
	}
	base := filepath.Dir(path)
	if !filepath.IsAbs(c.Database.Path) {
		c.Database.Path = filepath.Join(base, c.Database.Path)
	}
	if !filepath.IsAbs(c.Server.WebDirectory) {
		c.Server.WebDirectory = filepath.Join(base, c.Server.WebDirectory)
	}
	return c, nil
}

func NextRun(now time.Time, clock, zone string) time.Time {
	loc, err := time.LoadLocation(zone)
	if err != nil {
		loc = time.FixedZone("Asia/Shanghai", 8*3600)
	}
	t, err := time.Parse("15:04", clock)
	if err != nil {
		t, _ = time.Parse("15:04", "09:00")
	}
	n := now.In(loc)
	next := time.Date(n.Year(), n.Month(), n.Day(), t.Hour(), t.Minute(), 0, 0, loc)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}
