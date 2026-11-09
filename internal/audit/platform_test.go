package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testConfig(t *testing.T) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("accounts: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDefaultConfigurationAndBeijingSchedule(t *testing.T) {
	c := testConfig(t)
	if c.Auth.Username != "auditroot" || bcrypt.CompareHashAndPassword([]byte(c.Auth.PasswordHash), []byte("a181818.")) != nil {
		t.Fatal("default login mismatch")
	}
	if c.Auth.Password != "" {
		t.Fatal("plaintext password retained in loaded config")
	}
	for _, tc := range []struct{ now, want string }{
		{"2026-11-09T00:59:59Z", "2026-11-09T01:00:00Z"},
		{"2026-11-09T01:00:00Z", "2026-11-10T01:00:00Z"},
		{"2026-11-09T20:00:00Z", "2026-11-10T01:00:00Z"},
	} {
		now, _ := time.Parse(time.RFC3339, tc.now)
		got := NextRun(now, c.Sync.Time, c.Sync.Timezone).UTC().Format(time.RFC3339)
		if got != tc.want {
			t.Fatalf("%s -> %s, want %s", tc.now, got, tc.want)
		}
	}
}

func TestSnapshotFailureAnnotationsAndRemovedAccount(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := AccountConfig{ID: "prod", Name: "Production", ExpectedAccountID: "123456789012"}
	a := Account{ID: c.ExpectedAccountID, Name: c.Name, Status: "success", LastSyncedAt: "2026-11-09T01:00:00Z", UserCount: 1}
	users := []AuditUser{{AccountID: a.ID, UserID: "AIDAEXAMPLE", Username: "reader", ReviewStatus: "pending"}}
	if err = s.SaveSnapshot(c.ID, a, users); err != nil {
		t.Fatal(err)
	}
	note := Annotation{Owner: "Audit owner", ReviewStatus: "reviewed", Note: "Verified"}
	if err = s.Annotate(a.ID, users[0].UserID, note, []AccountConfig{c}); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkFailure(c, "AccessDenied"); err != nil {
		t.Fatal(err)
	}
	accounts, got, err := s.ReadDashboard([]AccountConfig{c})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Owner != note.Owner || accounts[0].Status != "error" || accounts[0].LastSyncedAt != a.LastSyncedAt {
		t.Fatalf("last good snapshot/annotation lost: %#v %#v", accounts, got)
	}
	if err = s.SaveSnapshot(c.ID, a, users); err != nil {
		t.Fatal(err)
	}
	_, got, err = s.ReadDashboard([]AccountConfig{c})
	if err != nil || got[0].ReviewStatus != "reviewed" {
		t.Fatal("sync overwrote annotation", err)
	}
	accounts, got, err = s.ReadDashboard(nil)
	if err != nil || len(accounts) != 0 || len(got) != 0 {
		t.Fatal("removed config account still exposed", err)
	}
}

type testCollector func(context.Context, AccountConfig) (Account, []AuditUser, error)

func (f testCollector) Collect(ctx context.Context, c AccountConfig) (Account, []AuditUser, error) {
	return f(ctx, c)
}

func TestAuthenticationOriginAndNoAccountSync(t *testing.T) {
	c := testConfig(t)
	s, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	svc := NewService(c, s, testCollector(func(context.Context, AccountConfig) (Account, []AuditUser, error) {
		return Account{}, nil, errors.New("unexpected call")
	}))
	defer svc.Close()
	h := NewHandler(svc)
	call := func(method, path, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/dashboard", "", nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("POST", "/api/auth/login", `{"username":"auditroot","password":"wrong"}`, nil, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := call("POST", "/api/auth/login", `{"username":"auditroot","password":"a181818."}`, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	cookie := cookies[0]
	if w = call("GET", "/api/dashboard", "", cookie, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	var data Dashboard
	if json.Unmarshal(w.Body.Bytes(), &data) != nil || data.Sync.Schedule != "09:00" || data.Sync.Timezone != "Asia/Shanghai" || data.Users == nil {
		t.Fatal(w.Body.String())
	}
	if w = call("POST", "/api/sync", "", cookie, "https://attacker.invalid"); w.Code != 403 {
		t.Fatal("cross origin write accepted", w.Code)
	}
	if w = call("POST", "/api/sync", "", cookie, ""); w.Code != 400 {
		t.Fatal("empty config sync should fail clearly", w.Code)
	}
	if w = call("POST", "/api/auth/logout", "", cookie, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = call("GET", "/api/auth/me", "", cookie, ""); w.Code != 401 {
		t.Fatal("logout session remains active", w.Code)
	}
}

func TestSyncLockAndPersistentHistory(t *testing.T) {
	c := testConfig(t)
	c.Accounts = []AccountConfig{{ID: "prod", Name: "Production"}}
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	svc := NewService(c, store, testCollector(func(ctx context.Context, a AccountConfig) (Account, []AuditUser, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return Account{}, nil, ctx.Err()
		}
		return Account{ID: "123456789012", Name: a.Name, Status: "success"}, []AuditUser{}, nil
	}))
	if err = svc.StartSync("manual"); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err = svc.StartSync("manual"); !errors.Is(err, ErrRunning) {
		t.Fatal("concurrent sync allowed", err)
	}
	close(release)
	svc.wg.Wait()
	status, err := svc.Status()
	if err != nil || status.Running || status.LastResult != "success" || len(status.Logs) != 1 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	svc.Close()
}
