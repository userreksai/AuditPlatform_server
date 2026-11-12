package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookie = "audit_session"

type loginAttempt struct {
	Count int
	Until time.Time
}
type API struct {
	Service  *Service
	mu       sync.Mutex
	sessions map[[32]byte]time.Time
	attempts map[string]loginAttempt
}

func NewHandler(service *Service) http.Handler {
	a := &API{Service: service, sessions: map[[32]byte]time.Time{}, attempts: map[string]loginAttempt{}}
	m := http.NewServeMux()
	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("POST /api/auth/login", a.login)
	m.HandleFunc("GET /api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]string{"username": service.Config.Auth.Username})
	})
	m.HandleFunc("POST /api/auth/logout", a.logout)
	m.HandleFunc("GET /api/dashboard", func(w http.ResponseWriter, r *http.Request) {
		d, e := service.Dashboard()
		if e != nil {
			fail(w, 500, "读取审计数据失败")
			return
		}
		reply(w, 200, d)
	})
	m.HandleFunc("GET /api/rds-secrets", func(w http.ResponseWriter, r *http.Request) {
		v, e := service.RDSSecrets()
		if e != nil {
			fail(w, 500, "读取 RDS 托管数据失败")
			return
		}
		reply(w, 200, v)
	})
	m.HandleFunc("GET /api/sync/status", func(w http.ResponseWriter, r *http.Request) {
		d, e := service.Status()
		if e != nil {
			fail(w, 500, "读取同步状态失败")
			return
		}
		reply(w, 200, d)
	})
	m.HandleFunc("POST /api/sync", func(w http.ResponseWriter, r *http.Request) {
		e := service.StartSync("manual")
		if errors.Is(e, ErrRunning) {
			fail(w, 409, e.Error())
			return
		}
		if errors.Is(e, ErrNoAccounts) {
			fail(w, 400, e.Error())
			return
		}
		if e != nil {
			fail(w, 500, "创建同步任务失败")
			return
		}
		reply(w, 202, map[string]string{"message": "已开始全量获取所有配置账号"})
	})
	m.HandleFunc("PATCH /api/users/{accountId}/{userId}/annotations", func(w http.ResponseWriter, r *http.Request) {
		var v Annotation
		if !decode(w, r, &v) {
			return
		}
		if len(v.Owner) > 200 || len(v.Note) > 10000 {
			fail(w, 400, "负责人或备注过长")
			return
		}
		if v.ReviewStatus != "pending" && v.ReviewStatus != "reviewed" && v.ReviewStatus != "attention" {
			fail(w, 400, "无效的需求检查状态")
			return
		}
		e := service.Store.Annotate(r.PathValue("accountId"), r.PathValue("userId"), v, service.Config.Accounts)
		if e == sql.ErrNoRows {
			fail(w, 404, "IAM 用户不存在")
			return
		}
		if e != nil {
			fail(w, 500, "保存审计备注失败")
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "接口不存在") })
	files := http.FileServer(http.Dir(service.Config.Server.WebDirectory))
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "不支持的请求方法")
			return
		}
		clean := filepath.Clean(filepath.FromSlash(r.URL.Path))
		p := filepath.Join(service.Config.Server.WebDirectory, clean)
		if info, e := os.Stat(p); e == nil && !info.IsDir() {
			files.ServeHTTP(w, r)
			return
		}
		if filepath.Ext(r.URL.Path) != "" {
			http.NotFound(w, r)
			return
		}
		index := filepath.Join(service.Config.Server.WebDirectory, "index.html")
		if _, e := os.Stat(index); e != nil {
			http.Error(w, "Frontend not installed. Build AuditPlatform_web and set server.web_directory.", 503)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, index)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != "GET" && r.Method != "HEAD" {
				if !sameOrigin(r) {
					fail(w, 403, "已拒绝跨站请求")
					return
				}
			}
			if r.URL.Path != "/api/health" && r.URL.Path != "/api/auth/login" && !a.authenticated(r) {
				fail(w, 401, "请先登录")
				return
			}
		}
		defer func() {
			if e := recover(); e != nil {
				log.Printf("HTTP handler panic: %v", e)
				fail(w, 500, "服务器内部错误")
			}
		}()
		m.ServeHTTP(w, r)
	})
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "请求 JSON 无效")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	return e == nil && (u.Scheme == "http" || u.Scheme == "https") && strings.EqualFold(u.Host, r.Host) && u.Path == ""
}
func (a *API) authenticated(r *http.Request) bool {
	c, e := r.Cookie(sessionCookie)
	if e != nil {
		return false
	}
	key := sha256.Sum256([]byte(c.Value))
	a.mu.Lock()
	defer a.mu.Unlock()
	expires, ok := a.sessions[key]
	if ok && time.Now().Before(expires) {
		return true
	}
	delete(a.sessions, key)
	return false
}
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		ip = r.RemoteAddr
	}
	now := time.Now()
	a.mu.Lock()
	for k, t := range a.attempts {
		if now.After(t.Until) {
			delete(a.attempts, k)
		}
	}
	for k, t := range a.sessions {
		if now.After(t) {
			delete(a.sessions, k)
		}
	}
	attempt := a.attempts[ip]
	if attempt.Count >= 10 && now.Before(attempt.Until) {
		a.mu.Unlock()
		w.Header().Set("Retry-After", "900")
		fail(w, 429, "登录尝试过多，请 15 分钟后重试")
		return
	}
	if len(a.attempts) > 10000 {
		a.mu.Unlock()
		fail(w, 429, "登录请求过多，请稍后重试")
		return
	}
	if attempt.Until.IsZero() || now.After(attempt.Until) {
		attempt = loginAttempt{Until: now.Add(15 * time.Minute)}
	}
	attempt.Count++
	a.attempts[ip] = attempt
	a.mu.Unlock()
	passwordOK := bcrypt.CompareHashAndPassword([]byte(a.Service.Config.Auth.PasswordHash), []byte(v.Password)) == nil
	usernameOK := subtle.ConstantTimeCompare([]byte(v.Username), []byte(a.Service.Config.Auth.Username)) == 1
	if !passwordOK || !usernameOK {
		fail(w, 401, "账号或密码错误")
		return
	}
	b := make([]byte, 32)
	if _, e = rand.Read(b); e != nil {
		fail(w, 500, "创建会话失败")
		return
	}
	token := hex.EncodeToString(b)
	expires := now.Add(time.Duration(a.Service.Config.Server.SessionHours) * time.Hour)
	a.mu.Lock()
	if old, er := r.Cookie(sessionCookie); er == nil {
		delete(a.sessions, sha256.Sum256([]byte(old.Value)))
	}
	a.sessions[sha256.Sum256([]byte(token))] = expires
	delete(a.attempts, ip)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: a.Service.Config.Server.SecureCookie, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(time.Until(expires).Seconds())})
	reply(w, 200, map[string]string{"username": a.Service.Config.Auth.Username})
}
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie(sessionCookie); e == nil {
		a.mu.Lock()
		delete(a.sessions, sha256.Sum256([]byte(c.Value)))
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: a.Service.Config.Server.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	reply(w, 200, map[string]bool{"ok": true})
}
