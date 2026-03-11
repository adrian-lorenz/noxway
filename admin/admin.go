package admin

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/adrian-lorenz/noxway/global"
	"github.com/adrian-lorenz/noxway/middleware"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var templateFiles embed.FS

const cookieName = "noxway_session"

// ─── Login rate limiter ───────────────────────────────────────────────────────

type loginCounter struct {
	count   int
	resetAt time.Time
}

var (
	loginAttempts = make(map[string]*loginCounter)
	loginMu       sync.Mutex
)

const (
	maxLoginAttempts = 10
	loginWindow      = 15 * time.Minute
)

func checkLoginRateLimit(ip string) bool {
	loginMu.Lock()
	defer loginMu.Unlock()
	now := time.Now()
	entry := loginAttempts[ip]
	if entry == nil || now.After(entry.resetAt) {
		loginAttempts[ip] = &loginCounter{count: 1, resetAt: now.Add(loginWindow)}
		return true
	}
	entry.count++
	return entry.count <= maxLoginAttempts
}

// ─── Routes ──────────────────────────────────────────────────────────────────

func RegisterRoutes(r *gin.Engine) {
	r.GET("/web/*any", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/admin/")
	})

	g := r.Group("/admin")
	g.Use(middleware.SecurityHeaders())
	g.GET("", func(c *gin.Context) {
		_, err := c.Cookie(cookieName)
		if err != nil {
			c.Redirect(http.StatusFound, "/admin/login")
			return
		}
		c.Redirect(http.StatusFound, "/admin/dashboard")
	})
	g.GET("/login", showLogin)
	g.POST("/login", handleLogin)
	g.GET("/logout", handleLogout)

	auth := g.Group("", authMiddleware(), csrfMiddleware())
	auth.GET("/dashboard", showDashboard)
	auth.GET("/gateway", showGateway)
	auth.POST("/gateway", saveGateway)
	auth.GET("/endpoints", showEndpoints)
	auth.GET("/logs", showLogs)
	auth.GET("/reload", reloadConfig)

	// HTMX partials
	auth.GET("/htmx/dashboard", htmxDashboard)
	auth.GET("/htmx/logs", htmxLogs)
	auth.GET("/htmx/endpoint/edit/:svc/:ep", htmxEndpointEdit)
	auth.POST("/htmx/endpoint/save", htmxEndpointSave)
	auth.DELETE("/htmx/service/:uuid", htmxDeleteService)
	auth.POST("/htmx/service/add", htmxAddService)
	auth.POST("/htmx/endpoint/add/:svc", htmxAddEndpoint)
	auth.DELETE("/htmx/endpoint/:svc/:ep", htmxDeleteEndpoint)
	auth.GET("/htmx/endpoint/cancel", htmxCancelEdit)
	auth.GET("/htmx/endpoints-table", htmxEndpointsTable)
	auth.GET("/htmx/waf/edit/:svc", htmxWAFEdit)
	auth.POST("/htmx/waf/save/:svc", htmxWAFSave)
	auth.POST("/htmx/gateway", htmxSaveGateway)
	auth.POST("/htmx/cert/retrieve", htmxRetrieveCert)
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(cookieName)
		if err != nil || !validateToken(token) {
			if c.GetHeader("HX-Request") == "true" {
				c.Header("HX-Redirect", "/admin/login")
				c.AbortWithStatus(http.StatusUnauthorized)
			} else {
				c.Redirect(http.StatusFound, "/admin/login")
				c.Abort()
			}
			return
		}
		c.Next()
	}
}

// csrfMiddleware protects HTMX state-changing endpoints from CSRF.
// All POST/DELETE/PATCH/PUT requests under /admin/htmx/* must carry the
// HX-Request: true header, which cross-origin form submissions cannot set.
func csrfMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/admin/htmx/") {
			if c.GetHeader("HX-Request") != "true" {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		c.Next()
	}
}

func validateToken(tokenStr string) bool {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(os.Getenv("JWTSECRET")), nil
	})
	if err != nil || !token.Valid {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return false
		}
	}
	return claims["role"] == "admin"
}

// ─── Auth handlers ────────────────────────────────────────────────────────────

func showLogin(c *gin.Context) {
	renderLogin(c, "")
}

func handleLogin(c *gin.Context) {
	ip := middleware.GetIP(c)
	if !checkLoginRateLimit(ip) {
		renderLoginError(c, "Too many login attempts. Please try again later.")
		return
	}

	username := c.PostForm("username")
	password := c.PostForm("password")

	cfg := global.GetConfig()
	if len(cfg.SystemWhitelist) > 0 || len(cfg.SystemWhitelistDNS) > 0 {
		allowed := false
		for _, w := range cfg.SystemWhitelist {
			if w == ip {
				allowed = true
				break
			}
		}
		if !allowed {
			renderLoginError(c, "Access not allowed from your IP")
			return
		}
	}

	for _, u := range global.Auth.Users {
		if u.Username == username {
			if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err == nil && u.Role == "admin" {
				tokenStr, err := createToken(username, u.Role)
				if err != nil {
					renderLoginError(c, "Internal error")
					return
				}
				setSessionCookie(c, tokenStr, int((8 * time.Hour).Seconds()))
				c.Header("HX-Redirect", "/admin/dashboard")
				c.Status(http.StatusOK)
				return
			}
		}
	}
	renderLoginError(c, "Invalid username or password")
}

func handleLogout(c *gin.Context) {
	setSessionCookie(c, "", -1)
	c.Redirect(http.StatusFound, "/admin/login")
}

// setSessionCookie writes the session cookie with SameSite=Strict.
// Secure flag is enabled when SSL is configured.
func setSessionCookie(c *gin.Context, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		MaxAge:   maxAge,
		Path:     "/",
		HttpOnly: true,
		Secure:   global.GetConfig().SSL,
		SameSite: http.SameSiteStrictMode,
	})
}

func createToken(username, role string) (string, error) {
	claims := jwt.MapClaims{
		"issuer":   "api-gateway",
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(8 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWTSECRET")))
}

func renderLogin(c *gin.Context, errMsg string) {
	t, err := template.ParseFS(templateFiles, "templates/login.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "template error: %v", err)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(c.Writer, "login", gin.H{"Error": errMsg})
}

func renderLoginError(c *gin.Context, msg string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusUnauthorized, `<div class="error">%s</div>`, msg)
}

// ─── Template helpers ─────────────────────────────────────────────────────────

var funcMap = template.FuncMap{
	"toJSON":        toJSON,
	"fmtTime":       fmtTime,
	"fmtMs":         fmtMs,
	"rateWindowMin": rateWindowMin,
	"dict":          templateDict,
}

func renderPage(c *gin.Context, page string, data any) {
	t, err := template.New("").Funcs(funcMap).ParseFS(templateFiles,
		"templates/layout.html",
		"templates/components.html",
		"templates/"+page+".html",
	)
	if err != nil {
		c.String(http.StatusInternalServerError, "template error: %v", err)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(c.Writer, "layout", data); err != nil {
		c.String(http.StatusInternalServerError, "render error: %v", err)
	}
}

func renderPartial(c *gin.Context, tmplName string, data any, files ...string) {
	fullPaths := make([]string, len(files))
	for i, f := range files {
		fullPaths[i] = "templates/" + f
	}
	t, err := template.New("").Funcs(funcMap).ParseFS(templateFiles, fullPaths...)
	if err != nil {
		c.String(http.StatusInternalServerError, "template error: %v", err)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(c.Writer, tmplName, data); err != nil {
		c.String(http.StatusInternalServerError, "render error: %v", err)
	}
}
