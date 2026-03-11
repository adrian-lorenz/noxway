package admin

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-for-unit-tests-only"

func makeToken(role string, exp time.Time) string {
	claims := jwt.MapClaims{
		"issuer":   "api-gateway",
		"username": "admin",
		"role":     role,
		"exp":      exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := tok.SignedString([]byte(testSecret))
	return s
}

func TestMain(m *testing.M) {
	os.Setenv("JWTSECRET", testSecret)
	os.Exit(m.Run())
}

// ─── validateToken ────────────────────────────────────────────────────────────

func TestValidateToken_Valid(t *testing.T) {
	tok := makeToken("admin", time.Now().Add(1*time.Hour))
	if !validateToken(tok) {
		t.Error("valid admin token should pass")
	}
}

func TestValidateToken_WrongRole(t *testing.T) {
	tok := makeToken("viewer", time.Now().Add(1*time.Hour))
	if validateToken(tok) {
		t.Error("non-admin role should be rejected")
	}
}

func TestValidateToken_Expired(t *testing.T) {
	tok := makeToken("admin", time.Now().Add(-1*time.Second))
	if validateToken(tok) {
		t.Error("expired token should be rejected")
	}
}

func TestValidateToken_EmptyString(t *testing.T) {
	if validateToken("") {
		t.Error("empty string should be rejected")
	}
}

func TestValidateToken_Garbage(t *testing.T) {
	if validateToken("not.a.jwt") {
		t.Error("garbage token should be rejected")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	claims := jwt.MapClaims{
		"role": "admin",
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := tok.SignedString([]byte("wrong-secret"))
	if validateToken(s) {
		t.Error("token signed with wrong secret should be rejected")
	}
}

func TestValidateToken_AlgNoneAttack(t *testing.T) {
	// Classic JWT "alg=none" attack: craft a token with no signature.
	// A vulnerable validator would accept this; ours must reject it.
	header := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"           // {"alg":"none","typ":"JWT"}
	payload := "eyJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9" // {"role":"admin","exp":9999999999}
	noneToken := header + "." + payload + "."
	if validateToken(noneToken) {
		t.Error("alg=none token must be rejected")
	}
}

func TestValidateToken_TamperedSignature(t *testing.T) {
	tok := makeToken("admin", time.Now().Add(1*time.Hour))
	// Replace the last character with a different one to ensure the signature is actually changed.
	last := tok[len(tok)-1]
	replacement := byte('X')
	if last == 'X' {
		replacement = 'Y'
	}
	tampered := tok[:len(tok)-1] + string(replacement)
	if validateToken(tampered) {
		t.Error("token with tampered signature must be rejected")
	}
}

// ─── Login rate limiter ───────────────────────────────────────────────────────

func resetLoginAttempts() {
	loginMu.Lock()
	defer loginMu.Unlock()
	loginAttempts = make(map[string]*loginCounter)
}

func TestLoginRateLimit_AllowsUnderLimit(t *testing.T) {
	resetLoginAttempts()
	ip := "1.2.3.4"
	for i := 0; i < maxLoginAttempts; i++ {
		if !checkLoginRateLimit(ip) {
			t.Fatalf("attempt %d should be allowed (limit=%d)", i+1, maxLoginAttempts)
		}
	}
}

func TestLoginRateLimit_BlocksAfterLimit(t *testing.T) {
	resetLoginAttempts()
	ip := "1.2.3.5"
	for i := 0; i < maxLoginAttempts; i++ {
		checkLoginRateLimit(ip)
	}
	if checkLoginRateLimit(ip) {
		t.Errorf("attempt %d should be blocked (limit=%d)", maxLoginAttempts+1, maxLoginAttempts)
	}
}

func TestLoginRateLimit_DifferentIPsIndependent(t *testing.T) {
	resetLoginAttempts()
	ipA := "10.0.0.1"
	ipB := "10.0.0.2"
	// Exhaust ipA
	for i := 0; i < maxLoginAttempts+1; i++ {
		checkLoginRateLimit(ipA)
	}
	// ipB should still be allowed
	if !checkLoginRateLimit(ipB) {
		t.Error("rate limit on one IP should not affect other IPs")
	}
}

func TestLoginRateLimit_ResetsAfterWindow(t *testing.T) {
	resetLoginAttempts()
	ip := "10.0.0.9"
	// Exhaust the limit
	for i := 0; i < maxLoginAttempts+2; i++ {
		checkLoginRateLimit(ip)
	}
	// Manually backdate the reset time so the window has passed
	loginMu.Lock()
	if entry := loginAttempts[ip]; entry != nil {
		entry.resetAt = time.Now().Add(-1 * time.Second)
	}
	loginMu.Unlock()
	if !checkLoginRateLimit(ip) {
		t.Error("should be allowed again after window expires")
	}
}
