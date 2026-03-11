package waf

import "testing"

// ─── helpers ──────────────────────────────────────────────────────────────────

func allRules() WAFConfig {
	return WAFConfig{
		Enabled:            true,
		BlockSQLi:          true,
		BlockXSS:           true,
		BlockPathTraversal: true,
		BlockCommandInj:    true,
		BlockLargeBody:     false,
	}
}

func assertBlocked(t *testing.T, cfg WAFConfig, path, query, body, wantRule string) {
	t.Helper()
	r := Check(cfg, path, query, body)
	if r == nil {
		t.Errorf("expected block (rule=%q) but request was allowed — path=%q query=%q body=%q", wantRule, path, query, body)
		return
	}
	if r.Rule != wantRule {
		t.Errorf("wrong rule: got %q, want %q", r.Rule, wantRule)
	}
}

func assertAllowed(t *testing.T, cfg WAFConfig, path, query, body string) {
	t.Helper()
	r := Check(cfg, path, query, body)
	if r != nil {
		t.Errorf("expected allow but got blocked (rule=%q matched=%q) — path=%q query=%q body=%q", r.Rule, r.Matched, path, query, body)
	}
}

// ─── WAF disabled ─────────────────────────────────────────────────────────────

func TestWAFDisabled(t *testing.T) {
	cfg := allRules()
	cfg.Enabled = false
	// Even with clear attack payloads, nothing should be blocked when WAF is off.
	assertAllowed(t, cfg, "/path", "x=1 UNION SELECT 1,2,3", "<script>alert(1)</script>")
}

// ─── SQL injection ────────────────────────────────────────────────────────────

func TestSQLi_Blocked(t *testing.T) {
	cfg := allRules()
	cases := []struct{ path, query, body string }{
		{"/api", "id=1 UNION SELECT 1,2,3", ""},
		{"/api", "q=1' OR '1'='1", ""},
		{"/api", "", "DROP TABLE users"},
		{"/api", "", "INSERT INTO users VALUES(1,'admin')"},
		{"/api", "", "'; EXEC xp_cmdshell('cmd')"},
		{"/api", "x=1-- comment", ""},  // regex requires whitespace/text after --
		{"/api", "", "1 OR 1=1"},
		// URL-encoded variant
		{"/api", "x=1%20UNION%20SELECT%201%2C2", ""},
	}
	for _, tc := range cases {
		assertBlocked(t, cfg, tc.path, tc.query, tc.body, "sqli")
	}
}

func TestSQLi_RuleDisabled(t *testing.T) {
	cfg := allRules()
	cfg.BlockSQLi = false
	assertAllowed(t, cfg, "/api", "x=UNION SELECT 1", "")
}

func TestSQLi_LegitimateRequests(t *testing.T) {
	cfg := allRules()
	cases := []struct{ path, query, body string }{
		{"/api/users", "name=Alice&age=30", ""},
		{"/api/search", "q=select+all+items", ""},       // "select" as normal word, no SQL keywords around it
		{"/api/orders", "status=pending", `{"id":123}`}, // JSON body
	}
	for _, tc := range cases {
		assertAllowed(t, cfg, tc.path, tc.query, tc.body)
	}
}

// ─── XSS ─────────────────────────────────────────────────────────────────────

func TestXSS_Blocked(t *testing.T) {
	cfg := allRules()
	cases := []struct{ path, query, body string }{
		{"/api", "x=<script>alert(1)</script>", ""},
		{"/api", "", "<script src='evil.js'>"},
		{"/api", "cb=javascript:void(0)", ""},
		{"/api", "", "<img onerror=alert(1) src=x>"},
		{"/api", "", "<iframe src='evil.com'>"},
		{"/api", "x=vbscript:msgbox(1)", ""},
		{"/api", "", "document.cookie"},
		{"/api", "", "eval(atob('..'))"},
		// URL-encoded
		{"/api", "x=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ""},
	}
	for _, tc := range cases {
		assertBlocked(t, cfg, tc.path, tc.query, tc.body, "xss")
	}
}

func TestXSS_RuleDisabled(t *testing.T) {
	cfg := allRules()
	cfg.BlockXSS = false
	assertAllowed(t, cfg, "/api", "x=<script>alert(1)</script>", "")
}

func TestXSS_LegitimateRequests(t *testing.T) {
	cfg := allRules()
	assertAllowed(t, cfg, "/api/docs", "format=html", "")
	assertAllowed(t, cfg, "/api/search", "q=react+components", "")
}

// ─── Path traversal ───────────────────────────────────────────────────────────

func TestPathTraversal_Blocked(t *testing.T) {
	cfg := allRules()
	cases := []struct{ path, query, body string }{
		{"/../etc/passwd", "", ""},
		{"/api", "file=../../etc/shadow", ""},
		{"/api", "", "../../../windows/system32/cmd.exe"},
		{"/api", "p=%2e%2e%2fetc%2fpasswd", ""},
		{"/api", "p=..%2fetc%2fpasswd", ""},
		// %252e decodes to %2e (double-encoded dot); needs trailing slash to match
		{"/api", "p=%252e%252e%2f", ""},
		{"/api/files", "path=/proc/self/environ", ""},
	}
	for _, tc := range cases {
		assertBlocked(t, cfg, tc.path, tc.query, tc.body, "path-traversal")
	}
}

func TestPathTraversal_RuleDisabled(t *testing.T) {
	cfg := allRules()
	cfg.BlockPathTraversal = false
	assertAllowed(t, cfg, "/../etc/passwd", "", "")
}

func TestPathTraversal_LegitimateRequests(t *testing.T) {
	cfg := allRules()
	assertAllowed(t, cfg, "/api/files/report.pdf", "", "")
	assertAllowed(t, cfg, "/api/v2/users", "sort=name", "")
}

// ─── Command injection ────────────────────────────────────────────────────────

func TestCmdInj_Blocked(t *testing.T) {
	cfg := allRules()
	cases := []struct{ path, query, body string }{
		// pipe operator
		{"/api", "", "value=test|whoami"},
		// logical AND
		{"/api", "cmd=id && whoami", ""},
		// backtick subshell
		{"/api", "", "name=`id`"},
		// $() subshell
		{"/api", "", "x=$(whoami)"},
		// semicolon + known binary
		{"/api", "q=test;curl evil.com", ""},
		{"/api", "", "x=test;bash"},
		{"/api", "x=foo; ls -la", ""},
	}
	for _, tc := range cases {
		assertBlocked(t, cfg, tc.path, tc.query, tc.body, "cmdinj")
	}
}

func TestCmdInj_SemicolonLsGap(t *testing.T) {
	cfg := allRules()
	assertBlocked(t, cfg, "/api", "x=foo; ls -la", "", "cmdinj")
}

func TestCmdInj_RuleDisabled(t *testing.T) {
	cfg := allRules()
	cfg.BlockCommandInj = false
	assertAllowed(t, cfg, "/api", "x=foo; ls -la", "")
}

func TestCmdInj_LegitimateRequests(t *testing.T) {
	cfg := allRules()
	assertAllowed(t, cfg, "/api/shell-scripts", "name=deploy.sh", "")
	assertAllowed(t, cfg, "/api/search", "q=bash+scripting+tutorial", "")
}

// ─── Only specific rules enabled ─────────────────────────────────────────────

func TestOnlySQLiEnabled(t *testing.T) {
	cfg := WAFConfig{
		Enabled:            true,
		BlockSQLi:          true,
		BlockXSS:           false,
		BlockPathTraversal: false,
		BlockCommandInj:    false,
	}
	assertBlocked(t, cfg, "/api", "x=UNION SELECT 1", "", "sqli")
	assertAllowed(t, cfg, "/api", "x=<script>alert(1)</script>", "")
	assertAllowed(t, cfg, "/../etc/passwd", "", "")
	assertAllowed(t, cfg, "/api", "x=; ls", "")
}

// ─── Inputs in different positions ───────────────────────────────────────────

func TestDetectsInPath(t *testing.T) {
	cfg := allRules()
	assertBlocked(t, cfg, "/api/../../../etc/passwd", "", "", "path-traversal")
}

func TestDetectsInQuery(t *testing.T) {
	cfg := allRules()
	assertBlocked(t, cfg, "/api", "q=UNION SELECT 1,2", "", "sqli")
}

func TestDetectsInBody(t *testing.T) {
	cfg := allRules()
	assertBlocked(t, cfg, "/api", "", "<script>evil()</script>", "xss")
}
