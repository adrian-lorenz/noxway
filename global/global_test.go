package global

import "testing"

// ─── safeLogPath ─────────────────────────────────────────────────────────────

func TestSafeLogPath_Valid(t *testing.T) {
	cases := []string{
		"./log/noxway.log",
		"/var/log/noxway.log",
		"/app/log/gateway.log",
		"log/access.log",
		"/tmp/noxway.log",
	}
	for _, p := range cases {
		if !safeLogPath(p) {
			t.Errorf("expected %q to be a safe path", p)
		}
	}
}

func TestSafeLogPath_Traversal(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		"../secret.log",
		"/app/../../../etc/cron.d/evil",
		"log/../../etc/shadow",
		"./../outside.log",
	}
	for _, p := range cases {
		if safeLogPath(p) {
			t.Errorf("expected %q to be rejected as unsafe path", p)
		}
	}
}
