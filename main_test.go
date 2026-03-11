package main

import (
	"net/http"
	"testing"
)

// ─── sanitizeHeader ───────────────────────────────────────────────────────────

func TestSanitizeHeader_RemovesCRLF(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"normal-value", "normal-value"},
		{"value\r\nX-Injected: evil", "value X-Injected: evil"}, // CRLF removed, spaces preserved after TrimSpace? No — let's check
		{"value\nInject: x", "value Inject: x"},
		{"value\rInject", "value Inject"},
		{"has\x00null", "hasnull"},
		{"  padded  ", "padded"},
	}
	for _, tc := range cases {
		got := sanitizeHeader(tc.input)
		// Key properties: no \r, \n, or \x00 in output
		for _, bad := range []byte{'\r', '\n', '\x00'} {
			for _, c := range []byte(got) {
				if c == bad {
					t.Errorf("sanitizeHeader(%q) still contains unsafe byte 0x%02x in output %q", tc.input, bad, got)
				}
			}
		}
	}
}

func TestSanitizeHeader_InjectionPrevented(t *testing.T) {
	// A classic header injection attempt
	payload := "legit\r\nX-Admin: true"
	got := sanitizeHeader(payload)
	for _, c := range got {
		if c == '\r' || c == '\n' {
			t.Errorf("injection payload not sanitized: %q → %q", payload, got)
		}
	}
}

func TestSanitizeHeader_CleanPassthrough(t *testing.T) {
	cases := []string{
		"application/json",
		"Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
		"en-US,en;q=0.9",
		"gzip, deflate, br",
	}
	for _, v := range cases {
		got := sanitizeHeader(v)
		if got != v {
			t.Errorf("clean header value should pass through unchanged: %q → %q", v, got)
		}
	}
}

// ─── isWebSocketRequest ───────────────────────────────────────────────────────

func TestIsWebSocketRequest_True(t *testing.T) {
	cases := []string{"websocket", "WebSocket", "WEBSOCKET", "Websocket"}
	for _, v := range cases {
		r, _ := http.NewRequest("GET", "/ws", nil)
		r.Header.Set("Upgrade", v)
		if !isWebSocketRequest(r) {
			t.Errorf("Upgrade: %q should be detected as WebSocket request", v)
		}
	}
}

func TestIsWebSocketRequest_False(t *testing.T) {
	cases := []struct{ key, val string }{
		{"Upgrade", ""},
		{"Upgrade", "h2c"},
		{"Connection", "upgrade"}, // Upgrade header missing
		{"", ""},
	}
	for _, tc := range cases {
		r, _ := http.NewRequest("GET", "/api", nil)
		if tc.key != "" {
			r.Header.Set(tc.key, tc.val)
		}
		if isWebSocketRequest(r) {
			t.Errorf("request with %q:%q should NOT be a WebSocket request", tc.key, tc.val)
		}
	}
}
