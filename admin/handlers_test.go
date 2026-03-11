package admin

import "testing"

// ─── validPort ────────────────────────────────────────────────────────────────

func TestValidPort_Valid(t *testing.T) {
	cases := []struct {
		input    string
		fallback string
		want     string
	}{
		{"8080", "80", "8080"},
		{"443", "80", "443"},
		{"1", "80", "1"},
		{"65535", "80", "65535"},
		{"3000", "8080", "3000"},
	}
	for _, tc := range cases {
		if got := validPort(tc.input, tc.fallback); got != tc.want {
			t.Errorf("validPort(%q, %q) = %q, want %q", tc.input, tc.fallback, got, tc.want)
		}
	}
}

func TestValidPort_Invalid(t *testing.T) {
	cases := []struct {
		input    string
		fallback string
	}{
		{"0", "8080"},      // below range
		{"65536", "8080"},  // above range
		{"-1", "8080"},     // negative
		{"abc", "8080"},    // not a number
		{"", "8080"},       // empty
		{"99999", "8080"},  // way out of range
		{"8080.5", "8080"}, // float
	}
	for _, tc := range cases {
		got := validPort(tc.input, tc.fallback)
		if got != tc.fallback {
			t.Errorf("validPort(%q, %q) = %q, want fallback %q", tc.input, tc.fallback, got, tc.fallback)
		}
	}
}

// ─── filterEmpty ─────────────────────────────────────────────────────────────

func TestFilterEmpty_RemovesEmpty(t *testing.T) {
	in := []string{"a", "", "b", "", "c"}
	out := filterEmpty(in)
	if len(out) != 3 {
		t.Errorf("expected 3 elements, got %d: %v", len(out), out)
	}
	for _, s := range out {
		if s == "" {
			t.Error("filterEmpty should not return empty strings")
		}
	}
}

func TestFilterEmpty_AllEmpty(t *testing.T) {
	out := filterEmpty([]string{"", "", ""})
	if len(out) != 0 {
		t.Errorf("expected empty slice, got %v", out)
	}
}

func TestFilterEmpty_NilInput(t *testing.T) {
	out := filterEmpty(nil)
	if out != nil && len(out) != 0 {
		t.Errorf("expected nil/empty slice for nil input, got %v", out)
	}
}

func TestFilterEmpty_PreservesOrder(t *testing.T) {
	in := []string{"", "first", "", "second", "third", ""}
	out := filterEmpty(in)
	want := []string{"first", "second", "third"}
	if len(out) != len(want) {
		t.Fatalf("length mismatch: got %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("out[%d] = %q, want %q", i, out[i], want[i])
		}
	}
}

// ─── parseIntForm ─────────────────────────────────────────────────────────────

func TestParseIntForm(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"42", 42},
		{"0", 0},
		{"-5", -5},
		{"", 0},
		{"abc", 0},
		{"3.14", 0},
	}
	for _, tc := range cases {
		if got := parseIntForm(tc.input); got != tc.want {
			t.Errorf("parseIntForm(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}
