package middleware

import "testing"

// ─── isBanned ─────────────────────────────────────────────────────────────────

func TestIsBanned_EmptyList(t *testing.T) {
	if isBanned([]string{}, "1.2.3.4") {
		t.Error("empty ban list should never match")
	}
}

func TestIsBanned_ExactMatch(t *testing.T) {
	list := []string{"1.2.3.4", "10.0.0.1"}
	if !isBanned(list, "1.2.3.4") {
		t.Error("exact match should be banned")
	}
	if !isBanned(list, "10.0.0.1") {
		t.Error("exact match should be banned")
	}
}

func TestIsBanned_ExactNoPartialMatch(t *testing.T) {
	// Old strings.Contains bug: "168" would match "192.168.1.100"
	// and "10" would match "10.0.0.1". Verify this is fixed.
	list := []string{"168", "10", "1.2.3"}
	cases := []string{"192.168.1.100", "10.0.0.1", "1.2.3.4"}
	for _, ip := range cases {
		if isBanned(list, ip) {
			t.Errorf("partial-string entry should NOT match IP %q (regression: was using strings.Contains)", ip)
		}
	}
}

func TestIsBanned_CIDR(t *testing.T) {
	list := []string{"192.168.0.0/16"}
	if !isBanned(list, "192.168.1.50") {
		t.Error("IP inside CIDR range should be banned")
	}
	if !isBanned(list, "192.168.255.255") {
		t.Error("IP at end of CIDR range should be banned")
	}
	if isBanned(list, "192.169.0.1") {
		t.Error("IP outside CIDR range should not be banned")
	}
}

func TestIsBanned_CIDR_Slash32(t *testing.T) {
	// /32 is a single host range — equivalent to exact match
	list := []string{"10.0.0.5/32"}
	if !isBanned(list, "10.0.0.5") {
		t.Error("/32 CIDR should match its single host")
	}
	if isBanned(list, "10.0.0.6") {
		t.Error("/32 CIDR should not match other hosts")
	}
}

func TestIsBanned_MixedList(t *testing.T) {
	list := []string{"1.2.3.4", "10.0.0.0/8", "172.16.5.5"}
	if !isBanned(list, "1.2.3.4") {
		t.Error("exact entry should match")
	}
	if !isBanned(list, "10.42.0.1") {
		t.Error("IP inside 10.0.0.0/8 should be banned")
	}
	if !isBanned(list, "172.16.5.5") {
		t.Error("exact entry should match")
	}
	if isBanned(list, "172.16.5.6") {
		t.Error("IP not in list should not be banned")
	}
	if isBanned(list, "8.8.8.8") {
		t.Error("unrelated IP should not be banned")
	}
}

func TestIsBanned_InvalidCIDR(t *testing.T) {
	// Invalid CIDR entries fall through to exact match — should not panic
	list := []string{"not-a-cidr/xyz", "256.0.0.1/8"}
	if isBanned(list, "192.168.1.1") {
		t.Error("invalid CIDR entry should not match arbitrary IPs")
	}
}

func TestIsBanned_IPv6(t *testing.T) {
	list := []string{"::1", "2001:db8::/32"}
	if !isBanned(list, "::1") {
		t.Error("exact IPv6 match should be banned")
	}
	if !isBanned(list, "2001:db8:1234::1") {
		t.Error("IPv6 inside CIDR should be banned")
	}
	if isBanned(list, "2001:db9::1") {
		t.Error("IPv6 outside CIDR should not be banned")
	}
}
