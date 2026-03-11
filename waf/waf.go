package waf

import (
	"net/url"
	"regexp"
	"strings"
)

// WAFConfig is stored per Service and controls which checks are active.
type WAFConfig struct {
	Enabled            bool `json:"enabled"`
	BlockSQLi          bool `json:"blockSQLi"`
	BlockXSS           bool `json:"blockXSS"`
	BlockPathTraversal bool `json:"blockPathTraversal"`
	BlockCommandInj    bool `json:"blockCommandInj"`
	BlockLargeBody     bool `json:"blockLargeBody"`
	MaxBodyKB          int  `json:"maxBodyKB"` // 0 = use default (512)
}

// BlockReason is returned when a request is blocked.
type BlockReason struct {
	Rule    string
	Matched string
}

var (
	sqliRe = regexp.MustCompile(
		`(?i)(` +
			`\b(union\s+select|insert\s+into|drop\s+table|drop\s+database|alter\s+table|exec\s*\(|execute\s*\(|xp_cmdshell)\b` +
			`|--\s|;\s*--` +
			`|'\s*(or|and)\s+'?\d` +
			`|\bor\b\s+\d+\s*=\s*\d+` +
			`|\band\b\s+\d+\s*=\s*\d+` +
			`|'\s*(or|and)\s+'[^']*'\s*=\s*'` +
			`|\/\*.*?\*\/` +
			`)`,
	)

	xssRe = regexp.MustCompile(
		`(?i)(` +
			`<\s*script[\s>]` +
			`|javascript\s*:` +
			`|vbscript\s*:` +
			`|\bon\w+\s*=` +
			`|<\s*(iframe|object|embed|applet|form|input|button|link|meta|base)[\s>]` +
			`|document\s*\.` +
			`|window\s*\.location` +
			`|alert\s*\(` +
			`|eval\s*\(` +
			`)`,
	)

	pathTraversalRe = regexp.MustCompile(
		`(?i)(` +
			`\.\.[/\\]` +
			`|%2e%2e[%2f%5c/\\]` +
			`|\.\.%2f` +
			`|\.\.%5c` +
			`|%252e%252e` +
			`|/etc/passwd` +
			`|/etc/shadow` +
			`|/proc/self` +
			`|\\windows\\system32` +
			`)`,
	)

	cmdInjRe = regexp.MustCompile(
		"(?i)(" +
			";\\s*(?:ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|python|perl|ruby|nc|ncat)(?:\\W|$)" +
			"|\\|\\s*(?:ls|cat|id|whoami|bash|sh)(?:\\W|$)" +
			"|&&\\s*(?:ls|cat|id|whoami|rm|wget|curl)(?:\\W|$)" +
			"|`[^`]{1,100}`" +
			"|\\$\\([^)]{1,100}\\)" +
			")",
	)
)

// Check inspects the given inputs against the active WAF rules.
// Returns a BlockReason if the request should be blocked, nil otherwise.
func Check(cfg WAFConfig, rawPath, rawQuery, body string) *BlockReason {
	if !cfg.Enabled {
		return nil
	}

	// URL-decode for better detection
	decodedPath, _ := url.QueryUnescape(rawPath)
	decodedQuery, _ := url.QueryUnescape(rawQuery)
	decodedBody, _ := url.QueryUnescape(body)

	targets := []string{
		strings.ToLower(decodedPath),
		strings.ToLower(decodedQuery),
		strings.ToLower(decodedBody),
	}

	for _, input := range targets {
		if input == "" {
			continue
		}

		if cfg.BlockPathTraversal {
			if m := pathTraversalRe.FindString(input); m != "" {
				return &BlockReason{Rule: "path-traversal", Matched: m}
			}
		}

		if cfg.BlockSQLi {
			if m := sqliRe.FindString(input); m != "" {
				return &BlockReason{Rule: "sqli", Matched: m}
			}
		}

		if cfg.BlockXSS {
			if m := xssRe.FindString(input); m != "" {
				return &BlockReason{Rule: "xss", Matched: m}
			}
		}

		if cfg.BlockCommandInj {
			if m := cmdInjRe.FindString(input); m != "" {
				return &BlockReason{Rule: "cmdinj", Matched: m}
			}
		}
	}

	return nil
}
