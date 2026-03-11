package middleware

import (
	"github.com/adrian-lorenz/noxway/global"
	"github.com/gin-gonic/gin"
)

// SecurityHeaders adds standard security headers to every response.
// Apply this only to admin routes, not to the reverse-proxy routes.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "0") // Disabled: legacy auditor is exploitable; rely on CSP
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'unsafe-inline' https://unpkg.com; "+
				"style-src 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'")
		if global.Config.SSL {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}
