package middleware

import (
	"net"

	"github.com/adrian-lorenz/noxway/global"
	"github.com/gin-gonic/gin"
)

func BannList() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(global.Config.Bannlist) == 0 {
			c.Next()
			return
		}
		ip := GetIP(c)
		if isBanned(global.Config.Bannlist, ip) {
			global.Log.Errorln("Banned IP", ip)
			c.AbortWithStatus(403)
			return
		}
		c.Next()
	}
}

// GetIP returns the real client IP, respecting Gin's trusted proxy configuration.
// To enable X-Forwarded-For trust, call router.SetTrustedProxies() with your proxy CIDRs.
func GetIP(c *gin.Context) string {
	return c.ClientIP()
}

// isBanned checks if the IP matches any ban list entry.
// Entries may be exact IPs or CIDR ranges (e.g. "192.168.1.0/24").
func isBanned(bannList []string, ip string) bool {
	parsed := net.ParseIP(ip)
	for _, entry := range bannList {
		if _, network, err := net.ParseCIDR(entry); err == nil {
			// CIDR range match
			if parsed != nil && network.Contains(parsed) {
				return true
			}
		} else {
			// Exact IP match only
			if entry == ip {
				return true
			}
		}
	}
	return false
}
