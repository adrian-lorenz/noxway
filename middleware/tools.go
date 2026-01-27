package middleware

import (
	"net"
	"strings"

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

func GetIP(c *gin.Context) string {
	i1 := c.Request.Header.Get("X-Forwarded-For")
	i2 := c.Request.RemoteAddr
	ip := i1
	if ip == "" {
		ip = i2
	}
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}
	return host
}

// isBanned checks if the IP matches any entry in the ban list using linear search
func isBanned(bannList []string, ip string) bool {
	for _, banned := range bannList {
		if strings.Contains(ip, banned) || strings.Contains(banned, ip) {
			return true
		}
	}
	return false
}
