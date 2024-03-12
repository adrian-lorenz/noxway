package middleware

import (
	"github.com/adrian-lorenz/noxway/global"
	"net"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

func BannList() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(global.Config.Bannlist) == 0 {
			c.Next()
			return
		}
		ip := GetIP(c)
		result := binarySearchSubstring(global.Config.Bannlist, ip)
		if len(result) > 0 {
			global.Log.Errorln("Banned IP", ip)
			c.AbortWithStatus(404)
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
func binarySearchSubstring(sliceStrings []string, substring string) []string {
	matches := []string{}
	index := sort.Search(len(sliceStrings), func(i int) bool {
		return strings.Compare(sliceStrings[i], substring) >= 0
	})
	for i := index; i < len(sliceStrings); i++ {
		if strings.Contains(sliceStrings[i], substring) {
			matches = append(matches, sliceStrings[i])
		} else {
			break
		}
	}
	return matches
}
