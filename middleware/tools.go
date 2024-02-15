package middleware

import (
	"api-gateway/global"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func Latency() gin.HandlerFunc {
	return func(c *gin.Context) {
		t := time.Now()
		c.Next()
		// after request
		latency := time.Since(t)
		log.Infoln("ResTime", latency)

	}
}

func BannList() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(global.Config.Bannlist) == 0 {
			c.Next()
			return
		}
		ip := GetIP(c)                                             
		result := binarySearchSubstring(global.Config.Bannlist, ip) 
		if len(result) > 0 {
			log.Errorln("Banned IP", ip)
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
		// Falls ein Fehler auftritt (was bedeuten könnte, dass es keinen Port gibt),
		// geben Sie einfach die ursprüngliche IP zurück, da sie möglicherweise bereits ohne Port ist.
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
