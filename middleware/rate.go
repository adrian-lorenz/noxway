package middleware

import (
	"api-gateway/global"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type RateLimiterConfig struct {
	Rate   int
	Burst  int
	Window time.Duration
}

type RequestCounter struct {
	Count       int
	LastRequest time.Time
}

// rateLimiter speichert die Anfragenzähler für jede IP
var rateLimiter = make(map[string]*RequestCounter)
var mu sync.Mutex

func RateLimiterMiddleware(config RateLimiterConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := GetIP(c)
		if slices.Contains(global.Config.RateWhitelist, ip) {
			c.Next()
			return
		}
		mu.Lock()
		defer mu.Unlock()

		counter, exists := rateLimiter[ip]
		if !exists {
			counter = &RequestCounter{}
			rateLimiter[ip] = counter
		}

		now := time.Now()
		if now.Sub(counter.LastRequest) > config.Window {

			counter.Count = 0
			counter.LastRequest = now
		}

		if counter.Count >= config.Rate {

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			return
		}

		counter.Count++
		counter.LastRequest = now
		c.Next()
	}
}
