package middleware

import (
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/adrian-lorenz/noxway/global"

	"github.com/gin-gonic/gin"
)

type RateLimiterConfig struct {
	Rate   int
	Window time.Duration
}

type RequestCounter struct {
	Count       int
	LastRequest time.Time
}

// rateLimiter speichert die Anfragenzähler für jede IP
var rateLimiter = make(map[string]*RequestCounter)
var rateMu sync.Mutex
var cleanupOnce sync.Once

// startCleanup starts a background goroutine that periodically removes stale entries
func startCleanup(window time.Duration) {
	cleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(window)
			defer ticker.Stop()
			for range ticker.C {
				cleanupStaleEntries(window)
			}
		}()
	})
}

// cleanupStaleEntries removes entries that haven't been accessed within the window
func cleanupStaleEntries(window time.Duration) {
	rateMu.Lock()
	defer rateMu.Unlock()

	now := time.Now()
	for ip, counter := range rateLimiter {
		if now.Sub(counter.LastRequest) > window {
			delete(rateLimiter, ip)
		}
	}
}

func RateLimiterMiddleware(config RateLimiterConfig) gin.HandlerFunc {
	// Start cleanup goroutine
	startCleanup(config.Window)

	return func(c *gin.Context) {
		ip := GetIP(c)
		if slices.Contains(global.Config.RateWhitelist, ip) {
			c.Next()
			return
		}
		rateMu.Lock()
		defer rateMu.Unlock()

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
