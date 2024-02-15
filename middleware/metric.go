package middleware

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type GlobalMetrics struct {
	sync.RWMutex
	TotalRequests     int64
	TotalRequestSize  int64
	TotalResponseSize int64
	TotalDuration     time.Duration
}

// Globale Instanz der Metriken
var AppMetrics = GlobalMetrics{}

// Funktion zur Aktualisierung der Anfragemetriken
func UpdateRequestMetrics(requestSize, responseSize int64, duration time.Duration) {
	AppMetrics.Lock()
	defer AppMetrics.Unlock()

	AppMetrics.TotalRequests++
	AppMetrics.TotalRequestSize += requestSize
	AppMetrics.TotalResponseSize += responseSize
	AppMetrics.TotalDuration += duration
}

// Middleware zur Erfassung von Metriken
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		c.Next()

		duration := time.Since(startTime)
		requestSize := c.Request.ContentLength // Größe der Anfrage
		responseSize := int64(c.Writer.Size()) // Größe der Antwort

		UpdateRequestMetrics(requestSize, responseSize, duration)
	}
}
