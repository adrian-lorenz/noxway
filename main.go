package main

import (
	"api-gateway/global"
	"api-gateway/middleware"
	"api-gateway/pservice"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

func PrefillServices() {
	global.Services = append(global.Services, pservice.Service{
		BasicEndpoint: pservice.Endpoint{
			Endpoint:  os.Getenv("u1"),
			VerifySSL: true,
			Active:    true,
			Name:      "default",
		},
		Endpoints: []pservice.Endpoint{},
		Active:    true,
		Name:      "bgm-gml",
	})

}

func main() {
	if _, err := os.Stat(".env"); err == nil {
		godotenv.Load()
	}
	config := middleware.RateLimiterConfig{
		Rate:   global.Config.Rate.Rate,
		Burst:  global.Config.Rate.Burst,
		Window: global.Config.Rate.Window,
	}

	//test service
	PrefillServices()
	// init Router
	if !global.Config.Debug {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	router.SetTrustedProxies(nil)
	if global.Config.Cors {
		router.Use(cors.Default())
	}
	router.Use(middleware.MetricsMiddleware())
	router.Use(middleware.BannList())
	router.Use(middleware.RateLimiterMiddleware(config))

	router.Any("/*path", middleware.Latency(), routing)

	// API-Gateway starten
	if global.Config.SSL {
		err := http.ListenAndServeTLS(":"+global.Config.SSLPort, global.Config.PemCrt, global.Config.PemKey, router)
		if err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	} else {
		router.Run(":" + global.Config.Port)
	}
}

func routing(c *gin.Context) {

	host := c.Request.Host

	// Security
	if slices.Contains(global.Config.ExcludedPaths, c.Param("path")) {
		log.Errorln("Excluded Path: " + c.Param("path"))
		c.AbortWithStatus(404)
		return
	}

	fullPath := strings.TrimPrefix(c.Param("path"), "/")
	pathParts := strings.Split(fullPath, "/")
	// Metrics
	if pathParts[0] == global.Config.MetricPath && slices.Contains(global.Config.MetricWhitelist, middleware.GetIP(c)) {
		middleware.AppMetrics.RLock()
		defer middleware.AppMetrics.RUnlock()

		c.JSON(200, gin.H{
			"total_requests":        middleware.AppMetrics.TotalRequests,
			"average_request_size":  float64(middleware.AppMetrics.TotalRequestSize) / float64(middleware.AppMetrics.TotalRequests),
			"average_response_size": float64(middleware.AppMetrics.TotalResponseSize) / float64(middleware.AppMetrics.TotalRequests),
			"average_duration":      middleware.AppMetrics.TotalDuration.Seconds() / float64(middleware.AppMetrics.TotalRequests),
		})
		return
	}

	if len(pathParts) == 0 {
		log.Errorln("No path parts")
		c.AbortWithStatus(404)
		return
	}

	var service pservice.Service
	for _, s := range global.Services {
		if s.Name == pathParts[0] {
			service = s
			break
		}
	}

	if service.Name == "" || !service.Active {
		log.Errorln("Service not found or not active")
		c.AbortWithStatus(404)
		return
	}

	remainingPath := strings.Join(pathParts[1:], "/")

	log.Infoln("----------------------------------------------")
	log.Infoln("Request from:", middleware.GetIP(c), "to:", pathParts[0])
	log.Infoln("Method:", c.Request.Method, " Path:", "/"+remainingPath)
	log.Infoln("RequestSize:", c.Request.ContentLength/1024, "KB") // Korrektur von 1042 zu 1024 für KB-Umrechnung
	log.Infoln("Headers Count:", len(c.Request.Header))
	log.Infoln("Request Host:", host)
	log.Infoln("----------------------------------------------")

	if service.BasicEndpoint.Active && len(service.Endpoints) == 0 {
		processRequest(c, service.BasicEndpoint.Endpoint, remainingPath, service.HeaderReplace)
	} else if len(service.Endpoints) > 0 {
		var endpoint pservice.Endpoint
		for _, e := range service.Endpoints {
			if len(e.HeaderMatches) > 0 && e.Active {
				matchFound := false
				for _, h := range e.HeaderMatches {
					if c.GetHeader(h.Header) == h.Value {
						endpoint = e
						matchFound = true
						break
					}
				}
				if matchFound {
					break
				}
			} else {
				endpoint = e
				break
			}
		}

		if endpoint.Name == "" || !endpoint.Active {
			log.Errorln("Endpoint not found or not active")
			c.AbortWithStatus(404)
			return
		}

		processRequest(c, endpoint.Endpoint, remainingPath, service.HeaderReplace)
	} else {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Service not active"})
	}
}

// processRequest sendet die HTTP-Anfrage und verarbeitet die Antwort
func processRequest(c *gin.Context, baseEndpoint, remainingPath string, headerReplacements []pservice.HeaderReplace) {
	// URL zusammenbauen
	newURL, _ := url.Parse(baseEndpoint)
	newURL.Path += "/" + remainingPath
	if c.Request.URL.RawQuery != "" {
		newURL.RawQuery = c.Request.URL.RawQuery
	}

	// HTTP-Request an den Microservice senden
	resp, err := http.Get(newURL.String())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()

	// Header verarbeiten
	processResponseHeaders(c, resp, headerReplacements)

	// Statuscode und Body an den Client weiterleiten
	c.Status(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Writer.Write(body)
}

// processResponseHeaders verarbeitet und ersetzt Header basierend auf den Konfigurationen
func processResponseHeaders(c *gin.Context, resp *http.Response, headerReplacements []pservice.HeaderReplace) {
	replacementMap := make(map[string]string)
	for _, hr := range headerReplacements {
		replacementMap[hr.Header] = hr.NewValue
	}

	for name, values := range resp.Header {
		if newValue, ok := replacementMap[name]; ok {
			c.Header(name, newValue)
		} else {
			c.Header(name, values[0])
		}
	}
}
