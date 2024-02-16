package main

import (
	"api-gateway/database"
	"api-gateway/global"
	"api-gateway/middleware"
	"api-gateway/pservice"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
)

func main() {
	if _, err := os.Stat(".env"); err == nil {
		godotenv.Load()
	}
	global.LoadAllConfig() // thread safe
	RateConfig := middleware.RateLimiterConfig{
		Rate:   global.Config.Rate.Rate,
		Window: global.Config.Rate.Window,
	}
	//init Databases
	dberr := database.ConnectDB(global.Path)
	if dberr != nil {
		log.Errorln("Fehler beim Verbinden zur Datenbank:", dberr)
		panic(dberr)
	}
	// init Router
	if !global.Config.Debug {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	router.SetTrustedProxies(nil)
	// Middleware
	if global.Config.Cors {
		router.Use(cors.Default())
	}
	if global.Config.Metrics {
		router.Use(middleware.MetricsMiddleware())
	}
	if global.Config.Bann {
		router.Use(middleware.BannList())
	}
	if global.Config.RateLimiter {
		router.Use(middleware.RateLimiterMiddleware(RateConfig))
	}

	router.Any(global.Config.Prefix+"*path", middleware.Latency(), routing)

	router.GET("/reload", func(c *gin.Context) {
		if slices.Contains(global.Config.MetricWhitelist, middleware.GetIP(c)) {
			global.LoadAllConfig()
			c.JSON(200, gin.H{
				"message": "Config reloaded",
			})
			return
		} else {
			c.AbortWithStatus(404)
			return

		}
	})
	router.GET(global.Config.MetricPath, func(c *gin.Context) {
		if global.Config.Metrics && slices.Contains(global.Config.MetricWhitelist, middleware.GetIP(c)) {
			middleware.AppMetrics.RLock()
			defer middleware.AppMetrics.RUnlock()
			c.JSON(200, gin.H{
				"total_requests":        middleware.AppMetrics.TotalRequests,
				"average_request_size":  float64(middleware.AppMetrics.TotalRequestSize) / float64(middleware.AppMetrics.TotalRequests),
				"average_response_size": float64(middleware.AppMetrics.TotalResponseSize) / float64(middleware.AppMetrics.TotalRequests),
				"average_duration":      middleware.AppMetrics.TotalDuration.Seconds() / float64(middleware.AppMetrics.TotalRequests),
			})
			return
		} else {
			c.AbortWithStatus(404)
		}
	})

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
	var litem database.Logtable
	defer func() {
		go safeLog(litem)
	}()
	host := c.Request.Host

	// Security nicht erforderlich, da prefix
	/*
		if slices.Contains(global.Config.ExcludedPaths, c.Param("path")) {
			log.Errorln("Excluded Path: " + c.Param("path"))
			c.AbortWithStatus(404)
			return
		}*/
	//Prefix handling
	trimmedPath := strings.TrimPrefix(c.Param("path"), global.Config.Prefix)
	trimmedPath = strings.Trim(trimmedPath, "/")
	pathParts := strings.Split(trimmedPath, "/")
	remainingPath := strings.Join(pathParts[1:], "/")

	litem.Path = remainingPath
	litem.Service = pathParts[0]
	litem.ServiceExists = false
	litem.Method = c.Request.Method
	litem.RequestSize = int(c.Request.ContentLength) / 1024
	litem.Host = host
	litem.HeaderRouting = false
	litem.IP = middleware.GetIP(c)
	litem.HeadersCount = len(c.Request.Header)
	litem.GUID = uuid.New().String()

	log.Infoln("----------------------------------------------")
	log.Infoln("Request from:", middleware.GetIP(c), "to:", pathParts[0])
	log.Infoln("Method:", c.Request.Method, " Path:", "/"+remainingPath)
	log.Infoln("RequestSize:", c.Request.ContentLength/1024, "KB")
	log.Infoln("Headers Count:", len(c.Request.Header))
	log.Infoln("Request Host:", host)
	log.Infoln("----------------------------------------------")

	if len(pathParts) == 0 {
		log.Errorln("No path parts")
		litem.Message = "No path parts"
		c.AbortWithStatus(404)
		return
	}

	// Service suchen

	var service pservice.Service
	for _, s := range global.Services.Services {
		if s.Name == pathParts[0] {
			service = s
			litem.ServiceExists = true
			break
		}
	}

	if service.Name == "" || !service.Active {
		log.Errorln("Service not found or not active")
		litem.Message = "Service not found or not active"
		c.AbortWithStatus(404)
		return
	}

	if service.BasicEndpoint.Active && len(service.Endpoints) == 0 {
		//Basic Enpoint Precheck
		litem.HeaderRouting = true
		if service.BasicEndpoint.JWTPreCheck.Active {
			if !JWTCheck(c, service.BasicEndpoint.JWTPreCheck) {
				log.Errorln("JWT not valid")
				litem.Message = "JWT not valid"
				c.AbortWithStatus(404)
				return
			}
		}
		if len(service.BasicEndpoint.HeaderExists) > 0 {
			if !headerExist(c, service.BasicEndpoint.HeaderExists) {
				log.Errorln("Header not found")
				litem.Message = "HeaderExist not found"
				c.AbortWithStatus(404)
				return
			}
		}
		//Basic Enpoint Router
		litem.EndPoint = service.BasicEndpoint.Endpoint
		processRequest(c, service.BasicEndpoint.Endpoint, remainingPath, service.BasicEndpoint.HeaderReplace, service.BasicEndpoint.HeaderAdd, &litem)

	} else if len(service.Endpoints) > 0 {
		var endpoint pservice.Endpoint
		for _, e := range service.Endpoints {
			if len(e.HeaderRouteMatches) > 0 && e.Active {
				if e.JWTPreCheck.Active {
					if !JWTCheck(c, e.JWTPreCheck) {
						log.Errorln("JWT not valid")
						litem.Message = "JWT not valid"
						c.AbortWithStatus(404)
						return
					}
				}

				if len(e.HeaderExists) > 0 {
					if !headerExist(c, e.HeaderExists) {
						log.Errorln("Header not found")
						litem.Message = "HeaderExist not found"

						c.AbortWithStatus(404)
						return
					}
				}
				matchFound := false
				for _, h := range e.HeaderRouteMatches {
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
			litem.Message = "Endpoint not found or not active"

			c.AbortWithStatus(404)
			return
		}
		//SUB Enpoint Router
		litem.HeaderRouting = true
		litem.EndPoint = endpoint.Endpoint
		processRequest(c, endpoint.Endpoint, remainingPath, endpoint.HeaderReplace, endpoint.HeaderAdd, &litem)
	} else {
		log.Errorln("No endpoint found")
		litem.Message = "No endpoint found"
		c.JSON(http.StatusBadGateway, gin.H{"error": "Service not active"})
	}
}

func safeLog(litem database.Logtable) {
	err := database.DB.Create(&litem).Error
	if err != nil {
		log.Errorln("Error while logging:", err)
	}
}
func headerExist(c *gin.Context, headerMatches []pservice.Header) bool {
	fmt.Println("HeaderExist", headerMatches[0].Header)
	for _, h := range headerMatches {
		if c.GetHeader(h.Header) == h.Value {
			return true
		}
	}
	return false
}

func JWTCheck(c *gin.Context, jw pservice.JWTPreCheck) bool {
	tokenString := c.GetHeader(jw.Header)
	if tokenString == "" {
		return false
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jw.Key), nil
	})

	if err != nil || !token.Valid {
		return false
	}
	if jw.OnlySign {
		return true
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		for _, m := range jw.Match {
			if val, ok := claims[jw.Field]; ok && val == m {
				return true
			}
		}
	}

	return false
}

// processRequest sendet die HTTP-Anfrage und verarbeitet die Antwort
/*func processRequest(c *gin.Context, baseEndpoint, remainingPath string, headerReplacements []pservice.HeaderReplace, headerAdds []pservice.Header, logItem *database.Logtable) {
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
	logItem.StatusCode = resp.StatusCode
	defer resp.Body.Close()

	// Header verarbeiten
	processResponseHeaders(c, resp, headerReplacements, headerAdds)

	// Statuscode und Body an den Client weiterleiten
	c.Status(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Writer.Write(body)

}*/
func processRequest(c *gin.Context, baseEndpoint, remainingPath string, headerReplacements []pservice.HeaderReplace, headerAdds []pservice.Header, logItem *database.Logtable) {
	// URL zusammenbauen
	newURL, _ := url.Parse(baseEndpoint)
	newURL.Path += "/" + remainingPath
	if c.Request.URL.RawQuery != "" {
		newURL.RawQuery = c.Request.URL.RawQuery
	}

	// Request-Body für neue Anfrage vorbereiten (falls notwendig)
	var requestBody io.Reader
	if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut || c.Request.Method == http.MethodPatch {
		bodyBytes, _ := io.ReadAll(c.Request.Body)
		// Wichtig: Body für weiteren Gebrauch im aktuellen Kontext wiederherstellen
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		requestBody = bytes.NewBuffer(bodyBytes)
	}

	// Neuen HTTP-Request basierend auf der Methode des Original-Requests erstellen
	req, err := http.NewRequest(c.Request.Method, newURL.String(), requestBody)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	// Original-Header kopieren oder modifizieren
	copyHeaders(c.Request.Header, req.Header)

	// Header ersetzen oder hinzufügen basierend auf headerReplacements und headerAdds

	// HTTP-Request senden
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	logItem.StatusCode = resp.StatusCode
	defer resp.Body.Close()

	// Header verarbeiten
	processResponseHeaders(c, resp, headerReplacements, headerAdds)

	// Statuscode und Body an den Client weiterleiten
	c.Status(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.Writer.Write(body)
}

// Hilfsfunktion zum Kopieren von Headern
func copyHeaders(src, dest http.Header) {
	for key, values := range src {
		for _, value := range values {
			dest.Add(key, value)
		}
	}
}

// processResponseHeaders verarbeitet und ersetzt Header basierend auf den Konfigurationen
func processResponseHeaders(c *gin.Context, resp *http.Response, headerReplacements []pservice.HeaderReplace, headerAdds []pservice.Header) {
	//hinzufügen der Headers
	if len(headerAdds) > 0 {
		for _, h := range headerAdds {
			c.Header(h.Header, h.Value)
		}
	}
	// Ersetzen der Headers
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
