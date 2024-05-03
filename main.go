package main

import (
	"bytes"
	"crypto/tls"
	"embed"
	"fmt"
	"github.com/adrian-lorenz/noxway/certs"
	"github.com/adrian-lorenz/noxway/security"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/adrian-lorenz/noxway/middleware"
	"github.com/adrian-lorenz/noxway/pservice"
	"github.com/adrian-lorenz/noxway/testservices"

	"github.com/adrian-lorenz/noxway/auth"
	"github.com/adrian-lorenz/noxway/database"
	"github.com/adrian-lorenz/noxway/global"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

//go:embed web/assets/*
var staticFiles embed.FS

//go:embed web/index.html
var indexHTML []byte

type LogTime struct {
	StartTimePRE time.Time
	StartTimeSRV time.Time
	EndTimePRE   time.Time
	EndTimeSRV   time.Time
	EndTimeFULL  time.Time
	DurationPRE  time.Duration
	DurationSRV  time.Duration
	DurationFULL time.Duration
}

func main() {

	global.LoadAllConfig() // thread safe
	global.InitLogger()
	if _, err := os.Stat(".env"); err == nil {
		errD := godotenv.Load()
		if errD != nil {
			return
		}
	}
	if os.Getenv("DATABASE") == "" {
		global.Log.Errorln("DATABASE not set")
		panic("DATABASE not set")
	}
	/*
		_, err := certs.CertPreCheck("server.noa-x.de")
		if err != nil {
			global.Log.Errorln("Failed to check certificate:", err)
		}
	*/
	RateConfig := middleware.RateLimiterConfig{
		Rate:   global.Config.Rate.Rate,
		Window: global.Config.Rate.Window,
	}
	//init Databases
	dberr := database.ConnectDB(global.Path)
	if dberr != nil {
		global.Log.Errorln("Fehler beim Verbinden zur Datenbank:", dberr)
		panic(dberr)
	} else {
		global.Log.Infoln("Database connected")

	}

	// init Router
	if !global.Config.Debug {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	errT := router.SetTrustedProxies(nil)
	if errT != nil {
		return
	}
	// Middleware
	if global.Config.Cors {
		if global.Config.CorsAdvanced {
			config := cors.DefaultConfig()
			config.AllowOrigins = global.Config.CorsAllowOrigins
			config.AllowMethods = global.Config.CorsAllowMethods
			config.AllowHeaders = global.Config.CorsAllowHeaders
			router.Use(cors.New(config))
		} else {
			router.Use(cors.Default())
		}

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

	staticFS, eerr := fs.Sub(staticFiles, "web/assets")

	if eerr != nil {
		global.Log.Errorln("Error while embedding static files:", eerr)
	}

	router.StaticFS("/assets", http.FS(staticFS))

	router.GET("/web/*any", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML)
	})

	router.GET("/testservice1", testservices.Testservice1)
	router.GET("/testservice2", testservices.Testservice2)

	router.POST("/retiveCert", certs.RetiveCert)

	router.Any(global.Config.Prefix+"*path", routing)

	router.GET("/reload", func(c *gin.Context) {
		if !security.IntJWTCheck(c, "admin") {
			c.AbortWithStatus(401)
			return
		}

		if security.CheckWhitelists(middleware.GetIP(c)) {
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
	router.GET("/database/:span", func(c *gin.Context) {
		if !security.IntJWTCheck(c, "admin") {
			c.AbortWithStatus(401)
			return
		}

		span := c.Param("span")
		var logs []database.Logtable
		if span == "all" {
			database.DB.Find(&logs)
			c.JSON(200, logs)
			return
		}
		if span == "hour" {
			database.DB.Where("created > ?", time.Now().Add(-time.Hour)).Find(&logs)
			c.JSON(200, logs)
			return
		}
		if span == "day" {
			database.DB.Where("created > ?", time.Now().Add(-time.Hour*24)).Find(&logs)
			c.JSON(200, logs)
			return
		}
	})

	router.GET("/config_global", func(c *gin.Context) {
		if !security.IntJWTCheck(c, "admin") {
			c.AbortWithStatus(401)
			return
		}
		if !security.CheckWhitelists(middleware.GetIP(c)) {
			c.AbortWithStatus(404)
			return
		}

		c.JSON(200, global.Config)

	})

	router.GET("/config_auth", func(c *gin.Context) {
		if !security.IntJWTCheck(c, "admin") {
			c.AbortWithStatus(401)
			return
		}
		if !security.CheckWhitelists(middleware.GetIP(c)) {
			c.AbortWithStatus(404)
			return
		}
		// geb nur usernamen und rolle zurück keine passwörter
		var users []auth.User
		for _, u := range global.Auth.Users {
			users = append(users, auth.User{
				Username: u.Username,
				Role:     u.Role,
			})
		}
		c.JSON(200, users)
	})

	router.POST("/set_user", func(c *gin.Context) {
		if !security.IntJWTCheck(c, "admin") {
			c.AbortWithStatus(401)
			return
		}
		if !security.CheckWhitelists(middleware.GetIP(c)) {
			c.AbortWithStatus(404)
			return
		}
		var user auth.User
		err := c.ShouldBindJSON(&user)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		err = auth.AddUser(&global.Auth, user, user.Role, user.Service)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		global.SaveAuthConfig()
		c.JSON(200, gin.H{
			"message": "User added",
		})
	})

	router.POST("/setAdmin", func(c *gin.Context) {
		// only is no whitelist is set
		setter := false
		if len(global.Config.SystemWhitelist) == 0 || len(global.Config.SystemWhitelistDNS) == 0 {
			setter = true
		} else {
			if security.CheckWhitelists(middleware.GetIP(c)) {
				setter = true
			}
		}
		if !setter {
			c.AbortWithStatus(404)
			return
		}
		type nAdminPwd struct {
			OldPassword  string   `json:"password" binding:"required"`
			NewPassword  string   `json:"newpassword" binding:"required"`
			DNSWhiteList []string `json:"dnswhitelist"`
			Whitelist    []string `json:"whitelist" binding:"required"`
		}
		var np nAdminPwd
		err := c.ShouldBindJSON(&np)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		foundUser := false
		for i, u := range global.Auth.Users {
			if u.Username == "admin" {
				err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(np.OldPassword))
				if err != nil {
					global.Log.Errorln("Old password not valid")
					c.AbortWithStatus(401)
					return
				}
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(np.NewPassword), bcrypt.DefaultCost)
				if err != nil {
					global.Log.Errorln("Error while hashing password:", err)
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				global.Auth.Users[i].Password = string(hashedPassword)
				global.Config.SystemWhitelist = np.Whitelist
				global.Config.SystemWhitelistDNS = np.DNSWhiteList
				global.Config.SystemWhitelist = append(global.Config.SystemWhitelist, middleware.GetIP(c))
				foundUser = true
				break
			}

		}
		if !foundUser {
			global.Log.Errorln("Admin user not found")
			c.AbortWithStatus(404)
			return

		}
		global.SaveAuthConfig()
		global.SaveGlobalConfig()
		global.LoadAllConfig()
		c.JSON(200, gin.H{
			"message": "Password changed",
		})

	})

	router.GET("/login", func(c *gin.Context) {
		if !security.CheckWhitelists(middleware.GetIP(c)) {
			c.AbortWithStatus(404)
			return
		}

		username, password, ok := c.Request.BasicAuth()
		if !ok {
			c.AbortWithStatus(401)
			return
		}
		aUser := auth.User{
			Username: username,
			Password: password,
			Role:     "",
		}
		valid := false

		for _, u := range global.Auth.Users {
			if u.Username == aUser.Username {
				err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(aUser.Password))
				if err != nil {
					c.AbortWithStatus(401)
					return
				}
				aUser.Role = u.Role
				valid = true
				break
			}
		}
		if !valid {
			c.AbortWithStatus(401)
			return
		}

		claims := jwt.MapClaims{
			"issuer":   "api-gateway",
			"username": username,
			"role":     aUser.Role,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(os.Getenv("JWTSECRET")))
		if err != nil {
			c.AbortWithStatus(500)
			return
		}
		fmt.Println("User logged in:", username, "Role:", aUser.Role, "IP:", middleware.GetIP(c))
		c.JSON(200, gin.H{"token": tokenString})
	})

	router.POST("/config_global", func(c *gin.Context) {
		if !security.IntJWTCheck(c, "admin") {
			c.AbortWithStatus(401)
			return
		}
		if security.CheckWhitelists(middleware.GetIP(c)) {
			err := c.ShouldBindJSON(&global.Config)
			if err != nil {
				c.JSON(400, gin.H{"error": err.Error()})
				return
			}
			global.SaveGlobalConfig()
			c.JSON(200, gin.H{
				"message": "Config saved",
			})
			return
		} else {
			c.AbortWithStatus(404)
			return
		}
	})

	router.GET("/config_service", func(c *gin.Context) {
		if !security.IntJWTCheck(c, "admin") {
			c.AbortWithStatus(401)
			return
		}
		if security.CheckWhitelists(middleware.GetIP(c)) {
			c.JSON(200, global.Services.Services)
			return
		} else {
			c.AbortWithStatus(404)
			return
		}
	})

	router.POST("/config_service", func(c *gin.Context) {
		if !security.IntJWTCheck(c, "admin") {
			c.AbortWithStatus(401)
			return
		}
		if security.CheckWhitelists(middleware.GetIP(c)) {
			err := c.ShouldBindJSON(&global.Services.Services)
			if err != nil {
				c.JSON(400, gin.H{"error": err.Error()})
				return
			}
			global.SaveServiceConfig()
			c.JSON(200, gin.H{
				"message": "Config saved",
			})
			return
		} else {
			c.AbortWithStatus(404)
			return
		}
	})

	// API-Gateway starten
	if global.Config.SSL {
		err := http.ListenAndServeTLS(":"+global.Config.SSLPort, global.Config.PemCrt, global.Config.PemKey, router)
		if err != nil {
			global.Log.Fatalf("Failed to start server: %v", err)
		}
	} else {
		errR := router.Run(":" + global.Config.Port)
		if errR != nil {
			global.Log.Fatalf("Failed to start server: %v", errR)
			return
		}
	}
}

func routing(c *gin.Context) {
	var ltime LogTime
	ltime.StartTimePRE = time.Now()
	//latency := time.Since(t)

	var litem database.Logtable
	defer func() {
		go saveLog(litem, ltime)
	}()
	host := c.Request.Host
	if global.Config.Hostnamecheck {
		if global.Config.Hostname != host {
			global.Log.Errorln("Hostname not valid")
			litem.Message = "Hostname not valid"
			c.AbortWithStatus(404)
			return
		}
	}

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
	litem.Routed = false

	global.Log.Infoln("----------------------------------------------")
	global.Log.Infoln("Request from:", middleware.GetIP(c), "to:", pathParts[0])
	global.Log.Infoln("Method:", c.Request.Method, " Path:", "/"+remainingPath)
	global.Log.Infoln("RequestSize:", c.Request.ContentLength/1024, "KB")
	global.Log.Infoln("Headers Count:", len(c.Request.Header))
	global.Log.Infoln("Request Host:", host)
	global.Log.Infoln("----------------------------------------------")

	if len(pathParts) == 0 {
		global.Log.Errorln("No path parts")
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
		global.Log.Errorln("Service not found or not active")
		litem.Message = "Service not found or not active"
		c.AbortWithStatus(404)
		return
	}

	if service.BasicEndpoint.Active && len(service.Endpoints) == 0 {
		//Basic Enpoint Precheck
		litem.HeaderRouting = true
		if service.BasicEndpoint.JWTPreCheck {
			if !JWTCheck(c, service.BasicEndpoint.JWTData) {
				global.Log.Errorln("JWT not valid")
				litem.Message = "JWT not valid"
				c.AbortWithStatus(404)
				return
			}
		}
		if len(service.BasicEndpoint.HeaderExists) > 0 {
			if !headerExist(c, service.BasicEndpoint.HeaderExists) {
				global.Log.Errorln("Header not found")
				litem.Message = "HeaderExist not found"
				c.AbortWithStatus(404)
				return
			}
		}
		//Basic Enpoint Router
		litem.EndPoint = service.BasicEndpoint.Endpoint

		processRequest(c, service.BasicEndpoint, remainingPath, &litem, &ltime)

	} else if len(service.Endpoints) > 0 {
		var endpoint pservice.Endpoint
		for _, e := range service.Endpoints {
			if e.Active {
				if e.JWTPreCheck {
					if !JWTCheck(c, e.JWTData) {
						global.Log.Errorln("JWT not valid")
						litem.Message = "JWT not valid"
						c.AbortWithStatus(404)
						return
					}
				}

				if len(e.HeaderExists) > 0 {
					if !headerExist(c, e.HeaderExists) {
						global.Log.Errorln("Header not found")
						litem.Message = "HeaderExist not found"

						c.AbortWithStatus(404)
						return
					}
				}
				matchFound := false
				fmt.Println("HeaderRouteMatches", e.HeaderRouteMatches)
				for _, h := range e.HeaderRouteMatches {
					if c.GetHeader(h.Header) == h.Value {
						endpoint = e
						matchFound = true
						break
					}
				}
				if matchFound {
					fmt.Println("MatchFound", endpoint)
					break
				} else {
					if service.BasicEndpoint.Active {
						endpoint = service.BasicEndpoint
					} else {
						global.Log.Errorln("Endpoint not found or not active")
						litem.Message = "Endpoint not found or not active"
						c.AbortWithStatus(404)
						return
					}

				}
			} else {
				if service.BasicEndpoint.Active {
					endpoint = service.BasicEndpoint
				} else {
					global.Log.Errorln("Endpoint not found or not active")
					litem.Message = "Endpoint not found or not active"
					c.AbortWithStatus(404)
					return
				}
				break
			}
		}

		if endpoint.Name == "" || !endpoint.Active {
			global.Log.Errorln("Endpoint not found or not active")
			litem.Message = "Endpoint not found or not active"

			c.AbortWithStatus(404)
			return
		}
		//SUB Enpoint Router
		litem.HeaderRouting = true
		litem.EndPoint = endpoint.Endpoint

		processRequest(c, endpoint, remainingPath, &litem, &ltime)
	} else {
		global.Log.Errorln("No endpoint found")
		litem.Message = "No endpoint found"
		c.JSON(http.StatusBadGateway, gin.H{"error": "Service not active"})
	}
}

func saveLog(litem database.Logtable, timemod LogTime) {
	timemod.EndTimeFULL = time.Now()

	if timemod.EndTimePRE.IsZero() {
		timemod.EndTimePRE = timemod.EndTimeFULL
	}
	if timemod.StartTimeSRV.IsZero() {
		timemod.StartTimeSRV = timemod.EndTimeFULL
	}
	if timemod.EndTimeSRV.IsZero() {
		timemod.EndTimeSRV = timemod.EndTimeFULL
	}

	timemod.DurationPRE = timemod.EndTimePRE.Sub(timemod.StartTimePRE)
	timemod.DurationSRV = timemod.EndTimeSRV.Sub(timemod.StartTimeSRV)
	timemod.DurationFULL = timemod.EndTimeFULL.Sub(timemod.StartTimePRE)
	litem.TimePre = float32(timemod.DurationPRE.Nanoseconds())
	litem.TimePost = float32(timemod.DurationSRV.Milliseconds())
	litem.TimeFull = float32(timemod.DurationFULL.Milliseconds())
	litem.ResponseTime = float32(timemod.DurationFULL.Milliseconds())
	err := database.DB.Create(&litem).Error
	if err != nil {
		global.Log.Errorln("Error while logging:", err)
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

func processRequest(c *gin.Context, endpoint pservice.Endpoint, remainingPath string, logItem *database.Logtable, timemod *LogTime) {
	// URL zusammenbauen
	global.Log.Infoln("BaseEndpoint:", endpoint.Endpoint)
	newURL, _ := url.Parse(endpoint.Endpoint)
	newURL.Path += "/" + remainingPath
	if c.Request.URL.RawQuery != "" {
		newURL.RawQuery = c.Request.URL.RawQuery
	}

	// Request-Body für neue Anfrage vorbereiten
	var requestBody io.Reader
	if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut || c.Request.Method == http.MethodPatch {
		bodyBytes, _ := io.ReadAll(c.Request.Body)
		// Wichtig: Body für weiteren Gebrauch im aktuellen Kontext wiederherstellen
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		requestBody = bytes.NewBuffer(bodyBytes)
	}
	timemod.EndTimePRE = time.Now()
	timemod.StartTimeSRV = time.Now()
	// Neuen HTTP-Request basierend auf der Methode des Original-Requests erstellen
	req, err := http.NewRequest(c.Request.Method, newURL.String(), requestBody)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	// Original-Header kopieren oder modifizieren
	copyHeaders(c.Request.Header, req.Header, endpoint.HeaderReplace, endpoint.HeaderAdd)

	// VerifySSL
	var client *http.Client
	if !endpoint.VerifySSL {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else if endpoint.CertAuth {
		cert, err := tls.X509KeyPair([]byte(endpoint.Certs.CertPEM), []byte(endpoint.Certs.CertKEY))
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		client = &http.Client{Transport: tr}

	} else {
		client = &http.Client{}
	}

	if endpoint.OverrideTimeout > 0 {
		client.Timeout = time.Duration(endpoint.OverrideTimeout) * time.Second
	} else {

		client.Timeout = 5 * time.Second
	}

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	logItem.StatusCode = resp.StatusCode
	logItem.Routed = true
	defer resp.Body.Close()

	// Statuscode und Body an den Client weiterleiten
	c.Status(resp.StatusCode)
	// überschreibe den Header mit den Headers der Antwort
	c.Header("Content-Type", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	_, errW := c.Writer.Write(body)
	if errW != nil {
		return
	}
	timemod.EndTimeSRV = time.Now()

}

// Hilfsfunktion zum Kopieren von Headern
func copyHeaders(src, dest http.Header, headerReplacements []pservice.HeaderReplace, headerAdds []pservice.Header) {
	//header adds
	for key, values := range src {
		for _, value := range values {
			dest.Add(key, value)
		}
	}
	//header replacements
	replacementMap := make(map[string]string)
	for _, hr := range headerReplacements {
		replacementMap[hr.Header] = hr.NewValue
	}
	for name, values := range src {
		if newValue, ok := replacementMap[name]; ok {
			dest.Set(name, newValue)
		} else {
			dest.Set(name, values[0])
		}
	}
	//hinzufügen der Headers
	if len(headerAdds) > 0 {
		for _, h := range headerAdds {
			dest.Add(h.Header, h.Value)
		}
	}

}
