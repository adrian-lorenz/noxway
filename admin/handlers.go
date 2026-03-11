package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/adrian-lorenz/noxway/certs"
	"github.com/adrian-lorenz/noxway/config"
	"github.com/adrian-lorenz/noxway/database"
	"github.com/adrian-lorenz/noxway/global"
	"github.com/adrian-lorenz/noxway/pservice"
	"github.com/adrian-lorenz/noxway/waf"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ─── Dashboard ───────────────────────────────────────────────────────────────

type IPStat struct {
	IP    string
	Count int
}

type ServiceStat struct {
	Name    string
	Count   int
	AvgTime float32
}

type DashboardData struct {
	TotalRequests int
	AvgResponseMs float32
	ErrorCount    int
	RoutedCount   int
	TopIPs        []IPStat
	TopServices   []ServiceStat
	ChartLabels   string
	ChartData     string
	Span          string
	GatewayName   string
}

func showDashboard(c *gin.Context) {
	renderPage(c, "dashboard", gin.H{"Span": "hour", "GatewayName": global.Config.Name})
}

func htmxDashboard(c *gin.Context) {
	span := c.DefaultQuery("span", "hour")
	var logs []database.Logtable
	switch span {
	case "day":
		database.DB.Where("created > ?", time.Now().Add(-24*time.Hour)).Find(&logs)
	case "all":
		database.DB.Find(&logs)
	default:
		database.DB.Where("created > ?", time.Now().Add(-time.Hour)).Find(&logs)
		span = "hour"
	}
	data := computeDashboard(logs, span)
	renderPartial(c, "dashboard_stats", data, "dashboard_stats.html")
}

func computeDashboard(logs []database.Logtable, span string) DashboardData {
	d := DashboardData{Span: span, GatewayName: global.Config.Name}
	d.TotalRequests = len(logs)

	ipCounts := map[string]int{}
	svcCounts := map[string]int{}
	svcTimes := map[string]float32{}
	var totalTime float32

	for _, l := range logs {
		totalTime += l.TimeFull
		if l.StatusCode >= 400 {
			d.ErrorCount++
		}
		if l.Routed {
			d.RoutedCount++
		}
		if l.IP != "" {
			ipCounts[l.IP]++
		}
		if l.Service != "" {
			svcCounts[l.Service]++
			svcTimes[l.Service] += l.TimeFull
		}
	}
	if d.TotalRequests > 0 {
		d.AvgResponseMs = totalTime / float32(d.TotalRequests)
	}

	for ip, cnt := range ipCounts {
		d.TopIPs = append(d.TopIPs, IPStat{ip, cnt})
	}
	sort.Slice(d.TopIPs, func(i, j int) bool { return d.TopIPs[i].Count > d.TopIPs[j].Count })
	if len(d.TopIPs) > 5 {
		d.TopIPs = d.TopIPs[:5]
	}

	for svc, cnt := range svcCounts {
		avg := float32(0)
		if cnt > 0 {
			avg = svcTimes[svc] / float32(cnt)
		}
		d.TopServices = append(d.TopServices, ServiceStat{svc, cnt, avg})
	}
	sort.Slice(d.TopServices, func(i, j int) bool { return d.TopServices[i].Count > d.TopServices[j].Count })
	if len(d.TopServices) > 5 {
		d.TopServices = d.TopServices[:5]
	}

	// Chart: bucket by time
	var buckets int
	var bucketDur time.Duration
	switch span {
	case "day":
		buckets = 24
		bucketDur = time.Hour
	case "all":
		buckets = 20
		bucketDur = 24 * time.Hour
	default:
		buckets = 12
		bucketDur = 5 * time.Minute
	}

	now := time.Now()
	counts := make([]int, buckets)
	labels := make([]string, buckets)
	for i := 0; i < buckets; i++ {
		t := now.Add(-time.Duration(buckets-1-i) * bucketDur)
		labels[i] = t.Format("15:04")
	}
	for _, l := range logs {
		for i := 0; i < buckets; i++ {
			bucketStart := now.Add(-time.Duration(buckets-1-i) * bucketDur)
			bucketEnd := bucketStart.Add(bucketDur)
			if l.Created.After(bucketStart) && l.Created.Before(bucketEnd) {
				counts[i]++
				break
			}
		}
	}

	lb, _ := json.Marshal(labels)
	cb, _ := json.Marshal(counts)
	d.ChartLabels = string(lb)
	d.ChartData = string(cb)
	return d
}

// ─── Logs ────────────────────────────────────────────────────────────────────

func showLogs(c *gin.Context) {
	renderPage(c, "logs", gin.H{"Span": "hour"})
}

func htmxLogs(c *gin.Context) {
	span := c.DefaultQuery("span", "hour")
	var logs []database.Logtable
	switch span {
	case "day":
		database.DB.Where("created > ?", time.Now().Add(-24*time.Hour)).Order("created desc").Find(&logs)
	case "all":
		database.DB.Order("created desc").Limit(500).Find(&logs)
	default:
		database.DB.Where("created > ?", time.Now().Add(-time.Hour)).Order("created desc").Find(&logs)
	}
	renderPartial(c, "log_rows", logs, "log_rows.html")
}

// ─── Gateway ─────────────────────────────────────────────────────────────────

func showGateway(c *gin.Context) {
	cfg := global.GetConfig()
	renderPage(c, "gateway", gin.H{"Config": cfg})
}

func saveGateway(c *gin.Context) {
	cfg := global.GetConfig()
	applyGatewayForm(c, &cfg)
	global.SetGlobConfig(cfg)
	global.SaveGlobalConfig()
	renderPage(c, "gateway", gin.H{"Config": cfg, "Success": "Configuration saved"})
}

func htmxSaveGateway(c *gin.Context) {
	cfg := global.GetConfig()
	applyGatewayForm(c, &cfg)
	global.SetGlobConfig(cfg)
	global.SaveGlobalConfig()
	c.String(http.StatusOK, `<div class="toast success">Configuration saved</div>`)
}

func htmxRetrieveCert(c *gin.Context) {
	cfg := global.GetConfig()
	if cfg.SSLDomain == "" || cfg.SSLMail == "" {
		c.String(http.StatusBadRequest, `<div class="toast error">Domain und Mail müssen zuerst gespeichert werden</div>`)
		return
	}
	dnsCheck, err := certs.CheckDNS(cfg.SSLDomain)
	if err != nil {
		c.String(http.StatusOK, `<div class="toast error">DNS Fehler: `+err.Error()+`</div>`)
		return
	}
	if !dnsCheck {
		c.String(http.StatusOK, `<div class="toast error">DNS stimmt nicht überein - Domain zeigt nicht auf diesen Server</div>`)
		return
	}
	if err := certs.RetriveCert(cfg.SSLDomain, cfg.SSLMail); err != nil {
		c.String(http.StatusOK, `<div class="toast error">Zertifikat Fehler: `+err.Error()+`</div>`)
		return
	}
	cp, kp, err := certs.CertExist(cfg.SSLDomain)
	if err != nil {
		c.String(http.StatusOK, `<div class="toast error">Zertifikat erstellt aber nicht gefunden: `+err.Error()+`</div>`)
		return
	}
	cfg.PemCrt = cp
	cfg.PemKey = kp
	global.SetGlobConfig(cfg)
	global.SaveGlobalConfig()
	c.String(http.StatusOK, `<div class="toast success">Zertifikat erfolgreich erstellt und gespeichert</div>`)
}

func validPort(s, fallback string) string {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return fallback
	}
	return strconv.Itoa(p)
}

func applyGatewayForm(c *gin.Context, cfg *config.ConfigStruct) {
	cfg.Name = c.PostForm("name")
	cfg.Prefix = c.PostForm("prefix")
	cfg.Debug = c.PostForm("debug") == "on"
	cfg.Port = validPort(c.PostForm("port"), "8080")
	cfg.SSLPort = validPort(c.PostForm("sslPort"), "443")
	cfg.ExportLog = c.PostForm("exportLog") == "on"
	cfg.ExportLogPath = c.PostForm("exportLogPath")
	cfg.Hostnamecheck = c.PostForm("hostnamecheck") == "on"
	cfg.Hostname = c.PostForm("hostname")
	cfg.SSL = c.PostForm("ssl") == "on"
	cfg.SSLDomain = c.PostForm("sslDomain")
	cfg.SSLMail = c.PostForm("sslMail")
	cfg.RateLimiter = c.PostForm("rateLimiter") == "on"
	if rate, err := strconv.Atoi(c.PostForm("rateRate")); err == nil {
		cfg.Rate.Rate = rate
	}
	if win, err := strconv.ParseFloat(c.PostForm("rateWindowMin"), 64); err == nil {
		cfg.Rate.Window = time.Duration(win * float64(time.Minute))
	}
	cfg.Cors = c.PostForm("cors") == "on"
	cfg.CorsAdvanced = c.PostForm("corsAdvanced") == "on"

	cfg.SystemWhitelist = filterEmpty(c.PostFormArray("systemWhitelist[]"))
	cfg.SystemWhitelistDNS = filterEmpty(c.PostFormArray("systemWhitelistDNS[]"))
	cfg.RateWhitelist = filterEmpty(c.PostFormArray("rateWhitelist[]"))
	cfg.CorsAllowOrigins = filterEmpty(c.PostFormArray("corsAllowOrigins[]"))
	cfg.CorsAllowMethods = filterEmpty(c.PostFormArray("corsAllowMethods[]"))
	cfg.CorsAllowHeaders = filterEmpty(c.PostFormArray("corsAllowHeaders[]"))
	cfg.DNSResolver = c.PostForm("dnsResolver")
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

func showEndpoints(c *gin.Context) {
	svcs := global.GetServices()
	renderPage(c, "endpoints", gin.H{"Services": svcs.Services})
}

func htmxEndpointsTable(c *gin.Context) {
	svcs := global.GetServices()
	renderPartial(c, "endpoints_table", gin.H{"Services": svcs.Services}, "endpoints.html")
}

func htmxEndpointEdit(c *gin.Context) {
	svcUUID := c.Param("svc")
	epUUID := c.Param("ep")
	svcs := global.GetServices()

	for _, svc := range svcs.Services {
		if svc.BasicEndpoint.UUID == epUUID {
			renderPartial(c, "endpoint_edit", gin.H{
				"Endpoint":    svc.BasicEndpoint,
				"ServiceUUID": svcUUID,
				"IsBasic":     true,
			}, "components.html", "endpoint_edit.html")
			return
		}
		for _, ep := range svc.Endpoints {
			if ep.UUID == epUUID {
				renderPartial(c, "endpoint_edit", gin.H{
					"Endpoint":    ep,
					"ServiceUUID": svcUUID,
					"IsBasic":     false,
				}, "components.html", "endpoint_edit.html")
				return
			}
		}
	}
	c.String(http.StatusNotFound, "Endpoint not found")
}

func htmxEndpointSave(c *gin.Context) {
	svcUUID := c.PostForm("ServiceUUID")
	epUUID := c.PostForm("UUID")
	isBasic := c.PostForm("IsBasic") == "true"

	ep := pservice.Endpoint{
		UUID:            epUUID,
		Name:            c.PostForm("Name"),
		Endpoint:        c.PostForm("Endpoint"),
		Active:          c.PostForm("Active") == "on",
		VerifySSL:       c.PostForm("VerifySSL") == "on",
		CertAuth:        c.PostForm("CertAuth") == "on",
		WebSocket:       c.PostForm("WebSocket") == "on",
		JWTPreCheck:     c.PostForm("JWTPreCheck") == "on",
		OverrideTimeout: parseIntForm(c.PostForm("OverrideTimeout")),
		Certs: pservice.Certs{
			CertPEM: c.PostForm("CertPEM"),
			CertKEY: c.PostForm("CertKEY"),
		},
		JWTData: pservice.JWTPreCheck{
			Header:   c.PostForm("JWTHeader"),
			Key:      c.PostForm("JWTKey"),
			OnlySign: c.PostForm("JWTOnlySign") == "on",
			Field:    c.PostForm("JWTField"),
		},
	}

	ep.HeaderRouteMatches = parseHeaderPairs(c, "HRM_Header", "HRM_Value")
	ep.HeaderExists = parseHeaderPairs(c, "HEX_Header", "HEX_Value")
	ep.HeaderAdd = parseHeaderPairs(c, "HA_Header", "HA_Value")
	ep.HeaderReplace = parseHeaderReplace(c)
	ep.JWTData.Match = filterEmpty(c.PostFormArray("JWTMatch[]"))
	ep.Whitelist = filterEmpty(c.PostFormArray("Whitelist[]"))

	svcs := global.GetServices()
	updated := false
	for i, svc := range svcs.Services {
		if svc.UUID == svcUUID {
			if isBasic && svc.BasicEndpoint.UUID == epUUID {
				svcs.Services[i].BasicEndpoint = ep
				updated = true
				break
			}
			for j, e := range svc.Endpoints {
				if e.UUID == epUUID {
					svcs.Services[i].Endpoints[j] = ep
					updated = true
					break
				}
			}
		}
		if updated {
			break
		}
	}

	if !updated {
		c.String(http.StatusNotFound, "Endpoint not found")
		return
	}

	global.SetSrvConfig(svcs)
	global.SaveServiceConfig()
	c.Header("HX-Trigger", "refreshEndpoints")
	c.String(http.StatusOK, `<div class="toast success">Saved</div>`)
}

func htmxCancelEdit(c *gin.Context) {
	c.String(http.StatusOK, "")
}

func htmxDeleteService(c *gin.Context) {
	svcUUID := c.Param("uuid")
	svcs := global.GetServices()
	filtered := svcs.Services[:0]
	for _, s := range svcs.Services {
		if s.UUID != svcUUID {
			filtered = append(filtered, s)
		}
	}
	svcs.Services = filtered
	global.SetSrvConfig(svcs)
	global.SaveServiceConfig()
	c.Header("HX-Trigger", "refreshEndpoints")
	c.String(http.StatusOK, "")
}

func htmxDeleteEndpoint(c *gin.Context) {
	svcUUID := c.Param("svc")
	epUUID := c.Param("ep")
	svcs := global.GetServices()
	for i, svc := range svcs.Services {
		if svc.UUID == svcUUID {
			filtered := svc.Endpoints[:0]
			for _, ep := range svc.Endpoints {
				if ep.UUID != epUUID {
					filtered = append(filtered, ep)
				}
			}
			svcs.Services[i].Endpoints = filtered
			break
		}
	}
	global.SetSrvConfig(svcs)
	global.SaveServiceConfig()
	c.Header("HX-Trigger", "refreshEndpoints")
	c.String(http.StatusOK, "")
}

func htmxAddService(c *gin.Context) {
	name := c.PostForm("name")
	if name == "" {
		c.String(http.StatusBadRequest, "Name required")
		return
	}
	newSvc := pservice.Service{
		UUID:   uuid.New().String(),
		Name:   name,
		Active: false,
		BasicEndpoint: pservice.Endpoint{
			UUID:               uuid.New().String(),
			Name:               "basic",
			Endpoint:           "https://",
			Active:             false,
			VerifySSL:          true,
			HeaderRouteMatches: []pservice.Header{},
			HeaderExists:       []pservice.Header{},
			HeaderAdd:          []pservice.Header{},
			HeaderReplace:      []pservice.HeaderReplace{},
			Whitelist:          []string{},
		},
		Endpoints: []pservice.Endpoint{},
	}
	svcs := global.GetServices()
	svcs.Services = append(svcs.Services, newSvc)
	global.SetSrvConfig(svcs)
	global.SaveServiceConfig()
	c.Header("HX-Trigger", "refreshEndpoints")
	c.String(http.StatusOK, "")
}

func htmxAddEndpoint(c *gin.Context) {
	svcUUID := c.Param("svc")
	name := c.PostForm("name")
	if name == "" {
		name = "sub"
	}
	newEp := pservice.Endpoint{
		UUID:               uuid.New().String(),
		Name:               name,
		Endpoint:           "https://",
		Active:             false,
		VerifySSL:          true,
		HeaderRouteMatches: []pservice.Header{{Header: "system", Value: "dev"}},
		HeaderExists:       []pservice.Header{},
		HeaderAdd:          []pservice.Header{},
		HeaderReplace:      []pservice.HeaderReplace{},
		Whitelist:          []string{},
	}
	svcs := global.GetServices()
	for i, svc := range svcs.Services {
		if svc.UUID == svcUUID {
			svcs.Services[i].Endpoints = append(svcs.Services[i].Endpoints, newEp)
			break
		}
	}
	global.SetSrvConfig(svcs)
	global.SaveServiceConfig()
	c.Header("HX-Trigger", "refreshEndpoints")
	c.String(http.StatusOK, "")
}

func htmxWAFEdit(c *gin.Context) {
	svcUUID := c.Param("svc")
	svcs := global.GetServices()
	for _, svc := range svcs.Services {
		if svc.UUID == svcUUID {
			renderPartial(c, "waf_edit", gin.H{
				"WAF":         svc.WAF,
				"ServiceUUID": svcUUID,
				"ServiceName": svc.Name,
			}, "components.html", "waf_edit.html")
			return
		}
	}
	c.String(http.StatusNotFound, "Service not found")
}

func htmxWAFSave(c *gin.Context) {
	svcUUID := c.Param("svc")
	wafCfg := waf.WAFConfig{
		Enabled:            c.PostForm("Enabled") == "on",
		BlockSQLi:          c.PostForm("BlockSQLi") == "on",
		BlockXSS:           c.PostForm("BlockXSS") == "on",
		BlockPathTraversal: c.PostForm("BlockPathTraversal") == "on",
		BlockCommandInj:    c.PostForm("BlockCommandInj") == "on",
		BlockLargeBody:     c.PostForm("BlockLargeBody") == "on",
		MaxBodyKB:          parseIntForm(c.PostForm("MaxBodyKB")),
	}

	svcs := global.GetServices()
	for i, svc := range svcs.Services {
		if svc.UUID == svcUUID {
			svcs.Services[i].WAF = wafCfg
			break
		}
	}
	global.SetSrvConfig(svcs)
	global.SaveServiceConfig()
	c.Header("HX-Trigger", "refreshEndpoints")
	c.String(http.StatusOK, `<div class="toast success">WAF Konfiguration gespeichert</div>`)
}

func reloadConfig(c *gin.Context) {
	global.LoadAllConfig()
	c.String(http.StatusOK, `<div class="toast success">Gateway reloaded</div>`)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func parseIntForm(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func parseJSONField[T any](s string, dest *T) {
	if s == "" {
		return
	}
	_ = json.Unmarshal([]byte(s), dest)
}

func parseHeaderPairs(c *gin.Context, headerKey, valueKey string) []pservice.Header {
	headers := c.PostFormArray(headerKey + "[]")
	values := c.PostFormArray(valueKey + "[]")
	var result []pservice.Header
	for i, h := range headers {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		if h != "" {
			result = append(result, pservice.Header{Header: h, Value: v})
		}
	}
	return result
}

func parseHeaderReplace(c *gin.Context) []pservice.HeaderReplace {
	headers := c.PostFormArray("HR_Header[]")
	values := c.PostFormArray("HR_Value[]")
	newValues := c.PostFormArray("HR_NewValue[]")
	var result []pservice.HeaderReplace
	for i, h := range headers {
		if h == "" {
			continue
		}
		v, nv := "", ""
		if i < len(values) {
			v = values[i]
		}
		if i < len(newValues) {
			nv = newValues[i]
		}
		result = append(result, pservice.HeaderReplace{Header: h, Value: v, NewValue: nv})
	}
	return result
}

func filterEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func templateDict(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("dict requires an even number of arguments")
	}
	m := make(map[string]any, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		m[key] = values[i+1]
	}
	return m, nil
}

func toJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func fmtTime(t time.Time) string {
	return t.Format("02.01.2006 15:04:05")
}

func fmtMs(f float32) string {
	return strconv.FormatFloat(float64(f), 'f', 1, 64)
}

func rateWindowMin(d time.Duration) int {
	m := int(d.Minutes())
	if m < 1 {
		return 60
	}
	return m
}
