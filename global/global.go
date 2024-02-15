package global

import "api-gateway/pservice"


var Services = []pservice.Service{}
var Config = ConfigStruct{
	SSL:           false,
	Debug:         true,
	ExcludedPaths: []string{"/favicon.ico", "/robots.txt", "/sitemap.xml", "/sitemap.xml.gz", "/", ""},
	Port:          "8080",
	SSLPort:       "443",
	Cors: 		true,
	PemCrt: "/etc/letsencrypt/live/deine-domain.de/fullchain.pem",
	PemKey: "/etc/letsencrypt/live/deine-domain.de/privkey.pem",
	MetricPath: "mdata",
	MetricWhitelist: []string{"127.0.0.1"},
	Bannlist: []string{},
	
}


type ConfigStruct struct {
	SSL bool
	Debug bool
	ExcludedPaths []string
	Port string
	SSLPort string
	Cors bool
	PemCrt string
	PemKey string
	MetricPath string
	MetricWhitelist []string
	Bannlist []string
}


