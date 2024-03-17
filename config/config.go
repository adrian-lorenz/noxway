package config

import (
	"encoding/json"
	"os"
	"time"
)

type ConfigStruct struct {
	SSL                bool     `json:"ssl"`
	Debug              bool     `json:"debug"`
	ExcludedPaths      []string `json:"excludedPaths"`
	Port               string   `json:"port"`
	SSLPort            string   `json:"sslPort"`
	SSLDomain          string   `json:"sslDomain"`
	SSLCertDays        int      `json:"sslCertDays"`
	SSLMail            string   `json:"sslMail"`
	Cors               bool     `json:"cors"`
	RateLimiter        bool     `json:"rateLimiter"`
	Bann               bool     `json:"bann"`
	Metrics            bool     `json:"metric"`
	Prefix             string   `json:"prefix"`
	PemCrt             string   `json:"pemCrt"`
	PemKey             string   `json:"pemKey"`
	SystemWhitelist    []string `json:"systemWhitelist"`
	SystemWhitelistDNS []string `json:"systemWhitelistDNS"`
	Bannlist           []string `json:"bannlist"`
	Rate               Rates    `json:"rate"`
	RateWhitelist      []string `json:"rateWhitelist"`
	CorsAllowOrigins   []string `json:"corsAllowOrigins"`
	CorsAllowMethods   []string `json:"corsAllowMethods"`
	CorsAllowHeaders   []string `json:"corsAllowHeaders"`
	CorsAdvanced       bool     `json:"corsAdvanced"`
	ExportLog          bool     `json:"exportLog"`
	ExportLogPath      string   `json:"exportLogPath"`
	Hostnamecheck      bool     `json:"hostnamecheck"`
	Hostname           string   `json:"hostname"`
	Name               string   `json:"name"`
}

type Rates struct {
	Rate   int           `json:"rate"`
	Window time.Duration `json:"window"`
}

// LoadConfig lädt die Konfiguration aus einer JSON-Datei.
func LoadConfig(path string) (*ConfigStruct, error) {
	var config ConfigStruct
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

//chek if the config exists, else create a new one

func MarshalConfig(config ConfigStruct) ([]byte, error) {
	return json.MarshalIndent(config, "", "  ")
}
