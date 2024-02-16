package config

import (
	"encoding/json"
	"os"
	"time"
)

type ConfigStruct struct {
	SSL             bool     `json:"ssl"`
	Debug           bool     `json:"debug"`
	ExcludedPaths   []string `json:"excludedPaths"`
	Port            string   `json:"port"`
	SSLPort         string   `json:"sslPort"`
	Cors            bool     `json:"cors"`
	RateLimiter     bool     `json:"rateLimiter"`
	Bann            bool     `json:"bann"`
	Metrics         bool     `json:"metric"`
	PemCrt          string   `json:"pemCrt"`
	PemKey          string   `json:"pemKey"`
	MetricPath      string   `json:"metricPath"`
	MetricWhitelist []string `json:"metricWhitelist"`
	Bannlist        []string `json:"bannlist"`
	Rate            Rates    `json:"rate"`
	RateWhitelist   []string `json:"rateWhitelist"`
}

type Rates struct {
	Rate   int           `json:"rate"`
	Burst  int           `json:"burst"`
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
