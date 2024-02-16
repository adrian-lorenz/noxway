package pservice

import (
	"encoding/json"
	"os"
)

type Services struct {
	Services []Service
}

type Service struct {
	Endpoints     []Endpoint
	BasicEndpoint Endpoint
	Active        bool
	Name          string
	HeaderReplace []HeaderReplace
}

type Endpoint struct {
	Endpoint      string
	VerifySSL     bool
	Active        bool
	Name          string
	HeaderMatches []HeaderMatch
}

type HeaderMatch struct {
	Header string
	Value  string
}

type HeaderReplace struct {
	Header   string
	Value    string
	NewValue string
}

func LoadConfig(path string) (*Services, error) {
	var config Services
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
