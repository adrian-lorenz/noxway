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
	
}

type Endpoint struct {
	Endpoint      string
	VerifySSL     bool
	CertAuth    bool
	Certs		 Certs
	Active        bool
	Name          string
	HeaderRouteMatches []Header
	HeaderExists  []Header
	HeaderAdd []Header
	JWTPreCheck   JWTPreCheck
	HeaderReplace []HeaderReplace
}

type JWTPreCheck struct {
	Active bool
	Header string
	Key   string
	OnlySign bool
	Field string
	Match []string
}

type Header struct {
	Header string
	Value  string
}
type Certs struct {
	CertPEM string
	CertKEY  string
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
