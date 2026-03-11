package global

import (
	"encoding/json"
	"fmt"

	"github.com/adrian-lorenz/noxway/auth"
	"github.com/adrian-lorenz/noxway/config"
	"github.com/adrian-lorenz/noxway/database"
	"github.com/adrian-lorenz/noxway/pservice"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func CheckConfigGlob() {
	_, err := database.LoadConfigEntry("global")
	if err == nil {
		return // already exists
	}
	configA := config.ConfigStruct{
		SSL:                false,
		Debug:              false,
		ExcludedPaths:      []string{},
		Port:               "8080",
		SSLPort:            "443",
		Cors:               true,
		RateLimiter:        true,
		Bann:               false,
		SystemWhitelistDNS: []string{},
		SSLMail:            "",
		SSLDomain:          "",
		Prefix:             "/v1/",
		PemCrt:             "./certs/cert.pem",
		PemKey:             "./certs/privkey.pem",
		SystemWhitelist:    []string{},
		Bannlist:           []string{},
		Rate: config.Rates{
			Rate:   500,
			Window: 3600000000000,
		},
		RateWhitelist:    []string{"127.0.0.1"},
		CorsAllowOrigins: []string{"*"},
		CorsAllowMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		CorsAllowHeaders: []string{"*"},
		CorsAdvanced:     true,
		ExportLog:        true,
		ExportLogPath:    "./log/noxway.log",
		Hostnamecheck:    false,
		Hostname:         "",
		Name:             "Noxway API Gateway",
	}
	Config = configA
	SaveGlobalConfig()
	fmt.Println("Created default global config in database")
}

// defaultTestServices lists built-in test service names that must always exist.
var defaultTestServices = []struct {
	name     string
	endpoint string
}{
	{"testservice1", "http://127.0.0.1:8080/testservice1"},
	{"testservice2", "http://127.0.0.1:8080/testservice2"},
	{"testservice3", "http://127.0.0.1:8080/testservice3"},
}

func CheckConfigService() {
	val, err := database.LoadConfigEntry("services")
	if err == nil {
		// Config exists — load into Services first, then migrate.
		var svcs pservice.Services
		if jsonErr := json.Unmarshal([]byte(val), &svcs); jsonErr == nil {
			mu.Lock()
			Services = svcs
			mu.Unlock()
		}
		migrateDefaultServices()
		return
	}
	services := pservice.Services{
		Services: []pservice.Service{
			{
				Name:   "testservice1",
				Active: true,
				UUID:   "7652ba0d-008a-4f39-bfe4-a6cae84e8076",
				BasicEndpoint: pservice.Endpoint{
					Endpoint:           "http://127.0.0.1:8080/testservice1",
					VerifySSL:          false,
					CertAuth:           false,
					Active:             true,
					Name:               "Testservice1",
					UUID:               "a79231a8-2c5b-465d-853c-ffc1282c662c",
					OverrideTimeout:    0,
					HeaderRouteMatches: []pservice.Header{},
					HeaderExists:       []pservice.Header{},
					HeaderAdd:          []pservice.Header{},
					HeaderReplace:      []pservice.HeaderReplace{},
					Whitelist:          []string{},
					JWTPreCheck:        false,
					JWTData:            pservice.JWTPreCheck{},
				},
				Endpoints: []pservice.Endpoint{
					{
						Endpoint:        "http://127.0.0.1:8080/testservice2",
						VerifySSL:       false,
						CertAuth:        false,
						Active:          true,
						Name:            "testservice2",
						UUID:            "9f2e6487-8dea-428d-a87a-f878d1548966",
						OverrideTimeout: 0,
						HeaderRouteMatches: []pservice.Header{
							{
								Header: "system",
								Value:  "dev",
							},
						},
						HeaderExists:  []pservice.Header{},
						HeaderAdd:     []pservice.Header{},
						HeaderReplace: []pservice.HeaderReplace{},
						Whitelist:     []string{},
						JWTPreCheck:   false,
						JWTData:       pservice.JWTPreCheck{},
					},
				},
			},
			{
				Name:   "testservice3",
				Active: true,
				UUID:   "b3c7e912-4f1a-4d8e-9c2b-a1f0e5d63821",
				BasicEndpoint: pservice.Endpoint{
					Endpoint:           "http://127.0.0.1:8080/testservice3",
					VerifySSL:          false,
					CertAuth:           false,
					Active:             true,
					Name:               "Testservice3",
					UUID:               "c8d4f023-5a2b-4e9f-8d1c-b2e1f6e74932",
					OverrideTimeout:    0,
					HeaderRouteMatches: []pservice.Header{},
					HeaderExists:       []pservice.Header{},
					HeaderAdd:          []pservice.Header{},
					HeaderReplace:      []pservice.HeaderReplace{},
					Whitelist:          []string{},
					JWTPreCheck:        false,
					JWTData:            pservice.JWTPreCheck{},
				},
				Endpoints: []pservice.Endpoint{},
			},
		},
	}
	Services = services
	SaveServiceConfig()
	fmt.Println("Created default services config in database")
}

func CheckConfigAuth() {
	_, err := database.LoadConfigEntry("auth")
	if err == nil {
		return // already exists
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error generating password:", err)
		return
	}
	authA := auth.AuthStruct{
		Users: []auth.User{
			{
				Username: "admin",
				Password: string(hashedPassword),
				Role:     "admin",
			},
		},
	}
	Auth = authA
	SaveAuthConfig()
	fmt.Println("Created default auth config in database")
}

// migrateDefaultServices adds any missing default test services to the
// existing services config and persists the updated list to the database.
func migrateDefaultServices() {
	changed := false
	for _, def := range defaultTestServices {
		found := false
		for _, s := range Services.Services {
			if s.Name == def.name {
				found = true
				break
			}
		}
		if found {
			continue
		}
		Services.Services = append(Services.Services, pservice.Service{
			Name:   def.name,
			Active: true,
			UUID:   uuid.New().String(),
			BasicEndpoint: pservice.Endpoint{
				Endpoint:           def.endpoint,
				VerifySSL:          false,
				CertAuth:           false,
				Active:             true,
				Name:               def.name,
				UUID:               uuid.New().String(),
				HeaderRouteMatches: []pservice.Header{},
				HeaderExists:       []pservice.Header{},
				HeaderAdd:          []pservice.Header{},
				HeaderReplace:      []pservice.HeaderReplace{},
				Whitelist:          []string{},
			},
			Endpoints: []pservice.Endpoint{},
		})
		fmt.Printf("Migration: added missing default service %q\n", def.name)
		changed = true
	}

	// Ensure testservice1 BasicEndpoint has WebSocket enabled.
	for i, s := range Services.Services {
		if s.Name == "testservice1" && !s.BasicEndpoint.WebSocket {
			Services.Services[i].BasicEndpoint.WebSocket = true
			fmt.Println("Migration: enabled WebSocket on testservice1 BasicEndpoint")
			changed = true
			break
		}
	}

	if changed {
		SaveServiceConfig()
	}
}
