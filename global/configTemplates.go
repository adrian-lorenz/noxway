package global

import (
	"api-gateway/auth"
	"api-gateway/config"
	"api-gateway/pservice"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func CheckConfigGlob(path string) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		config := config.ConfigStruct{
			SSL:             false,
			Debug:           false,
			ExcludedPaths:   []string{},
			Port:            "8080",
			SSLPort:         "443",
			Cors:            true,
			RateLimiter:     true,
			Bann:            false,
			Prefix:          "/v1/",
			PemCrt:          "",
			PemKey:          "",
			SystemWhitelist: []string{"127.0.0.1"},
			Bannlist:        []string{},
			Rate: config.Rates{
				Rate:   500,
				Window: 3600000000000,
			},
			RateWhitelist:    []string{"127.0.0.1"},
			CorsAllowOrigins: []string{"*"},
			CorsAllowMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
			CorsAllowHeaders: []string{"*"},
			CorsAdvanced:     true,
			ExportLog:        false,
			ExportLogPath:    "/var/log/noxway.log",
			Hostnamecheck:    false,
			Hostname:         "",
			Name:             "Noway API Gateway",
		}
		Config = config
		SaveGlobalConfig()
	}

}

func CheckConfigService(path string) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		services := pservice.Services{
			Services: []pservice.Service{
				{
					Name:   "testservice1",
					Active: true,
					UUID:   "7652ba0d-008a-4f39-bfe4-a6cae84e8076",
					BasicEndpoint: pservice.Endpoint{
						Endpoint:  "http://127.0.0.1:8080/testservice1",
						VerifySSL: false,
						CertAuth:  false,
						Active:             true,
						Name:               "Testservice1",
						UUID:               "a79231a8-2c5b-465d-853c-ffc1282c662c",
						OverrideTimeout:    0,
						HeaderRouteMatches: []pservice.Header{},
						HeaderExists:       []pservice.Header{},
						HeaderAdd:          []pservice.Header{},
						HeaderReplace:      []pservice.HeaderReplace{},
						JWTPreCheck:        false,
						JWTData:            pservice.JWTPreCheck{},
					},
					Endpoints: []pservice.Endpoint{
						{
							Endpoint:  "http://127.0.0.1:8080/testservice2",
							VerifySSL: false,
							CertAuth:  false,
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
							JWTPreCheck:   false,
							JWTData:       pservice.JWTPreCheck{},
						},
					},
				},
			},
		}

		Services = services
		SaveServiceConfig()
	}
}

func CheckConfigAuth(path string) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Fehler beim Generieren des Passworts:", err)
			return
		}
		auth := auth.AuthStruct{
			Users: []auth.User{
				{
					Username: "admin",
					Password: string(hashedPassword),
					Role:     "admin",
				},
			},
		}

		Auth = auth
		SaveAuthConfig()
	}
}
