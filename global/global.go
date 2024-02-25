package global

import (
	"api-gateway/auth"
	"api-gateway/config"
	"api-gateway/pservice"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"
)

var (
	Services = pservice.Services{}
	Config   = config.ConfigStruct{}
	mu       sync.Mutex
	Path     string
	Log      *log.Logger
	Auth     = auth.AuthStruct{}
)

func InitLogger() {
	Log = log.New()
	Log.SetLevel(log.DebugLevel)

	if Config.ExportLog {
		file, err := os.OpenFile(Config.ExportLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {

			Log.SetOutput(io.MultiWriter(file, os.Stderr))
		} else {
			Log.Info("Failed to log to file, using default stderr")
		}
	} else {

		Log.SetOutput(os.Stderr)
	}
}
func SetGlobConfig(newConfig config.ConfigStruct) {
	mu.Lock() // Sperren vor der Aktualisierung
	Config = newConfig
	mu.Unlock() // Freigeben nach der Aktualisierung
}

func SetSrvConfig(newConfig pservice.Services) {
	mu.Lock() // Sperren vor der Aktualisierung
	Services = newConfig
	mu.Unlock() // Freigeben nach der Aktualisierung
}

func LoadAllConfig() {

	Path, err := os.Getwd()
	if err != nil {
		fmt.Println("Fehler beim Ermitteln des aktuellen Verzeichnisses:", err)
		panic(err)
	}

	gPath := filepath.Join(Path, "config", "config_global.json")
	sPath := filepath.Join(Path, "config", "config_service.json")
	aPath := filepath.Join(Path, "config", "config_auth.json")

	CheckConfigGlob(gPath)
	CheckConfigService(sPath)
	CheckConfigAuth(aPath)

	authStruct, err := auth.LoadConfig(aPath)
	if err != nil {
		fmt.Println("Fehler beim Laden der Konfiguration:", err)
		panic(err)
	}

	configStruct, err := config.LoadConfig(gPath)
	if err != nil {
		fmt.Println("Fehler beim Laden der Konfiguration:", err)
		panic(err)
	}
	serviceStruct, err := pservice.LoadConfig(sPath)
	if err != nil {
		fmt.Println("Fehler beim Laden der Konfiguration:", err)
		panic(err)
	}
	fmt.Println("Config loaded")
	SetSrvConfig(*serviceStruct)
	SetGlobConfig(*configStruct)
	SetAuthConfig(*authStruct)
}

func SaveGlobalConfig() {
	mu.Lock() // Sperren vor der Aktualisierung
	data, err := config.MarshalConfig(Config)
	if err != nil {
		fmt.Println("Fehler beim Speichern der Konfiguration:", err)
		panic(err)
	}
	err = os.WriteFile(filepath.Join(Path, "config", "config_global.json"), data, 0666)
	if err != nil {
		fmt.Println("Fehler beim Speichern der Konfiguration:", err)
		panic(err)
	}
	mu.Unlock() // Freigeben nach der Aktualisierung
}

func SaveServiceConfig() {
	mu.Lock() // Sperren vor der Aktualisierung
	data, err := pservice.MarshalConfig(Services)
	if err != nil {
		fmt.Println("Fehler beim Speichern der Konfiguration:", err)
		panic(err)
	}
	err = os.WriteFile(filepath.Join(Path, "config", "config_service.json"), data, 0666)
	if err != nil {
		fmt.Println("Fehler beim Speichern der Konfiguration:", err)
		panic(err)
	}
	mu.Unlock() // Freigeben nach der Aktualisierung
}

func SaveAuthConfig() {
	mu.Lock() // Sperren vor der Aktualisierung
	data, err := auth.MarshalConfig(Auth)
	if err != nil {
		fmt.Println("Fehler beim Speichern der Konfiguration:", err)
		panic(err)
	}
	err = os.WriteFile(filepath.Join(Path, "config", "config_auth.json"), data, 0666)
	if err != nil {
		fmt.Println("Fehler beim Speichern der Konfiguration:", err)
		panic(err)
	}
	mu.Unlock() // Freigeben nach der Aktualisierung
}

func SetAuthConfig(newConfig auth.AuthStruct) {
	mu.Lock() // Sperren vor der Aktualisierung
	Auth = newConfig
	mu.Unlock() // Freigeben nach der Aktualisierung
}
