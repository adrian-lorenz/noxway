package global

import (
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
	configStruct, err := config.LoadConfig(filepath.Join(Path, "config", "config_global.json"))
	if err != nil {
		fmt.Println("Fehler beim Laden der Konfiguration:", err)
		panic(err)
	}
	serviceStruct, err := pservice.LoadConfig(filepath.Join(Path, "config", "config_service.json"))
	if err != nil {
		fmt.Println("Fehler beim Laden der Konfiguration:", err)
		panic(err)
	}
	fmt.Println("Config loaded")
	SetSrvConfig(*serviceStruct)
	SetGlobConfig(*configStruct)
}
