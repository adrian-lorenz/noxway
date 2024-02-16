package global

import (
	"api-gateway/config"
	"api-gateway/pservice"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"
)

var (
	Services = pservice.Services{}
	Config   = config.ConfigStruct{}
	mu       sync.Mutex
	Path	 string
	Log 	*log.Logger
)
func InitLogger() {
    Log = log.New()
    Log.SetLevel(log.DebugLevel) // Setze das gewünschte Log-Level
	/*
    Log.SetFormatter(&log.TextFormatter{
        FullTimestamp: true,
    })
    file, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err == nil {
        Log.SetOutput(file)
    } else {
        Log.Warn("Failed to log to file, using default stderr")
    }
	*/
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
		log.Errorln("Fehler beim Ermitteln des aktuellen Verzeichnisses:", err)
		panic(err)
	}
	configStruct, err := config.LoadConfig(filepath.Join(Path, "config", "config_global.json"))
	if err != nil {
		log.Errorln("Fehler beim Laden der Konfiguration:", err)
		panic(err)
	}
	serviceStruct, err := pservice.LoadConfig(filepath.Join(Path, "config", "config_service.json"))
	if err != nil {
		log.Errorln("Fehler beim Laden der Konfiguration:", err)
		panic(err)
	}
	log.Infoln("Config loaded")
	SetSrvConfig(*serviceStruct)
	SetGlobConfig(*configStruct)
}
