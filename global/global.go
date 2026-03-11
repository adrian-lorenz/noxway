package global

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/adrian-lorenz/noxway/auth"
	"github.com/adrian-lorenz/noxway/config"
	"github.com/adrian-lorenz/noxway/database"
	"github.com/adrian-lorenz/noxway/pservice"

	log "github.com/sirupsen/logrus"
)

var (
	Services = pservice.Services{}
	Config   = config.ConfigStruct{}
	mu       sync.RWMutex
	Path     string
	Log      *log.Logger
	Auth     = auth.AuthStruct{}
)

// GetConfig returns a copy of the global config with read-lock protection
func GetConfig() config.ConfigStruct {
	mu.RLock()
	defer mu.RUnlock()
	return Config
}

// GetServices returns a copy of the services config with read-lock protection
func GetServices() pservice.Services {
	mu.RLock()
	defer mu.RUnlock()
	return Services
}

// GetAuth returns a copy of the auth config with read-lock protection
func GetAuth() auth.AuthStruct {
	mu.RLock()
	defer mu.RUnlock()
	return Auth
}

// safeLogPath returns true when the path does not escape via path traversal.
func safeLogPath(p string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	cleaned := filepath.Clean(p)
	return !strings.Contains(cleaned, "..")
}

func InitLogger() {
	Log = log.New()
	Log.SetLevel(log.DebugLevel)

	if Config.ExportLog {
		logPath := Config.ExportLogPath
		if !safeLogPath(logPath) {
			fmt.Println("Warning: ExportLogPath contains path traversal, falling back to stderr")
			Log.SetOutput(os.Stderr)
			return
		}
		// Ensure parent directory exists
		_ = os.MkdirAll(filepath.Dir(logPath), 0755)
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
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
	mu.Lock()
	Config = newConfig
	mu.Unlock()
}

func SetSrvConfig(newConfig pservice.Services) {
	mu.Lock()
	Services = newConfig
	mu.Unlock()
}

func SetAuthConfig(newConfig auth.AuthStruct) {
	mu.Lock()
	Auth = newConfig
	mu.Unlock()
}

func LoadAllConfig() {
	var err error
	Path, err = os.Getwd()
	if err != nil {
		fmt.Println("Error getting working directory:", err)
		panic(err)
	}

	CheckConfigGlob()
	CheckConfigService()
	CheckConfigAuth()

	val, err := database.LoadConfigEntry("global")
	if err != nil {
		fmt.Println("Error loading global config:", err)
		panic(err)
	}
	var cfg config.ConfigStruct
	if err := json.Unmarshal([]byte(val), &cfg); err != nil {
		fmt.Println("Error parsing global config:", err)
		panic(err)
	}

	val, err = database.LoadConfigEntry("services")
	if err != nil {
		fmt.Println("Error loading services config:", err)
		panic(err)
	}
	var svcs pservice.Services
	if err := json.Unmarshal([]byte(val), &svcs); err != nil {
		fmt.Println("Error parsing services config:", err)
		panic(err)
	}

	val, err = database.LoadConfigEntry("auth")
	if err != nil {
		fmt.Println("Error loading auth config:", err)
		panic(err)
	}
	var authCfg auth.AuthStruct
	if err := json.Unmarshal([]byte(val), &authCfg); err != nil {
		fmt.Println("Error parsing auth config:", err)
		panic(err)
	}

	fmt.Println("Config loaded from database")
	SetSrvConfig(svcs)
	SetGlobConfig(cfg)
	SetAuthConfig(authCfg)
}

func SaveGlobalConfig() {
	mu.Lock()
	defer mu.Unlock()
	data, err := json.Marshal(Config)
	if err != nil {
		fmt.Println("Error marshaling global config:", err)
		panic(err)
	}
	if err := database.SaveConfigEntry("global", string(data)); err != nil {
		fmt.Println("Error saving global config:", err)
		panic(err)
	}
}

func SaveServiceConfig() {
	mu.Lock()
	defer mu.Unlock()
	data, err := json.Marshal(Services)
	if err != nil {
		fmt.Println("Error marshaling services config:", err)
		panic(err)
	}
	if err := database.SaveConfigEntry("services", string(data)); err != nil {
		fmt.Println("Error saving services config:", err)
		panic(err)
	}
}

func SaveAuthConfig() {
	mu.Lock()
	defer mu.Unlock()
	data, err := json.Marshal(Auth)
	if err != nil {
		fmt.Println("Error marshaling auth config:", err)
		panic(err)
	}
	if err := database.SaveConfigEntry("auth", string(data)); err != nil {
		fmt.Println("Error saving auth config:", err)
		panic(err)
	}
}
