package certs

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/adrian-lorenz/noxway/global"
	"github.com/adrian-lorenz/noxway/tools"
)

func CertExist(domain string) (string, string, error) {
	Path, err := os.Getwd()
	if err != nil {
		global.Log.Errorln("Failed to get current working directory:", err)
		return "", "", fmt.Errorf("failed to get current working directory: %v", err)
	}

	cPath := filepath.Join(Path, "certs", domain+".pem")
	kPath := filepath.Join(Path, "certs", domain+".key")

	_, err = os.Stat(cPath)
	if os.IsNotExist(err) {
		global.Log.Warningln("Certificate does not exist")
		return "", "", err
	}
	_, err = os.Stat(kPath)
	if os.IsNotExist(err) {
		global.Log.Errorln("Key does not exist")
		return "", "", err
	}
	global.Log.Infoln("Certificate and key exist")

	return cPath, kPath, nil
}

func CheckDNS(domain string) (bool, error) {
	extIP, err := tools.GetExtIP()
	if err != nil {
		global.Log.Errorln("Failed to get external IP:", err)
		return false, err
	}

	dnsIP, err := tools.GetDnsIP(domain)
	if err != nil {
		global.Log.Errorln("Failed to get DNS IP:", err)
		return false, err
	}
	global.Log.Infoln("External IP:", extIP, "DNS IP:", dnsIP)

	if extIP != dnsIP {
		global.Log.Errorln("External IP and DNS IP are not the same")
		return false, fmt.Errorf("external IP and DNS IP are mot the same")
	}
	return true, nil
}
