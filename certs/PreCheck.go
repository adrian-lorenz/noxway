package certs

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/adrian-lorenz/noxway/global"
	"github.com/adrian-lorenz/noxway/tools"
)

func CertPreCheck(domain string) (bool, error) {
	Path, err := os.Getwd()
	if err != nil {
		global.Log.Errorln("Failed to get current working directory:", err)
		return false, fmt.Errorf("failed to get current working directory: %v", err)
	}

	cPath := filepath.Join(Path, "noxway", "certs", domain+".pem")
	kPath := filepath.Join(Path, "noxway", "certs", domain+".key")

	_, err = os.Stat(cPath)
	if os.IsNotExist(err) {
		global.Log.Warningln("Certificate does not exist")
		return false, err
	}
	_, err = os.Stat(kPath)
	if os.IsNotExist(err) {
		global.Log.Errorln("Key does not exist")
		return false, err
	}
	global.Log.Infoln("Certificate and key exist")

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
		global.Log.Errorln("External IP and DNS IP are the same")
		return false, fmt.Errorf("external IP and DNS IP are the same")
	}

	//daysleft

	daysleft, err := GetCertDays(cPath)
	if err != nil {
		global.Log.Errorln("Failed to get certificate days left:", err)
		return false, err
	}
	if daysleft < 10 {
		global.Log.Errorln("Certificate is less than 30 days left")
		return false, fmt.Errorf("certificate is less than 30 days left")
	}
	global.Log.Infoln("Certificate days left:", daysleft)

	return true, nil
}
