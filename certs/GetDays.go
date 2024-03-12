package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

func GetCertDays(path string) (int, error) {

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return 0, fmt.Errorf("certificate does not exist")
	}

	pemData, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read certificate: %v", err)
	}

	// PEM-Inhalt parsen
	block, _ := pem.Decode(pemData)
	if block == nil {
		return 0, fmt.Errorf("failed to decode certificate PEM")
	}

	// Zertifikat aus dem PEM-Block parsen
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Verbleibende Tage berechnen
	now := time.Now()
	duration := cert.NotAfter.Sub(now)
	daysRemaining := int(duration.Hours() / 24)

	return daysRemaining, nil

}
