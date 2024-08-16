package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/adrian-lorenz/noxway/global"

	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge/http01"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
)

type myUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *myUser) GetEmail() string {
	return u.Email
}
func (u myUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *myUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func savePrivateKeyToFile(key *ecdsa.PrivateKey, file string) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(file, keyPEM, 0600)
}

func loadPrivateKeyFromFile(file string) (*ecdsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// RetriveCert retrieves and saves a certificate for the given domain and email.
func RetriveCert(domain, mail string) error {
	if domain == "" {
		return fmt.Errorf("domain is empty")
	}

	if mail == "" {
		return fmt.Errorf("mail is empty")
	}

	Path, err := os.Getwd()
	if err != nil {
		fmt.Println("Fehler beim Ermitteln des aktuellen Verzeichnisses:", err)
		panic(err)
	}

	cPath := filepath.Join(Path, "certs", domain+".pem")
	kPath := filepath.Join(Path, "certs", domain+".key")
	// prüfen on Zertifikat bereits vorhanden
	if _, err := os.Stat(cPath); err == nil {
		global.Log.Infoln("Zertifikat bereits vorhanden")
		days, errC := GetCertDays(cPath)
		if errC != nil {
			return errC
		}
		global.Log.Infoln("Verbleibende Tage:", days)
		if days > 10 {
			global.Log.Infoln("Zertifikat ist noch gültig")
			return nil
		}
	}

	var privateKey *ecdsa.PrivateKey
	if _, err := os.Stat(kPath); err == nil {
		// load private key from file
		global.Log.Infoln("Loading priv key from file")
		privateKey, err = loadPrivateKeyFromFile(kPath)
		if err != nil {
			global.Log.Errorln("Failed to read private key file:", err)
			return err
		}
	} else {
		global.Log.Infoln("Gen priv key")
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		err = savePrivateKeyToFile(privateKey, kPath)
		if err != nil {
			global.Log.Errorln("Failed to save private key to file:", err)
			return err
		}
	}

	myUserA := myUser{
		Email: mail,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUserA)

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
	if err != nil {
		return err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	myUserA.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}
	log.Printf("Zertifikat erfolgreich erhalten für %s", domain)

	err = os.WriteFile(kPath, certificates.PrivateKey, 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(cPath, certificates.Certificate, 0644)
	if err != nil {
		return err
	}

	log.Printf("Zertifikat und privater Schlüssel erfolgreich gespeichert für %s", domain)

	return nil
}
