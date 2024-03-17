package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/adrian-lorenz/noxway/global"
	"log"
	"os"
	"path/filepath"

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

// RetriveCert retrieves and saves a certificate for the given domain and email.
//
// Parameters: domain string, mail string
// Return type: error
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

	cPath := filepath.Join(Path, "noxway", "certs", domain+".pem")
	kPath := filepath.Join(Path, "noxway", "certs", domain+".key")
	configFile := filepath.Join(Path, "noxway", "certs", domain+".json")
	//pkey := filepath.Join(Path, "noxway", "certs", domain+  ".pkey")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	myUserA := myUser{
		Email: mail,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUserA)
	//save config to file

	configBytes, err := json.Marshal(privateKey)
	if err != nil {
		global.Log.Errorln("Failed to serialize config:", err)
		return err
	}

	err = os.WriteFile(configFile, configBytes, 0644)
	if err != nil {
		global.Log.Errorln("Failed to write config file:", err)
		return err
	}
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
