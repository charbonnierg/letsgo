package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/charbonnierg/letsgo/client"
	"github.com/charbonnierg/letsgo/configuration"
	"github.com/charbonnierg/letsgo/stores"
)

func main() {
	// Get current working directory
	cwd, err := os.Getwd()
	// Create stores
	stores := stores.NewStores()
	// Generate config for user
	config, err := configuration.NewUserConfigFromEnv(stores)
	if err != nil {
		log.Fatal(err)
	}
	// Generate certificate
	resource, err := client.RequestCertificate(config)
	if err != nil {
		log.Fatal(err)
	}
	// Write certificate to file
	certPath := filepath.Join(cwd, config.Alias+".crt")
	keyPath := filepath.Join(cwd, config.Alias+".key")
	issuerPath := filepath.Join(cwd, config.Alias+".issuer.crt")
	err = os.WriteFile(certPath, resource.Certificate, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(keyPath, resource.PrivateKey, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(issuerPath, resource.IssuerCertificate, 0o600)
	if err != nil {
		log.Fatal(err)
	}
}
