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
	// Create stores
	stores := stores.DefaultStores()
	// Generate config for user
	config, err := configuration.NewUserConfig(&stores)
	if err != nil {
		log.Fatal(err)
	}
	// Generate certificate
	resource, err := client.RequestCertificate(*config)
	if err != nil {
		log.Fatal(err)
	}
	// Write certificate to file
	certPath := filepath.Join(config.OutputDirectory, config.Filename+".crt")
	keyPath := filepath.Join(config.OutputDirectory, config.Filename+".key")
	issuerPath := filepath.Join(config.OutputDirectory, config.Filename+".issuer.crt")
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
