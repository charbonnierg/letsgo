package letsgo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charbonnierg/letsgo/stores"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/net/idna"
)

// User configuration parsed from env
type UserConfig struct {
	Email                string
	Key                  crypto.PrivateKey
	CADirURL             string
	CADirKeyType         certcrypto.KeyType
	TermsOfServiceAgreed bool
	Domains              []string
	AuthToken            string
	DisableCP            bool
	DNSResolvers         []string
	DNSTimeout           time.Duration
}

// User type that implements acme.User
//
// Implements the following methods:
//   - User.GetEmail()
//   - User.GetRegistration()
//   - User.GetPrivateKey()
type User struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}
func (u User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// Sanitize a domain name.
//
// The return name can safely be used as a filename.
func SanitizedDomain(domain string) (string, error) {
	safe, err := idna.ToASCII(strings.ReplaceAll(domain, "*", "_"))
	if err != nil {
		return safe, err
	}
	return safe, nil
}

// Get an environment variable
//
// A fallback value must be provided as argument.
// If environment variable is not defined, fallback value
// is used instead.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// Check if a file exists.
//
// Return `true` when file exists, else `false`.
func fileExists(path string) bool {
	// Check if a file exists
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

// Get or create an account private key.
//
// When given filepath exists, this function attempts to
// load a private key from file content.
// If an error is encountered while loading the key, this
// function aso returns the error.
// If filepath does not exist, a new key if generated and
// written to filepath before function returns.
func getOrCreateAccountKey(path string) (crypto.PrivateKey, error) {
	if fileExists(path) {
		pemKey, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		keyBlock, _ := pem.Decode(pemKey)

		switch keyBlock.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(keyBlock.Bytes)
		}

		return nil, errors.New("unknown private key type")
	}
	// Create a private key. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyFile, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(keyFile, pemKey)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Get certificate key type from environment variable.
//
// If key type is not supported, this function returns an error.
func getKeyType(fallback string) (certcrypto.KeyType, error) {
	keyType := getEnv("LE_CRT_KEY_TYPE", fallback)
	switch keyType {
	case "RSA2048":
		return certcrypto.RSA2048, nil
	case "RSA4096":
		return certcrypto.RSA4096, nil
	case "RSA8192":
		return certcrypto.RSA8192, nil
	default:
		return certcrypto.RSA2048, errors.New("Invalid key type. Allowed values are 'RSA2048', 'RSA4096' and 'RSA8192'.")
	}
}

// Get auth token required to interact with DNS provider.
//
// Auth token can be provided through 3 different ways:
// - Using `DO_AUTH_TOKEN_FILE` environment variable
// - Using `DO_AUTH_TOKEN` environment variable
// - Using `DO_AUTH_TOKEN_VAULT` (and optionally `DO_AUTH_TOKEN_SECRET`) environment variable
func getAuthToken(storage stores.Stores) (string, error) {
	// read from DO_AUTH_TOKEN env variable
	token := getEnv("DO_AUTH_TOKEN", "")
	// Check that token is not empty
	if token != "" {
		envstore := storage.GetEnvStore()
		return envstore.GetToken()
	}
	// Check if token should be fetched from file
	tokenFile := getEnv("DO_AUTH_TOKEN_FILE", "")
	if tokenFile != "" {
		filestore := storage.GetFileStore()
		return filestore.GetToken()
	}
	// Check if token should be fetched from vault
	tokenVault := getEnv("DO_AUTH_TOKEN_VAULT", "")
	if tokenVault != "" {
		keyvault := storage.GetKeyvaultStore()
		return keyvault.GetToken()
	}
	// Return an error
	return "", errors.New("Invalid digital ocean token. Use one of 'DO_AUTH_TOKEN_VAULT', 'DO_AUTH_TOKEN_FILE' or 'DO_AUTH_TOKEN' env variable.")
}

func getCADir() string {
	// Check if token should be fetched from file
	caEnv := getEnv("CA_DIR", "STAGING")
	// Return URL associated with environment
	switch strings.ToUpper(caEnv) {
	case "PRODUCTION":
		return "https://acme-v02.api.letsencrypt.org/directory"
	case "STAGING":
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	case "TEST":
		return "http://localhost:4000/directory"
	default:
		return caEnv
	}
}

func NewConfig(storage stores.Stores) (UserConfig, error) {
	// Define key type
	keyType, err := getKeyType("RSA2048")
	if err != nil {
		return UserConfig{}, err
	}
	// Define boolean indicating whether user agrees to TOS
	tosAgreed, err := strconv.ParseBool(getEnv("LE_TOS_AGREED", "true"))
	if err != nil {
		return UserConfig{}, err
	}
	// Define list of domain names
	domains := strings.Split(getEnv("DOMAINS", ""), ",")
	if len(domains) == 0 {
		return UserConfig{}, errors.New("A comma-separated list of domain names must be provided through DOMAINS environment variable")
	}
	if len(domains) == 1 && (domains[0] == "") {
		return UserConfig{}, errors.New("A comma-separated list of domain names must be provided through DOMAINS environment variable")
	}
	// Define account email
	email := getEnv("ACCOUNT_EMAIL", "")
	if email == "" {
		return UserConfig{}, errors.New("An email must be provided through ACCOUNT_EMAIL environment variable")
	}
	// Fetch or create account private key (when key is created, it is also written to file)
	key, err := getOrCreateAccountKey(getEnv("ACCOUNT_KEY_FILE", "./account.key"))
	if err != nil {
		return UserConfig{}, err
	}
	// Define CA directory to which client will request certificates
	caDir := getCADir()
	// Fetch auth token
	token, err := getAuthToken(storage)
	if err != nil {
		return UserConfig{}, err
	}
	// Get resolvers
	rawDNSResolvers := getEnv("DNS_RESOLVERS", "")
	dnsResolvers := []string{}
	if rawDNSResolvers != "" {
		dnsResolvers = strings.Split(rawDNSResolvers, ",")
	}
	// Get complete duration challenge option
	disableCPOption, err := strconv.ParseBool(getEnv("DISABLE_CP", "true"))
	if err != nil {
		return UserConfig{}, err
	}
	// Get DNS timeout options
	dnsTimeout, err := strconv.ParseFloat(getEnv("DNS_TIMEOUT", "0"), 32)
	if err != nil {
		return UserConfig{}, err
	}
	// Return complete user config
	return UserConfig{
		Email:                email,
		Key:                  key,
		CADirURL:             caDir,
		CADirKeyType:         keyType,
		TermsOfServiceAgreed: tosAgreed,
		Domains:              domains,
		AuthToken:            token,
		DNSResolvers:         dnsResolvers,
		DisableCP:            disableCPOption,
		DNSTimeout:           time.Duration(dnsTimeout) * time.Second,
	}, nil
}

func NewClient(config UserConfig, user *User) lego.Client {
	// Generate config for user
	legoConfig := lego.NewConfig(user)
	// The ACME URL for our ACME v2 staging environment
	legoConfig.CADirURL = config.CADirURL
	legoConfig.Certificate.KeyType = config.CADirKeyType
	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		log.Fatal(err)
	}
	providerConfig := digitalocean.NewDefaultConfig()
	providerConfig.AuthToken = config.AuthToken
	// Use a propagation timeout of 1 minute and 30 seconds
	providerConfig.PropagationTimeout = time.Duration(time.Second * 90)
	// Create DNS provider
	dnsProvider, err := digitalocean.NewDNSProviderConfig(providerConfig)
	if err != nil {
		log.Fatal(err)
	}
	// Use DNS provider
	err = client.Challenge.SetDNS01Provider(dnsProvider,
		dns01.CondOption(
			len(config.DNSResolvers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(config.DNSResolvers)),
		),
		dns01.CondOption(config.DisableCP,
			dns01.DisableCompletePropagationRequirement(),
		),
		dns01.CondOption(config.DNSTimeout > 0,
			dns01.AddDNSTimeout(config.DNSTimeout),
		),
	)
	if err != nil {
		log.Fatal(err)
	}
	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	user.Registration = reg
	// Return client
	return *client
}

func main() {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	// Generate config for user
	config, err := NewConfig(stores.NewStores())
	if err != nil {
		log.Fatal(err)
	}
	// Generate user
	user := User{
		Email: config.Email,
		Key:   config.Key,
	}
	// Generate lego client
	client := NewClient(config, &user)
	// Gather request
	request := certificate.ObtainRequest{
		Domains: config.Domains,
		Bundle:  true,
	}
	// Send request
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}
	// Save certificates and key under domain name
	domain, err := SanitizedDomain(certificates.Domain)
	if err != nil {
		log.Fatal(err)
	}
	certPath := filepath.Join(cwd, domain+".crt")
	keyPath := filepath.Join(cwd, domain+".key")
	issuerPath := filepath.Join(cwd, domain+".issuer.crt")
	err = os.WriteFile(certPath, certificates.Certificate, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(keyPath, certificates.PrivateKey, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(issuerPath, certificates.IssuerCertificate, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	// ... all done.
}
