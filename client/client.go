package client

import (
	"crypto"
	"log"
	"time"

	"github.com/charbonnierg/letsgo/configuration"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/registration"
)

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

// Create a new client to request certificate
func NewClient(userConfig configuration.UserConfig) (lego.Client, error) {
	// Generate user
	user := &User{
		Email: userConfig.Email,
		Key:   userConfig.Key,
	}
	// Generate config for user
	legoConfig := lego.NewConfig(user)
	// The default URL is ACME v2 staging environment
	legoConfig.CADirURL = userConfig.CADirURL
	legoConfig.Certificate.KeyType = userConfig.CADirKeyType
	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return lego.Client{}, err
	}
	// Generate DigitalOcean provider configuration
	providerConfig := digitalocean.NewDefaultConfig()
	// Set auth token from user config
	providerConfig.AuthToken = userConfig.AuthToken
	// Use a propagation timeout of 1 minute and 30 seconds
	providerConfig.PropagationTimeout = time.Duration(time.Second * 90)
	// Create DigitalOcean DNS Provider
	dnsProvider, err := digitalocean.NewDNSProviderConfig(providerConfig)
	if err != nil {
		return lego.Client{}, err
	}
	// Use DNS provider with some conditional options
	err = client.Challenge.SetDNS01Provider(dnsProvider,
		dns01.CondOption(
			len(userConfig.DNSResolvers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(userConfig.DNSResolvers)),
		),
		dns01.CondOption(userConfig.DisableCP,
			dns01.DisableCompletePropagationRequirement(),
		),
		dns01.CondOption(userConfig.DNSTimeout > 0,
			dns01.AddDNSTimeout(userConfig.DNSTimeout),
		),
	)
	if err != nil {
		return lego.Client{}, err
	}
	// Perform use registration
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	user.Registration = reg
	// Return client
	return *client, err
}

// Request certificate according to user configuration
func RequestCertificate(config configuration.UserConfig) (*certificate.Resource, error) {
	// Generate lego client
	client, err := NewClient(config)
	if err != nil {
		return &certificate.Resource{}, err
	}
	// Gather request
	request := certificate.ObtainRequest{
		Domains: config.Domains,
		Bundle:  true,
	}
	// Send request
	return client.Certificate.Obtain(request)
}
