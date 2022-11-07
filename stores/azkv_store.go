package stores

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/charbonnierg/letsgo/constants"
)

// Azure Keyvault store implementation to fetch token from azure keyvault
type KeyVault struct{}

func (k *KeyVault) GetToken() (string, error) {
	vaultURI, err := GetVaultURI()
	if err != nil {
		return "", err
	}
	secretName, err := GetVaultSecretName()
	if err != nil {
		return "", err
	}
	// Generate azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", err
	}
	// Create client to interact with key vault
	client := azsecrets.NewClient(vaultURI, cred, nil)
	// Fetch the token
	resp, err := client.GetSecret(context.TODO(), secretName, "", nil)
	if err != nil {
		return "", err
	}
	// Return the token (secret value)
	return strings.TrimSuffix(*resp.Value, "\n"), nil
}

// Utils functions to fetch keyvault options
func GetVaultURI() (string, error) {
	tokenVault, ok := os.LookupEnv(constants.DNS_AUTH_TOKEN_VAULT)
	if ok {
		if tokenVault == "" {
			return "", errors.New(fmt.Sprintf("Empty %s environment variable", constants.DNS_AUTH_TOKEN_VAULT))
		}
	} else {
		return "", errors.New(fmt.Sprintf("Missing %s environment variable", constants.DNS_AUTH_TOKEN_VAULT))
	}
	if strings.HasPrefix(tokenVault, "https://") {
		return tokenVault, nil
	} else {
		return fmt.Sprintf("https://%s.vault.azure.net/", tokenVault), nil
	}
}

func GetVaultSecretName() (string, error) {
	tokenSecret, ok := os.LookupEnv(constants.DNS_AUTH_TOKEN_SECRET)
	if !ok {
		tokenSecret = "do-auth-token"
	}
	if tokenSecret == "" {
		return "", errors.New(fmt.Sprintf("Empty %s environment variable", constants.DNS_AUTH_TOKEN_SECRET))
	}
	return tokenSecret, nil
}
