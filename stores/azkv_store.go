package stores

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

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

func GetVaultURI() (string, error) {
	tokenVault, ok := os.LookupEnv("DO_AUTH_TOKEN_VAULT")
	if ok {
		if tokenVault == "" {
			return "", errors.New("Empty DO_AUTH_TOKEN_VAULT environment variable")
		}
	} else {
		return "", errors.New("Missing DO_AUTH_TOKEN_VAULT environment variable")
	}
	if strings.HasPrefix(tokenVault, "https://") {
		return tokenVault, nil
	} else {
		return fmt.Sprintf("https://%s.vault.azure.net/", tokenVault), nil
	}
}

func GetVaultSecretName() (string, error) {
	tokenSecret, ok := os.LookupEnv("DO_AUTH_TOKEN_SECRET")
	if !ok {
		tokenSecret = "do-auth-token"
	}
	if tokenSecret == "" {
		return "", errors.New("Empty DO_AUTH_TOKEN_SECRET environment variable")
	}
	return tokenSecret, nil
}
