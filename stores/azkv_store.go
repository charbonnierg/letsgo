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
	if tokenVault, ok := os.LookupEnv("DO_AUTH_TOKEN_VAULT"); ok {
		if tokenVault == "" {
			return "", errors.New("Empty DO_AUTH_TOKEN_VAULT environment variable")
		}
		tokenSecret, ok := os.LookupEnv("DO_AUTH_TOKEN_SECRET")
		if !ok {
			tokenSecret = "do-auth-token"
		}
		// Generate azure credentials
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return "", err
		}
		// Fetch vault URI
		vaultUri := ""
		if strings.HasPrefix(tokenVault, "https://") {
			vaultUri = tokenVault
		} else {
			vaultUri = fmt.Sprintf("https://%s.vault.azure.net/", tokenVault)
		}
		// Create client to interact with key vault
		client := azsecrets.NewClient(vaultUri, cred, nil)
		// Fetch the token
		resp, err := client.GetSecret(context.TODO(), tokenSecret, "", nil)
		if err != nil {
			return "", err
		}
		// Return the token (secret value)
		return strings.TrimSuffix(*resp.Value, "\n"), nil
	}
	return "", errors.New("Missing DO_AUTH_TOKEN_VAULT environment variable")
}
