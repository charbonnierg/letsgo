package stores

import (
	"errors"
	"os"
)

type KeyVaultMock struct {
	Token string
}

func (k *KeyVaultMock) GetToken() (string, error) {
	if tokenVault, ok := os.LookupEnv("DO_AUTH_TOKEN_VAULT"); ok {
		if tokenVault == "" {
			return "", errors.New("Empty DO_AUTH_TOKEN_VAULT environment variable")
		}
		return k.Token, nil
	}
	return "", errors.New("Missing DO_AUTH_TOKEN_VAULT environment variable")
}
