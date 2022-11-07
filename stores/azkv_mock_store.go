package stores

// Keyvault mock implementation to return token found in mock instance
type KeyVaultMock struct {
	Token string
}

func (k *KeyVaultMock) GetToken() (string, error) {
	_, err := GetVaultURI()
	if err != nil {
		return "", err
	}
	_, err = GetVaultSecretName()
	if err != nil {
		return "", err
	}
	return k.Token, nil
}
