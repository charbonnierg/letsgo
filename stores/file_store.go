package stores

import (
	"errors"
	"io/ioutil"
	"os"
	"strings"
)

type FileStore struct{}

func (s *FileStore) GetToken() (string, error) {
	if tokenFile, ok := os.LookupEnv("DO_AUTH_TOKEN_FILE"); ok {
		// Read file
		rawToken, err := ioutil.ReadFile(tokenFile)
		// Or return an error
		if err != nil {
			return "", err
		}
		// Convert to string and strip line break
		token := strings.TrimSuffix(string(rawToken), "\n")
		// Check that token is not empty
		if token == "" {
			return "", errors.New("Invalid token found in DO_AUTH_TOKEN_FILE file")
		}
		// Return token
		return token, nil
	}
	// Return empty token, but without error
	return "", errors.New("Missing DO_AUTH_TOKEN_FILE environment variable")
}
