package stores

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/charbonnierg/letsgo/constants"
)

// File store implementation to fetch token from file
type FileStore struct{}

func (s *FileStore) GetToken() (string, error) {
	if tokenFile, ok := os.LookupEnv(constants.DNS_AUTH_TOKEN_FILE); ok {
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
			return "", errors.New(fmt.Sprintf("Invalid token found in %s file", constants.DNS_AUTH_TOKEN_FILE))
		}
		// Return token
		return token, nil
	}
	// Return empty token, but without error
	return "", errors.New(fmt.Sprintf("Missing %s environment variable", constants.DNS_AUTH_TOKEN_FILE))
}
