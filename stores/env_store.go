package stores

import (
	"errors"
	"fmt"
	"os"

	"github.com/charbonnierg/letsgo/constants"
)

// Environment variable store implementation to fetch token from environment variable
type EnvStore struct{}

func (s *EnvStore) GetToken() (string, error) {
	if token, ok := os.LookupEnv(constants.DNS_AUTH_TOKEN); ok {
		if token == "" {
			return "", errors.New(fmt.Sprintf("Empty %s environment variable", constants.DNS_AUTH_TOKEN))
		}
		return token, nil
	}
	return "", errors.New(fmt.Sprintf("Missing %s environment variable", constants.DNS_AUTH_TOKEN))
}
