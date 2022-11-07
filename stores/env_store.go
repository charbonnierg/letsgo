package stores

import (
	"errors"
	"os"
)

type EnvStore struct{}

func (s *EnvStore) GetToken() (string, error) {
	if token, ok := os.LookupEnv("DO_AUTH_TOKEN"); ok {
		if token == "" {
			return "", errors.New("Empty DO_AUTH_TOKEN")
		}
		return token, nil
	}
	return "", errors.New("Missing DO_AUTH_TOKEN environment variable")
}
