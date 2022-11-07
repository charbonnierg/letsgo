package configuration

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/charbonnierg/letsgo/constants"
	"github.com/charbonnierg/letsgo/stores"
	"github.com/go-acme/lego/v4/certcrypto"
	"golang.org/x/exp/slices"
)

// Test that domain names are sanitized into valid filenames
func TestSanitizeDomainWithWildcard(t *testing.T) {
	got, err := SanitizedDomain("*.example.com")
	if err != nil {
		t.Errorf(err.Error())
	}
	want := "_.example.com"
	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

// Test that domain names are sanitized into valid filenames
func TestSanitizeDomainSimple(t *testing.T) {
	got, err := SanitizedDomain("example.com")
	if err != nil {
		t.Errorf(err.Error())
	}
	want := "example.com"
	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

// Test that getEnv funcion can return the fallback value
func TestGetEnvReturnsFallback(t *testing.T) {
	got := getEnv("test-var", "default")
	want := "default"
	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

// Test that getEnv function can return the value from environment variable
func TestGetEnvReturnsValue(t *testing.T) {
	t.Setenv("test-var", "value")
	got := getEnv("test-var", "default")
	want := "value"
	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

// Test that fileExists function behaves as expected
func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.txt")
	if fileExists(file) != false {
		t.Errorf("File does not exist but fileExists returned true")
	}
	os.WriteFile(file, []byte{}, 0o600)
	if fileExists(file) != true {
		t.Errorf("File exists but fileExists returned false")
	}
}

// Test that getOrCreateAccountKey function behaves as expected
func TestGetOrCreateAccountKey(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "account.key")
	key, err := getOrCreateAccountKey(file)
	if err != nil {
		t.Errorf(err.Error())
	}
	secondKey, err := getOrCreateAccountKey(file)
	if bytes.Equal(certcrypto.PEMBlock(key).Bytes, certcrypto.PEMBlock(secondKey).Bytes) != true {
		t.Errorf("getOrCreateAccountKey did not load existing key but created a new key instead")
	}
	os.Remove(file)
	thirdKey, err := getOrCreateAccountKey(file)
	if bytes.Equal(certcrypto.PEMBlock(key).Bytes, certcrypto.PEMBlock(thirdKey).Bytes) != false {
		t.Errorf("getOrCreateAccountKey did not create a new key")
	}
}

// Test that getKeyType function can return the fallback value
func TestGetKeyTypeFallback(t *testing.T) {
	typ, err := getKeyType("RSA2048")
	if err != nil {
		t.Errorf(err.Error())
	}
	if typ != certcrypto.RSA2048 {
		t.Errorf(fmt.Sprintf("Expected RSA2048 but got %s", typ))
	}
}

// Test that getKeyType function can return the value from environment variable
func TestGetKeyTypeFromEnv(t *testing.T) {
	t.Setenv("LE_CRT_KEY_TYPE", "RSA4096")
	typ, err := getKeyType("RSA2048")
	if err != nil {
		t.Errorf(err.Error())
	}
	if typ != certcrypto.RSA4096 {
		t.Errorf(fmt.Sprintf("Expected RSA4096 but got %s", typ))
	}
}

// Test that getKeyType function returns an error with an error message if key type is invalid
func TestGetKeyTypeInvalid(t *testing.T) {
	t.Setenv("LE_CRT_KEY_TYPE", "A")
	keyType := getEnv("LE_CRT_KEY_TYPE", "RSA2048")
	if keyType != "A" {
		t.Errorf(fmt.Sprintf("Expected A but received %s", keyType))
	}
	typ, err := getKeyType("RSA2048")
	if err == nil {
		t.Errorf(fmt.Sprintf("Expected an error but got %s", typ))
	}
	got := err.Error()
	want := "Invalid key type. Allowed values are 'RSA2048', 'RSA4096' and 'RSA8192'."
	if got != want {
		t.Errorf(fmt.Sprintf("Bad error message. Want: %s. Got: %s", want, got))
	}
}

// Test that getCADir function behaves as expected
func TestGetCADir(t *testing.T) {
	want := "https://acme-staging-v02.api.letsencrypt.org/directory"
	got := getCADir()
	if want != got {
		t.Errorf("Bad default value. Want: %s. Got: %s", want, got)
	}

	t.Setenv("CA_DIR", "staging")
	want = "https://acme-staging-v02.api.letsencrypt.org/directory"
	got = getCADir()
	if want != got {
		t.Errorf("Bad default value. Want: %s. Got: %s", want, got)
	}

	t.Setenv("CA_DIR", "PRODUCTION")
	want = "https://acme-v02.api.letsencrypt.org/directory"
	got = getCADir()
	if want != got {
		t.Errorf("Bad default value. Want: %s. Got: %s", want, got)
	}

	t.Setenv("CA_DIR", "production")
	want = "https://acme-v02.api.letsencrypt.org/directory"
	got = getCADir()
	if want != got {
		t.Errorf("Bad default value. Want: %s. Got: %s", want, got)
	}

	t.Setenv("CA_DIR", "TEST")
	want = "http://localhost:4000/directory"
	got = getCADir()
	if want != got {
		t.Errorf("Bad default value. Want: %s. Got: %s", want, got)
	}

	t.Setenv("CA_DIR", "test")
	want = "http://localhost:4000/directory"
	got = getCADir()
	if want != got {
		t.Errorf("Bad default value. Want: %s. Got: %s", want, got)
	}

	t.Setenv("CA_DIR", "http://somewhere:4000/directory")
	want = "http://somewhere:4000/directory"
	got = getCADir()
	if want != got {
		t.Errorf("Bad default value. Want: %s. Got: %s", want, got)
	}
}

// Test that getAuthToken behaves as expected
func TestGetAuthTokenFail(t *testing.T) {
	token, err := getAuthToken(stores.DefaultStores())
	if token != "" || err == nil {
		t.Errorf(fmt.Sprintf("Expected empty token and error, got token: %s", token))
	}
	err_want := "Invalid DNS auth token. Use one of 'DNS_AUTH_TOKEN_VAULT', 'DNS_AUTH_TOKEN_FILE' or 'DNS_AUTH_TOKEN' env variable"
	err_got := err.Error()
	if err_want != err_got {
		t.Errorf(fmt.Sprintf("Invalid error message. Want: %s. Got %s.", err_want, err_got))
	}
}

func TestGetAuthTokenFromValue(t *testing.T) {
	want := "XXXXX"
	t.Setenv("DNS_AUTH_TOKEN", want)
	token, err := getAuthToken(stores.DefaultStores())
	if err != nil {
		t.Errorf(err.Error())
	}
	if token != want {
		t.Errorf(fmt.Sprintf("Bad token. Want: %s. Got: %s", want, token))
	}
}

func TestGetAuthTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	want := "XXXXX"
	data := []byte(want)
	os.WriteFile(tokenFile, data, 0o600)
	t.Setenv("DNS_AUTH_TOKEN_FILE", tokenFile)
	token, err := getAuthToken(stores.DefaultStores())
	if err != nil {
		t.Errorf(err.Error())
	}
	if token != want {
		t.Errorf(fmt.Sprintf("Bad token. Want: %s. Got: %s", want, token))
	}
}

func TestGetAuthTokenFromKeyVault(t *testing.T) {
	want := "XXXXX"
	t.Setenv("DNS_AUTH_TOKEN_VAULT", "test-vault")
	storage := stores.DefaultStores()
	storage.Keyvault = &stores.KeyVaultMock{Token: want}
	token, err := getAuthToken(storage)
	if err != nil {
		t.Errorf(err.Error())
	}
	if token != want {
		t.Errorf(fmt.Sprintf("Bad token. Want: %s. Got: %s", want, token))
	}
}

func TestNewUserConfigFromEnv(t *testing.T) {
	stores := stores.DefaultStores()
	_, err := NewUserConfigFromEnv(stores)
	err_want := "A comma-separated list of domain names must be provided through DOMAINS environment variable"
	if err == nil {
		t.Fatalf("Expected error. Want: %s. Got: nil", err_want)
	}
	err_got := err.Error()
	if err_got != err_want {
		t.Fatalf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}

	t.Setenv("DOMAINS", "example.com")
	_, err = NewUserConfigFromEnv(stores)
	err_want = "An email must be provided through ACCOUNT_EMAIL environment variable"
	if err == nil {
		t.Fatalf("Expected error. Want: %s. Got: nil", err_want)
	}
	err_got = err.Error()
	if err_got != err_want {
		t.Fatalf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}

	t.Setenv("ACCOUNT_EMAIL", "support@example.com")
	_, err = NewUserConfigFromEnv(stores)
	err_want = "Invalid DNS auth token. Use one of 'DNS_AUTH_TOKEN_VAULT', 'DNS_AUTH_TOKEN_FILE' or 'DNS_AUTH_TOKEN' env variable"
	if err == nil {
		t.Fatalf("Expected error. Want: %s. Got: nil", err_want)
	}
	err_got = err.Error()
	if err_got != err_want {
		t.Fatalf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}
	want_token := "XXXXX"
	t.Setenv("DNS_AUTH_TOKEN", want_token)
	config, err := NewUserConfigFromEnv(stores)

	want_domains := []string{"example.com"}
	if !slices.Equal(config.Domains, want_domains) {
		t.Fatalf("Bad domain. Want: %s. Got: %s", config.Domains, want_domains)
	}
	if config.AuthToken != want_token {
		t.Fatalf(
			"Bad token. Want: %s. Got: %s", want_token, config.AuthToken,
		)
	}

	want_resolvers := []string{"1.1.1.1:53"}
	t.Setenv("DNS_RESOLVERS", want_resolvers[0])
	config, err = NewUserConfigFromEnv(stores)
	if !slices.Equal(config.DNSResolvers, want_resolvers) {
		t.Fatalf("Bad resolvers. Want: %s. Got: %s", want_resolvers, config.DNSResolvers)
	}

	want_timeout := 12.0
	t.Setenv("DNS_TIMEOUT", fmt.Sprintf("%f", want_timeout))
	config, err = NewUserConfigFromEnv(stores)
	if config.DNSTimeout != time.Second*time.Duration(want_timeout) {
		t.Fatalf("Bad resolvers. Want: %s. Got: %s", time.Second*time.Duration(want_timeout), config.DNSTimeout)
	}

	t.Setenv("DISABLE_CP", "false")
	config, err = NewUserConfigFromEnv(stores)
	if config.DisableCP {
		t.Fatalf("Bad DisableCP option. Want: false. Got: true")
	}

	t.Setenv("DISABLE_CP", "true")
	config, err = NewUserConfigFromEnv(stores)
	if !config.DisableCP {
		t.Fatalf("Bad DisableCP option. Want: true. Got: false")
	}

	t.Setenv(constants.LE_TOS_AGREED, "false")
	err_want = "It is mandatory to agree to Let's Encrypt Term of Usage through LE_TOS_AGREED environment variable"
	_, err = NewUserConfigFromEnv(stores)
	if err == nil {
		t.Fatalf("Expected error. Want: %s. Got: nil", err_want)
	}
	err_got = err.Error()
	if err_got != err_want {
		t.Fatalf("Bad error. Want: %s. Got: %s", err_want, err_got)
	}
}
