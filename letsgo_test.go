package letsgo

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/charbonnierg/letsgo/stores"
	"github.com/go-acme/lego/v4/certcrypto"
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
	token, err := getAuthToken(stores.NewStores())
	if token != "" || err == nil {
		t.Errorf(fmt.Sprintf("Expected empty token and error, got token: %s", token))
	}
	err_want := "Invalid digital ocean token. Use one of 'DO_AUTH_TOKEN_VAULT', 'DO_AUTH_TOKEN_FILE' or 'DO_AUTH_TOKEN' env variable."
	err_got := err.Error()
	if err_want != err_got {
		t.Errorf(fmt.Sprintf("Invalid error message. Want: %s. Got %s.", err_want, err_got))
	}
}

func TestGetAuthTokenFromValue(t *testing.T) {
	want := "XXXXX"
	t.Setenv("DO_AUTH_TOKEN", want)
	token, err := getAuthToken(stores.NewStores())
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
	t.Setenv("DO_AUTH_TOKEN_FILE", tokenFile)
	token, err := getAuthToken(stores.NewStores())
	if err != nil {
		t.Errorf(err.Error())
	}
	if token != want {
		t.Errorf(fmt.Sprintf("Bad token. Want: %s. Got: %s", want, token))
	}
}

func TestGetAuthTokenFromKeyVault(t *testing.T) {
	want := "XXXXX"
	t.Setenv("DO_AUTH_TOKEN_VAULT", "test-vault")
	storage := stores.NewStores()
	storage.Keyvault = &stores.KeyVaultMock{Token: want}
	token, err := getAuthToken(storage)
	if err != nil {
		t.Errorf(err.Error())
	}
	if token != want {
		t.Errorf(fmt.Sprintf("Bad token. Want: %s. Got: %s", want, token))
	}
}
