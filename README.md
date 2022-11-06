# Custom Let's Encrypt TLS issuer

The goal of this project is to generate a binary as small as possible, which can generate valid certificates
issued by Let's Encrypt, while fetching necessary tokens from a remote keystore.

> The current size of the built executable is approximately `12.87Mb`, while the `lego` CLI is `34Mb` and does not include Azure Key Vault integration.


This library is designed to work only with DNS-01 challenges, using Digital Ocean provider. If we use another DNS provider in the project, we might update this tool accordingly.

## Configuration

### DNS Provider authentication

The token used to authenticate against Digital Ocean API (to update DNS records) can be specified through 3 different ways:

- `DO_AUTH_TOKEN_VAULT`: Name of an Azure Keyvault or URL pointing to an Azure Key Vault.

> When `DO_AUTH_TOKEN_VAULT` is specified, the name of the secret holding the API token can also be configured using `DO_AUTH_TOKEN_SECRET` environment variable. By default secret name is `do-auth-token`.

- `DO_AUTH_TOKEN_FILE`: A path to a file holding the API token.
- `DO_AUTH_TOKEN`: The API token.


### Domains configuration

Domains for which certificate should be generated can be specifeid through environment variable:

- `DOMAINS`: A comma-separated list of domains for which certificate should be valid.

### Let's Encrypt Account configuration

Let's Encrypt certificates are requested for an account. In order to generate certificates for a known account, environment variables can be used to configure account information:

- `ACCOUNT_EMAIL`: Email for which certificates are issued.

- `ACCOUNT_KEY_FILE` *(optional)*: Path to a file holding account private key. Default to `./account.key`.

- `LE_TOS_AGREED` *(optional)*: Whether user agrees to Let's Encrypt terms of usage or not. Default to `true`.

### CA Directory configuration

By default, certificates are issued by [Let's Encrypt Staging Environment Certificate Authorities](https://letsencrypt.org/docs/staging-environment/), but CA directory can be configured through environment variables:

- `CA_DIR` *(optional)*: URL pointing to CA directory. Default to `STAGING` which uses `https://acme-staging-v02.api.letsencrypt.org/directory`. Allowed values are `PRODUCTION`, `STAGING`, `TEST` or any other value.

- `LE_CRT_KEY_TYPE` *(optional)*: CA Certificate key type. Default to `RSA2048`. Both Let's Encrypt staging and production environments use `RSA2048` keys.

## Output

This tool generates 3 files:

- `certificate.key`: Certificate private key.

- `certificate.crt`: PEM-encoded certificate.

- `issuer.crt`: PEM-encoded issuer certificate.

## Examples

- Generate a certificate using token value:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export DO_AUTH_TOKEN="xxxxxxxxxxxxxxxxxxxx"
# Run binary to generate certs
letsgo
```

- Generate a certificate using token filepath :

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export DO_AUTH_TOKEN_FILE="$HOME/certificates/.dotoken"
# Run binary to generate certs
letsgo
```

- Generate a certificate using Azure Keyvault:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export DO_AUTH_TOKEN_VAULT="dev-quaraneb-jqtcetl-kv"
# Run binary to generate certs
letsgo
```

- It's also possible to use the complete keyvault URI or configure secret name:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export DO_AUTH_TOKEN_VAULT="https://dev-quaraneb-jqtcetl-kv.vault.azure.net/"
export DO_AUTH_TOKEN_SECRET="do-auth-token"
# Run binary to generate certs
letsgo
```

- Configure account key:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export ACCOUNT_KEY_FILE="./example-account.key"
# Run binary to generate certs
letsgo
```
