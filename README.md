# Minimal Let's Encrypt CLI

The goal of this project is to offer a binary, as small as possible, which can generate valid TLS certificates
issued by Let's Encrypt, while fetching necessary tokens from a remote keystore (Azure Key Vault).

> The current size of the built executable is approximately `13Mb`, while the `lego` CLI is `34Mb` and does not include Azure Key Vault integration. Binaries can be fetched from [latest release](https://github.com/charbonnierg/letsgo/releases/latest).

This library is designed to work only with DNS-01 challenges, using Digital Ocean provider.

## Configuration

`letsgo` can  only be configured through environment variables. It does not accept any command line argument.

### Authentication

| Environment Variable | Optional | Default         | Description                                      |
|----------------------|----------|-----------------|--------------------------------------------------|
| `DO_AUTH_TOKEN_VAULT`  | ✅    |                 | Name or URI of Azure Keyvault holding auth token |
| `DO_AUTH_TOKEN_SECRET` | ✅    | `"do-auth-token"` | Name of secret stored in Azure Keyvault          |
| `DO_AUTH_TOKEN_FILE`   | ✅    |                 | Path to file holding auth token                  |
| `DO_AUTH_TOKEN`        | ✅    |                 | Auth token value                                 |

> 💥 At least one of `DO_AUTH_TOKEN_VAULT`, `DO_AUTH_TOKEN_FILE`, or `DO_AUTH_TOKEN` must be set to a non-null value


### Domains


| Environment Variable | Optional | Default         | Description                                      |
|----------------------|----------|-----------------|--------------------------------------------------|
| `DOMAINS`            | 💥   |                 | Comma-separated list of domain names             |

> `DOMAINS` environment variable must be set to a non-null value.

### Let's Encrypt Account


| Environment Variable | Optional | Default         | Description                                                                                 |
|----------------------|----------|-----------------|---------------------------------------------------------------------------------------------|
| `ACCOUNT_EMAIL`        | 💥     |                 | Email of Let's Encrypt account for which certificate is issued                              |
| `ACCOUNT_KEY_FILE`     | ✅   | `"./account.key"` | Path to account key file. If account key does not exist, it is generated and saved to path. |
| `LE_TOS_AGREED`        | ✅    | `true`            | Agree to Let's Encrypt terms of usage                                                       |

> `ACCOUNT_EMAIL` environment variable must be set to a non-null value.

### CA Directory


| Environment Variable | Required | Default   | Description                                                                                                             |
|----------------------|----------|-----------|-------------------------------------------------------------------------------------------------------------------------|
| `CA_DIR`               | ✅    | `"STAGING"`   | Name of CA directory environment or URL to CA directory. Allowed values are [PRODUCTION](https://letsencrypt.org/certificates/), [STAGING](https://letsencrypt.org/docs/staging-environment/), [TEST](https://hub.docker.com/r/containous/boulder), or any http URL. |
| `LE_CRT_KEY_TYPE`      | ✅    | `"RSA2048"` | Certificate key type. Both Let's Encrypt staging and production environments use the `RSA2048` key type.                  |

## Output

This tool generates 3 files:

- `certificate.key`: Certificate private key.

- `certificate.crt`: PEM-encoded certificate.

- `issuer.crt`: PEM-encoded issuer certificate.

## Usage examples

- Generate a certificate using token value:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export DO_AUTH_TOKEN="xxxxxxxxxxxxxxxxxxxx"
# Run binary to generate certs
letsgo
```

> The command generates the following files:
>
> - `example.com.crt`: PEM-encoded x509 certificate
> - `example.com.key`: PEM-encoded RSA private key
> - `example.com.issuer.crt`: PEM-encoded x509 issuer certificate
>
> If account private key did not exist (default file is `./account.key`), this command also generates the private key file.

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
export DO_AUTH_TOKEN_VAULT="example-keyvault"
# Run binary to generate certs
letsgo
```

- It's also possible to use the complete keyvault URI or configure secret name:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export DO_AUTH_TOKEN_VAULT="https://example-keyvault.vault.azure.net/"
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
