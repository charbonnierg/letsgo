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


### Certificate


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

### DNS Challenge

| Environment Variable | Optional | Default | Description                                                                                                                                                     |
|----------------------|----------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `DNS_RESOLVERS`        | ✅    |         | A comma-separated list of DNS resolvers used to verify challenge in `host:port` format                                                                            |
| `DNS_TIMEOUT`          | ✅    |         | Timeout in seconds for DNS challenge resolution                                                                                                                 |
| `DISABLE_CP`           | ✅    | `true`    | Disable complete propagation check, I.E, only a single resolver must verify the DNS challenge to succeed. When enbled, all resolvers must verify the challenge. |


## Output

This tool generates 3 files:

- `certificate.key`: Certificate private key.

- `certificate.crt`: PEM-encoded certificate.

- `issuer.crt`: PEM-encoded issuer certificate.

Optionally, it can generate the account private key `account.key` when it does not exist.

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
letsgo
```

- Generate a certificate using Azure Keyvault:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export DO_AUTH_TOKEN_VAULT="example-keyvault"
letsgo
```

- It's also possible to use the complete keyvault URI or configure secret name:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export DO_AUTH_TOKEN_VAULT="https://example-keyvault.vault.azure.net/"
export DO_AUTH_TOKEN_SECRET="do-auth-token"
letsgo
```

- Configure account key:

```bash
export DOMAINS="example.com,*.example.com"
export ACCOUNT_EMAIL="admin@example.com"
export ACCOUNT_KEY_FILE="./example-account.key"
letsgo
```

- Run `letsgo` from Windows Powershell:

```powershell
$Env:DOMAINS="example.com,*.example.com"
$Env:ACCOUNT_EMAIL="admin@example.com"
$Env:DO_AUTH_TOKEN_VAULT="example-keyvault"
letsgo
```

- Run `letsgo` from Python:

Let's first define a function which requests certificate files and returns values as a dictionary rather than files written to disk. This can be useful when writing network-enabled services.

```python
import os
import pathlib
import subprocess
import tempfile
import shutil


BIN_NAME = "letsgo"
ACCOUNT_KEY = "account.key"


def letsgo(
    domain: str,
    account_email: str,
    keyvault: str,
    account_key: str = "",
    ca_dir: str = "STAGING",
    bin_name: str = BIN_NAME,
):
    # Use shutil.which to determine where letsgo binary is located
    if bin_name == BIN_NAME:
        # First resolve path then convert to string
        # shutil.which can return values which are not valid path for subprocess.run
        bin_path = pathlib.Path(shutil.which(bin_name)).resolve(True).as_posix()
        if bin_path is None:
            raise FileNotFoundError("letsgo binary not found")
    else:
        # Use value provided as argument
        bin_path = bin_name
    # Configure environment
    cmd_env = os.environ.copy()
    cmd_env["DOMAINS"] = domain
    cmd_env["ACCOUNT_EMAIL"] = account_email
    cmd_env["DO_AUTH_TOKEN_VAULT"] = keyvault
    cmd_env["CA_DIR"] = ca_dir
    # Always write to account.key in temporary directory
    cmd_env["ACCOUNT_KEY_FILE"] = ACCOUNT_KEY
    # Get domain name
    main_domain = domain.split(",")[0].replace("*", "_")
    # Prepare temporary directory to run command
    with tempfile.TemporaryDirectory() as tmpdir:
        # Get current directory
        old_dir = os.getcwd()
        # Change working directory
        os.chdir(tmpdir)
        try:
            # Write account key when provided
            if account_key:
                pathlib.Path(ACCOUNT_KEY).write_text(account_key)
            # Run command
            subprocess.run([bin_path], env=cmd_env)
            # Read cert and key
            cert = pathlib.Path(f"{main_domain}.crt").read_text()
            key = pathlib.Path(f"{main_domain}.key").read_text()
            issuer = pathlib.Path(f"{main_domain}.issuer.crt").read_text()
            # Read back account key in case it was generated
            account_key = pathlib.Path(ACCOUNT_KEY).read_text()
        finally:
            # Reset working directory
            os.chdir(old_dir)

    # Return PEM encoded strings
    return {
        "certificate": cert,
        "key": key,
        "issuer": issuer,
        "account_key": account_key,
    }
```

Now it's easy to create certificates:

```python
# Get a dictionary with files
results = letsgo(
    domain="example.com,*.example.com",
    account_email="admin@example.com",
    keyvault="example-keyvault"
)
# Do whatever is needed with file
print(results["certificate"])
print(results["key"])
print(results["issuer"])
# Request certificate again and confirm that no challenge is required this time (because account key is provided)
results = letsgo(
    domain="example.com,*.example.com",
    account_email="admin@example.com",
    keyvault="example-keyvault",
    account_key=results["account_key"],
)
```

> This code should run fine on any platform (Windows, Linux, or MacOS).
