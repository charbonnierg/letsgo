import os
import pathlib
import subprocess
import tempfile
import shutil


BIN_NAME = "letsgo"
ACCOUNT_KEYFILE = "account.key"


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
    cmd_env["DNS_AUTH_TOKEN_VAULT"] = keyvault
    cmd_env["CA_DIR"] = ca_dir
    # Get domain name
    main_domain = domain.split(",")[0].replace("*", "_")
    # Prepare temporary directory to run command
    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir = pathlib.Path(tmpdir)
        account_key_file = root_dir.joinpath(ACCOUNT_KEYFILE)
        # Certificate will be written to temporary directory
        cmd_env["OUTPUT_DIRECTORY"] = tmpdir
        # Certificate will be written under static name
        cmd_env["FILENAME"] = main_domain
        # Always write to account.key in temporary directory
        cmd_env["ACCOUNT_KEY_FILE"] = account_key_file.as_posix()
        # Write account key when provided
        if account_key:
            account_key_file.write_text(account_key)
        # Run command and check status code
        subprocess.check_output([bin_path], env=cmd_env)
        # Read cert, key and issuer
        cert = root_dir.joinpath(f"{main_domain}.crt").read_text()
        key = root_dir.joinpath(f"{main_domain}.key").read_text()
        issuer = root_dir.joinpath(f"{main_domain}.issuer.crt").read_text()
        # Read back account key in case it was generated
        account_key = account_key_file.read_text()

    # Return PEM encoded strings
    return {
        "alias": main_domain,
        "certificate": cert,
        "key": key,
        "issuer": issuer,
        "account_key": account_key,
    }

if __name__ == "__main__":
    # Change those variables before running the script
    DEMO_DOMAINS = "demo.example.com"
    DEMO_ACCOUNT = "support@example.com"
    DEMO_KEYVAULT = "demo-keyvault"
    # Get a dictionary with files
    results = letsgo(
        domain=DEMO_DOMAINS,
        account_email=DEMO_ACCOUNT,
        keyvault=DEMO_KEYVAULT,
    )
    # Do whatever is needed with file
    print(results["alias"])
    print(results["certificate"])
    print(results["key"])
    print(results["issuer"])
    # Request certificate again and confirm that no challenge is required this time (because account key is provided)
    results = letsgo(
        domain=DEMO_DOMAINS,
        account_email=DEMO_ACCOUNT,
        keyvault=DEMO_KEYVAULT,
        account_key=results["account_key"],
    )
    alias = results['alias']
    # Write results to file
    pathlib.Path("account.key").write_text(results["account_key"])
    pathlib.Path(f"{alias}.crt").write_text(results["certificate"])
    pathlib.Path(f"{alias}.issuer.crt").write_text(results["issuer"])
    pathlib.Path(f"{alias}.key").write_text(results["key"])
