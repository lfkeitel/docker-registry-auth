# Docker Registry Authenticator

This is an authentication server for Docker Registry V2. Users and permissions
are defined in a configuration file. See config.toml for an example. The server
must have an RSA private key in order to sign tokens. The respective public key
must be configured in the registry to verify the tokens.

## Examples

Please see "accounts.toml" and "config.toml" in the testdata directory for
configuration examples.

## Generate User Passwords

Passwords can be generated using any of the following algorithms:

- Argon2i
- scrypt-sha256
- sha512-crypt - `openssl passwd -6 demo`
- sha256-crypt - `openssl passwd -5 demo`
- bcrypt - `htpasswd -bnBC 10 "" demo | tr -d ':\n'`
- pbkdf2-sha512 (in passlib format)
- pbkdf2-sha256 (in passlib format)
- pbkdf2-sha1 (in passlib format)
