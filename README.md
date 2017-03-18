# Docker Registry Authenticator

This is an authentication server for Docker Registry V2. Users and permissions are defined in a configuration file. See config.toml for an example. The server must have an RSA private key in order to sign tokens. The respective public key must be configured in the registry to verify the tokens.

