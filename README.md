# Certificate Generator

A Rust library for generating X.509 certificates with support for CA, server, client and peer certificate profiles.

## Features

- Generate CA certificates
- Generate server/client/peer certificates signed by CA
- Configurable certificate options including:
  - Common name
  - Subject Alternative Names (SANs)
  - Organization details
  - Validity period
  - Key usage and extended key usage
- Uses ECDSA P-256 keys with SHA-256
- PEM format output
- Filesystem-based certificate storage

## Usage

```rust
rcssl generate --config ./config.yaml
```

To see all the options, run `rcssl generate --help`.

## Configuration

The configuration file is a YAML file that defines the certificates to be generated.

See the [config.yaml](./config/config.yaml) file for an example.
