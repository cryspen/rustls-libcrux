# A libcrux-backed crypto provider for Rustls

This library implements the crypto provider traits from Rustls, allowing to use
verified cryptography for TLS connections. The demo server injects a libcrux-enabled
Rustls config into actix-web to provide an example HTTPS server.

## Creating a libcrux-enabled Rustls server config

This is a simple example for building a config for a Rustls server:

```rust
    let certs: Vec<CertificateDer> = load_certs();
    let private_key: PrivateKeyDer = load_key();

    ServerConfig::builder_with_provider(Arc::new(rustls_libcrux_provider::provider()))
        .with_protocol_versions(DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
```
