use std::io::{self, Cursor};
use std::net::ToSocketAddrs;
use std::sync::Arc;

use cdrs_tokio::authenticators::StaticPasswordAuthenticator;
use cdrs_tokio::cluster::{NodeRustlsConfig, NodeRustlsConfigBuilder};
use rustls::{Certificate, PrivateKey};
use webpki::DNSNameRef;

pub struct AstraConfig<'a> {
    /// Database hostname (found in cqlshrc file)
    pub host: &'a str,
    /// Database port (found in cqlshrc file)
    pub port: u16,
    /// Database client ID (effective username)
    pub client_id: &'a str,
    /// Database client secret (effective password)
    pub client_secret: &'a str,
}

pub struct AstraSecureBundle {
    /// Trusted root ceritificate to use (found in 'ca.crt' file)
    pub trusted_cert: Certificate,
    /// Client ceritifcate to use (found in 'cert' file)
    pub client_cert: Certificate,
    /// Private key to use (found in 'key' file)
    pub private_key: PrivateKey,
}

impl AstraSecureBundle {
    /// Load the secure bundle from PEM encoded certificates
    pub fn load(trusted_cert: &[u8], client_cert: &[u8], private_key: &[u8]) -> Result<Self, io::Error> {
        let trusted_cert = rustls_pemfile::certs(&mut Cursor::new(trusted_cert))?
            .into_iter()
            .map(Certificate)
            .next()
            .expect("No trusted certificate found");

        let client_cert = rustls_pemfile::certs(&mut Cursor::new(client_cert))?
            .into_iter()
            .map(Certificate)
            .next()
            .expect("No client certificate found");

        let private_key = rustls_pemfile::rsa_private_keys(&mut Cursor::new(private_key))?
            .into_iter()
            .map(PrivateKey)
            .next()
            .expect("No private key found");

        let bundle = AstraSecureBundle {
            trusted_cert,
            client_cert,
            private_key,
        };
        Ok(bundle)
    }
}

pub fn new_astra_node<'a>(
    config: AstraConfig<'a>,
    secure_bundle: AstraSecureBundle,
) -> Result<NodeRustlsConfig, Box<dyn std::error::Error>> {
    let address = (config.host, config.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Couldn't resolve the hostname"))?;

    let mut ssl_config = rustls::ClientConfig::new();
    ssl_config
        .root_store
        .add(&secure_bundle.trusted_cert)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Couldn't load the trusted cert file"))?;
    ssl_config.set_single_client_cert(vec![secure_bundle.client_cert], secure_bundle.private_key)?;

    let auth = StaticPasswordAuthenticator::new(config.client_id, config.client_secret);

    let node_config = NodeRustlsConfigBuilder::new(
        address,
        DNSNameRef::try_from_ascii_str(config.host)?.into(),
        Arc::new(auth),
        Arc::new(ssl_config),
    )
    .build();
    Ok(node_config)
}
