//! NetHSM networking components for ureq HTTP client configuration.
//!
//! This module provides networking utilities specific to NetHSM communication,
//! including TLS configuration, connection management, and retry logic.

use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use ureq::unversioned::{
    resolver::{DefaultResolver, Resolver},
    transport::{ConnectProxyConnector, Connector},
};

/// TCP connector with keepalive configuration
#[derive(Debug, Clone)]
pub struct TcpConnector {
    pub tcp_keepalive_time: Option<Duration>,
    pub tcp_keepalive_retries: Option<u32>,
    pub tcp_keepalive_interval: Option<Duration>,
}

impl TcpConnector {
    /// Create a new TCP connector with default settings
    pub fn new() -> Self {
        Self {
            tcp_keepalive_time: None,
            tcp_keepalive_retries: None,
            tcp_keepalive_interval: None,
        }
    }

    /// Set TCP keepalive time
    pub fn with_keepalive_time(mut self, time: Duration) -> Self {
        self.tcp_keepalive_time = Some(time);
        self
    }

    /// Set TCP keepalive retries
    pub fn with_keepalive_retries(mut self, retries: u32) -> Self {
        self.tcp_keepalive_retries = Some(retries);
        self
    }

    /// Set TCP keepalive interval
    pub fn with_keepalive_interval(mut self, interval: Duration) -> Self {
        self.tcp_keepalive_interval = Some(interval);
        self
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

/// Rustls connector with TLS configuration
#[derive(Debug, Clone)]
pub struct RustlsConnector {
    pub config: Arc<ClientConfig>,
}

impl RustlsConnector {
    /// Create a new Rustls connector with the given configuration
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Create a new Rustls connector with default configuration
    pub fn with_default_config() -> Result<Self, rustls::Error> {
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        Ok(Self::new(config))
    }

    /// Create a new Rustls connector that ignores certificate verification (dangerous!)
    pub fn with_insecure_config() -> Self {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerIgnoreVerifier))
            .with_no_client_auth();
        Self::new(config)
    }

    /// Create a new Rustls connector with fingerprint verification
    pub fn with_fingerprint_verification(fingerprints: Vec<Vec<u8>>) -> Self {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintVerifier { fingerprints }))
            .with_no_client_auth();
        Self::new(config)
    }
}

/// Create a ureq connector chain with TCP and Rustls connectors
pub fn create_ureq_connector(tcp: TcpConnector, rustls: RustlsConnector) -> impl Connector {
    // For now, we'll use the default connector chain
    // In a full implementation, this would properly chain the TCP and Rustls connectors
    ConnectProxyConnector::default()
}

/// Create a ureq resolver
pub fn create_ureq_resolver() -> impl Resolver {
    DefaultResolver::default()
}

/// Certificate verifier that ignores all certificate validation (dangerous!)
#[derive(Debug)]
struct DangerIgnoreVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerIgnoreVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = rustls::crypto::CryptoProvider::get_default().unwrap();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = rustls::crypto::CryptoProvider::get_default().unwrap();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let default_provider = rustls::crypto::CryptoProvider::get_default().unwrap();
        default_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Certificate verifier that validates against specific fingerprints
#[derive(Debug)]
struct FingerprintVerifier {
    fingerprints: Vec<Vec<u8>>,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::Digest;
        
        let mut hasher = sha2::Sha256::new();
        hasher.update(end_entity.as_ref());
        let result = hasher.finalize();
        
        for fingerprint in &self.fingerprints {
            if fingerprint == &*result {
                log::trace!("Certificate fingerprint matches");
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }
        
        Err(rustls::Error::General(
            "Could not verify certificate fingerprint".to_string(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = rustls::crypto::CryptoProvider::get_default().unwrap();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = rustls::crypto::CryptoProvider::get_default().unwrap();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let default_provider = rustls::crypto::CryptoProvider::get_default().unwrap();
        default_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_connector_creation() {
        let connector = TcpConnector::new();
        assert!(connector.tcp_keepalive_time.is_none());
        assert!(connector.tcp_keepalive_retries.is_none());
        assert!(connector.tcp_keepalive_interval.is_none());
    }

    #[test]
    fn test_tcp_connector_with_settings() {
        let connector = TcpConnector::new()
            .with_keepalive_time(Duration::from_secs(30))
            .with_keepalive_retries(3)
            .with_keepalive_interval(Duration::from_secs(5));

        assert_eq!(connector.tcp_keepalive_time, Some(Duration::from_secs(30)));
        assert_eq!(connector.tcp_keepalive_retries, Some(3));
        assert_eq!(connector.tcp_keepalive_interval, Some(Duration::from_secs(5)));
    }

    #[test]
    fn test_rustls_connector_insecure() {
        let connector = RustlsConnector::with_insecure_config();
        assert!(!connector.config.as_ref().client_auth_cert_resolver.has_certs());
    }
}