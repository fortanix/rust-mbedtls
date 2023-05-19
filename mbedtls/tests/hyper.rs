use hyper::net::{NetworkStream, SslClient, SslServer};
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
extern crate mbedtls;
use mbedtls::ssl::{Config, Context};
mod support;
use support::{debug::set_config_debug, rand::test_rng};

// Native TLS compatibility - to move to native tls client in the future
#[derive(Clone)]
pub struct TlsStream<T> {
    context: Arc<Mutex<Context<T>>>,
    phantom: PhantomData<T>,
}

impl<T> TlsStream<T> {
    pub fn new(context: Arc<Mutex<Context<T>>>) -> Self {
        TlsStream {
            context: context,
            phantom: PhantomData,
        }
    }
}

impl<T: io::Read + io::Write> io::Read for TlsStream<T>
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.context.lock().unwrap().read(buf)
    }
}

impl<T: io::Read + io::Write> io::Write for TlsStream<T>
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.context.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.context.lock().unwrap().flush()
    }
}

impl<T> NetworkStream for TlsStream<T>
    where T: NetworkStream
{
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.context.lock().unwrap().io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .peer_addr()
    }
    
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context.lock().unwrap().io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context.lock().unwrap().io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .set_write_timeout(dur)
    }
}


#[derive(Clone)]
pub struct MbedSSLServer {
    rc_config: Arc<Config>,
}

impl MbedSSLServer {
    pub fn new(rc_config: Arc<Config>) -> Self {
        MbedSSLServer {
            rc_config,
        }
    }
}

/// An abstraction to allow any SSL implementation to be used with server-side HttpsStreams.
impl<T> SslServer<T> for MbedSSLServer
    where T: NetworkStream + Send + Clone + fmt::Debug + Sync
{
    /// The protected stream.
    type Stream = TlsStream<T>;

    /// Wrap a server stream with SSL.
    fn wrap_server(&self, stream: T) -> Result<Self::Stream, hyper::Error> {
        let mut ctx = Context::new(self.rc_config.clone());
        ctx.establish(stream, None).map_err(|e| hyper::error::Error::Ssl(e.into()))?;
        Ok(TlsStream::new(Arc::new(Mutex::new(ctx))))
    }
}

#[derive(Clone)]
pub struct MbedSSLClient {
    rc_config: Arc<Config>,
    verify_hostname: bool,

    // This can be used when verify_hostname is set to true.
    // It will force ssl client to send this specific SNI on all established connections disregarding any host provided by hyper.
    override_sni: Option<String>,
}

impl MbedSSLClient {
    #[allow(dead_code)]
    pub fn new(rc_config: Arc<Config>, verify_hostname: bool) -> Self {
        MbedSSLClient {
            rc_config,
            verify_hostname,
            override_sni: None,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_sni(rc_config: Arc<Config>, verify_hostname: bool, override_sni: Option<String>) -> Self {
        MbedSSLClient {
            rc_config,
            verify_hostname,
            override_sni,
        }
    }
}

impl<T> SslClient<T> for MbedSSLClient
    where T: NetworkStream + Send + Clone + fmt::Debug + Sync
{
    type Stream = TlsStream<T>;

    fn wrap_client(&self, stream: T, host: &str) -> hyper::Result<TlsStream<T>> {
        let mut context = Context::new(self.rc_config.clone());

        let verify_hostname = match self.verify_hostname {
            true => Some(self.override_sni.as_ref().map(|v| v.as_str()).unwrap_or(host)),
            false => None,
        };

        match context.establish(stream, verify_hostname) {
            Ok(()) => Ok(TlsStream::new(Arc::new(Mutex::new(context)))),
            Err(e) => Err(hyper::Error::Ssl(Box::new(e))),
        }
    }
}

// To implement SSL tickets and have faster connections to the same remote server:
// - implement Drop for TlsStream -> it should store the context into a cache.
// - update wrap_client to use TlsStream cache
//
// This is similar to what hyper does for keep alive connections: hyper/src/client/pool.rs

#[cfg(test)]
mod tests {
    use crate::support::debug::init_env_logger;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    use hyper::client::Pool;
    use hyper::net::{HttpListener, HttpsConnector, HttpsListener, NetworkListener};
    use hyper::status::StatusCode;
    use mbedtls::pk::Pk;
    use mbedtls::ssl::Config;
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode, Version, UseSessionTickets, Renegotiation};
    use mbedtls::ssl::context::HandshakeContext;
    use mbedtls::x509::{Certificate, VerifyError};
    use std::sync::Arc;
    use mbedtls::ssl::Tls12CipherSuite::*;
    use mbedtls::ssl::Tls13CipherSuite::*;
    use std::io::Write;
    use mbedtls::ssl::TicketContext;
    use rstest::rstest;

    #[cfg(not(target_env = "sgx"))]
    use mbedtls::rng::{OsEntropy, CtrDrbg};

    #[cfg(target_env = "sgx")]
    use mbedtls::rng::{Rdrand};

    #[cfg(not(target_env = "sgx"))]
    pub fn rng_new() -> Arc<CtrDrbg> {
        let entropy = Arc::new(OsEntropy::new());
        let rng = Arc::new(CtrDrbg::new(entropy, None).unwrap());
        rng
    }

    #[cfg(target_env = "sgx")]
    pub fn rng_new() -> Arc<Rdrand> {
        Arc::new(Rdrand)
    }

    fn make_request(
        client: Arc<hyper::Client>,
        method: hyper::method::Method,
        url: &str,
        body_str: Option<&str>,
        expected_status: StatusCode,
    ) {
        let mut rq = client.request(method.clone(), url);
        if let Some(body_str_data) = body_str {
            rq = rq.body(body_str_data);
        }
        match rq.send() {
            Ok(response) => {
                assert_eq!(response.status, expected_status);
                return;
            }
            Err(err) => panic!("Receive error when sending request: {:?}", err),
        }
    }

    #[rstest]
    #[case::tls12(Version::Tls12)]
    #[case::tls13(Version::Tls13)]
    fn test_simple_request(#[case] ver: Version) {
        init_env_logger();
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        set_config_debug(&mut config, "[Client]");

        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(ver).unwrap();
        config.set_max_version(ver).unwrap();
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(GOOGLE_ROOT_CA_CERT).unwrap()), None);

        let ssl = MbedSSLClient::new(Arc::new(config), true);
        let connector = HttpsConnector::new(ssl);
        let client = hyper::Client::with_connector(Pool::with_connector(Default::default(), connector));

        make_request(
            client.into(),
            hyper::Head,
            "https://www.google.com/",
            None,
            hyper::status::StatusCode::Ok,
        );
    }

    #[rstest]
    #[case::tls12(Version::Tls12)]
    #[case::tls13(Version::Tls13)]
    fn test_multiple_request(#[case] ver: Version) {
        init_env_logger();

        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        set_config_debug(&mut config, "[Client]");

        config.set_rng(rng_new());
        config.set_authmode(AuthMode::Required);
        config.set_min_version(ver).unwrap();
        config.set_max_version(ver).unwrap();
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(GOOGLE_ROOT_CA_CERT).unwrap()), None);

        // Immutable from this point on
        let ssl = MbedSSLClient::new(Arc::new(config), true);

        let client1 = hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl.clone())));
        make_request(
            client1.into(),
            hyper::Head,
            "https://cloud.google.com/",
            None,
            hyper::status::StatusCode::Ok,
        );

        let client2 = hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl.clone())));
        make_request(
            client2.into(),
            hyper::Head,
            "https://www.youtube.com/",
            None,
            hyper::status::StatusCode::Ok,
        );

        let client3 = hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl.clone())));
        make_request(
            client3.into(),
            hyper::Head,
            "https://www.android.com/",
            None,
            hyper::status::StatusCode::Ok,
        );
    }

    #[rstest]
    #[case::tls12(Version::Tls12)]
    #[case::tls13(Version::Tls13)]
    fn test_hyper_multithread(#[case] ver: Version) {
        init_env_logger();

        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        set_config_debug(&mut config, "[Client]");

        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(ver).unwrap();
        config.set_max_version(ver).unwrap();
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(GOOGLE_ROOT_CA_CERT).unwrap()), None);

        let ssl = MbedSSLClient::new(Arc::new(config), true);
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            HttpsConnector::new(ssl.clone()),
        )));

        let clone1 = client.clone();
        let clone2 = client.clone();
        let t1 = std::thread::spawn(move || {
            make_request(
                clone1,
                hyper::Head,
                "https://www.google.com/",
                None,
                hyper::status::StatusCode::Ok,
            );
        });

        let t2 = std::thread::spawn(move || {
            make_request(
                clone2,
                hyper::Post,
                "https://www.google.com/",
                Some("foo=bar"),
                hyper::status::StatusCode::MethodNotAllowed,
            );
        });

        t1.join().unwrap();
        t2.join().unwrap();
    }

    #[rstest]
    #[case::tls12(Version::Tls12)]
    #[case::tls13(Version::Tls13)]
    fn test_verify(#[case] ver: Version) {
        init_env_logger();

        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        set_config_debug(&mut config, "[Client]");

        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(ver).unwrap();
        config.set_max_version(ver).unwrap();

        let verify_callback = |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
            *verify_flags = VerifyError::CERT_OTHER;
            Ok(())
        };
        config.set_verify_callback(verify_callback);
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()), None);

        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let connector = HttpsConnector::new(ssl.clone());
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            connector,
        )));

        match client.get("https://www.google.com").send() {
            Err(hyper::Error::Ssl(_)) => (),
            _ => assert!(false),
        };
    }

    #[rstest]
    #[case::tls12(Version::Tls12)]
    #[case::tls13(Version::Tls13)]
    fn test_hyper_server(#[case] ver: Version) {
        init_env_logger();

        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
        set_config_debug(&mut config, "[Server]");

        config.set_rng(rng_new());
        config.set_authmode(AuthMode::None);
        config.set_min_version(ver).unwrap();
        config.set_max_version(ver).unwrap();

        let sig_algs = Arc::new(mbedtls::ssl::tls13_preset_default_sig_algs());
        config.set_signature_algorithms(sig_algs);

        let cert = Arc::new(Certificate::from_pem_multiple(PEM_CERT).unwrap());
        let key = Arc::new(Pk::from_private_key(&mut test_rng(), PEM_KEY, None).unwrap());
        config.push_cert(cert, key).unwrap();

        let ssl = MbedSSLServer {
            rc_config: Arc::new(config),
        };

        // Random port is intentional
        let mut listener = HttpListener::new("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let server = hyper::Server::new(HttpsListener::with_listener(listener, ssl));

        let mut handler = server
            .handle_threads(
                move |mut _req: hyper::server::Request, mut res: hyper::server::Response| {
                    *res.status_mut() = StatusCode::MethodNotAllowed;
                },
                3,
            )
            .unwrap();

        std::thread::sleep(core::time::Duration::from_millis(10));

        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        set_config_debug(&mut config, "[Client]");

        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(ver).unwrap();
        config.set_max_version(ver).unwrap();
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()), None);

        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            HttpsConnector::new(ssl.clone()),
        )));

        let client1 = client.clone();

        // If this fails due to EWOULDBLOCK it means not enough threads were created.
        let t1 = std::thread::Builder::new()
            .spawn(move || {
                let response = client1.post(&format!("https://{}/path", local_addr)).body("foo=bar").send();
                assert!(response.is_ok());
                println!("{:?}", response);
            })
            .unwrap();

        t1.join().unwrap();
        handler.close().unwrap();
    }

    #[rstest]
    #[case::tls12(Version::Tls12)]
    #[case::tls13(Version::Tls13)]
    fn test_sni_hyper_server(#[case] ver: Version) {
        init_env_logger();

        let rng = rng_new();

        let (local_addr, server) = {
            let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
            set_config_debug(&mut config, "[Server]");

            config.set_rng(rng.clone());
            config.set_min_version(ver).unwrap();
            config.set_max_version(ver).unwrap();

            let sig_algs = Arc::new(mbedtls::ssl::tls13_preset_default_sig_algs());
            config.set_signature_algorithms(sig_algs);

            let cert = Arc::new(Certificate::from_pem_multiple(PEM_CERT).unwrap());
            let key = Arc::new(Pk::from_private_key(&mut test_rng(), PEM_KEY, None).unwrap());

            let cipher_suites: Vec<i32> = vec![
                RsaWithAes128GcmSha256.into(),
                DheRsaWithAes128GcmSha256.into(),
                PskWithAes128GcmSha256.into(),
                DhePskWithAes128GcmSha256.into(),
                RsaPskWithAes128GcmSha256.into(),
                Tls13Aes128GcmSha256.into(),
                Tls13Aes256GcmSha384.into(),
                Tls13Chacha20Poly1305Sha256.into(),
                Tls13Aes128CcmSha256.into(),
                Tls13Aes128Ccm8Sha256.into(),
                0,
            ];

            config.set_ciphersuites(Arc::new(cipher_suites));

            let sni_callback = move |ctx: &mut HandshakeContext, name: &[u8]| -> Result<(), mbedtls::Error> {
                let name = std::str::from_utf8(name).unwrap();
                if name == "mbedtls.example" {
                    ctx.set_authmode(AuthMode::None).unwrap();
                    ctx.push_cert(cert.clone(), key.clone()).unwrap();
                    Ok(())
                } else {
                    return Err(mbedtls::error::codes::SslNoClientCertificate.into());
                }
            };

            config.set_sni_callback(sni_callback);

            let tctx = TicketContext::new(rng.clone(), mbedtls::cipher::raw::CipherType::Aes128Gcm, 300).unwrap();
            config.set_session_tickets_callback(Arc::new(tctx));

            let ssl = MbedSSLServer {
                rc_config: Arc::new(config),
            };

            // Random port is intentional
            let mut listener = HttpListener::new("127.0.0.1:0").unwrap();

            (
                listener.local_addr().unwrap(),
                hyper::Server::new(HttpsListener::with_listener(listener, ssl)),
            )
        };

        let mut handler = server
            .handle_threads(
                move |mut _req: hyper::server::Request, mut res: hyper::server::Response| {
                    *res.status_mut() = StatusCode::MethodNotAllowed;
                },
                3,
            )
            .unwrap();

        std::thread::sleep(core::time::Duration::from_millis(10));

        let client = {
            let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
            set_config_debug(&mut config, "[Client]");

            config.set_authmode(AuthMode::Required);
            config.set_rng(rng.clone());
            config.set_min_version(ver).unwrap();
            config.set_max_version(ver).unwrap();
            config.set_ca_list(Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()), None);

            config.set_session_tickets(UseSessionTickets::Enabled);
            config.set_renegotiation(Renegotiation::Enabled);

            let ssl = MbedSSLClient::new_with_sni(Arc::new(config), true, Some("mbedtls.example".to_string()));
            Arc::new(hyper::Client::with_connector(Pool::with_connector(
                Default::default(),
                HttpsConnector::new(ssl),
            )))
        };
        let do_tests = || -> Result<(), hyper::Error> {
            {
                let response = client.post(&format!("https://{}/path", local_addr)).body("foo=bar").send()?;
                println!("Response: {}", response.status);
                assert_eq!(response.status, StatusCode::MethodNotAllowed);
            }
            {
                let response = client.post(&format!("https://{}/path", local_addr)).body("foo=bar").send()?;
                println!("Response: {}", response.status);
                assert_eq!(response.status, StatusCode::MethodNotAllowed);
            }
            {
                let response = client.post(&format!("https://{}/path", local_addr)).body("foo=bar").send()?;
                println!("Response: {}", response.status);
                assert_eq!(response.status, StatusCode::MethodNotAllowed);
            }
            Ok(())
        };
        let result = do_tests();
        handler.close().unwrap();
        std::io::stdout().flush().unwrap();
        assert!(result.is_ok());
    }


    pub const PEM_KEY: &'static [u8] = concat!(include_str!("./support/keys/user.key"),"\0").as_bytes();
    pub const PEM_CERT: &'static [u8] = concat!(include_str!("./support/keys/user.crt"),"\0").as_bytes();
    pub const ROOT_CA_CERT: &'static [u8] = concat!(include_str!("./support/keys/ca.crt"),"\0").as_bytes();
    // root cert downloaded from Google Trust Services: https://pki.goog/roots.pem
    pub const GOOGLE_ROOT_CA_CERT: &'static [u8] = concat!(include_str!("./support/keys/roots.pem"), "\0").as_bytes();
}
