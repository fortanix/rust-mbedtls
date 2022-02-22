use hyper::net::{NetworkStream, SslClient, SslServer};
use mbedtls::ssl::{Config, Context};
use std::borrow::Cow;
use std::fmt;
use std::io;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

impl<T: io::Read + io::Write> io::Read for TlsStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.context.lock().unwrap().read(buf)
    }
}

impl<T: io::Read + io::Write> io::Write for TlsStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.context.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.context.lock().unwrap().flush()
    }
}

impl<T> NetworkStream for TlsStream<T>
where
    T: NetworkStream,
{
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.context
            .lock()
            .unwrap()
            .io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context
            .lock()
            .unwrap()
            .io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context
            .lock()
            .unwrap()
            .io_mut()
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
        MbedSSLServer { rc_config }
    }
}

/// An abstraction to allow any SSL implementation to be used with server-side HttpsStreams.
impl<T> SslServer<T> for MbedSSLServer
where
    T: NetworkStream + Send + Clone + fmt::Debug + Sync,
{
    /// The protected stream.
    type Stream = TlsStream<T>;

    /// Wrap a server stream with SSL.
    fn wrap_server(&self, stream: T) -> Result<Self::Stream, hyper::Error> {
        let mut ctx = Context::new(self.rc_config.clone());
        ctx.establish(stream, None)
            .map_err(|e| hyper::error::Error::Ssl(e.into()))?;
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
    pub fn new_with_sni(
        rc_config: Arc<Config>,
        verify_hostname: bool,
        override_sni: Option<String>,
    ) -> Self {
        MbedSSLClient {
            rc_config,
            verify_hostname,
            override_sni,
        }
    }
}

impl<T> SslClient<T> for MbedSSLClient
where
    T: NetworkStream + Send + Clone + fmt::Debug + Sync,
{
    type Stream = TlsStream<T>;

    fn wrap_client(&self, stream: T, host: &str) -> hyper::Result<TlsStream<T>> {
        let mut context = Context::new(self.rc_config.clone());

        let verify_hostname = match self.verify_hostname {
            true => Some(
                self.override_sni
                    .as_ref()
                    .map(|v| v.as_str())
                    .unwrap_or(host),
            ),
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
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    use hyper::client::Pool;
    use hyper::net::{HttpListener, HttpsConnector, HttpsListener, NetworkListener};
    use hyper::status::StatusCode;
    use mbedtls::pk::Pk;
    use mbedtls::ssl::config::{
        AuthMode, Endpoint, Preset, Renegotiation, Transport, UseSessionTickets, Version,
    };
    use mbedtls::ssl::context::HandshakeContext;
    use mbedtls::ssl::CipherSuite::*;
    use mbedtls::ssl::Config;
    use mbedtls::ssl::TicketContext;
    use mbedtls::x509::{Certificate, VerifyError};
    use std::io::Write;
    use std::sync::Arc;

    #[cfg(not(target_env = "sgx"))]
    use mbedtls::rng::{CtrDrbg, OsEntropy};

    #[cfg(target_env = "sgx")]
    use mbedtls::rng::Rdrand;

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

    #[test]
    fn test_simple_request() {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_authmode(AuthMode::None);
        config.set_rng(rng_new());
        config.set_min_version(Version::Tls1_2).unwrap();

        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let connector = HttpsConnector::new(ssl);
        let client =
            hyper::Client::with_connector(Pool::with_connector(Default::default(), connector));

        let response = client.get("https://www.google.com/").send().unwrap();

        assert_eq!(response.status, hyper::status::StatusCode::Ok);
    }

    #[test]
    fn test_multiple_request() {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_rng(rng_new());
        config.set_authmode(AuthMode::None);
        config.set_min_version(Version::Tls1_2).unwrap();

        // Immutable from this point on
        let ssl = MbedSSLClient::new(Arc::new(config), false);

        let client1 = hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            HttpsConnector::new(ssl.clone()),
        ));
        let response = client1.get("https://www.google.com/").send().unwrap();
        assert_eq!(response.status, hyper::status::StatusCode::Ok);

        let client2 = hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            HttpsConnector::new(ssl.clone()),
        ));
        let response = client2.get("https://www.google.com/").send().unwrap();
        assert_eq!(response.status, hyper::status::StatusCode::Ok);

        let client3 = hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            HttpsConnector::new(ssl.clone()),
        ));
        let response = client3.get("https://www.google.com/").send().unwrap();
        assert_eq!(response.status, hyper::status::StatusCode::Ok);
    }

    #[test]
    fn test_hyper_multithread() {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_authmode(AuthMode::None);
        config.set_rng(rng_new());
        config.set_min_version(Version::Tls1_2).unwrap();

        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            HttpsConnector::new(ssl.clone()),
        )));

        let clone1 = client.clone();
        let clone2 = client.clone();
        let t1 = std::thread::spawn(move || {
            let response = clone1.get("https://google.com").send().unwrap();
            assert_eq!(response.status, hyper::status::StatusCode::Ok);
        });

        let t2 = std::thread::spawn(move || {
            clone2
                .post("https://google.com")
                .body("foo=bar")
                .send()
                .unwrap();
        });

        t1.join().unwrap();
        t2.join().unwrap();
    }

    #[test]
    fn test_verify() {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(Version::Tls1_2).unwrap();

        let verify_callback = |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
            *verify_flags = VerifyError::CERT_OTHER;
            Ok(())
        };
        config.set_verify_callback(verify_callback);

        // This is mostly as an example - how to debug mbedtls
        let dbg_callback = |level: i32, file: Cow<'_, str>, line: i32, message: Cow<'_, str>| {
            println!("{} {}:{} {}", level, file, line, message);
        };
        config.set_dbg_callback(dbg_callback);

        config.set_ca_list(
            Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()),
            None,
        );

        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let connector = HttpsConnector::new(ssl.clone());
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            connector,
        )));

        match client.get("https://google.com").send() {
            Err(hyper::Error::Ssl(_)) => (),
            _ => assert!(false),
        };
    }

    #[test]
    fn test_hyper_server() {
        std::env::set_var("RUST_BACKTRACE", "full");

        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

        config.set_rng(rng_new());
        config.set_authmode(AuthMode::None);
        config.set_min_version(Version::Tls1_2).unwrap();

        let cert = Arc::new(Certificate::from_pem_multiple(PEM_CERT).unwrap());
        let key = Arc::new(Pk::from_private_key(PEM_KEY, None).unwrap());
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

        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(Version::Tls1_2).unwrap();
        config.set_ca_list(
            Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()),
            None,
        );

        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            HttpsConnector::new(ssl.clone()),
        )));

        let client1 = client.clone();

        // If this fails due to EWOULDBLOCK it means not enough threads were created.
        let t1 = std::thread::Builder::new()
            .spawn(move || {
                let response = client1
                    .post(&format!("https://{}/path", local_addr))
                    .body("foo=bar")
                    .send();
                println!("{:?}", response);
            })
            .unwrap();

        t1.join().unwrap();
        handler.close().unwrap();
    }

    #[test]
    fn test_sni_hyper_server() {
        std::env::set_var("RUST_BACKTRACE", "full");

        // This is mostly as an example - how to debug mbedtls
        let dbg_callback = |level: i32, file: Cow<'_, str>, line: i32, message: Cow<'_, str>| {
            println!("{} {}:{} {}", level, file, line, message);
        };

        let rng = rng_new();

        let (local_addr, server) = {
            let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

            config.set_rng(rng.clone());
            config.set_min_version(Version::Tls1_2).unwrap();
            config.set_dbg_callback(dbg_callback.clone());

            let cert = Arc::new(Certificate::from_pem_multiple(PEM_CERT).unwrap());
            let key = Arc::new(Pk::from_private_key(PEM_KEY, None).unwrap());

            let cipher_suites: Vec<i32> = vec![
                RsaWithAes128GcmSha256.into(),
                DheRsaWithAes128GcmSha256.into(),
                PskWithAes128GcmSha256.into(),
                DhePskWithAes128GcmSha256.into(),
                RsaPskWithAes128GcmSha256.into(),
                0,
            ];

            config.set_ciphersuites(Arc::new(cipher_suites));

            let sni_callback =
                move |ctx: &mut HandshakeContext, name: &[u8]| -> Result<(), mbedtls::Error> {
                    let name = std::str::from_utf8(name).unwrap();
                    if name == "mbedtls.example" {
                        ctx.set_authmode(AuthMode::None).unwrap();
                        ctx.push_cert(cert.clone(), key.clone()).unwrap();
                        Ok(())
                    } else {
                        return Err(mbedtls::Error::SslNoClientCertificate);
                    }
                };

            config.set_sni_callback(sni_callback);

            let tctx = TicketContext::new(
                rng.clone(),
                mbedtls::cipher::raw::CipherType::Aes128Gcm,
                300,
            )
            .unwrap();
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

            config.set_authmode(AuthMode::Required);
            config.set_rng(rng.clone());
            config.set_min_version(Version::Tls1_2).unwrap();
            config.set_ca_list(
                Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()),
                None,
            );

            config.set_dbg_callback(dbg_callback.clone());

            config.set_session_tickets(UseSessionTickets::Enabled);
            config.set_renegotiation(Renegotiation::Enabled);

            let ssl = MbedSSLClient::new_with_sni(
                Arc::new(config),
                true,
                Some("mbedtls.example".to_string()),
            );
            Arc::new(hyper::Client::with_connector(Pool::with_connector(
                Default::default(),
                HttpsConnector::new(ssl),
            )))
        };

        {
            let response = client
                .post(&format!("https://{}/path", local_addr))
                .body("foo=bar")
                .send()
                .unwrap();
            println!("Response: {}", response.status);
            assert_eq!(response.status, StatusCode::MethodNotAllowed);
        }
        {
            let response = client
                .post(&format!("https://{}/path", local_addr))
                .body("foo=bar")
                .send()
                .unwrap();
            println!("Response: {}", response.status);
            assert_eq!(response.status, StatusCode::MethodNotAllowed);
        }
        {
            let response = client
                .post(&format!("https://{}/path", local_addr))
                .body("foo=bar")
                .send()
                .unwrap();
            println!("Response: {}", response.status);
            assert_eq!(response.status, StatusCode::MethodNotAllowed);
        }

        handler.close().unwrap();
        std::io::stdout().flush().unwrap();
    }

    pub const PEM_KEY: &'static [u8] =
        concat!(include_str!("./support/keys/user.key"), "\0").as_bytes();
    pub const PEM_CERT: &'static [u8] =
        concat!(include_str!("./support/keys/user.crt"), "\0").as_bytes();
    pub const ROOT_CA_CERT: &'static [u8] =
        concat!(include_str!("./support/keys/ca.crt"), "\0").as_bytes();
}
