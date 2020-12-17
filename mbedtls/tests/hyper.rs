use hyper::net::{NetworkStream, SslClient, SslServer};
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::borrow::Cow;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use mbedtls::ssl::{Config, Context};

// Native TLS compatibility - to move to native tls client in the future
#[derive(Clone)]
pub struct TlsStream<T> {
    context: Arc<Mutex<Context>>,
    phantom: PhantomData<T>,
}

impl<T> TlsStream<T> {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        TlsStream {
            context: context,
            phantom: PhantomData,
        }
    }
}

unsafe impl<T> Send for TlsStream<T> {}
unsafe impl<T> Sync for TlsStream<T> {}

impl<T> io::Read for TlsStream<T>
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.context.lock().unwrap().read(buf)
    }
}

impl<T> io::Write for TlsStream<T>
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
            .downcast_mut::<T>().unwrap().peer_addr()
    }
    
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context.lock().unwrap().io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .downcast_mut::<T>().unwrap().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context.lock().unwrap().io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .downcast_mut::<T>().unwrap().set_write_timeout(dur)
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

unsafe impl Send for MbedSSLServer {}

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
    use mbedtls::ssl::CipherSuite::*;
    use std::io::Write;
    use mbedtls::ssl::TicketContext;
    
    #[cfg(not(target_env = "sgx"))]
    use mbedtls::set_global_debug_threshold;
    
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
    
    #[test]
    fn test_simple_request() {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_authmode(AuthMode::None);
        config.set_rng(rng_new());
        config.set_min_version(Version::Tls1_2).unwrap();

        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let connector = HttpsConnector::new(ssl);
        let client = hyper::Client::with_connector(Pool::with_connector(Default::default(), connector));

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

        let client1 = hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl.clone())));
        let response = client1.get("https://www.google.com/").send().unwrap();
        assert_eq!(response.status, hyper::status::StatusCode::Ok);

        let client2 = hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl.clone())));
        let response = client2.get("https://www.google.com/").send().unwrap();
        assert_eq!(response.status, hyper::status::StatusCode::Ok);

        let client3 = hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl.clone())));
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
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl.clone()))));

        let clone1 = client.clone();
        let clone2 = client.clone();
        let t1 = std::thread::spawn(move || {
            let response = clone1.get("https://google.com").send().unwrap();
            assert_eq!(response.status, hyper::status::StatusCode::Ok);
        });
        
        let t2 = std::thread::spawn(move || {
            clone2.post("https://google.com").body("foo=bar").send().unwrap();
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

        #[cfg(not(target_env = "sgx"))]
        unsafe { set_global_debug_threshold(1); }
        
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()), None);
        
        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let connector = HttpsConnector::new(ssl.clone());
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(Default::default(), connector)));

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
        
        let ssl = MbedSSLServer { rc_config: Arc::new(config) };

        // Random port is intentional
        let mut listener = HttpListener::new("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();

        let server = hyper::Server::new(HttpsListener::with_listener(listener, ssl));

        let mut handler = server.handle_threads(move |mut _req: hyper::server::Request, mut res: hyper::server::Response| {
            *res.status_mut() = StatusCode::MethodNotAllowed;
        }, 3).unwrap();

        std::thread::sleep(core::time::Duration::from_millis(10));
        
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(Version::Tls1_2).unwrap();
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()), None);
        
        let ssl = MbedSSLClient::new(Arc::new(config), false);
        let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl.clone()))));

        let client1 = client.clone();

        // If this fails due to EWOULDBLOCK it means not enough threads were created.
        let t1 = std::thread::Builder::new().spawn(move || {
            let response = client1.post(&format!("https://{}/path", local_addr)).body("foo=bar").send();
            println!("{:?}", response);
        }).unwrap();

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

        // Enable as needed for debug
        //set_global_debug_threshold(4);

        let rng = rng_new();
        
        let (local_addr, server) = {
            let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

            config.set_rng(rng.clone());
            config.set_min_version(Version::Tls1_2).unwrap();
            config.set_dbg_callback(dbg_callback.clone());

            let cert = Arc::new(Certificate::from_pem_multiple(PEM_CERT).unwrap());
            let key = Arc::new(Pk::from_private_key(PEM_KEY, None).unwrap());

            let cipher_suites : Vec<i32> = vec![RsaWithAes128GcmSha256.into(), DheRsaWithAes128GcmSha256.into(), PskWithAes128GcmSha256.into(), DhePskWithAes128GcmSha256.into(), RsaPskWithAes128GcmSha256.into(), 0];

            config.set_ciphersuites(Arc::new(cipher_suites));
            
            let sni_callback = move |ctx: &mut HandshakeContext, name: &[u8]| -> Result<(), mbedtls::Error> {
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

            let tctx = TicketContext::new(rng.clone(), mbedtls::cipher::raw::CipherType::Aes128Gcm, 300).unwrap();
            config.set_session_tickets_callback(Arc::new(tctx));

            let ssl = MbedSSLServer { rc_config: Arc::new(config) };

            // Random port is intentional
            let mut listener = HttpListener::new("127.0.0.1:0").unwrap();

            (listener.local_addr().unwrap(), hyper::Server::new(HttpsListener::with_listener(listener, ssl)))
        };

        let mut handler = server.handle_threads(move |mut _req: hyper::server::Request, mut res: hyper::server::Response| {
            *res.status_mut() = StatusCode::MethodNotAllowed;
        }, 3).unwrap();

        std::thread::sleep(core::time::Duration::from_millis(10));
        
        let client = {
            let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

            config.set_authmode(AuthMode::Required);
            config.set_rng(rng.clone());
            config.set_min_version(Version::Tls1_2).unwrap();
            config.set_ca_list(Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()), None);

            config.set_dbg_callback(dbg_callback.clone());
            
            config.set_session_tickets(UseSessionTickets::Enabled);
            config.set_renegotiation(Renegotiation::Enabled);
            
            let ssl = MbedSSLClient::new_with_sni(Arc::new(config), true, Some("mbedtls.example".to_string()));
            Arc::new(hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl))))
        };
        
        {
            let response = client.post(&format!("https://{}/path", local_addr)).body("foo=bar").send().unwrap();
            println!("Response: {}", response.status);
            assert_eq!(response.status, StatusCode::MethodNotAllowed);
        }
        {
            let response = client.post(&format!("https://{}/path", local_addr)).body("foo=bar").send().unwrap();
            println!("Response: {}", response.status);
            assert_eq!(response.status, StatusCode::MethodNotAllowed);
        }
        {
            let response = client.post(&format!("https://{}/path", local_addr)).body("foo=bar").send().unwrap();
            println!("Response: {}", response.status);
            assert_eq!(response.status, StatusCode::MethodNotAllowed);
        }

        handler.close().unwrap();
        std::io::stdout().flush().unwrap();
    }


// Signed by ROOT_CA below
    pub const PEM_CERT: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIIEGzCCAgOgAwIBAgIKElgwWDKDQhBIOTANBgkqhkiG9w0BAQsFADARMQ8wDQYD
VQQDEwZSb290Q0EwIBcNMjAwNTA4MDkxNDMwWhgPMjEwMDA0MTkwOTE0MzBaMBox
GDAWBgNVBAMMD21iZWR0bHMuZXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAN/SZjoB4zxaOxgtCjC6c88Y8twUUtNoNJu+D2X1vjoEEmeh0CCA
x6fvyDbZE7kad5pTVHWdiaepodWzTf4GcuGKa0qP0jwitDuqBoqraDxYT9saQd4I
rh8tPanoDQO2V6iewJT59EFxwC6pry+EWPox1UuKzd66x5a+yTq4d7ybkgBjoico
+0I4m+4BxZNPmZDSdIZpgfMANGvTZCLt/x4gypqotHH//8sssucJJgMwD+YybYis
wtRCt+Atw2YUQe0JhLs8nMTRQXqREBpz250hITpNsior4PhNsjiMElEFqx0ZmT84
tQW6lpJ5Yz297xAeUXrdVl+DrvvdhfrqJJ8CAwEAAaNqMGgwHQYDVR0OBBYEFJvl
m+3MJ2eYR9dGydOY0QNRRMaAMDkGA1UdIwQyMDCAFIkuNd0n1URsu71cJCyBnQwO
MsqLoRWkEzARMQ8wDQYDVQQDEwZSb290Q0GCAQEwDAYDVR0TAQH/BAIwADANBgkq
hkiG9w0BAQsFAAOCAgEAGbkSdZL5BC46GTGSR09lEh+cZ2o4fP6uSbkyT4xEPRWx
fNMLZeEJPVzZkar5tVDnpBb3gAoArHIn6ePPiTssYUD/3yN7ZL6YFn4Bg0VBig8e
ZWzQT6BiAmXKRY7JtDdgnhggxfo1x1bwW0r3qz/BYeC1cdqbC9CRmTPFNIKFhZyY
fC1BQ49dI/prfiBlgGO/bIDZfzMNC9b5b7g5aKVQH1e1ViGkRKL4l6tIKp/pL7Nx
1e1H/f2cl33rm+kTvkH5H02Z+Fg2tVnx2xPxMIkpGOnhtrh5H48xT1oxqcZ/ySmp
W7xiCt4QAW7DafRLwhsMhKSxcBxHEl4mRTX2pz5BV5yyq/rTGDRFQAlzBUEteLh3
fCPsdYOQEQMdPUzx3VAieaHSbR424kcd5Iw3uMBCk2NzyLxbIWKA4Q+9XFIacEdh
TFO2Z/pvkTWMOo1yKzC8NM26QT/o0USgtHBIc2F8FlGEYBLZXvqtOeKJ5mneyLR/
jnAr18OJv+/DPPSv4qB6LpF+CAQFm0pZisqZdwsMBRgWQ3wml/A+lOLmiajNB3gk
XfzmCVga7Kik6cjP0ExV7rRvvQ9akWgsMLYJm28Ck6k3Nl3AsfiAGf5kFj5VlBrd
Ecs4CTdh5ZsL2pDU+QmWsqRNdN+Kz1IVX7fLvR48MgpKZhK+d97/P37e1kEtXoo=
-----END CERTIFICATE-----\0";

    pub const PEM_KEY: &'static [u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDf0mY6AeM8WjsY
LQowunPPGPLcFFLTaDSbvg9l9b46BBJnodAggMen78g22RO5GneaU1R1nYmnqaHV
s03+BnLhimtKj9I8IrQ7qgaKq2g8WE/bGkHeCK4fLT2p6A0DtleonsCU+fRBccAu
qa8vhFj6MdVLis3euseWvsk6uHe8m5IAY6InKPtCOJvuAcWTT5mQ0nSGaYHzADRr
02Qi7f8eIMqaqLRx///LLLLnCSYDMA/mMm2IrMLUQrfgLcNmFEHtCYS7PJzE0UF6
kRAac9udISE6TbIqK+D4TbI4jBJRBasdGZk/OLUFupaSeWM9ve8QHlF63VZfg677
3YX66iSfAgMBAAECggEAL/Pq9Picj7yhNo/HxCLeVvt4ZNBx4ltMEiYJNIYO6G0g
6FURuzT8Ea3czmt5v0m9YDIEQWKsMGC2jItq5UbKbCn0zLe9iibBSJsn5aPNpEgj
a8TXYdOoQoO112YhC6+QXk8M4Z4fx7mwPA8cumh3i7sLgLDPZK3Nvy1G/a6x8JVZ
g3W1Oyrbn29z1XANTAj2Q0NrdTogKUgNOLYRWB9SeONCnWQmxtzx3jlUIGSn5J9T
RBQo5ZIhRqOOe8Td3coU+OJ+Z2g7XETTlU3hYmi70/PeXaRxq3k9sX95LtnjgduK
r2H0KNxyhCmC8cdXL5ogBfnnLColW4Ya1/vyN7sAIQKBgQDwPYJcz3636j8xh1Pt
U4kxfA4ozqDOXK6jnl6ujhYfwhAghEEFqV2yWYkQbLkkQu2ewRuQxNYLCT+O6WBH
DF8uoYBtbdH47MLM+TuLUnglHEC1qwwaO62Eb+2cn5f1i5Z/mLQOG3uxlnSPbIC5
2mEpKmWqdFJAGwOF3/rbVr+88QKBgQDugSqpXgIg4RR3rRzUZog/ReieoG+cf2WO
rHfmIXBSACktfoQMlrgO/sD2zq1sjQXSUNbQCzMV7kIrLrb+Y7xtZljFJj3wSG/k
LQBJy1qk7uVfoFfndmYgrkb7+aNkMR0KrqEZPuS3bmXcD2BUzzgYsD9LoC5nD55U
EAnKGRE6jwKBgQCmtpiLnXZbXJQj47xrGig/jc4ppVJUQl7yrkkYKwPRYBNe7UhO
DH038gg6vKgyMLvDClD9woqit/VCUFN+mmhG7M45ohcu/eYk5ePbSAyV/CgvqZZJ
chZ0rFOg9+M1A3wZ6bcxfwL0dutGSE6AKrp4HbLVeclGMTjdo1Pq+CUwkQKBgQDU
MWEGTFgybm4qR38lzY8cVBMwxeZm4sU1GWaW/VsT6Ya5Lh1HofRhiu+c5aZPtGvg
gQGNGNm7gj2mc6plS9DBuFP0GyDyHVBHPm5KOT0NDmpOGLb8fE9Cdis7VQ+0PSns
bg9wCY+tTvAayCdZbP8on+3AV+PQ14lyms5K2uCEKwKBgQCrpoMycTrB2KOczWNp
kZouBK4tU5rGjBj3/0p+wHszyCOtiX5sdBT66eRHYY/t9YcOTWA8w3OO/8sj4X4d
nMsuXM/jD/NWW9JD9+vPUQz4db5evhQBNIkOG4FIRnSh15pDIcEeLxEamNV82fRS
26jlsLNCILTT9RsfswR3U+1GuA==
-----END PRIVATE KEY-----\0";

pub const ROOT_CA_CERT: &'static [u8] = b"-----BEGIN CERTIFICATE-----
MIIE4jCCAsqgAwIBAgIBATANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDEwZSb290
Q0EwHhcNMTkwOTA1MTg0NTMyWhcNMjEwMzA1MTg0NTI2WjARMQ8wDQYDVQQDEwZS
b290Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQD6AOBz7HbIi8w3
Wjjk16oglHRQcICTkvgfl6gbGuSjOoVHmOAn2EWT9AuXtcyNcVFyk90h0dsadqkJ
Enrk3BkTJQmtGW0u5UvcI+famYjZDvYQpGcgXBFmrH7/g/BN4v5VvdrXxUVy6Uyv
Ql60yG7JxlMY8K2OMV13bOpABXhnG/zNr1hCPLQWu52Mn3M1nudFBZff7tZz4dBo
YoMeXkIWQ3t2wypD3WunlQcuGxNOCcXONZRDzeUidh/Yv/4tTggZe8KAnEngKb86
KwKAhVjinGIN2C+ISpKsDurDxhExA2Na6+EbtLEgkI9AeoBz6tIjt/yv/inil+Du
fEDSmG+P97oY1GNcZMkftjjJd0u57YWz0Ck5bfHdgploh/1VHGdoC677MDWJOb31
O3mGdpTiBHP2Gh6Xwm8NuZc+tQSPVr/GaYg7slLBl/7GWU9QGjr9DGj/qYozD8tT
cazIHFh9zDP4XC+a+D+3lMA5EMfvVmDmr2QZJoiKBrxbNXXZ0QQcc+Wr9jFBBx/i
BRlpnxr+EDG+Q7nFnbG6x1DkvKhc1KDGBhq/HDb5bBVSr7Pjl2FMNh8HVX64mDbA
7clQJHa1rIjB+HxtZB5DNKQbRobyrWgkTpi5XHPhMw966zrhBWgOdAh+PSeq9FEf
Y0w328/EBWGqIg3rRMOvDAQpbojNdwIDAQABo0UwQzAOBgNVHQ8BAf8EBAMCAQYw
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUiS413SfVRGy7vVwkLIGdDA4y
yoswDQYJKoZIhvcNAQELBQADggIBAHcRzQhesOTpFG4KINJyzZf7a5lrc8kayTaL
lzSXW1pEl3/OFiMvOayjDq+yVAJB+5j3WZu8AOTFuZ4pBjz2I1hdIt5F2asqnVN3
8ymuC7t4gNAQGhWJldnsL58iTYGlxFciiT/8QSHJJjYRkKxyhF08Oj3Zbs13J4xc
ENLmwCZMFait+qm7aX3idnUa1XMGO26ioQOi0uEVqu9N4p62OQKd/76vmnaqmIAw
5s47DaaUi7DeiBguLZrNzfZcJTAHNM5VxCjsXW4PieN6mJhQSar40794n7HLHxtG
Xc5UdxT3nLclEAviDJFubA1N/szWtu4vdfehdAKCXkIjwoUEVEOpPYEeYr27JFlP
kaxezxswwxY2UD0MZq21FhO7SpVQdmmvfoJvjQwIsiyoa9UNzC6mTqsJPjln+2mK
p6WHzX+E6GeA7Ng6CyvJsHRsqbQdJ0OXHm4GIG2Z05r4AgBtvI6hkhSfAotBt3Xi
lo5BEO6SbUnPYo03zD4x/76c4j/uZLYxy2n+Qrlm2KTQIUu7KEsKdUnLAxjWYePH
VxcYz0/9Z5H4OzhW4J1Qd6OBW0dqETLlMJauPX5DV/slyYQQasPStEJGgiDiKG+B
Jpjv6PefPTqZawP6gPoGmhF4UyMRWZ+NgqLft1uXTHhrHdnrZFag1oPLjxWFs5hx
pElsC4v+
-----END CERTIFICATE-----\0";
}
