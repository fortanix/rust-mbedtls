/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(not(target_env = "sgx"))]
extern crate mbedtls;

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use hyper14::client::connect::{Connected, Connection};
use hyper14::client::Client;
use hyper14::rt::Executor;
use hyper14::server::{accept::Accept, Server};
use hyper14::service::{make_service_fn, service_fn, Service};
use hyper14::{Body, Method, Request, Response, StatusCode, Uri};
use mbedtls::ssl::{Config, Context as MbedtlsContext};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
mod support;
use support::rand::test_rng;

use futures::stream::FuturesUnordered;
use futures::Stream;
use futures::StreamExt;

#[derive(Debug)]
struct ForceHttpsButUriNotHttps;

impl StdError for ForceHttpsButUriNotHttps {}

impl fmt::Display for ForceHttpsButUriNotHttps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("https required but URI was not https")
    }
}

#[derive(Clone)]
pub struct HttpsConnector {
    config: Arc<Config>,
    verify_hostname: bool,

    // This can be used when verify_hostname is set to true.
    // It will force ssl client to send this specific SNI on all established connections disregarding any host provided by
    // hyper.
    override_sni: Option<String>,
}

const DEFAULT_HTTPS_PORT: u16 = 443;

impl Service<Uri> for HttpsConnector {
    type Response = AsyncTlsStream<MbedtlsContext<TcpStream>>;
    type Error = Box<dyn StdError + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        // Strip [] for IPv6 addresses
        let host = dst.host().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_owned();
        let port = dst.port_u16().unwrap_or(DEFAULT_HTTPS_PORT);
        let verify_hostname: Option<String> = match self.verify_hostname {
            true => self.override_sni.clone().or(Some(host.clone())),
            false => None,
        };
        let config = self.config.clone();
        Box::pin(async move {
            if dst.scheme_str() != Some("https") {
                return Err(ForceHttpsButUriNotHttps.into());
            }

            let tcp = TcpStream::connect((host.clone(), port)).await?;
            let mut tls = MbedtlsContext::new(config);

            tls.establish_async(tcp, verify_hostname.as_deref()).await?;
            Ok(AsyncTlsStream(tls))
        })
    }
}

pub struct AsyncTlsStream<T: Unpin>(T);

impl<T: Unpin> Connection for AsyncTlsStream<T> {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        connected
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for AsyncTlsStream<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext, read_buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, read_buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for AsyncTlsStream<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[derive(Copy, Clone)]
pub struct TokioExecutor;

impl<F> Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

pub struct HyperAcceptor {
    clients: FuturesUnordered<tokio::task::JoinHandle<Result<AsyncTlsStream<MbedtlsContext<TcpStream>>, IoError>>>,
    listener: TcpListener,
    config: Arc<Config>,
}

impl HyperAcceptor {
    pub async fn create(config: Arc<Config>, addr: &str) -> Result<HyperAcceptor, IoError> {
        let listener = TcpListener::bind(addr).await?;

        Ok(HyperAcceptor {
            clients: FuturesUnordered::new(),
            listener,
            config,
        })
    }
}

const MAX_CONCURRENT_ACCEPTS: usize = 100;

impl Accept for HyperAcceptor {
    type Conn = AsyncTlsStream<MbedtlsContext<TcpStream>>;
    type Error = IoError;

    fn poll_accept(mut self: Pin<&mut Self>, cx: &mut TaskContext) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        if self.clients.len() < MAX_CONCURRENT_ACCEPTS {
            match self.listener.poll_accept(cx) {
                Poll::Pending => (),
                Poll::Ready(Ok((conn, _addr))) => {
                    let config = self.config.clone();
                    self.clients.push(tokio::spawn(async move {
                        let mut context = MbedtlsContext::new(config);
                        context
                            .establish_async(conn, None)
                            .await
                            .map_err(|e| IoError::new(IoErrorKind::Other, e.to_string()))?;
                        Ok(AsyncTlsStream(context))
                    }));
                }
                Poll::Ready(Err(e)) => {
                    // We likely don't care about user errors enough to stop processing under normal
                    // circumstances
                    return Poll::Ready(Some(Err(e)));
                }
            };
        }

        if self.clients.len() > 0 {
            match Pin::new(&mut self.clients).poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(v)) => Poll::Ready(Some(v?)), // fold Result<Result
                Poll::Ready(None) => Poll::Ready(None),
            }
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    use mbedtls::pk::Pk;
    use mbedtls::ssl::config::{AuthMode, Endpoint, Preset, Transport, Version};
    use mbedtls::x509::Certificate;
    use rstest::rstest;
    use tokio::sync::oneshot;

    #[cfg(not(target_env = "sgx"))]
    use mbedtls::rng::{CtrDrbg, OsEntropy};

    #[cfg(target_env = "sgx")]
    use mbedtls::rng::Rdrand;

    // use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // use tokio::stream::StreamExt;
    use futures::stream::FuturesUnordered;

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

    pub const PEM_KEY: &'static [u8] = concat!(include_str!("./support/keys/user.key"), "\0").as_bytes();
    pub const PEM_CERT: &'static [u8] = concat!(include_str!("./support/keys/user.crt"), "\0").as_bytes();
    pub const ROOT_CA_CERT: &'static [u8] = concat!(include_str!("./support/keys/ca.crt"), "\0").as_bytes();
    // root cert downloaded from Google Trust Services: https://pki.goog/roots.pem
    pub const GOOGLE_ROOT_CA_CERT: &'static [u8] = concat!(include_str!("./support/keys/roots.pem"), "\0").as_bytes();

    #[rstest]
    #[case::tls12(Version::Tls12)]
    #[case::tls13(Version::Tls13)]
    #[tokio::test]
    async fn async_hyper_client_test(#[case] ver: Version) {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(ver).unwrap();
        config.set_max_version(ver).unwrap();
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(GOOGLE_ROOT_CA_CERT).unwrap()), None);

        let https = HttpsConnector {
            config: Arc::new(config),
            verify_hostname: true,
            override_sni: None,
        };
        let client = Client::builder().executor(TokioExecutor).build::<_, Body>(https);

        let res = client.get("https://www.google.com".parse().unwrap()).await.unwrap();
        assert_eq!(res.status(), 200);
    }

    async fn echo(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let mut response = Response::new(Body::empty());

        match (req.method(), req.uri().path()) {
            (&Method::GET, "/") => *response.body_mut() = Body::from("Try POST /echo\n"),
            (&Method::POST, "/echo") => *response.body_mut() = req.into_body(),
            _ => *response.status_mut() = StatusCode::NOT_FOUND,
        };

        Ok(response)
    }

    async fn get_acceptor(address: &str) -> Result<HyperAcceptor, IoError> {
        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

        config.set_rng(rng_new());
        config.set_authmode(AuthMode::None);
        config.set_min_version(Version::Tls12).unwrap();
        config.set_min_version(Version::Tls13).unwrap();
        let sig_algs = Arc::new(mbedtls::ssl::tls13_preset_default_sig_algs());
        config.set_signature_algorithms(sig_algs);
        let cert = Arc::new(Certificate::from_pem_multiple(PEM_CERT).unwrap());
        let key = Arc::new(Pk::from_private_key(&mut test_rng(), PEM_KEY, None).unwrap());
        config.push_cert(cert, key).unwrap();

        HyperAcceptor::create(Arc::new(config), address).await
    }

    #[rstest]
    #[case::tls12(Version::Tls12)]
    #[case::tls13(Version::Tls13)]
    #[tokio::test]
    async fn async_hyper_server_full_handshake_test(#[case] ver: Version) {
        // Set up hyper server to echo function and a graceful shutdown
        let acceptor = get_acceptor("127.0.0.1:0").await.unwrap();
        let local_addr = acceptor.listener.local_addr().unwrap().clone();

        let service = make_service_fn(|_| async { Ok::<_, IoError>(service_fn(echo)) });
        let server = Server::builder(acceptor).executor(TokioExecutor).serve(service);

        let (tx, rx) = oneshot::channel::<()>();
        let graceful = server.with_graceful_shutdown(async {
            rx.await.ok();
        });

        let s = tokio::spawn(graceful);

        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_authmode(AuthMode::Required);
        config.set_rng(rng_new());
        config.set_min_version(ver).unwrap();
        config.set_max_version(ver).unwrap();
        config.set_ca_list(Arc::new(Certificate::from_pem_multiple(ROOT_CA_CERT).unwrap()), None);
        let config = Arc::new(config);

        let mut clients = FuturesUnordered::new();
        for _ in 0..5 {
            let config = config.clone();

            clients.push(tokio::spawn(async move {
                let client = Client::builder()
                    .executor(TokioExecutor)
                    .build::<_, hyper14::Body>(HttpsConnector {
                        config,
                        verify_hostname: true,
                        override_sni: Some("mbedtls.example".to_string()),
                    });

                let res = client.get(format!("https://{}/", local_addr).parse().unwrap()).await.unwrap();
                assert_eq!(res.status(), 200);

                let body_bytes = hyper14::body::to_bytes(res.into_body()).await.unwrap();
                let body = String::from_utf8(body_bytes.to_vec()).expect("response was not valid utf-8");
                assert_eq!(body, "Try POST /echo\n");
            }));

            if clients.len() > MAX_CONCURRENT_ACCEPTS {
                let _ = clients.next().await.unwrap();
            }
        }

        while let Some(r) = clients.next().await {
            r.unwrap();
        }

        let _ = tx.send(());
        s.await.unwrap().unwrap();
    }
}
