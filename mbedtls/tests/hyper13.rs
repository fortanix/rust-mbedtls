#![allow(unused_imports)]


use async_stream::stream;

use std::fmt;
use std::future::Future;
use std::io;
use std::io::{Error as IoError};
use std::pin::Pin;
use std::sync::{Arc};
use std::task::{Context as TaskContext, Poll};
use std::net::SocketAddr;

use hyper13::Server;
use hyper13::service::{make_service_fn, service_fn};
use hyper13::client::connect::{Connected, Connection};
use hyper13::{Client, service::Service, Uri, Request, Body, Method, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, TcpListener};
use tokio_02::io::{AsyncRead as AsyncRead02, AsyncWrite as AsyncWrite02};

use mbedtls::ssl::async_utils::IoAdapter;
use mbedtls::ssl::{Config, AsyncContext};

use futures::stream::{FuturesUnordered};

#[derive(Clone)]
pub struct HttpsConnector {
    config: Arc<Config>,
}

#[derive(Debug)]
struct ForceHttpsButUriNotHttps;

impl std::error::Error for ForceHttpsButUriNotHttps {}

impl fmt::Display for ForceHttpsButUriNotHttps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("https required but URI was not https")
    }
}

const DEFAULT_HTTPS_PORT: u16 = 443;

impl Service<Uri> for HttpsConnector {
    type Response = IoCompat<AsyncContext<TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        // Strip [] for IPv6 addresses
        let host = dst.host().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_owned();
        let port = dst.port_u16().unwrap_or(DEFAULT_HTTPS_PORT);
        let config = self.config.clone();

        Box::pin(async move {
            if dst.scheme_str() != Some("https") {
                return Err(ForceHttpsButUriNotHttps.into());
            }

            let tcp = TcpStream::connect((host.clone(), port)).await?;
            let mut tls = AsyncContext::new(config);
            tls.establish_async(tcp, Some(&host)).await?;
            Ok(IoCompat(tls))
        })
    }
}

// IoCompat is needed because hyper 0.13 relies on tokio 0.2's `AsyncRead`
// and `AsyncWrite` traits. It would have been nice if we could use
// `tokio_compat_02::IoCompat`, but that type does not implement `Connection`
// and we cannot impl `Connection` for it here either since it's not defined
// in this crate.
pub struct IoCompat<T: Unpin>(T);

impl<T: Unpin> Connection for IoCompat<T> {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        //check_alpn(&self.0, connected)
        connected
    }
}

impl<T: AsyncRead + Unpin> AsyncRead02 for IoCompat<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut self.get_mut().0).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite02 for IoCompat<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[derive(Copy, Clone)]
pub struct TokioExecutor;

impl<F> hyper13::rt::Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}



use tokio_02::stream::Stream;

type TlsFuture = Pin<Box<dyn Future<Output = Result<IoCompat<AsyncContext<TcpStream>>, IoError>> + Send>>;

pub struct HyperAcceptor {
    clients: FuturesUnordered<tokio::task::JoinHandle<Result<IoCompat<mbedtls::ssl::Context<IoAdapter<tokio::net::TcpStream>>>, io::Error>>>,
    listener: TcpListener,
    config: Arc<Config>,
}

impl HyperAcceptor {
    pub async fn create(config: Arc<Config>, addr: &str) -> Result<HyperAcceptor, io::Error> {
        let listener = TcpListener::bind(addr).await?;
        
        Ok(HyperAcceptor {
            clients: FuturesUnordered::new(),
            listener,
            config,
        })
    }
}

const MAX_CONCURRENT_ACCEPTS: usize = 100;

impl hyper13::server::accept::Accept for HyperAcceptor {
    type Conn = IoCompat<AsyncContext<TcpStream>>;
    type Error = io::Error;

    fn poll_accept(mut self: Pin<&mut Self>, cx: &mut TaskContext,) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        if self.clients.len() < MAX_CONCURRENT_ACCEPTS {
            match self.listener.poll_accept(cx) {
                Poll::Pending => (),
                Poll::Ready(Ok((conn, _addr))) => {
                    let config = self.config.clone();
                    self.clients.push(tokio::spawn(async move {
                        let context = AsyncContext::accept_async(config, conn, None).await?;
                        Ok(IoCompat(context))
                    }));
                },
                Poll::Ready(Err(e)) => {
                    // We likely don't care about user errors enough to stop processing under normal circumstances
                    return Poll::Ready(Some(Err(e)));
                },
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
    use mbedtls::ssl::Config;
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode, Version, UseSessionTickets, Renegotiation};
    use mbedtls::ssl::context::HandshakeContext;
    use mbedtls::x509::{Certificate, VerifyError};
    use std::sync::Arc;
    use mbedtls::ssl::CipherSuite::*;
    use std::io::Write;
    use mbedtls::ssl::TicketContext;
    use std::time::Instant;
    
    #[cfg(not(target_env = "sgx"))]
    use mbedtls::rng::{OsEntropy, CtrDrbg, HmacDrbg};

    #[cfg(target_env = "sgx")]
    use mbedtls::rng::{Rdrand};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_02::stream::StreamExt;
    use futures::stream::{FuturesUnordered};
    
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
    
    pub const PEM_KEY: &'static [u8] = concat!(include_str!("./support/keys/user.key"),"\0").as_bytes();
    pub const PEM_CERT: &'static [u8] = concat!(include_str!("./support/keys/user.crt"),"\0").as_bytes();
    pub const ROOT_CA_CERT: &'static [u8] = concat!(include_str!("./support/keys/ca.crt"),"\0").as_bytes();
    
    #[tokio::test]
    async fn async_hyper_client_test() {

        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_authmode(AuthMode::None);
        config.set_rng(rng_new());
        config.set_min_version(Version::Tls1_2).unwrap();

        let https = HttpsConnector { config: Arc::new(config) };
        let client = Client::builder().executor(TokioExecutor).build::<_, hyper13::Body>(https);
        
        let res = client.get("https://hyper.rs".parse().unwrap()).await.unwrap();
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

    async fn get_acceptor(address: &str) -> Result<HyperAcceptor, io::Error> {
        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

        config.set_rng(rng_new());
        config.set_authmode(AuthMode::None);
        config.set_min_version(Version::Tls1_2).unwrap();

        let cert = Arc::new(Certificate::from_pem_multiple(PEM_CERT).unwrap());
        let key = Arc::new(Pk::from_private_key(PEM_KEY, None).unwrap());
        config.push_cert(cert, key).unwrap();

        HyperAcceptor::create(Arc::new(config), address).await
    }

    #[tokio::test]
    async fn async_hyper_server_fullhandshake_test() {
        std::env::set_var("RUST_BACKTRACE", "full");

        // Set up hyper server to echo function and a graceful shutdown
        let acceptor = get_acceptor("127.0.0.1:0").await.unwrap();
        let local_addr = acceptor.listener.local_addr().unwrap().clone();
        
        let service = make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(echo)) });
        let server = Server::builder(acceptor).executor(TokioExecutor).serve(service);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let graceful = server.with_graceful_shutdown(async { rx.await.ok(); });

        let s = tokio::spawn(graceful);

        let mut clients = FuturesUnordered::new();

        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_authmode(AuthMode::None);
        config.set_rng(rng_new());
        config.set_min_version(Version::Tls1_2).unwrap();
        let config = Arc::new(config);

        let start = Instant::now();
        
        for _ in 0..100 {
            let config = config.clone();

            clients.push(tokio::spawn(async move {
                let client = Client::builder().executor(TokioExecutor).build::<_, hyper13::Body>(HttpsConnector { config });

                let mut res = client.get(format!("https://{}/", local_addr).parse().unwrap()).await.unwrap();
                assert_eq!(res.status(), 200);
                
                let body_bytes = hyper13::body::to_bytes(res.into_body()).await.unwrap();
                let body = String::from_utf8(body_bytes.to_vec()).expect("response was not valid utf-8");
                assert_eq!(body, "Try POST /echo\n");
            }));
            
            if clients.len() > MAX_CONCURRENT_ACCEPTS {
                clients.next().await.unwrap();
            }
        }

        while let Some(r) = clients.next().await {
            r.unwrap();
        }

        tx.send(());
        s.await.unwrap().unwrap();
    }    
}
