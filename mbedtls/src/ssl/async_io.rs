/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(all(feature = "std", feature = "async"))]

use crate::{
    error::{Error, Result, codes},
    ssl::{
        context::Context,
        io::{IoCallback, IoCallbackUnsafe},
    },
};
use std::{
    future::Future,
    io::Result as IoResult,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Marker type for an IO implementation that implements both
/// `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`.
pub enum AsyncStream {}

// TODO: Add enum `AnyAsyncIo` as marker type for an IO implementation that
// doesn't implement `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`.

// TODO: Add `AsyncIo` trait for async IO that that doesn't implement
// `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`. For example:
//     pub trait AsyncIo {
//        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
//         async fn send(&mut self, buf: &[u8]) -> Result<usize>;
//     }
// Could implement by using `async-trait` crate or
// #![feature(async_fn_in_trait)] or Associated Types

impl<'a, 'b, 'c, IO: AsyncRead + AsyncWrite + std::marker::Unpin + 'static> IoCallback<AsyncStream>
    for (&'a mut TaskContext<'b>, &'c mut IO)
{
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut buf = ReadBuf::new(buf);
        let io = Pin::new(&mut self.1);
        match io.poll_read(self.0, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(_)) => Err(codes::NetRecvFailed.into()),
            Poll::Pending => Err(codes::SslWantRead.into()),
        }
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize> {
        let io = Pin::new(&mut self.1);
        match io.poll_write(self.0, buf) {
            Poll::Ready(Err(_)) => Err(codes::NetSendFailed.into()),
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Pending => Err(codes::SslWantWrite.into()),
        }
    }
}

impl<T: Unpin + AsyncRead + AsyncWrite + 'static> Context<T> {
    pub async fn establish_async<IoType>(&mut self, io: T, hostname: Option<&str>) -> Result<()>
    where
        for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<IoType>,
    {
        struct HandshakeFuture<'a, T>(&'a mut Context<T>);
        impl<T> Future for HandshakeFuture<'_, T>
        where
            for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
        {
            type Output = Result<()>;
            fn poll(mut self: Pin<&mut Self>, ctx: &mut TaskContext) -> std::task::Poll<Self::Output> {
                self.0
                    .with_bio_async(ctx, |ssl_ctx| match ssl_ctx.handshake() {
                        Err(e) if matches!(e.high_level(), Some(codes::SslWantRead | codes::SslWantWrite)) => Poll::Pending,
                        Err(e) => Poll::Ready(Err(e)),
                        Ok(()) => Poll::Ready(Ok(())),
                    })
                    .unwrap_or(Poll::Ready(Err(Error::from(codes::NetSendFailed))))
            }
        }

        self.prepare_handshake(io, hostname)?;

        HandshakeFuture(self).await
    }
}

impl<T: AsyncRead> AsyncRead for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        self.with_bio_async(cx, |ssl_ctx| loop {
            match ssl_ctx.recv(buf.initialize_unfilled()) {
                Err(e) if e.high_level() == Some(codes::SslPeerCloseNotify) => return Poll::Ready(Ok(())),
                #[cfg(not(feature = "tls13"))]
                Err(e) if e.high_level() == Some(codes::SslWantRead) => return Poll::Pending,
                #[cfg(feature = "tls13")]
                Err(e) if e.high_level() == Some(codes::SslWantRead) => {
                    // In TLS 1.3, mbedtls decided to leave user to handle logic of saving `NewSessionTicket`
                    // When using a client, it's possible that we were waiting for application data
                    // but got a NewSessionTicket instead. In this case, mbedtls
                    // might return `SslWantRead` to indicate to read incoming data of
                    // `NewSessionTicket`.
                    // There is an issue for tracking: https://github.com/Mbed-TLS/mbedtls/issues/6640
                    if matches!(ssl_ctx.config().endpoint(), super::config::Endpoint::Client)
                        && ssl_ctx.handle().private_state as mbedtls_sys::ssl_states
                            == super::ssl_states::SslStates::Tls13NewSessionTicket.into()
                    {
                        continue;
                    }
                    return Poll::Pending;
                }
                // In TLS 1.3, mbedtls decided to leave user to handle logic of saving `NewSessionTicket`
                // When using a client, it's possible that we were waiting for application data but got a `NewSessionTicket`
                // instead. In this case, mbedtls will return `SslReceivedNewSessionTicket` Error, here we catch it and
                // continue reading since we accept session resumption.
                // There is an issue for tracking: https://github.com/Mbed-TLS/mbedtls/issues/6640
                #[cfg(feature = "tls13")]
                Err(e) if e.high_level() == Some(codes::SslReceivedNewSessionTicket) => continue,
                Err(e) => return Poll::Ready(Err(crate::private::error_to_io_error(e))),
                Ok(i) => {
                    buf.advance(i);
                    return Poll::Ready(Ok(()));
                }
            }
        })
        .unwrap_or_else(|| Poll::Ready(Err(crate::private::error_to_io_error(Error::from(codes::NetRecvFailed)))))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Context<T>
where
    for<'c, 'cx> (&'c mut TaskContext<'cx>, &'c mut T): IoCallbackUnsafe<AsyncStream>,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        self
            .with_bio_async(cx, |ssl_ctx| match ssl_ctx.async_write(buf) {
                Err(e) if e.high_level() == Some(codes::SslPeerCloseNotify) => Poll::Ready(Ok(0)),
                Err(e) if e.high_level() == Some(codes::SslWantWrite) => Poll::Pending,
                Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
                Ok(i) => Poll::Ready(Ok(i)),
            })
            .unwrap_or_else(|| Poll::Ready(Err(crate::private::error_to_io_error(Error::from(codes::NetSendFailed)))))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        match self
            .with_bio_async(cx, Context::flush_output)
            .unwrap_or(Err(Error::from(codes::NetSendFailed)))
        {
            Err(e) if e.high_level() == Some(codes::SslWantWrite) => Poll::Pending,
            Err(e) => Poll::Ready(Err(crate::private::error_to_io_error(e))),
            Ok(()) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        match self
            .with_bio_async(cx, Context::close_notify)
            .unwrap_or(Err(Error::from(codes::NetSendFailed)))
        {
            Err(e) if matches!(e.high_level(), Some(codes::SslWantRead | codes::SslWantWrite)) => Poll::Pending,
            Err(e) => {
                self.drop_io();
                Poll::Ready(Err(crate::private::error_to_io_error(e)))
            }
            Ok(()) => {
                self.drop_io();
                Poll::Ready(Ok(()))
            }
        }
    }
}

// TODO: AsyncIo impl for tokio::net::UdpSocket
