/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(all(feature = "std", feature = "tokio"))]

use std::cell::Cell;
use std::future::Future;
use std::io::{self, Read, Write};
use std::marker::Unpin;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::ptr::null_mut;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ssl::{Context, HandshakeError, MidHandshake, Session, Version};
use crate::x509::VerifyError;
use crate::Error;

#[derive(Clone)]
struct ErasedContext(Rc<Cell<*mut ()>>);

unsafe impl Send for ErasedContext {}

impl ErasedContext {
    fn new() -> Self {
        Self(Rc::new(Cell::new(null_mut())))
    }

    unsafe fn get(&self) -> &mut TaskContext<'_> {
        let ptr = self.0.get();
        assert!(!ptr.is_null());
        &mut *(ptr as *mut _)
    }

    fn set(&self, cx: &mut TaskContext<'_>) {
        self.0.set(cx as *mut _ as *mut ());
    }

    fn clear(&self) {
        self.0.set(null_mut());
    }
}

pub struct IoAdapter<S> {
    inner: S,
    ecx: ErasedContext,
}

impl<S> IoAdapter<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            ecx: ErasedContext::new(),
        }
    }
}

impl<S: Unpin> IoAdapter<S> {
    fn with_context<F, R>(&mut self, f: F) -> io::Result<R>
    where
        F: FnOnce(&mut TaskContext<'_>, Pin<&mut S>) -> Poll<io::Result<R>>,
    {
        unsafe {
            let cx = self.ecx.get();
            match f(cx, Pin::new(&mut self.inner)) {
                Poll::Ready(r) => r,
                Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        }
    }
}

impl<S: AsyncRead + Unpin> Read for IoAdapter<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        self.with_context(|ctx, stream| stream.poll_read(ctx, &mut buf))?;
        Ok(buf.filled().len())
    }
}

impl<S: AsyncWrite + Unpin> Write for IoAdapter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.with_context(|ctx, stream| stream.poll_write(ctx, buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.with_context(|ctx, stream| stream.poll_flush(ctx))
    }
}

struct SessionWrapper<'ctx>(Session<'ctx>);

impl<'a> Deref for SessionWrapper<'a> {
    type Target = Session<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for SessionWrapper<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> From<Session<'a>> for SessionWrapper<'a> {
    fn from(s: Session<'a>) -> Self {
        Self(s)
    }
}

impl Drop for SessionWrapper<'_> {
    fn drop(&mut self) {
        unsafe {
            self.0.release_io();
        }
        // Make sure `ssl_close_notify()` is not called since that would cause
        // a panic if `ecx` field in `AsyncSession` is not set.
        mem::forget(self);
    }
}

pub struct AsyncSession<'ctx> {
    session: Option<SessionWrapper<'ctx>>,
    ecx: ErasedContext,
}

unsafe impl<'c> Send for AsyncSession<'c> {}

struct Guard<'a, 'b>(&'a mut AsyncSession<'b>);

impl Drop for Guard<'_, '_> {
    fn drop(&mut self) {
        (self.0).ecx.clear();
    }
}

fn already_shutdown() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "stream has been shutdown")
}

impl<'c> AsyncSession<'c> {
    fn with_context<F, R>(&mut self, cx: &mut TaskContext<'_>, f: F) -> Poll<io::Result<R>>
    where
        F: FnOnce(&mut Session<'c>) -> io::Result<R>,
    {
        if self.session.is_none() {
            return Err(already_shutdown()).into();
        }
        self.ecx.set(cx);
        let g = Guard(self);
        match f(g.0.session.as_mut().unwrap()) {
            Ok(v) => Ok(v).into(),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Err(e).into(),
        }
    }

    fn poll_close_notify(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut session = match self.session.take() {
            Some(session) => session,
            None => return Err(already_shutdown()).into(),
        };
        self.ecx.set(cx);
        let res = unsafe { session.close_notify() };
        self.ecx.clear();

        match res {
            Ok(()) => Ok(()).into(),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.session = Some(session);
                Poll::Pending
            }
            Err(e) => Err(e).into(),
        }
    }
}

impl Drop for AsyncSession<'_> {
    fn drop(&mut self) {
        // Theoretically, we could use [`Handle::try_current()`] to get the
        // current runtime and [`Handle::block_on()`] to block on completion of
        // `self.shutdown()`, however there are some caveats to that approach
        // that make it very undesirable:
        //
        // - When using basic scheduler, we need to call [`Handle::block_on()`]
        //   in a separate thread, while with threaded scheduler we don't need
        //   a separate thread. However, there is no way to know which
        //   scheduler is being used, therefore we need to call `block_on` in a
        //   separate thread to support both schedulers.
        //
        // - To be able to `block_on(self.shutdown())` in a separate thread, we
        //   need to somehow send `self` or `self.shutdown()` to that thread,
        //   but that would normally require the object being sent to be
        //   `'static`. We could do some unsafe shenanigans to make that work,
        //   but is it really worth it?
        //
        // We should revisit this once there is support for async drop in Rust.
        //
        // [`Handle::try_current()`]: https://docs.rs/tokio/0.2.22/tokio/runtime/struct.Handle.html#method.try_current
        // [`Handle::block_on()`]: https://docs.rs/tokio/0.2.22/tokio/runtime/struct.Handle.html#method.block_on
    }
}

impl AsyncRead for AsyncSession<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(cx, |s| {
            let n = s.read(buf.initialize_unfilled())?;
            buf.advance(n);
            Ok(())
        })
    }
}

impl AsyncWrite for AsyncSession<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context(cx, |s| s.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.with_context(cx, |s| s.flush())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.poll_close_notify(cx)
    }
}

enum HandshakeState<'ctx> {
    Ready(AsyncSession<'ctx>),
    InProgress(MidHandshakeFuture<'ctx>),
}

struct StartHandshake<'a, 'b, 'c, S>(Option<StartHandshakeInner<'a, 'b, 'c, S>>);
struct StartHandshakeInner<'a, 'b, 'c, S> {
    context: &'b mut Context<'a>,
    io: &'b mut IoAdapter<S>,
    hostname: Option<&'c str>,
}

impl<'ctx, S: AsyncRead + AsyncWrite + Unpin> Future for StartHandshake<'_, 'ctx, '_, S> {
    type Output = Result<HandshakeState<'ctx>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let mut_self = self.get_mut();
        let inner = mut_self.0.take().expect("future polled after completion");

        inner.io.ecx.set(cx);
        let ecx = inner.io.ecx.clone();
        let output = match inner.context.establish_internal(inner.io, inner.hostname) {
            Ok(session) => Ok(HandshakeState::Ready(AsyncSession {
                session: Some(session.into()),
                ecx,
            })),
            Err(HandshakeError::WouldBlock(mid, _err)) => Ok(HandshakeState::InProgress(
                MidHandshakeFuture(Some(MidHandshakeFutureInner { mid, ecx })),
            )),
            Err(HandshakeError::Failed(err)) => Err(err),
        };
        output.into()
    }
}

struct MidHandshakeFuture<'ctx>(Option<MidHandshakeFutureInner<'ctx>>);
struct MidHandshakeFutureInner<'ctx> {
    mid: MidHandshake<'ctx>,
    ecx: ErasedContext,
}

impl<'c> Future for MidHandshakeFuture<'c> {
    type Output = Result<AsyncSession<'c>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let mut_self = self.get_mut();
        let mut inner = mut_self.0.take().expect("future polled after completion");

        inner.ecx.set(cx);
        match inner.mid.handshake() {
            Ok(session) => {
                inner.ecx.clear();
                Ok(AsyncSession {
                    session: Some(session.into()),
                    ecx: inner.ecx,
                }).into()
            }
            Err(HandshakeError::WouldBlock(mid, _err)) => {
                inner.ecx.clear();
                inner.mid = mid;
                mut_self.0 = Some(inner);
                Poll::Pending
            }
            Err(HandshakeError::Failed(e)) => Err(e).into(),
        }
    }
}

impl<'config> Context<'config> {
    pub async fn establish_async<'c, S: AsyncRead + AsyncWrite + Unpin>(
        &'c mut self,
        io: &'c mut IoAdapter<S>,
        hostname: Option<&str>,
    ) -> Result<AsyncSession<'c>, Error> {
        let start = StartHandshake(Some(StartHandshakeInner {
            context: self,
            io,
            hostname,
        }));
        match start.await {
            Ok(HandshakeState::Ready(session)) => Ok(session),
            Ok(HandshakeState::InProgress(fut)) => fut.await,
            Err(err) => Err(err),
        }
    }
}

// Forward method calls instead of Deref since that would enable Read/Write
impl<'a> AsyncSession<'a> {
    fn session(&self) -> io::Result<&Session<'a>> {
        self.session
            .as_ref()
            .map(|s| s.deref())
            .ok_or_else(|| already_shutdown())
    }

    /// Return the minor number of the negotiated TLS version
    pub fn minor_version(&self) -> io::Result<i32> {
        self.session().map(|session| session.minor_version())
    }

    /// Return the major number of the negotiated TLS version
    pub fn major_version(&self) -> io::Result<i32> {
        self.session().map(|session| session.major_version())
    }

    /// Return the number of bytes currently available to read that
    /// are stored in the Session's internal read buffer
    pub fn bytes_available(&self) -> io::Result<usize> {
        self.session().map(|session| session.bytes_available())
    }

    pub fn version(&self) -> io::Result<Version> {
        self.session().map(|session| session.version())
    }

    /// Return the 16-bit ciphersuite identifier.
    /// All assigned ciphersuites are listed by the IANA in
    /// https://www.iana.org/assignments/tls-parameters/tls-parameters.txt
    pub fn ciphersuite(&self) -> io::Result<u16> {
        self.session().map(|session| session.ciphersuite())
    }

    pub fn peer_cert(&self) -> io::Result<Option<crate::x509::certificate::Iter>> {
        self.session().map(|session| session.peer_cert())
    }

    pub fn verify_result(&self) -> io::Result<Result<(), VerifyError>> {
        self.session().map(|session| session.verify_result())
    }

    pub fn get_alpn_protocol(&self) -> io::Result<Result<Option<&'a str>, Error>> {
        self.session().map(|session| session.get_alpn_protocol())
    }
}
