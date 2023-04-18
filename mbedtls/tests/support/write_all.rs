
#![cfg(all(feature = "std", feature = "async"))]
use tokio::io::AsyncWrite;

use pin_project_lite::pin_project;
use std::future::Future;
use std::io;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    #[derive(Debug)]
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct WriteAll<'a, W: ?Sized> {
        writer: &'a mut W,
        buf: &'a [u8],
        l: usize,
        r: usize,
        // Make this future `!Unpin` for compatibility with async trait methods.
        #[pin]
        _pin: PhantomPinned,
    }
}

pub(crate) fn write_all<'a, W>(writer: &'a mut W, buf: &'a [u8]) -> WriteAll<'a, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let min_len = 1000;
    assert!(buf.len() > min_len, "Please provide a buffer with length > {}", min_len);
    WriteAll {
        writer,
        buf,
        l: 0,
        r: min_len,
        _pin: PhantomPinned,
    }
}

impl<W> Future for WriteAll<'_, W>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.project();
        while me.l < me.r {
            let buf_len = me.buf.len();
            match Pin::new(&mut *me.writer).poll_write(cx, &me.buf[*me.l..*me.r]){
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    *me.l += n;
                    *me.r += n;
                    if *me.r > buf_len {
                        *me.r = buf_len;
                    }
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    *me.r = *me.l + (*me.r - *me.l) * 101 / 100 ;
                    if *me.r > buf_len {
                        *me.r = buf_len;
                    }
                    return Poll::Pending;
                },
            }
        }

        Poll::Ready(Ok(()))
    }
}
