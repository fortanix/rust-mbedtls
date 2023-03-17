/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(all(feature = "std", feature = "async"))]
    
use std::cell::Cell;
use std::ptr::null_mut;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll};


#[cfg(feature = "std")]
use std::io::{Error as IoError, Result as IoResult, ErrorKind as IoErrorKind};


#[derive(Clone)]
pub struct ErasedContext(Rc<Cell<*mut ()>>);

unsafe impl Send for ErasedContext {}

impl ErasedContext {
    pub fn new() -> Self {
        Self(Rc::new(Cell::new(null_mut())))
    }

    pub unsafe fn get(&self) -> Option<&mut TaskContext<'_>> {
        let ptr = self.0.get();
        if ptr.is_null() {
            None 
        } else {
            Some(&mut *(ptr as *mut _))
        }
    }

    pub fn set(&self, cx: &mut TaskContext<'_>) {
        self.0.set(cx as *mut _ as *mut ());
    }

    pub fn clear(&self) {
        self.0.set(null_mut());
    }
}

// mbedtls_ssl_write() has some weird semantics w.r.t non-blocking I/O:
//
// > When this function returns MBEDTLS_ERR_SSL_WANT_WRITE/READ, it must be
// > called later **with the same arguments**, until it returns a value greater
// > than or equal to 0. When the function returns MBEDTLS_ERR_SSL_WANT_WRITE
// > there may be some partial data in the output buffer, however this is not
// > yet sent.
//
// WriteTracker is used to ensure we pass the same data in that scenario.
//
// Reference:
// https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
pub struct WriteTracker {
    pending: Option<Box<DigestAndLen>>,
}

struct DigestAndLen {
    #[cfg(debug_assertions)]
    digest: [u8; 20], // SHA-1
    len: usize,
}

impl WriteTracker {
    fn new() -> Self {
        WriteTracker {
            pending: None,
        }
    }

    #[cfg(debug_assertions)]
    fn digest(buf: &[u8]) -> [u8; 20] {
        use crate::hash::{Md, Type};
        let mut out = [0u8; 20];
        let res = Md::hash(Type::Sha1, buf, &mut out[..]);
        assert_eq!(res, Ok(out.len()));
        out
    }

    pub fn adjust_buf<'a>(&self, buf: &'a [u8]) -> IoResult<&'a [u8]> {
        match self.pending.as_ref() {
            None => Ok(buf),
            Some(pending) => {
                if pending.len <= buf.len() {
                    let buf = &buf[..pending.len];

                    // We only do this check in debug mode since it's an expensive check.
                    #[cfg(debug_assertions)]
                    if Self::digest(buf) == pending.digest {
                        return Ok(buf);
                    }

                    #[cfg(not(debug_assertions))]
                    return Ok(buf);
                }
                Err(IoError::new(
                    IoErrorKind::Other,
                    "mbedtls expects the same data if the previous call to poll_write() returned Poll::Pending"
                ))
            },
        }
    }

    pub fn post_write(&mut self, buf: &[u8], res: &Poll<IoResult<usize>>) {
        match res {
            &Poll::Pending => {
                if self.pending.is_none() {
                    self.pending = Some(Box::new(DigestAndLen {
                        #[cfg(debug_assertions)]
                        digest: Self::digest(buf),
                        len: buf.len(),
                    }));
                }
            },
            _ => {
                self.pending = None;
            }
        }
    }
}

pub struct IoAdapter<S> {
    pub inner: S,
    pub ecx: ErasedContext,
    pub write_tracker: WriteTracker,
}

impl<S> IoAdapter<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            ecx: ErasedContext::new(),
            write_tracker: WriteTracker::new(),
        }
    }
}
