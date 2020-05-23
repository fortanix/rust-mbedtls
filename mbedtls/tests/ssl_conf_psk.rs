#![allow(dead_code)]
extern crate mbedtls;

use std::net::TcpStream;

mod support;
use support::entropy::entropy_new;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context, HandshakeContext};
use mbedtls::Result as TlsResult;


fn client(mut conn: TcpStream, psk: &[u8]) -> TlsResult<()> {
    {
        let mut entropy = entropy_new();
        let mut rng = CtrDrbg::new(&mut entropy, None)?;
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_rng(Some(&mut rng));
        config.set_psk(psk, "Client_identity")?;
        let mut ctx = Context::new(&config)?;
        ctx.establish(&mut conn, None).map(|_| ())?;
        Ok(())
    }
}

fn server<F>(mut conn: TcpStream, mut psk_callback: F) -> TlsResult<()>
    where
        F: FnMut(&mut HandshakeContext, &str) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.set_psk_callback(&mut psk_callback);
    let mut ctx = Context::new(&config)?;
    let _ = ctx.establish(&mut conn, None)?;
    Ok(())
}

#[cfg(unix)]
mod test {
    use super::*;
    use std::thread;
    use crate::support::net::create_tcp_pair;
    use crate::support::keys;

    #[test]
    fn callback_standard_psk() {
        let (c, s) = create_tcp_pair().unwrap();
        let psk_callback = 
            |ctx: &mut HandshakeContext, _: &str| { ctx.set_psk(keys::PRESHARED_KEY) };
        let c = thread::spawn(move || super::client(c, keys::PRESHARED_KEY).unwrap());
        let s = thread::spawn(move || super::server(s, psk_callback).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }
}
