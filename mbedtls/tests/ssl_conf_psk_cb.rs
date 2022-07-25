/* Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(not(target_env = "sgx"))]

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::net::TcpStream;
use std::sync::Arc;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::ssl::context::HandshakeContext;
use mbedtls::Result as TlsResult;
use mbedtls::ssl::config::PskCallback;

mod support;
use support::entropy::entropy_new;

fn client(conn: TcpStream, psk: &[u8]) -> TlsResult<()>
{
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_psk(psk, "Client_identity")?;
    let mut ctx = Context::new(Arc::new(config));
    ctx.establish(conn, None).map(|_| ())
}

fn server<F>(conn: TcpStream, psk_callback: F) -> TlsResult<()>
    where
        F: PskCallback + Send + 'static,
{
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_psk_callback(psk_callback);
    let mut ctx = Context::new(Arc::new(config));
    ctx.establish(conn, None).map(|_| ())
}

mod test {
    use super::*;
    use std::thread;
    use crate::support::net::create_tcp_pair;
    use crate::support::keys;

    #[test]
    fn callback_standard_psk() {
        let (c, s) = create_tcp_pair().unwrap();

        let psk_callback =
            |ctx: &mut HandshakeContext, _: &str| {
                ctx.set_psk(keys::PRESHARED_KEY)
            };
        let c = thread::spawn(move || super::client(c, keys::PRESHARED_KEY).unwrap());
        let s = thread::spawn(move || super::server(s, psk_callback).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }
}
