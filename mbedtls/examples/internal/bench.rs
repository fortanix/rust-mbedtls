/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![cfg(not(target_env = "sgx"))]

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mbedtls::alloc::{Box as MbedtlsBox, CString, List as MbedtlsList};
use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::TicketContext;
use mbedtls::ssl::UseSessionTickets;
use mbedtls::ssl::config::AuthMode;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::context::Timer;
use mbedtls::ssl::io::{ConnectedUdpSocket, IoCallback};
use mbedtls::ssl::CipherSuite;
use mbedtls::ssl::{Config, Context, CookieContext, Io, Version};
use mbedtls::x509::{Certificate, VerifyError};
use mbedtls::Error;
use mbedtls::Result as TlsResult;
use std::sync::Arc;

#[path = "../../tests/support/mod.rs"]
mod support;
use support::entropy::entropy_new;
use support::keys;

fn duration_nanos(d: Duration) -> f64 {
    (d.as_secs() as f64) + f64::from(d.subsec_nanos()) / 1e9
}

fn time<F>(mut f: F) -> f64
where
    F: FnMut(),
{
    let start = Instant::now();
    f();
    let end = Instant::now();
    duration_nanos(end.duration_since(start))
}

#[derive(PartialEq, Clone, Copy)]
enum ClientAuth {
    No,
    Yes,
}

struct BenchmarkParam {
    key_type: KeyType,
    ciphersuite: CipherSuite,
    version: Version,
}

impl BenchmarkParam {
    const fn new(key_type: KeyType, ciphersuite: CipherSuite, version: Version) -> Self {
        Self {
            key_type,
            ciphersuite,
            version,
        }
    }
}

static ALL_BENCHMARKS: &[BenchmarkParam] = &[
    BenchmarkParam::new(KeyType::Rsa, CipherSuite::EcdheRsaWithChacha20Poly1305Sha256, Version::Tls1_2),
    BenchmarkParam::new(
        KeyType::Ecdsa,
        CipherSuite::EcdheEcdsaWithChacha20Poly1305Sha256,
        Version::Tls1_2,
    ),
    BenchmarkParam::new(KeyType::Rsa, CipherSuite::EcdheRsaWithAes128GcmSha256, Version::Tls1_2),
    BenchmarkParam::new(KeyType::Rsa, CipherSuite::EcdheRsaWithAes256GcmSha384, Version::Tls1_2),
    BenchmarkParam::new(KeyType::Ecdsa, CipherSuite::EcdheEcdsaWithAes128GcmSha256, Version::Tls1_2),
    BenchmarkParam::new(KeyType::Ecdsa, CipherSuite::EcdheEcdsaWithAes256GcmSha384, Version::Tls1_2),
];

const ASCII_NULL: [u8; 1] = [0];

fn read_pem_file(file_path: &str) -> std::io::Result<Vec<u8>> {
    // Open the file in read-only mode
    let mut file = fs::File::open(&file_path)?;

    // Get the metadata to determine the file size
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;

    // Create a Vec<u8> with the appropriate capacity
    let mut buffer = Vec::with_capacity(file_size);

    // Read the entire file content into the buffer
    file.read_to_end(&mut buffer)?;

    // Check if the string ends with ASCII null
    if !buffer.ends_with(&ASCII_NULL) {
        buffer.extend_from_slice(&ASCII_NULL);
    }

    Ok(buffer)
}

impl KeyType {
    fn path_for(&self, part: &str) -> String {
        match self {
            Self::Rsa => format!("test-ca/rsa/{}", part),
            Self::Ecdsa => format!("test-ca/ecdsa/{}", part),
        }
    }

    fn get_chain(&self) -> mbedtls::Result<MbedtlsList<Certificate>> {
        let pem = read_pem_file(&self.path_for("end.fullchain")).unwrap();
        Certificate::from_pem_multiple(&pem)
    }

    fn get_key(&self) -> mbedtls::Result<Pk> {
        let key = read_pem_file(&self.path_for("end.key")).unwrap();
        Pk::from_private_key(&key, None)
    }

    fn get_client_chain(&self) -> mbedtls::Result<MbedtlsList<Certificate>> {
        let pem = read_pem_file(&self.path_for("client.fullchain")).unwrap();
        Certificate::from_pem_multiple(&pem)
    }

    fn get_client_key(&self) -> mbedtls::Result<Pk> {
        let key = read_pem_file(&self.path_for("client.key")).unwrap();
        Pk::from_private_key(&key, None)
    }
}

#[derive(PartialEq, Clone, Copy)]
enum ResumptionParam {
    No,
    // mbedtls does not support SessionId
    // SessionId,
    Tickets,
}

impl ResumptionParam {
    fn label(&self) -> &'static str {
        match *self {
            Self::No => "no-resume",
            // mbedtls does not support SessionId
            // Self::SessionId => "sessionid",
            Self::Tickets => "tickets",
        }
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum KeyType {
    Rsa,
    Ecdsa,
}

fn make_client_config(
    params: &BenchmarkParam,
    client_auth: ClientAuth,
    resume: ResumptionParam,
    max_fragment_size: Option<usize>,
) -> mbedtls::Result<Config> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

    config.set_rng(rng);
    config.set_min_version(params.version)?;
    config.set_max_version(params.version)?;
    let cert = Arc::new(params.key_type.get_chain()?);
    let key = Arc::new(params.key_type.get_key()?);
    config.push_cert(cert, key)?;

    match client_auth {
        ClientAuth::Yes => {
            let roots = params.key_type.get_chain()?;
            config.set_ca_list(Arc::new(roots), None);
            config.set_authmode(AuthMode::Required);
        }
        ClientAuth::No => config.set_authmode(AuthMode::None),
    };
    match resume {
        ResumptionParam::No => {},
        ResumptionParam::Tickets => {
            let ticket_ctx = TicketContext::new(rng.clone(), mbedtls::cipher::raw::CipherType::Aes128Gcm, 300).unwrap();
            config.set_session_tickets_callback(Arc::new(ticket_ctx));
        },
    }
    Ok(config)
}

// fn client<C: IoCallback<T> + TransportType, T>(
//     conn: C,
//     min_version: Version,
//     max_version: Version,
//     exp_version: Option<Version>,
//     use_psk: bool,
// ) -> TlsResult<()> {
//     let entropy = Arc::new(entropy_new());
//     let rng = Arc::new(CtrDrbg::new(entropy, None)?);
//     let mut config = Config::new(Endpoint::Client, C::get_transport_type(), Preset::Default);
//     config.set_rng(rng);
//     config.set_min_version(min_version)?;
//     config.set_max_version(max_version)?;
//     if !use_psk {
//         // for certificate-based operation, set up ca and verification callback
//         let cacert = Arc::new(Certificate::from_pem_multiple(keys::ROOT_CA_CERT.as_bytes())?);
//         let expected_flags = VerifyError::empty();
//         #[cfg(feature = "time")]
//         let expected_flags = expected_flags | VerifyError::CERT_EXPIRED;
//         let verify_callback = move |crt: &Certificate, depth: i32, verify_flags: &mut VerifyError| {
//             match (crt.subject().unwrap().as_str(), depth, &verify_flags) {
//                 ("CN=RootCA", 1, _) => (),
//                 (keys::EXPIRED_CERT_SUBJECT, 0, flags) => assert_eq!(**flags, expected_flags),
//                 _ => assert!(false),
//             };

//             verify_flags.remove(VerifyError::CERT_EXPIRED); //we check the flags at the end,
//                                                             //so removing this flag here prevents the connections from failing with
//                                                             // VerifyError
//             Ok(())
//         };
//         config.set_verify_callback(verify_callback);
//         config.set_ca_list(cacert, None);
//     } else {
//         // for psk-based operation, only PSK required
//         config.set_psk(&[0x12, 0x34, 0x56, 0x78], "client")?;
//     }
//     let mut ctx = Context::new(Arc::new(config));

//     // For DTLS, timers are required to support retransmissions
//     if C::get_transport_type() == Transport::Datagram {
//         ctx.set_timer_callback(Box::new(Timer::new()));
//     }

//     match ctx.establish(conn, None) {
//         Ok(()) => {
//             assert_eq!(ctx.version(), exp_version.unwrap());
//         }
//         Err(e) => {
//             match e {
//                 Error::SslBadHsProtocolVersion => {
//                     assert!(exp_version.is_none())
//                 }
//                 Error::SslFatalAlertMessage => {}
//                 e => panic!("Unexpected error {}", e),
//             };
//             return Ok(());
//         }
//     };

//     let ciphersuite = ctx.ciphersuite().unwrap();
//     let buf = format!("Client2Server {:4x}", ciphersuite);
//     assert_eq!(<C as TransportType>::send(&mut ctx, buf.as_bytes()).unwrap(), buf.len());
//     let mut buf = [0u8; 13 + 4 + 1];
//     assert_eq!(<C as TransportType>::recv(&mut ctx, &mut buf).unwrap(), buf.len());
//     assert_eq!(&buf, format!("Server2Client {:4x}", ciphersuite).as_bytes());
//     Ok(())
// }

fn make_server_config(
    params: &BenchmarkParam,
    client_auth: ClientAuth,
    resume: ResumptionParam,
    max_fragment_size: Option<usize>,
) -> mbedtls::Result<Config> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

    config.set_rng(rng);
    config.set_min_version(params.version)?;
    config.set_max_version(params.version)?;
    let cert = Arc::new(params.key_type.get_chain()?);
    let key = Arc::new(params.key_type.get_key()?);
    config.push_cert(cert, key)?;

    match client_auth {
        ClientAuth::Yes => {
            let roots = params.key_type.get_chain()?;
            config.set_ca_list(Arc::new(roots), None);
            config.set_authmode(AuthMode::Required);
        }
        ClientAuth::No => config.set_authmode(AuthMode::None),
    };
    match resume {
        ResumptionParam::No => {},
        ResumptionParam::Tickets => {
            let ticket_ctx = TicketContext::new(rng.clone(), mbedtls::cipher::raw::CipherType::Aes128Gcm, 300).unwrap();
            config.set_session_tickets_callback(Arc::new(ticket_ctx));
        },
    }
    Ok(config)
}

fn with_client<F, R>(conn: TcpStream, f: F) -> R
where
    F: FnOnce(Context<TcpStream>) -> R,
{
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None).unwrap());
    let cacert = Arc::new(Certificate::from_pem_multiple(keys::ROOT_CA_CERT.as_bytes()).unwrap());

    let verify_callback = move |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
        verify_flags.remove(VerifyError::CERT_EXPIRED);
        Ok(())
    };

    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_verify_callback(verify_callback);
    config.set_ca_list(cacert, None);
    let mut context = Context::new(Arc::new(config));

    context.establish(conn, None).unwrap();

    f(context)
}

fn with_server<F, R>(conn: TcpStream, f: F) -> R
where
    F: FnOnce(Context<TcpStream>) -> R,
{
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None).unwrap());
    let cert = Arc::new(Certificate::from_pem_multiple(keys::EXPIRED_CERT.as_bytes()).unwrap());
    let key = Arc::new(Pk::from_private_key(keys::EXPIRED_KEY.as_bytes(), None).unwrap());

    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.push_cert(cert, key).unwrap();
    let mut context = Context::new(Arc::new(config));

    context.establish(conn, None).unwrap();

    f(context)
}

fn main() {
    todo!()
}
