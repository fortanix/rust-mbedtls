/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::str::Utf8Error;
#[cfg(feature = "std")]
use std::error::Error as StdError;

use mbedtls_sys::types::raw_types::c_int;

pub type Result<T> = ::core::result::Result<T, Error>;

pub trait IntoResult: Sized {
    fn into_result(self) -> Result<Self>;
    fn into_result_discard(self) -> Result<()> {
        self.into_result().map(|_| ())
    }
}

// This is intended not to overlap with mbedtls error codes. Utf8Error is
// generated in the bindings when converting to rust UTF-8 strings. Only in rare
// circumstances (callbacks from mbedtls to rust) do we need to pass a Utf8Error
// back in to mbedtls.
pub const ERR_UTF8_INVALID: c_int = -0x10000;

macro_rules! error_enum {
	{$n:ident {$($rust:ident => $c:ident,)*}} => {
		#[derive(Debug, Eq, PartialEq)]
		pub enum $n {
			$($rust,)*
			Other(c_int),
			Utf8Error(Option<Utf8Error>),
		}

		impl IntoResult for c_int {
			fn into_result(self) -> Result<c_int> {
				let err_code = match self {
					_ if self >= 0 => return Ok(self),
					ERR_UTF8_INVALID => return Err(Error::Utf8Error(None)),
					_ => -self,
				};
				let (high_level_code, low_level_code) = (err_code & 0xFF80, err_code & 0x7F);
				Err($n::from_mbedtls_code(if high_level_code > 0 { -high_level_code } else { -low_level_code }))
			}
		}

		impl $n {
			pub fn from_mbedtls_code(code: c_int) -> Self {
				match code {
					$(::mbedtls_sys::$c => $n::$rust),*,
					_ => $n::Other(code)
				}
			}

			pub fn as_str(&self) -> &'static str {
				match self {
					$(&$n::$rust => concat!("mbedTLS error ",stringify!($n::$rust)),)*
					&$n::Other(_) => "mbedTLS unknown error",
					&$n::Utf8Error(_) => "error converting to UTF-8",
				}
			}

			pub fn to_int(&self) -> c_int {
				match *self {
					$($n::$rust => ::mbedtls_sys::$c,)*
					$n::Other(code) => code,
					$n::Utf8Error(_) => ERR_UTF8_INVALID,
				}
			}
		}
	};
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Error {
        Error::Utf8Error(Some(e))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Utf8Error(Some(ref e)) => {
                f.write_fmt(format_args!("Error converting to UTF-8: {}", e))
            }
            &Error::Utf8Error(None) => f.write_fmt(format_args!("Error converting to UTF-8")),
            &Error::Other(i) => f.write_fmt(format_args!("mbedTLS unknown error ({})", i)),
            e @ _ => f.write_fmt(format_args!("mbedTLS error {:?}", e)),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Error {
    fn description(&self) -> &str {
        self.as_str()
    }
}

error_enum!(Error {
	MpiFileIoError                => ERR_MPI_FILE_IO_ERROR,
	MpiBadInputData               => ERR_MPI_BAD_INPUT_DATA,
	MpiInvalidCharacter           => ERR_MPI_INVALID_CHARACTER,
	MpiBufferTooSmall             => ERR_MPI_BUFFER_TOO_SMALL,
	MpiNegativeValue              => ERR_MPI_NEGATIVE_VALUE,
	MpiDivisionByZero             => ERR_MPI_DIVISION_BY_ZERO,
	MpiNotAcceptable              => ERR_MPI_NOT_ACCEPTABLE,
	MpiAllocFailed                => ERR_MPI_ALLOC_FAILED,
	MdFeatureUnavailable          => ERR_MD_FEATURE_UNAVAILABLE,
	MdBadInputData                => ERR_MD_BAD_INPUT_DATA,
	MdAllocFailed                 => ERR_MD_ALLOC_FAILED,
	MdFileIoError                 => ERR_MD_FILE_IO_ERROR,
	EcpBadInputData               => ERR_ECP_BAD_INPUT_DATA,
	EcpBufferTooSmall             => ERR_ECP_BUFFER_TOO_SMALL,
	EcpFeatureUnavailable         => ERR_ECP_FEATURE_UNAVAILABLE,
	EcpVerifyFailed               => ERR_ECP_VERIFY_FAILED,
	EcpAllocFailed                => ERR_ECP_ALLOC_FAILED,
	EcpRandomFailed               => ERR_ECP_RANDOM_FAILED,
	EcpInvalidKey                 => ERR_ECP_INVALID_KEY,
	EcpSigLenMismatch             => ERR_ECP_SIG_LEN_MISMATCH,
	RsaBadInputData               => ERR_RSA_BAD_INPUT_DATA,
	RsaInvalidPadding             => ERR_RSA_INVALID_PADDING,
	RsaKeyGenFailed               => ERR_RSA_KEY_GEN_FAILED,
	RsaKeyCheckFailed             => ERR_RSA_KEY_CHECK_FAILED,
	RsaPublicFailed               => ERR_RSA_PUBLIC_FAILED,
	RsaPrivateFailed              => ERR_RSA_PRIVATE_FAILED,
	RsaVerifyFailed               => ERR_RSA_VERIFY_FAILED,
	RsaOutputTooLarge             => ERR_RSA_OUTPUT_TOO_LARGE,
	RsaRngFailed                  => ERR_RSA_RNG_FAILED,
	Asn1OutOfData                 => ERR_ASN1_OUT_OF_DATA,
	Asn1UnexpectedTag             => ERR_ASN1_UNEXPECTED_TAG,
	Asn1InvalidLength             => ERR_ASN1_INVALID_LENGTH,
	Asn1LengthMismatch            => ERR_ASN1_LENGTH_MISMATCH,
	Asn1InvalidData               => ERR_ASN1_INVALID_DATA,
	Asn1AllocFailed               => ERR_ASN1_ALLOC_FAILED,
	Asn1BufTooSmall               => ERR_ASN1_BUF_TOO_SMALL,
	PkAllocFailed                 => ERR_PK_ALLOC_FAILED,
	PkTypeMismatch                => ERR_PK_TYPE_MISMATCH,
	PkBadInputData                => ERR_PK_BAD_INPUT_DATA,
	PkFileIoError                 => ERR_PK_FILE_IO_ERROR,
	PkKeyInvalidVersion           => ERR_PK_KEY_INVALID_VERSION,
	PkKeyInvalidFormat            => ERR_PK_KEY_INVALID_FORMAT,
	PkUnknownPkAlg                => ERR_PK_UNKNOWN_PK_ALG,
	PkPasswordRequired            => ERR_PK_PASSWORD_REQUIRED,
	PkPasswordMismatch            => ERR_PK_PASSWORD_MISMATCH,
	PkInvalidPubkey               => ERR_PK_INVALID_PUBKEY,
	PkInvalidAlg                  => ERR_PK_INVALID_ALG,
	PkUnknownNamedCurve           => ERR_PK_UNKNOWN_NAMED_CURVE,
	PkFeatureUnavailable          => ERR_PK_FEATURE_UNAVAILABLE,
	PkSigLenMismatch              => ERR_PK_SIG_LEN_MISMATCH,
	X509FeatureUnavailable        => ERR_X509_FEATURE_UNAVAILABLE,
	X509UnknownOid                => ERR_X509_UNKNOWN_OID,
	X509InvalidFormat             => ERR_X509_INVALID_FORMAT,
	X509InvalidVersion            => ERR_X509_INVALID_VERSION,
	X509InvalidSerial             => ERR_X509_INVALID_SERIAL,
	X509InvalidAlg                => ERR_X509_INVALID_ALG,
	X509InvalidName               => ERR_X509_INVALID_NAME,
	X509InvalidDate               => ERR_X509_INVALID_DATE,
	X509InvalidSignature          => ERR_X509_INVALID_SIGNATURE,
	X509InvalidExtensions         => ERR_X509_INVALID_EXTENSIONS,
	X509UnknownVersion            => ERR_X509_UNKNOWN_VERSION,
	X509UnknownSigAlg             => ERR_X509_UNKNOWN_SIG_ALG,
	X509SigMismatch               => ERR_X509_SIG_MISMATCH,
	X509CertVerifyFailed          => ERR_X509_CERT_VERIFY_FAILED,
	X509CertUnknownFormat         => ERR_X509_CERT_UNKNOWN_FORMAT,
	X509BadInputData              => ERR_X509_BAD_INPUT_DATA,
	X509AllocFailed               => ERR_X509_ALLOC_FAILED,
	X509FileIoError               => ERR_X509_FILE_IO_ERROR,
	X509BufferTooSmall            => ERR_X509_BUFFER_TOO_SMALL,
	CipherFeatureUnavailable      => ERR_CIPHER_FEATURE_UNAVAILABLE,
	CipherBadInputData            => ERR_CIPHER_BAD_INPUT_DATA,
	CipherAllocFailed             => ERR_CIPHER_ALLOC_FAILED,
	CipherInvalidPadding          => ERR_CIPHER_INVALID_PADDING,
	CipherFullBlockExpected       => ERR_CIPHER_FULL_BLOCK_EXPECTED,
	CipherAuthFailed              => ERR_CIPHER_AUTH_FAILED,
	CipherInvalidContext          => ERR_CIPHER_INVALID_CONTEXT,
	DhmBadInputData               => ERR_DHM_BAD_INPUT_DATA,
	DhmReadParamsFailed           => ERR_DHM_READ_PARAMS_FAILED,
	DhmMakeParamsFailed           => ERR_DHM_MAKE_PARAMS_FAILED,
	DhmReadPublicFailed           => ERR_DHM_READ_PUBLIC_FAILED,
	DhmMakePublicFailed           => ERR_DHM_MAKE_PUBLIC_FAILED,
	DhmCalcSecretFailed           => ERR_DHM_CALC_SECRET_FAILED,
	DhmInvalidFormat              => ERR_DHM_INVALID_FORMAT,
	DhmAllocFailed                => ERR_DHM_ALLOC_FAILED,
	DhmFileIoError                => ERR_DHM_FILE_IO_ERROR,
	SslFeatureUnavailable         => ERR_SSL_FEATURE_UNAVAILABLE,
	SslBadInputData               => ERR_SSL_BAD_INPUT_DATA,
	SslInvalidMac                 => ERR_SSL_INVALID_MAC,
	SslInvalidRecord              => ERR_SSL_INVALID_RECORD,
	SslConnEof                    => ERR_SSL_CONN_EOF,
	SslUnknownCipher              => ERR_SSL_UNKNOWN_CIPHER,
	SslNoCipherChosen             => ERR_SSL_NO_CIPHER_CHOSEN,
	SslNoRng                      => ERR_SSL_NO_RNG,
	SslNoClientCertificate        => ERR_SSL_NO_CLIENT_CERTIFICATE,
	SslCertificateTooLarge        => ERR_SSL_CERTIFICATE_TOO_LARGE,
	SslCertificateRequired        => ERR_SSL_CERTIFICATE_REQUIRED,
	SslPrivateKeyRequired         => ERR_SSL_PRIVATE_KEY_REQUIRED,
	SslCaChainRequired            => ERR_SSL_CA_CHAIN_REQUIRED,
	SslUnexpectedMessage          => ERR_SSL_UNEXPECTED_MESSAGE,
	SslFatalAlertMessage          => ERR_SSL_FATAL_ALERT_MESSAGE,
	SslPeerVerifyFailed           => ERR_SSL_PEER_VERIFY_FAILED,
	SslPeerCloseNotify            => ERR_SSL_PEER_CLOSE_NOTIFY,
	SslBadHsClientHello           => ERR_SSL_BAD_HS_CLIENT_HELLO,
	SslBadHsServerHello           => ERR_SSL_BAD_HS_SERVER_HELLO,
	SslBadHsCertificate           => ERR_SSL_BAD_HS_CERTIFICATE,
	SslBadHsCertificateRequest    => ERR_SSL_BAD_HS_CERTIFICATE_REQUEST,
	SslBadHsServerKeyExchange     => ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE,
	SslBadHsServerHelloDone       => ERR_SSL_BAD_HS_SERVER_HELLO_DONE,
	SslBadHsClientKeyExchange     => ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE,
	SslBadHsClientKeyExchangeRp   => ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP,
	SslBadHsClientKeyExchangeCs   => ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS,
	SslBadHsCertificateVerify     => ERR_SSL_BAD_HS_CERTIFICATE_VERIFY,
	SslBadHsChangeCipherSpec      => ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC,
	SslBadHsFinished              => ERR_SSL_BAD_HS_FINISHED,
	SslAllocFailed                => ERR_SSL_ALLOC_FAILED,
	SslHwAccelFailed              => ERR_SSL_HW_ACCEL_FAILED,
	SslHwAccelFallthrough         => ERR_SSL_HW_ACCEL_FALLTHROUGH,
	SslCompressionFailed          => ERR_SSL_COMPRESSION_FAILED,
	SslBadHsProtocolVersion       => ERR_SSL_BAD_HS_PROTOCOL_VERSION,
	SslBadHsNewSessionTicket      => ERR_SSL_BAD_HS_NEW_SESSION_TICKET,
	SslSessionTicketExpired       => ERR_SSL_SESSION_TICKET_EXPIRED,
	SslPkTypeMismatch             => ERR_SSL_PK_TYPE_MISMATCH,
	SslUnknownIdentity            => ERR_SSL_UNKNOWN_IDENTITY,
	SslInternalError              => ERR_SSL_INTERNAL_ERROR,
	SslCounterWrapping            => ERR_SSL_COUNTER_WRAPPING,
	SslWaitingServerHelloRenego   => ERR_SSL_WAITING_SERVER_HELLO_RENEGO,
	SslHelloVerifyRequired        => ERR_SSL_HELLO_VERIFY_REQUIRED,
	SslBufferTooSmall             => ERR_SSL_BUFFER_TOO_SMALL,
	SslNoUsableCiphersuite        => ERR_SSL_NO_USABLE_CIPHERSUITE,
	SslWantRead                   => ERR_SSL_WANT_READ,
	SslTimeout                    => ERR_SSL_TIMEOUT,
	SslClientReconnect            => ERR_SSL_CLIENT_RECONNECT,
	SslUnexpectedRecord           => ERR_SSL_UNEXPECTED_RECORD,
	AesInvalidKeyLength           => ERR_AES_INVALID_KEY_LENGTH,
	AesInvalidInputLength         => ERR_AES_INVALID_INPUT_LENGTH,
	XteaInvalidInputLength        => ERR_XTEA_INVALID_INPUT_LENGTH,
	Pkcs5BadInputData             => ERR_PKCS5_BAD_INPUT_DATA,
	Pkcs5InvalidFormat            => ERR_PKCS5_INVALID_FORMAT,
	Pkcs5FeatureUnavailable       => ERR_PKCS5_FEATURE_UNAVAILABLE,
	Pkcs5PasswordMismatch         => ERR_PKCS5_PASSWORD_MISMATCH,
	Pkcs12BadInputData            => ERR_PKCS12_BAD_INPUT_DATA,
	Pkcs12FeatureUnavailable      => ERR_PKCS12_FEATURE_UNAVAILABLE,
	Pkcs12PbeInvalidFormat        => ERR_PKCS12_PBE_INVALID_FORMAT,
	Pkcs12PasswordMismatch        => ERR_PKCS12_PASSWORD_MISMATCH,
	PadlockDataMisaligned         => ERR_PADLOCK_DATA_MISALIGNED,
	OidNotFound                   => ERR_OID_NOT_FOUND,
	OidBufTooSmall                => ERR_OID_BUF_TOO_SMALL,
	NetSocketFailed               => ERR_NET_SOCKET_FAILED,
	NetConnectFailed              => ERR_NET_CONNECT_FAILED,
	NetBindFailed                 => ERR_NET_BIND_FAILED,
	NetListenFailed               => ERR_NET_LISTEN_FAILED,
	NetAcceptFailed               => ERR_NET_ACCEPT_FAILED,
	NetRecvFailed                 => ERR_NET_RECV_FAILED,
	NetSendFailed                 => ERR_NET_SEND_FAILED,
	NetConnReset                  => ERR_NET_CONN_RESET,
	NetUnknownHost                => ERR_NET_UNKNOWN_HOST,
	NetBufferTooSmall             => ERR_NET_BUFFER_TOO_SMALL,
	NetInvalidContext             => ERR_NET_INVALID_CONTEXT,
	HmacDrbgRequestTooBig         => ERR_HMAC_DRBG_REQUEST_TOO_BIG,
	HmacDrbgInputTooBig           => ERR_HMAC_DRBG_INPUT_TOO_BIG,
	HmacDrbgFileIoError           => ERR_HMAC_DRBG_FILE_IO_ERROR,
	HmacDrbgEntropySourceFailed   => ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED,
	GcmAuthFailed                 => ERR_GCM_AUTH_FAILED,
	GcmBadInput                   => ERR_GCM_BAD_INPUT,
	EntropySourceFailed           => ERR_ENTROPY_SOURCE_FAILED,
	EntropyMaxSources             => ERR_ENTROPY_MAX_SOURCES,
	EntropyNoSourcesDefined       => ERR_ENTROPY_NO_SOURCES_DEFINED,
	EntropyNoStrongSource         => ERR_ENTROPY_NO_STRONG_SOURCE,
	EntropyFileIoError            => ERR_ENTROPY_FILE_IO_ERROR,
	DesInvalidInputLength         => ERR_DES_INVALID_INPUT_LENGTH,
	CtrDrbgEntropySourceFailed    => ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED,
	CtrDrbgRequestTooBig          => ERR_CTR_DRBG_REQUEST_TOO_BIG,
	CtrDrbgInputTooBig            => ERR_CTR_DRBG_INPUT_TOO_BIG,
	CtrDrbgFileIoError            => ERR_CTR_DRBG_FILE_IO_ERROR,
	CcmBadInput                   => ERR_CCM_BAD_INPUT,
	CcmAuthFailed                 => ERR_CCM_AUTH_FAILED,
	CamelliaInvalidKeyLength      => ERR_CAMELLIA_INVALID_KEY_LENGTH,
	CamelliaInvalidInputLength    => ERR_CAMELLIA_INVALID_INPUT_LENGTH,
	BlowfishInvalidKeyLength      => ERR_BLOWFISH_INVALID_KEY_LENGTH,
	BlowfishInvalidInputLength    => ERR_BLOWFISH_INVALID_INPUT_LENGTH,
	Base64BufferTooSmall          => ERR_BASE64_BUFFER_TOO_SMALL,
	Base64InvalidCharacter        => ERR_BASE64_INVALID_CHARACTER,
	PemNoHeaderFooterPresent      => ERR_PEM_NO_HEADER_FOOTER_PRESENT,
	PemInvalidData                => ERR_PEM_INVALID_DATA,
	PemAllocFailed                => ERR_PEM_ALLOC_FAILED,
	PemInvalidEncIv               => ERR_PEM_INVALID_ENC_IV,
	PemUnknownEncAlg              => ERR_PEM_UNKNOWN_ENC_ALG,
	PemPasswordRequired           => ERR_PEM_PASSWORD_REQUIRED,
	PemPasswordMismatch           => ERR_PEM_PASSWORD_MISMATCH,
	PemFeatureUnavailable         => ERR_PEM_FEATURE_UNAVAILABLE,
	PemBadInputData               => ERR_PEM_BAD_INPUT_DATA,
});
