/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::str::Utf8Error;
use core::convert::Infallible;
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
    {enum $n:ident {$($rust:ident = $c:ident,)*}} => {
        #[derive(Debug, Eq, PartialEq)]
        pub enum $n {
            $($rust,)*
            Other(c_int),
            Utf8Error(Option<Utf8Error>),
            // Stable-Rust equivalent of `#[non_exhaustive]` attribute. This
            // value should never be used by users of this crate!
            #[doc(hidden)]
            __Nonexhaustive,
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
                    &$n::__Nonexhaustive => unreachable!("__Nonexhaustive value should not be instantiated"),
                }
            }

            pub fn to_int(&self) -> c_int {
                match *self {
                    $($n::$rust => ::mbedtls_sys::$c,)*
                    $n::Other(code) => code,
                    $n::Utf8Error(_) => ERR_UTF8_INVALID,
                    $n::__Nonexhaustive => unreachable!("__Nonexhaustive value should not be instantiated"),
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

impl From<Infallible> for Error {
    fn from(x: Infallible) -> Error {
        match x {}
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
            &Error::__Nonexhaustive => unreachable!("__Nonexhaustive value should not be instantiated"),
            e => f.write_fmt(format_args!("mbedTLS error {:?}", e)),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Error {
    fn description(&self) -> &str {
        self.as_str()
    }
}

error_enum!(
    enum Error {
        AesBadInputData = ERR_AES_BAD_INPUT_DATA,
        AesInvalidInputLength = ERR_AES_INVALID_INPUT_LENGTH,
        AesInvalidKeyLength = ERR_AES_INVALID_KEY_LENGTH,
        AriaBadInputData = ERR_ARIA_BAD_INPUT_DATA,
        AriaInvalidInputLength = ERR_ARIA_INVALID_INPUT_LENGTH,
        Asn1AllocFailed = ERR_ASN1_ALLOC_FAILED,
        Asn1BufTooSmall = ERR_ASN1_BUF_TOO_SMALL,
        Asn1InvalidData = ERR_ASN1_INVALID_DATA,
        Asn1InvalidLength = ERR_ASN1_INVALID_LENGTH,
        Asn1LengthMismatch = ERR_ASN1_LENGTH_MISMATCH,
        Asn1OutOfData = ERR_ASN1_OUT_OF_DATA,
        Asn1UnexpectedTag = ERR_ASN1_UNEXPECTED_TAG,
        Base64BufferTooSmall = ERR_BASE64_BUFFER_TOO_SMALL,
        Base64InvalidCharacter = ERR_BASE64_INVALID_CHARACTER,
        CamelliaBadInputData = ERR_CAMELLIA_BAD_INPUT_DATA,
        CamelliaInvalidInputLength = ERR_CAMELLIA_INVALID_INPUT_LENGTH,
        CcmAuthFailed = ERR_CCM_AUTH_FAILED,
        CcmBadInput = ERR_CCM_BAD_INPUT,
        Chacha20BadInputData = ERR_CHACHA20_BAD_INPUT_DATA,
        ChachapolyAuthFailed = ERR_CHACHAPOLY_AUTH_FAILED,
        ChachapolyBadState = ERR_CHACHAPOLY_BAD_STATE,
        CipherAllocFailed = ERR_CIPHER_ALLOC_FAILED,
        CipherAuthFailed = ERR_CIPHER_AUTH_FAILED,
        CipherBadInputData = ERR_CIPHER_BAD_INPUT_DATA,
        CipherFeatureUnavailable = ERR_CIPHER_FEATURE_UNAVAILABLE,
        CipherFullBlockExpected = ERR_CIPHER_FULL_BLOCK_EXPECTED,
        CipherInvalidContext = ERR_CIPHER_INVALID_CONTEXT,
        CipherInvalidPadding = ERR_CIPHER_INVALID_PADDING,
        CtrDrbgEntropySourceFailed = ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED,
        CtrDrbgFileIoError = ERR_CTR_DRBG_FILE_IO_ERROR,
        CtrDrbgInputTooBig = ERR_CTR_DRBG_INPUT_TOO_BIG,
        CtrDrbgRequestTooBig = ERR_CTR_DRBG_REQUEST_TOO_BIG,
        DesInvalidInputLength = ERR_DES_INVALID_INPUT_LENGTH,
        DhmAllocFailed = ERR_DHM_ALLOC_FAILED,
        DhmBadInputData = ERR_DHM_BAD_INPUT_DATA,
        DhmCalcSecretFailed = ERR_DHM_CALC_SECRET_FAILED,
        DhmFileIoError = ERR_DHM_FILE_IO_ERROR,
        DhmInvalidFormat = ERR_DHM_INVALID_FORMAT,
        DhmMakeParamsFailed = ERR_DHM_MAKE_PARAMS_FAILED,
        DhmMakePublicFailed = ERR_DHM_MAKE_PUBLIC_FAILED,
        DhmReadParamsFailed = ERR_DHM_READ_PARAMS_FAILED,
        DhmReadPublicFailed = ERR_DHM_READ_PUBLIC_FAILED,
        DhmSetGroupFailed = ERR_DHM_SET_GROUP_FAILED,
        EcpAllocFailed = ERR_ECP_ALLOC_FAILED,
        EcpBadInputData = ERR_ECP_BAD_INPUT_DATA,
        EcpBufferTooSmall = ERR_ECP_BUFFER_TOO_SMALL,
        EcpFeatureUnavailable = ERR_ECP_FEATURE_UNAVAILABLE,
        EcpInProgress = ERR_ECP_IN_PROGRESS,
        EcpInvalidKey = ERR_ECP_INVALID_KEY,
        EcpRandomFailed = ERR_ECP_RANDOM_FAILED,
        EcpSigLenMismatch = ERR_ECP_SIG_LEN_MISMATCH,
        EcpVerifyFailed = ERR_ECP_VERIFY_FAILED,
        EntropyFileIoError = ERR_ENTROPY_FILE_IO_ERROR,
        EntropyMaxSources = ERR_ENTROPY_MAX_SOURCES,
        EntropyNoSourcesDefined = ERR_ENTROPY_NO_SOURCES_DEFINED,
        EntropyNoStrongSource = ERR_ENTROPY_NO_STRONG_SOURCE,
        EntropySourceFailed = ERR_ENTROPY_SOURCE_FAILED,
        ErrorCorruptionDetected = ERR_ERROR_CORRUPTION_DETECTED,
        ErrorGenericError = ERR_ERROR_GENERIC_ERROR,
        GcmAuthFailed = ERR_GCM_AUTH_FAILED,
        GcmBadInput = ERR_GCM_BAD_INPUT,
        GcmBufferTooSmall = ERR_GCM_BUFFER_TOO_SMALL,
        HkdfBadInputData = ERR_HKDF_BAD_INPUT_DATA,
        HmacDrbgEntropySourceFailed = ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED,
        HmacDrbgFileIoError = ERR_HMAC_DRBG_FILE_IO_ERROR,
        HmacDrbgInputTooBig = ERR_HMAC_DRBG_INPUT_TOO_BIG,
        HmacDrbgRequestTooBig = ERR_HMAC_DRBG_REQUEST_TOO_BIG,
        MdAllocFailed = ERR_MD_ALLOC_FAILED,
        MdBadInputData = ERR_MD_BAD_INPUT_DATA,
        MdFeatureUnavailable = ERR_MD_FEATURE_UNAVAILABLE,
        MdFileIoError = ERR_MD_FILE_IO_ERROR,
        MpiAllocFailed = ERR_MPI_ALLOC_FAILED,
        MpiBadInputData = ERR_MPI_BAD_INPUT_DATA,
        MpiBufferTooSmall = ERR_MPI_BUFFER_TOO_SMALL,
        MpiDivisionByZero = ERR_MPI_DIVISION_BY_ZERO,
        MpiFileIoError = ERR_MPI_FILE_IO_ERROR,
        MpiInvalidCharacter = ERR_MPI_INVALID_CHARACTER,
        MpiNegativeValue = ERR_MPI_NEGATIVE_VALUE,
        MpiNotAcceptable = ERR_MPI_NOT_ACCEPTABLE,
        NetAcceptFailed = ERR_NET_ACCEPT_FAILED,
        NetBadInputData = ERR_NET_BAD_INPUT_DATA,
        NetBindFailed = ERR_NET_BIND_FAILED,
        NetBufferTooSmall = ERR_NET_BUFFER_TOO_SMALL,
        NetConnectFailed = ERR_NET_CONNECT_FAILED,
        NetConnReset = ERR_NET_CONN_RESET,
        NetInvalidContext = ERR_NET_INVALID_CONTEXT,
        NetListenFailed = ERR_NET_LISTEN_FAILED,
        NetPollFailed = ERR_NET_POLL_FAILED,
        NetRecvFailed = ERR_NET_RECV_FAILED,
        NetSendFailed = ERR_NET_SEND_FAILED,
        NetSocketFailed = ERR_NET_SOCKET_FAILED,
        NetUnknownHost = ERR_NET_UNKNOWN_HOST,
        OidBufTooSmall = ERR_OID_BUF_TOO_SMALL,
        OidNotFound = ERR_OID_NOT_FOUND,
        PemAllocFailed = ERR_PEM_ALLOC_FAILED,
        PemBadInputData = ERR_PEM_BAD_INPUT_DATA,
        PemFeatureUnavailable = ERR_PEM_FEATURE_UNAVAILABLE,
        PemInvalidData = ERR_PEM_INVALID_DATA,
        PemInvalidEncIv = ERR_PEM_INVALID_ENC_IV,
        PemNoHeaderFooterPresent = ERR_PEM_NO_HEADER_FOOTER_PRESENT,
        PemPasswordMismatch = ERR_PEM_PASSWORD_MISMATCH,
        PemPasswordRequired = ERR_PEM_PASSWORD_REQUIRED,
        PemUnknownEncAlg = ERR_PEM_UNKNOWN_ENC_ALG,
        PkAllocFailed = ERR_PK_ALLOC_FAILED,
        PkBadInputData = ERR_PK_BAD_INPUT_DATA,
        PkBufferTooSmall = ERR_PK_BUFFER_TOO_SMALL,
        Pkcs12BadInputData = ERR_PKCS12_BAD_INPUT_DATA,
        Pkcs12FeatureUnavailable = ERR_PKCS12_FEATURE_UNAVAILABLE,
        Pkcs12PasswordMismatch = ERR_PKCS12_PASSWORD_MISMATCH,
        Pkcs12PbeInvalidFormat = ERR_PKCS12_PBE_INVALID_FORMAT,
        Pkcs5BadInputData = ERR_PKCS5_BAD_INPUT_DATA,
        Pkcs5FeatureUnavailable = ERR_PKCS5_FEATURE_UNAVAILABLE,
        Pkcs5InvalidFormat = ERR_PKCS5_INVALID_FORMAT,
        Pkcs5PasswordMismatch = ERR_PKCS5_PASSWORD_MISMATCH,
        PkFeatureUnavailable = ERR_PK_FEATURE_UNAVAILABLE,
        PkFileIoError = ERR_PK_FILE_IO_ERROR,
        PkInvalidAlg = ERR_PK_INVALID_ALG,
        PkInvalidPubkey = ERR_PK_INVALID_PUBKEY,
        PkKeyInvalidFormat = ERR_PK_KEY_INVALID_FORMAT,
        PkKeyInvalidVersion = ERR_PK_KEY_INVALID_VERSION,
        PkPasswordMismatch = ERR_PK_PASSWORD_MISMATCH,
        PkPasswordRequired = ERR_PK_PASSWORD_REQUIRED,
        PkSigLenMismatch = ERR_PK_SIG_LEN_MISMATCH,
        PkTypeMismatch = ERR_PK_TYPE_MISMATCH,
        PkUnknownNamedCurve = ERR_PK_UNKNOWN_NAMED_CURVE,
        PkUnknownPkAlg = ERR_PK_UNKNOWN_PK_ALG,
        PlatformFeatureUnsupported = ERR_PLATFORM_FEATURE_UNSUPPORTED,
        PlatformHwAccelFailed = ERR_PLATFORM_HW_ACCEL_FAILED,
        Poly1305BadInputData = ERR_POLY1305_BAD_INPUT_DATA,
        RsaBadInputData = ERR_RSA_BAD_INPUT_DATA,
        RsaInvalidPadding = ERR_RSA_INVALID_PADDING,
        RsaKeyCheckFailed = ERR_RSA_KEY_CHECK_FAILED,
        RsaKeyGenFailed = ERR_RSA_KEY_GEN_FAILED,
        RsaOutputTooLarge = ERR_RSA_OUTPUT_TOO_LARGE,
        RsaPrivateFailed = ERR_RSA_PRIVATE_FAILED,
        RsaPublicFailed = ERR_RSA_PUBLIC_FAILED,
        RsaRngFailed = ERR_RSA_RNG_FAILED,
        RsaVerifyFailed = ERR_RSA_VERIFY_FAILED,
        Sha1BadInputData = ERR_SHA1_BAD_INPUT_DATA,
        Sha256BadInputData = ERR_SHA256_BAD_INPUT_DATA,
        Sha512BadInputData = ERR_SHA512_BAD_INPUT_DATA,
        SslAllocFailed = ERR_SSL_ALLOC_FAILED,
        SslAsyncInProgress = ERR_SSL_ASYNC_IN_PROGRESS,
        SslBadCertificate = ERR_SSL_BAD_CERTIFICATE,
        SslBadConfig = ERR_SSL_BAD_CONFIG,
        SslBadInputData = ERR_SSL_BAD_INPUT_DATA,
        SslBadProtocolVersion = ERR_SSL_BAD_PROTOCOL_VERSION,
        SslBufferTooSmall = ERR_SSL_BUFFER_TOO_SMALL,
        SslCaChainRequired = ERR_SSL_CA_CHAIN_REQUIRED,
        SslClientReconnect = ERR_SSL_CLIENT_RECONNECT,
        SslConnEof = ERR_SSL_CONN_EOF,
        SslContinueProcessing = ERR_SSL_CONTINUE_PROCESSING,
        SslCounterWrapping = ERR_SSL_COUNTER_WRAPPING,
        SslCryptoInProgress = ERR_SSL_CRYPTO_IN_PROGRESS,
        SslDecodeError = ERR_SSL_DECODE_ERROR,
        SslEarlyMessage = ERR_SSL_EARLY_MESSAGE,
        SslFatalAlertMessage = ERR_SSL_FATAL_ALERT_MESSAGE,
        SslFeatureUnavailable = ERR_SSL_FEATURE_UNAVAILABLE,
        SslHandshakeFailure = ERR_SSL_HANDSHAKE_FAILURE,
        SslHelloVerifyRequired = ERR_SSL_HELLO_VERIFY_REQUIRED,
        SslHwAccelFailed = ERR_SSL_HW_ACCEL_FAILED,
        SslHwAccelFallthrough = ERR_SSL_HW_ACCEL_FALLTHROUGH,
        SslIllegalParameter = ERR_SSL_ILLEGAL_PARAMETER,
        SslInternalError = ERR_SSL_INTERNAL_ERROR,
        SslInvalidMac = ERR_SSL_INVALID_MAC,
        SslInvalidRecord = ERR_SSL_INVALID_RECORD,
        SslNoApplicationProtocol = ERR_SSL_NO_APPLICATION_PROTOCOL,
        SslNoClientCertificate = ERR_SSL_NO_CLIENT_CERTIFICATE,
        SslNonFatal = ERR_SSL_NON_FATAL,
        SslNoRng = ERR_SSL_NO_RNG,
        SslPeerCloseNotify = ERR_SSL_PEER_CLOSE_NOTIFY,
        SslPkTypeMismatch = ERR_SSL_PK_TYPE_MISMATCH,
        SslPrivateKeyRequired = ERR_SSL_PRIVATE_KEY_REQUIRED,
        SslSessionTicketExpired = ERR_SSL_SESSION_TICKET_EXPIRED,
        SslTimeout = ERR_SSL_TIMEOUT,
        SslUnexpectedCid = ERR_SSL_UNEXPECTED_CID,
        SslUnexpectedMessage = ERR_SSL_UNEXPECTED_MESSAGE,
        SslUnexpectedRecord = ERR_SSL_UNEXPECTED_RECORD,
        SslUnknownIdentity = ERR_SSL_UNKNOWN_IDENTITY,
        SslUnrecognizedName = ERR_SSL_UNRECOGNIZED_NAME,
        SslUnsupportedExtension = ERR_SSL_UNSUPPORTED_EXTENSION,
        SslVersionMismatch = ERR_SSL_VERSION_MISMATCH,
        SslWaitingServerHelloRenego = ERR_SSL_WAITING_SERVER_HELLO_RENEGO,
        SslWantRead = ERR_SSL_WANT_READ,
        SslWantWrite = ERR_SSL_WANT_WRITE,
        ThreadingBadInputData = ERR_THREADING_BAD_INPUT_DATA,
        ThreadingMutexError = ERR_THREADING_MUTEX_ERROR,
        X509AllocFailed = ERR_X509_ALLOC_FAILED,
        X509BadInputData = ERR_X509_BAD_INPUT_DATA,
        X509BufferTooSmall = ERR_X509_BUFFER_TOO_SMALL,
        X509CertUnknownFormat = ERR_X509_CERT_UNKNOWN_FORMAT,
        X509CertVerifyFailed = ERR_X509_CERT_VERIFY_FAILED,
        X509FatalError = ERR_X509_FATAL_ERROR,
        X509FeatureUnavailable = ERR_X509_FEATURE_UNAVAILABLE,
        X509FileIoError = ERR_X509_FILE_IO_ERROR,
        X509InvalidAlg = ERR_X509_INVALID_ALG,
        X509InvalidDate = ERR_X509_INVALID_DATE,
        X509InvalidExtensions = ERR_X509_INVALID_EXTENSIONS,
        X509InvalidFormat = ERR_X509_INVALID_FORMAT,
        X509InvalidName = ERR_X509_INVALID_NAME,
        X509InvalidSerial = ERR_X509_INVALID_SERIAL,
        X509InvalidSignature = ERR_X509_INVALID_SIGNATURE,
        X509InvalidVersion = ERR_X509_INVALID_VERSION,
        X509SigMismatch = ERR_X509_SIG_MISMATCH,
        X509UnknownOid = ERR_X509_UNKNOWN_OID,
        X509UnknownSigAlg = ERR_X509_UNKNOWN_SIG_ALG,
        X509UnknownVersion = ERR_X509_UNKNOWN_VERSION,
    }
);
