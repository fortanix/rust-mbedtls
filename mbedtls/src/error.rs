/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::ops::BitOr;
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

pub mod codes {
    pub use super::HiError::*;
    pub use super::LoError::*;
}

// This is intended not to overlap with mbedtls error codes. Utf8Error is
// generated in the bindings when converting to rust UTF-8 strings. Only in rare
// circumstances (callbacks from mbedtls to rust) do we need to pass a Utf8Error
// back in to mbedtls.
pub const ERR_UTF8_INVALID: c_int = -0x10000;

macro_rules! error_enum {
    {
        const MASK: c_int = $mask:literal;
        enum $n:ident {$($rust:ident = $c:ident,)*}
    } => {
        #[non_exhaustive]
        #[derive(Debug, Eq, PartialEq, Copy, Clone)]
        pub enum $n {
            $($rust,)*
            Unknown(c_int)
        }

        impl From<c_int> for $n {
            fn from(code: c_int) -> $n {
                // check against mask here (not in match blook) to make it compile-time
                $(const $c: c_int = $n::assert_in_mask(::mbedtls_sys::$c);)*
                match -code {
                    $($c => return $n::$rust),*,
                    _ => return $n::Unknown(-code)
                }
            }
        }

        impl From<$n> for c_int {
            fn from(error: $n) -> c_int {
                match error {
                    $($n::$rust => return ::mbedtls_sys::$c,)*
                    $n::Unknown(code) => return code,
                }
            }
        }

        impl $n {
            const fn mask() -> c_int {
                $mask
            }
            
            const fn assert_in_mask(val: c_int) -> c_int {
                assert!((-val & !Self::mask()) == 0);
                val
            }

            pub fn as_str(&self)-> &'static str {
                match self {
                    $($n::$rust => concat!("mbedTLS error ", stringify!($n::$rust)),)*
                    $n::Unknown(_) => concat!("mbedTLS unknown ", stringify!($n), " error")
                }
            }
        }
    };
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    HighLevel(HiError),
    LowLevel(LoError),
    HighAndLowLevel(HiError, LoError),
    Other(c_int),
    Utf8Error(Option<Utf8Error>),
}

impl Error {

    pub fn low_level(&self) -> Option<LoError> {
        match self {
            Error::LowLevel(error)
            | Error::HighAndLowLevel(_, error) => Some(*error),
            _ => None
        }
    }

    pub fn high_level(&self) -> Option<HiError> {
        match self {
            Error::HighLevel(error)
            | Error::HighAndLowLevel(error, _) => Some(*error),
            _ => None
        }
    }

    pub fn as_str(&self) -> &'static str {
        match &self {
            &Error::HighLevel(e) => e.as_str(),
            &Error::LowLevel(e) => e.as_str(),
            &Error::HighAndLowLevel(e, _) => e.as_str(),
            &Error::Other(_) => "mbedTLS unknown error",
            &Error::Utf8Error(_) => "error converting to UTF-8"
        }
    }

    pub fn to_int(&self) -> c_int {
        match self {
            &Error::HighLevel(error) => error.into(),
            &Error::LowLevel(error) => error.into(),
            &Error::HighAndLowLevel(hl_error, ll_error) => c_int::from(hl_error) + c_int::from(ll_error),
            &Error::Other(error) => error,
            &Error::Utf8Error(_) => ERR_UTF8_INVALID,
        }
    }
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

impl From<LoError> for Error {
    fn from(error: LoError) -> Error {
        Error::LowLevel(error)
    }
}

impl From<HiError> for Error {
    fn from(error: HiError) -> Error {
        Error::HighLevel(error)
    }
}

impl BitOr<LoError> for HiError {
    type Output = Error;
    fn bitor(self, rhs: LoError) -> Self::Output {
        Error::HighAndLowLevel(self, rhs)
    }
}
impl BitOr<HiError> for LoError {
    type Output = Error;
    fn bitor(self, rhs: HiError) -> Self::Output {
        Error::HighAndLowLevel(rhs, self)
    }
}

impl From<c_int> for Error {
    fn from(x: c_int) -> Error {
        let (high_level_code, low_level_code) = (-x & HiError::mask(), -x & LoError::mask());
        if -x & (HiError::mask() | LoError::mask()) != -x || x >= 0 {
            Error::Other(x)
        } else if high_level_code == 0 {
            Error::LowLevel(low_level_code.into())
        } else if low_level_code == 0 {
            Error::HighLevel(high_level_code.into())
        } else {
            Error::HighAndLowLevel(high_level_code.into(), low_level_code.into())
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Utf8Error(Some(ref e)) => {
                write!(f, "Error converting to UTF-8: {}", e)
            }
            &Error::Utf8Error(None) => write!(f, "Error converting to UTF-8"),
            &Error::LowLevel(e) => write!(f, "{}", e.as_str()),
            &Error::HighLevel(e) => write!(f, "{}", e.as_str()),
            &Error::HighAndLowLevel(hi, lo) => write!(f, "({}, {})", hi.as_str(), lo.as_str()),
            &Error::Other(code) => write!(f, "mbedTLS unknown error code {}", code),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Error {}

impl IntoResult for c_int {
    fn into_result(self) -> Result<c_int> {
        match self {
            0.. => return Ok(self),
            ERR_UTF8_INVALID => return Err(Error::Utf8Error(None)),
            _ => return Err(Error::from(self))
        };
    }
}

error_enum!(
    const MASK: c_int = 0x7F80;
    enum HiError {
        AriaBadInputData = ERR_ARIA_BAD_INPUT_DATA,
        CamelliaBadInputData = ERR_CAMELLIA_BAD_INPUT_DATA,
        CipherAllocFailed = ERR_CIPHER_ALLOC_FAILED,
        CipherAuthFailed = ERR_CIPHER_AUTH_FAILED,
        CipherBadInputData = ERR_CIPHER_BAD_INPUT_DATA,
        CipherFeatureUnavailable = ERR_CIPHER_FEATURE_UNAVAILABLE,
        CipherFullBlockExpected = ERR_CIPHER_FULL_BLOCK_EXPECTED,
        CipherInvalidContext = ERR_CIPHER_INVALID_CONTEXT,
        CipherInvalidPadding = ERR_CIPHER_INVALID_PADDING,
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
        ErrorCorruptionDetected = ERR_ERROR_CORRUPTION_DETECTED,
        ErrorGenericError = ERR_ERROR_GENERIC_ERROR,
        GcmBufferTooSmall = ERR_GCM_BUFFER_TOO_SMALL,
        HkdfBadInputData = ERR_HKDF_BAD_INPUT_DATA,
        MdAllocFailed = ERR_MD_ALLOC_FAILED,
        MdBadInputData = ERR_MD_BAD_INPUT_DATA,
        MdFeatureUnavailable = ERR_MD_FEATURE_UNAVAILABLE,
        MdFileIoError = ERR_MD_FILE_IO_ERROR,
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
        SslCryptoInProgress = ERR_SSL_CRYPTO_IN_PROGRESS,
        SslFeatureUnavailable = ERR_SSL_FEATURE_UNAVAILABLE,
        SslBadInputData = ERR_SSL_BAD_INPUT_DATA,
        SslInvalidMac = ERR_SSL_INVALID_MAC,
        SslInvalidRecord = ERR_SSL_INVALID_RECORD,
        SslConnEof = ERR_SSL_CONN_EOF,
        SslDecodeError = ERR_SSL_DECODE_ERROR,
        SslNoRng = ERR_SSL_NO_RNG,
        SslNoClientCertificate = ERR_SSL_NO_CLIENT_CERTIFICATE,
        SslUnsupportedExtension = ERR_SSL_UNSUPPORTED_EXTENSION,
        SslNoApplicationProtocol = ERR_SSL_NO_APPLICATION_PROTOCOL,
        SslPrivateKeyRequired = ERR_SSL_PRIVATE_KEY_REQUIRED,
        SslCaChainRequired = ERR_SSL_CA_CHAIN_REQUIRED,
        SslUnexpectedMessage = ERR_SSL_UNEXPECTED_MESSAGE,
        SslFatalAlertMessage = ERR_SSL_FATAL_ALERT_MESSAGE,
        SslUnrecognizedName = ERR_SSL_UNRECOGNIZED_NAME,
        SslPeerCloseNotify = ERR_SSL_PEER_CLOSE_NOTIFY,
        SslBadCertificate = ERR_SSL_BAD_CERTIFICATE,
        SslReceivedNewSessionTicket = ERR_SSL_RECEIVED_NEW_SESSION_TICKET,
        SslCannotReadEarlyData = ERR_SSL_CANNOT_READ_EARLY_DATA,
        SslCannotWriteEarlyData = ERR_SSL_CANNOT_WRITE_EARLY_DATA,
        SslAllocFailed = ERR_SSL_ALLOC_FAILED,
        SslHwAccelFallthrough = ERR_SSL_HW_ACCEL_FALLTHROUGH,
        SslBadProtocolVersion = ERR_SSL_BAD_PROTOCOL_VERSION,
        SslHandshakeFailure = ERR_SSL_HANDSHAKE_FAILURE,
        SslSessionTicketExpired = ERR_SSL_SESSION_TICKET_EXPIRED,
        SslPkTypeMismatch = ERR_SSL_PK_TYPE_MISMATCH,
        SslUnknownIdentity = ERR_SSL_UNKNOWN_IDENTITY,
        SslInternalError = ERR_SSL_INTERNAL_ERROR,
        SslCounterWrapping = ERR_SSL_COUNTER_WRAPPING,
        SslWaitingServerHelloRenego = ERR_SSL_WAITING_SERVER_HELLO_RENEGO,
        SslHelloVerifyRequired = ERR_SSL_HELLO_VERIFY_REQUIRED,
        SslBufferTooSmall = ERR_SSL_BUFFER_TOO_SMALL,
        SslWantRead = ERR_SSL_WANT_READ,
        SslWantWrite = ERR_SSL_WANT_WRITE,
        SslTimeout = ERR_SSL_TIMEOUT,
        SslClientReconnect = ERR_SSL_CLIENT_RECONNECT,
        SslUnexpectedRecord = ERR_SSL_UNEXPECTED_RECORD,
        SslNonFatal = ERR_SSL_NON_FATAL,
        SslIllegalParameter = ERR_SSL_ILLEGAL_PARAMETER,
        SslContinueProcessing = ERR_SSL_CONTINUE_PROCESSING,
        SslAsyncInProgress = ERR_SSL_ASYNC_IN_PROGRESS,
        SslEarlyMessage = ERR_SSL_EARLY_MESSAGE,
        SslUnexpectedCid = ERR_SSL_UNEXPECTED_CID,
        SslVersionMismatch = ERR_SSL_VERSION_MISMATCH,
        SslBadConfig = ERR_SSL_BAD_CONFIG,
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

error_enum!(
    const MASK: c_int = 0x7F;
    enum LoError {
        AesBadInputData = ERR_AES_BAD_INPUT_DATA,
        AesFeatureUnavailable = ERR_AES_FEATURE_UNAVAILABLE,
        AesHwAccelFailed = ERR_AES_HW_ACCEL_FAILED,
        AesInvalidInputLength = ERR_AES_INVALID_INPUT_LENGTH,
        AesInvalidKeyLength = ERR_AES_INVALID_KEY_LENGTH,
        Arc4HwAccelFailed = ERR_ARC4_HW_ACCEL_FAILED,
        AriaFeatureUnavailable = ERR_ARIA_FEATURE_UNAVAILABLE,
        AriaHwAccelFailed = ERR_ARIA_HW_ACCEL_FAILED,
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
        BlowfishHwAccelFailed = ERR_BLOWFISH_HW_ACCEL_FAILED,
        BlowfishInvalidInputLength = ERR_BLOWFISH_INVALID_INPUT_LENGTH,
        CamelliaHwAccelFailed = ERR_CAMELLIA_HW_ACCEL_FAILED,
        CamelliaInvalidInputLength = ERR_CAMELLIA_INVALID_INPUT_LENGTH,
        CcmAuthFailed = ERR_CCM_AUTH_FAILED,
        CcmBadInput = ERR_CCM_BAD_INPUT,
        CcmHwAccelFailed = ERR_CCM_HW_ACCEL_FAILED,
        Chacha20BadInputData = ERR_CHACHA20_BAD_INPUT_DATA,
        Chacha20FeatureUnavailable = ERR_CHACHA20_FEATURE_UNAVAILABLE,
        Chacha20HwAccelFailed = ERR_CHACHA20_HW_ACCEL_FAILED,
        ChachapolyAuthFailed = ERR_CHACHAPOLY_AUTH_FAILED,
        ChachapolyBadState = ERR_CHACHAPOLY_BAD_STATE,
        CmacHwAccelFailed = ERR_CMAC_HW_ACCEL_FAILED,
        CtrDrbgEntropySourceFailed = ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED,
        CtrDrbgFileIoError = ERR_CTR_DRBG_FILE_IO_ERROR,
        CtrDrbgInputTooBig = ERR_CTR_DRBG_INPUT_TOO_BIG,
        CtrDrbgRequestTooBig = ERR_CTR_DRBG_REQUEST_TOO_BIG,
        DesHwAccelFailed = ERR_DES_HW_ACCEL_FAILED,
        DesInvalidInputLength = ERR_DES_INVALID_INPUT_LENGTH,
        EntropyFileIoError = ERR_ENTROPY_FILE_IO_ERROR,
        EntropyMaxSources = ERR_ENTROPY_MAX_SOURCES,
        EntropyNoSourcesDefined = ERR_ENTROPY_NO_SOURCES_DEFINED,
        EntropyNoStrongSource = ERR_ENTROPY_NO_STRONG_SOURCE,
        EntropySourceFailed = ERR_ENTROPY_SOURCE_FAILED,
        GcmAuthFailed = ERR_GCM_AUTH_FAILED,
        GcmBadInput = ERR_GCM_BAD_INPUT,
        GcmHwAccelFailed = ERR_GCM_HW_ACCEL_FAILED,
        HmacDrbgEntropySourceFailed = ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED,
        HmacDrbgFileIoError = ERR_HMAC_DRBG_FILE_IO_ERROR,
        HmacDrbgInputTooBig = ERR_HMAC_DRBG_INPUT_TOO_BIG,
        HmacDrbgRequestTooBig = ERR_HMAC_DRBG_REQUEST_TOO_BIG,
        Md5HwAccelFailed = ERR_MD5_HW_ACCEL_FAILED,
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
        NetConnReset = ERR_NET_CONN_RESET,
        NetConnectFailed = ERR_NET_CONNECT_FAILED,
        NetInvalidContext = ERR_NET_INVALID_CONTEXT,
        NetListenFailed = ERR_NET_LISTEN_FAILED,
        NetPollFailed = ERR_NET_POLL_FAILED,
        NetRecvFailed = ERR_NET_RECV_FAILED,
        NetSendFailed = ERR_NET_SEND_FAILED,
        NetSocketFailed = ERR_NET_SOCKET_FAILED,
        NetUnknownHost = ERR_NET_UNKNOWN_HOST,
        OidBufTooSmall = ERR_OID_BUF_TOO_SMALL,
        OidNotFound = ERR_OID_NOT_FOUND,
        PadlockDataMisaligned = ERR_PADLOCK_DATA_MISALIGNED,
        PlatformHwAccelFailed = ERR_PLATFORM_HW_ACCEL_FAILED,
        Poly1305BadInputData = ERR_POLY1305_BAD_INPUT_DATA,
        Poly1305FeatureUnavailable = ERR_POLY1305_FEATURE_UNAVAILABLE,
        Poly1305HwAccelFailed = ERR_POLY1305_HW_ACCEL_FAILED,
        Ripemd160HwAccelFailed = ERR_RIPEMD160_HW_ACCEL_FAILED,
        Sha1HwAccelFailed = ERR_SHA1_HW_ACCEL_FAILED,
        Sha256HwAccelFailed = ERR_SHA256_HW_ACCEL_FAILED,
        Sha512HwAccelFailed = ERR_SHA512_HW_ACCEL_FAILED,
        SslHwAccelFailed = ERR_SSL_HW_ACCEL_FAILED,
        XteaHwAccelFailed = ERR_XTEA_HW_ACCEL_FAILED,
        XteaInvalidInputLength = ERR_XTEA_INVALID_INPUT_LENGTH,
    }
);

#[cfg(test)]
mod tests {
    use super::{Error, codes, HiError, LoError};

    #[test]
    fn test_common_error_operations() {
        let (hi, lo) = (codes::CipherAllocFailed, codes::AesBadInputData);
        let (hi_only_error, lo_only_error, combined_error) = (Error::HighLevel(hi), Error::LowLevel(lo), Error::HighAndLowLevel(hi, lo));
        assert_eq!(combined_error.high_level().unwrap(), hi);
        assert_eq!(combined_error.low_level().unwrap(), lo);
        assert_eq!(hi_only_error.to_int(), -24960);
        assert_eq!(lo_only_error.to_int(), -33);
        assert_eq!(combined_error.to_int(), hi_only_error.to_int() + lo_only_error.to_int());
        assert_eq!(codes::CipherAllocFailed | codes::AesBadInputData, combined_error);
        assert_eq!(codes::AesBadInputData | codes::CipherAllocFailed, combined_error);
    }

    #[test]
    fn test_error_display() {
        let (hi, lo) = (HiError::CipherAllocFailed, LoError::AesBadInputData);
        let (hi_only_error, lo_only_error, combined_error) = (Error::HighLevel(hi), Error::LowLevel(lo), Error::HighAndLowLevel(hi, lo));
        assert_eq!(format!("{}", hi_only_error), "mbedTLS error HiError :: CipherAllocFailed");
        assert_eq!(format!("{}", lo_only_error), "mbedTLS error LoError :: AesBadInputData");
        assert_eq!(format!("{}", combined_error), "(mbedTLS error HiError :: CipherAllocFailed, mbedTLS error LoError :: AesBadInputData)");
    }

    #[test]
    fn test_error_from_int() {
        // positive error code
        assert_eq!(Error::from(0), Error::Other(0));
        assert_eq!(Error::from(1), Error::Other(1));
        // Lo, Hi, HiAndLo cases
        assert_eq!(Error::from(-1), Error::LowLevel(LoError::Unknown(-1)));
        assert_eq!(Error::from(-0x80), Error::HighLevel(HiError::Unknown(-0x80)));
        assert_eq!(Error::from(-0x81), Error::HighAndLowLevel(HiError::Unknown(-0x80), LoError::Unknown(-1)));
        assert_eq!(Error::from(-24993), Error::HighAndLowLevel(HiError::CipherAllocFailed, LoError::AesBadInputData));
        assert_eq!(Error::from(-24960), Error::HighLevel(HiError::CipherAllocFailed));
        assert_eq!(Error::from(-33), Error::LowLevel(LoError::AesBadInputData ));
        // error code out of boundaries
        assert_eq!(Error::from(-0x01FFFF), Error::Other(-0x01FFFF));
    }
}