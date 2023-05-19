/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::*;

define!(
    #[non_exhaustive]
    #[c_ty(ssl_states)]
    enum SslStates {
        HelloRequest = SSL_HELLO_REQUEST,
        ClientHello = SSL_CLIENT_HELLO,
        ServerHello = SSL_SERVER_HELLO,
        ServerCertificate = SSL_SERVER_CERTIFICATE,
        ServerKeyExchange = SSL_SERVER_KEY_EXCHANGE,
        CertificateRequest = SSL_CERTIFICATE_REQUEST,
        ServerHelloDone = SSL_SERVER_HELLO_DONE,
        ClientCertificate = SSL_CLIENT_CERTIFICATE,
        ClientKeyExchange = SSL_CLIENT_KEY_EXCHANGE,
        CertificateVerify = SSL_CERTIFICATE_VERIFY,
        ClientChangeCipherSpec = SSL_CLIENT_CHANGE_CIPHER_SPEC,
        ClientFinished = SSL_CLIENT_FINISHED,
        ServerChangeCipherSpec = SSL_SERVER_CHANGE_CIPHER_SPEC,
        ServerFinished = SSL_SERVER_FINISHED,
        FlushBuffers = SSL_FLUSH_BUFFERS,
        HandshakeWrapup = SSL_HANDSHAKE_WRAPUP,
        NewSessionTicket = SSL_NEW_SESSION_TICKET,
        ServerHelloVerifyRequestSent = SSL_SERVER_HELLO_VERIFY_REQUEST_SENT,
        HelloRetryRequest = SSL_HELLO_RETRY_REQUEST,
        EncryptedExtensions = SSL_ENCRYPTED_EXTENSIONS,
        EndOfEarlyData = SSL_END_OF_EARLY_DATA,
        ClientCertificateVerify = SSL_CLIENT_CERTIFICATE_VERIFY,
        ClientCcsAfterServerFinished = SSL_CLIENT_CCS_AFTER_SERVER_FINISHED,
        ClientCcsBefore2ndClientHello = SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO,
        ServerCcsAfterServerHello = SSL_SERVER_CCS_AFTER_SERVER_HELLO,
        ClientCcsAfterClientHello = SSL_CLIENT_CCS_AFTER_CLIENT_HELLO,
        ServerCcsAfterHelloRetryRequest = SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST,
        HandshakeOver = SSL_HANDSHAKE_OVER,
        Tls13NewSessionTicket = SSL_TLS1_3_NEW_SESSION_TICKET,
        Tls13NewSessionTicketFlush = SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH,
    }
);
