/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate mbedtls;

use mbedtls::x509::certificate::{Certificate, List, LinkedCertificate};
use mbedtls::x509::Crl;
use std::ffi::CString;

mod support;

#[test]
fn verify_x509() {
    fn read_cert(cert: &'static str) -> Option<Certificate> {
        let cert = CString::new(cert.as_bytes()).ok()?;
        Certificate::from_pem(cert.as_bytes_with_nul()).ok()
    }

    let mut root = read_cert(include_str!("data/root.crt")).unwrap();
    let cert = read_cert(include_str!("data/certificate.crt")).unwrap();

    let mut certs = vec![cert];
    let certs = &mut List::from_vec(&mut certs).unwrap();

    assert!(LinkedCertificate::verify(certs.into(), &mut root, None, None).is_ok());

    let mut crl = Crl::new();
    crl.push_from_der(include_bytes!("data/root.empty.crl")).unwrap();
    assert!(LinkedCertificate::verify(certs.into(), &mut root, Some(&mut crl), None).is_ok());

    // A bug in the ARMmbed mbedtls library only revokes certificates when a time source is
    // available. We temporarily disable the following test, until patch
    // https://github.com/ARMmbed/mbedtls/pull/3433 lands and we use the updated library
    #[cfg(time)]
    {
        let mut crl = Crl::new();
        crl.push_from_der(include_bytes!("data/root.revoked.crl")).unwrap();
        let mut err = String::new();

        assert_eq!(LinkedCertificate::verify(certs.into(), &mut root, Some(&mut crl), Some(&mut err)).unwrap_err(), Error::X509CertVerifyFailed);
        assert_eq!(err, "The certificate has been revoked (is on a CRL)\n");
    }
}
