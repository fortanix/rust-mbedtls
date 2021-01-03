/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::bignum::Mpi;
use crate::rng::Random;
use crate::hash::{MdInfo, Type as MdType};
use crate::pk::rfc6979::generate_rfc6979_nonce;
use crate::{Result, Error};

use yasna::models::ObjectIdentifier;
pub use yasna::{ASN1Error, ASN1ErrorKind};
use num_bigint::BigUint;
use bit_vec::BitVec;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DsaParams {
    p: Mpi,
    q: Mpi,
    g: Mpi,
}

impl DsaParams {
    pub fn from_components(p: Mpi, q: Mpi, g: Mpi) -> Result<Self> {
        if g > p || q > p {
            return Err(Error::PkBadInputData);
        }

        if p.modulo(&q)? != Mpi::new(1)? {
            return Err(Error::PkBadInputData);
        }

        Ok(Self { p, q, g })
    }

}

fn reduce_mod_q(m: &[u8], q: &Mpi) -> Result<Mpi> {
    // First truncate bitlength then reduce (see FIPS 186-4 sec 4.6)
    let q_bits = q.bit_length()?;

    let m_bits = m.len() * 8;

    let dec_len = if m_bits < q_bits {
        m.len()
    } else {
        (q_bits + 7) / 8
    };

    let m_bn = Mpi::from_binary(&m[..dec_len])?;
    m_bn.modulo(q)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DsaPublicKey {
    params: DsaParams,
    y: Mpi,
}

const DSA_OBJECT_IDENTIFIER: &[u64] = &[1, 2, 840, 10040, 4, 1];

impl DsaPublicKey {

    pub fn from_components(params: DsaParams, y: Mpi) -> Result<Self> {
        if y < Mpi::new(1)? || y >= params.p {
            return Err(Error::PkBadInputData);
        }
        // Verify that y is of order q modulo p
        if y.mod_exp(&params.q, &params.p)? != Mpi::new(1)? {
            return Err(Error::PkBadInputData);
        }
        Ok(Self { params, y })
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (p,q,g,y) = yasna::parse_der(der, |r| {
            r.read_sequence(|r| {
                let (p,q,g) = r.next().read_sequence(|r| {
                    let oid = r.next().read_oid()?;
                    if oid != ObjectIdentifier::from_slice(DSA_OBJECT_IDENTIFIER) {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    r.next().read_sequence(|r| {
                        let p = r.next().read_biguint()?;
                        let q = r.next().read_biguint()?;
                        let g = r.next().read_biguint()?;
                        Ok((p,q,g))
                    })
                })?;
                let y = r.next().read_bitvec()?;
                Ok((p,q,g,y))
            })
        }).map_err(|_| Error::PkInvalidPubkey)?;

        let y = yasna::parse_der(&y.to_bytes(), |r| {
            r.read_biguint()
        }).map_err(|_| Error::PkInvalidPubkey)?;

        let p = Mpi::from_binary(&p.to_bytes_be()).expect("Success");
        let q = Mpi::from_binary(&q.to_bytes_be()).expect("Success");
        let g = Mpi::from_binary(&g.to_bytes_be()).expect("Success");
        let y = Mpi::from_binary(&y.to_bytes_be()).expect("Success");

        let params = DsaParams::from_components(p, q, g)?;

        DsaPublicKey::from_components(params, y)
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let p = BigUint::from_bytes_be(&self.params.p.to_binary()?);
        let q = BigUint::from_bytes_be(&self.params.q.to_binary()?);
        let g = BigUint::from_bytes_be(&self.params.g.to_binary()?);
        let y = BigUint::from_bytes_be(&self.y.to_binary()?);

        let y_as_int = yasna::construct_der(|w| {
            w.write_biguint(&y)
        });

        let der = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_oid(&ObjectIdentifier::from_slice(DSA_OBJECT_IDENTIFIER));
                    w.next().write_sequence(|w| {
                        w.next().write_biguint(&p);
                        w.next().write_biguint(&q);
                        w.next().write_biguint(&g);
                    });
                });
                w.next().write_bitvec(&BitVec::from_bytes(&y_as_int));
            })
        });

        Ok(der)
    }

    pub fn verify(&self, signature: &[u8], pre_hashed_message: &[u8]) -> Result<bool> {
        if signature.len() % 2 == 1 {
            return Ok(false);
        }

        let p = &self.params.p;
        let q = &self.params.q;

        let half = signature.len() / 2;
        let r = Mpi::from_binary(&signature[..half])?;
        let s = Mpi::from_binary(&signature[half..])?;

        let zero = Mpi::new(0)?;

        if r <= zero || s <= zero {
            return Ok(false);
        }

        if &r >= q || &s >= q {
            return Ok(false);
        }

        let m = reduce_mod_q(pre_hashed_message, q)?;

        let s_inv = s.modinv(q)?;

        let sr = (&s_inv * &r)?.modulo(q)?;
        let sm = (&s_inv * &m)?.modulo(q)?;

        // Compute (g^sm * y^sr) mod p
        // mbedtls doesn't support multi-exponentiation
        let gsm = self.params.g.mod_exp(&sm, p)?;
        let ysr = self.y.mod_exp(&sr, p)?;
        let gsm_ysr = (&gsm * &ysr)?.modulo(p)?;

        Ok(gsm_ysr.modulo(q)? == r)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DsaPrivateKey {
    params: DsaParams,
    x: Mpi,
}

fn sample_secret_value<F: Random>(upper_bound: &Mpi, rng: &mut F) -> Result<Mpi> {
    /*
    See FIPS 186-4 Appendix B.2.1
     */
    let bits = upper_bound.bit_length()?;
    let mut rnd_buf = vec![0u8; (bits + 7 + 64) / 8];
    rng.random(&mut rnd_buf)?;
    let c = Mpi::from_binary(&rnd_buf)?;
    let mut c = c.modulo(&(upper_bound - 1)?)?;
    c += 1;
    Ok(c)
}

fn encode_dsa_signature(q_bits: usize, r: &Mpi, s: &Mpi) -> Result<Vec<u8>> {
    let q_bytes = (q_bits + 7) / 8;
    let r = r.to_binary_padded(q_bytes)?;
    let s = s.to_binary_padded(q_bytes)?;
    let mut sig = Vec::with_capacity(r.len() + s.len());
    sig.extend_from_slice(&r);
    sig.extend_from_slice(&s);
    Ok(sig)
}

impl DsaPrivateKey {
    pub fn from_components(params: DsaParams, x: Mpi) -> Result<Self> {
        if x <= Mpi::new(1)? || x >= params.q {
            return Err(Error::PkBadInputData);
        }
        Ok(Self { params, x })
    }

    pub fn generate<F: Random>(params: DsaParams, rng: &mut F) -> Result<Self> {
        let x = sample_secret_value(&params.q, rng)?;
        Ok(Self { params, x })
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (p,q,g,x) = yasna::parse_der(der, |r| {
            r.read_sequence(|r| {
                if r.next().read_u8()? != 0 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                let (p,q,g) = r.next().read_sequence(|r| {
                    let oid = r.next().read_oid()?;
                    if oid != ObjectIdentifier::from_slice(DSA_OBJECT_IDENTIFIER) {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    r.next().read_sequence(|r| {
                        let p = r.next().read_biguint()?;
                        let q = r.next().read_biguint()?;
                        let g = r.next().read_biguint()?;
                        Ok((p,q,g))
                    })
                })?;
                let x = r.next().read_bytes()?;
                Ok((p,q,g,x))
            })
        }).map_err(|_| Error::PkInvalidPubkey)?;

        let x = yasna::parse_der(&x, |r| { r.read_biguint() }).
            map_err(|_| Error::PkInvalidPubkey)?;

        let p = Mpi::from_binary(&p.to_bytes_be()).expect("Success");
        let q = Mpi::from_binary(&q.to_bytes_be()).expect("Success");
        let g = Mpi::from_binary(&g.to_bytes_be()).expect("Success");
        let x = Mpi::from_binary(&x.to_bytes_be()).expect("Success");

        let params = DsaParams::from_components(p, q, g)?;

        DsaPrivateKey::from_components(params, x)
    }

    pub fn to_der(&self) -> Result<Vec<u8>> {
        let p = BigUint::from_bytes_be(&self.params.p.to_binary()?);
        let q = BigUint::from_bytes_be(&self.params.q.to_binary()?);
        let g = BigUint::from_bytes_be(&self.params.g.to_binary()?);
        let x = BigUint::from_bytes_be(&self.x.to_binary()?);

        let x_as_int = yasna::construct_der(|w| { w.write_biguint(&x) });

        let der = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_u8(0); // version
                w.next().write_sequence(|w| {
                    w.next().write_oid(&ObjectIdentifier::from_slice(DSA_OBJECT_IDENTIFIER));
                    w.next().write_sequence(|w| {
                        w.next().write_biguint(&p);
                        w.next().write_biguint(&q);
                        w.next().write_biguint(&g);
                    });
                });
                w.next().write_bytes(&x_as_int)
            })
        });

        Ok(der)
    }

    pub fn public_key(&self) -> Result<DsaPublicKey> {
        let y = self.params.g.mod_exp(&self.x, &self.params.p)?;
        DsaPublicKey::from_components(self.params.clone(), y)
    }

    pub fn sign<F: Random>(&self, pre_hashed_message: &[u8], rng: &mut F) -> Result<Vec<u8>> {
        let k = sample_secret_value(&self.params.q, rng)?;
        self.sign_with_explicit_nonce(pre_hashed_message, k, rng)
    }

    pub fn sign_deterministic<F: Random>(&self, md_type: MdType, pre_hashed_message: &[u8], rng: &mut F) -> Result<Vec<u8>> {
        let md: MdInfo = match md_type.into() {
            Some(md) => md,
            None => panic!("no such digest"),
        };
        let rfc6979_nonce = generate_rfc6979_nonce(&md, &self.x, &self.params.q, pre_hashed_message)?;
        let k = Mpi::from_binary(&rfc6979_nonce)?;
        self.sign_with_explicit_nonce(pre_hashed_message, k, rng)
    }

    // Exposed for testing
    fn sign_with_explicit_nonce<F: Random>(&self, pre_hashed_message: &[u8], k: Mpi, rng: &mut F) -> Result<Vec<u8>> {
        let q = &self.params.q;

        let m = reduce_mod_q(pre_hashed_message, q)?;
        let k_inv = k.modinv(q)?;

        // Mask k by using k+r*q for random r as the scalar
        let k_mask = sample_secret_value(&self.params.q, rng)?;
        let masked_k = (&k + &(&k_mask * q)?)?;

        let g_k_p = self.params.g.mod_exp(&masked_k, &self.params.p)?;
        let r = g_k_p.modulo(q)?;

        // Blind the input message and compute x*r+m as (x*r*z + m*z)/z
        // to avoid ROHNP-style attacks

        let z_mask = sample_secret_value(&self.params.q, rng)?;
        let z_inv = z_mask.modinv(q)?;

        let zm = (&z_mask * &m)?;
        let xrz = (&(&z_mask * &self.x)? * &r)?;

        let xr_m = (&(&xrz + &zm)? * &z_inv)?.modulo(q)?;

        let s = (&xr_m * &k_inv)?.modulo(q)?;

        let zero = Mpi::new(0)?;
        if r == zero || s == zero {
            return Err(Error::MpiBadInputData);
        }
        encode_dsa_signature(q.bit_length()?, &r, &s)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::mbedtls::bignum::Mpi;
    use crate::mbedtls::hash::{Md, Type as MdType};
    use crate::mbedtls::rng::HmacDrbg;
    use std::time::SystemTime;
    use std::collections::HashMap;

    fn hardcoded_2048_256() -> Result<DsaParams> {
        use core::str::FromStr;
        // Randomly generated by OpenSSL
        DsaParams::from_components(
            Mpi::from_str("0xD15B37F9EE581E6F19F11FAD3A543392C3553D040FC1A665E772DFF80F348396EEC4E8BBE47ED7589FEAB470837323399EF0D3E68E44EF8AC82D644D257CEC56FDA76E86ADDFA0A70DF914F230BD387E6305B82650793AB57598DAA60549A4A7EAF13FC005DE7CCB863F33C4EED789751A17AA3E652818170E57F9E8917ED9A3A2618EC982A9CC42D98D807B5692980B28787B149788316971F4E8F9E57548D552D81D25350CE26CF321085203F54BA7B3A4522F85E70BB0FCF31EB14130698AD645AEF8088255EA98298C37DE8292A98CCD89142AD47B39780864C021EA648DCC0096F6E869312E1F5C7FC648D59CC0F0BBEA70463953DDB3627713C1C0F401")?,
            Mpi::from_str("0xC461FA60DCCBC684AD5249C114D5470B74B41CFFD058C924EC5B585AA27E9825")?,
            Mpi::from_str("0x3A9D1D6269467C80CDFFBAFABFC1EF0AD5F43463F0F0010D7F5DAF2E7097465472AB0BCD78F6A4710DE817174F6698A1A7C036463932DE3FC53579E2E9D3CF753006BC12FD21ECCCEF9860BDAE93927E10F447D75B4283E0B25BC748750E415CC8CD6FEF6A667753800A3A5A51B8EC04764A1019E9F2CFE7A10B63C813C889EB7327D9B7BA62D61196D2B9687F5616C84F0867AEAE5A484B54150B6446590DB3820D23E03F19BF092B240E9A7FF524DE7EDEB421C4F33CD686308D546BB04FA6B04BE9811A6B5673D1057EDD7798B9EEDACFFC9AED8C4BC26F88042D2E7536F968C3B52FF270F3E8B666339BFFBD7F041672C39EBDC5021EB2AF808DA2E3CFDD")?
        )
    }


    fn hex_to_bn(input: &str) -> Mpi {
        let bin = hex::decode(input).expect("valid hex");
        Mpi::from_binary(&bin).unwrap()
    }

    fn hash_to_mdt(hash: &str) -> MdType {
        match hash {
            "SHA-1" => MdType::Sha1,
            "SHA-224" => MdType::Sha224,
            "SHA-256" => MdType::Sha256,
            "SHA-384" => MdType::Sha384,
            "SHA-512" => MdType::Sha512,
            _ => panic!("unknown hash")
        }
    }

    fn hash_input(input: &[u8], mdt: MdType) -> Vec<u8> {
        let mut output = vec![0u8; 64]; // biggest in SHA-512
        let len = Md::hash(mdt, input, &mut output).unwrap();
        output.truncate(len);
        output
    }

    #[test]
    fn dsa_der() {
        let params = hardcoded_2048_256().unwrap();

        let mdinfo: MdInfo = match MdType::Sha256.into() {
            Some(mdinfo) => mdinfo,
            None => panic!("no such digest"),
        };
        let mut rng = HmacDrbg::from_buf(mdinfo, &[0u8; 32]).unwrap();

        let privkey = DsaPrivateKey::generate(params, &mut rng).unwrap();
        let decoded = DsaPrivateKey::from_der(&privkey.to_der().unwrap()).unwrap();
        assert_eq!(privkey, decoded);

        let pubkey = privkey.public_key().unwrap();
        let decoded = DsaPublicKey::from_der(&pubkey.to_der().unwrap()).unwrap();
        assert_eq!(pubkey, decoded);
    }

    #[test]
    fn dsa_der_pubkey_roundtrip() {
        /*
        Generated by
        $ openssl dsaparam 2048 > dsaparam.pem
        $ openssl gendsa dsaparam.pem > dsapriv.pem
        $ openssl dsa -in dsapriv.pem -pubout > dsapub.pem
        $ openssl dsa -in dsapub.pem -pubin -outform DER > dsapub.der
         */
        let dsa_der = hex::decode("308203463082023906072A8648CE3804013082022C02820101008A92DA7803B00B5E5876CB45FAE65AC8449E8E1290F371B8038446D2D8E9A1AFAB231F813E915545513A596FBD05535ED5C41739A45EEDA8CE7C285F23158F772CE079ADF60E123A08AE8810377268399A618474617FA481D0FDE32C9860E80EA1FA5BE3F94493EA1C4EC8DA1BB2942ACF735C4DB76A1CEACBFEE20F5A96EFF0DC90B57CFB43C7ABADCA56D4334B14B4AE9570F678C3D765730A5DF83ACAC9C3374BE2DF28B0078FB06193F26842F134D4A94AEF54CE83A010EEE11C0C14A74FBB67EFA84DFA48A020CB8DF9D942F2D9E8EEFA6C2C8F59A115BC1C799B57ECA5F55B36B3DF09C08099C0D0FD614C488781AACC2B977080BF388D9A4E3AFC7B7102210094843407F4C5C7D71470464DCF36FE222882589B0E901C6658107229EC3D499F028201002E37AEF72420A5C4601A11A6E403488F4FE017E9491182157B7D731B4544CA27C666DEC9FC22E8FCBE3DAD4492904D31F6429B2A4AE9684F1C5AAF22AFB8F7FB99A84E38E9A70F1A00725AD12F3BC8CB8E1F069A7CA5C619E0EC8F1BAC7C81D9E16A0AAAF5A76F982AB2083CAF5CC2D492B3BBC460E6D4294524B15FAE74F688852EBF82A3564E10B412C1BCC268019B167403BFEF87B8C3692790A0377B27FA542B8422D2A042AD55652913091CF6DC8E0C488B38978BDA8C1FEE04895615F207DA5FD820A0672889D73BF186C862E49352D4F1A19FC83A89625E275E1E3184F99DA021038E73E436C090DA885F2F1AD7816200B2591E0D2896A82C655A09DA03820105000282010076B655A2183B21C6D14992AB51029DFEB9F3BDC9DA3FE744F1570E0F778CB2691E312C4C68244AB6A31DB6906F77A19BA694C0F147F213C1EAFC80D52A05AD223F8131B5A4D777A578F770073B90A4EB7ED3DFC550D5A75900B5DA0437BB33CC16BEF721CFAFEA5F14E083B07EE7940089258720F177A6133EE2C7EA00EAB69BA53FB64DD14377F43A4E7A91CA262791FCD43486D8017EC83CB1DE2D536DF99277DA46DF586166E141B827DF4D320480DD3097F8BF82ECA7C92CAC39FC95DB86D2B04FBD29FF5AE0C1A0CB31781F4DC38940406A056F5A61D354C5D3D30D6426ED5F6D84D9DED571D4D401C9365C2CCBC8CACC4607DA183459D45C64C1174DE4").unwrap();

        let key = DsaPublicKey::from_der(&dsa_der).unwrap();

        assert_eq!(key.params.q, hex_to_bn("94843407f4c5c7d71470464dcf36fe222882589b0e901c6658107229ec3d499f"));

        let reencoded = key.to_der().unwrap();

        assert_eq!(reencoded, dsa_der);
    }

    #[test]
    fn dsa_out_of_range_signatures() {
        let params = hardcoded_2048_256().unwrap();

        let q = params.q.clone();

        let q_bits = q.bit_length().unwrap();
        let y = params.g.clone();

        let pubkey = DsaPublicKey::from_components(params, y).unwrap();

        let zero_sig = encode_dsa_signature(q_bits, &Mpi::new(0).unwrap(), &Mpi::new(0).unwrap()).unwrap();
        let junk_message = vec![42; q_bits*8];

        assert!(!pubkey.verify(&zero_sig, &junk_message).unwrap());

        let q_sig = encode_dsa_signature(q_bits, &q, &q).unwrap();
        assert!(!pubkey.verify(&q_sig, &junk_message).unwrap());
    }

    #[test]
    fn dsa_rfc6979_kats() {
        // These tests come from RFC 6979 section A.2.2

        let p = hex_to_bn("9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44FFE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE235567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA153E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B");

        let q = hex_to_bn("F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F");

        let g = hex_to_bn("5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C46A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7");

        let x = hex_to_bn("69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC");

        let params = DsaParams::from_components(p, q, g).unwrap();
        let privkey = DsaPrivateKey::from_components(params, x).unwrap();
        let pubkey = privkey.public_key().unwrap();

        let rfc6979_results = [
            ("sample", MdType::Sha1,   "3a1b2dbd7489d6ed7e608fd036c83af396e290dbd602408e8677daabd6e7445ad26fcba19fa3e3058ffc02ca1596cdbb6e0d20cb37b06054f7e36ded0cdbbccf"),
            ("sample", MdType::Sha224, "dc9f4deada8d8ff588e98fed0ab690ffce858dc8c79376450eb6b76c24537e2ca65a9c3bc7babe286b195d5da68616da8d47fa0097f36dd19f517327dc848cec"),
            ("sample", MdType::Sha256, "eace8bdbbe353c432a795d9ec556c6d021f7a03f42c36e9bc87e4ac7932cc8097081e175455f9247b812b74583e9e94f9ea79bd640dc962533b0680793a38d53"),
            ("sample", MdType::Sha384, "b2da945e91858834fd9bf616ebac151edbc4b45d27d0dd4a7f6a22739f45c00b19048b63d9fd6bca1d9bae3664e1bcb97f7276c306130969f63f38fa8319021b"),
            ("sample", MdType::Sha512, "2016ed092dc5fb669b8efb3d1f31a91eecb199879be0cf78f02ba062cb4c942ed0c76f84b5f091e141572a639a4fb8c230807eea7d55c8a154a224400aff2351"),
            ("test", MdType::Sha1,     "c18270a93cfc6063f57a4dfa86024f700d980e4cf4e2cb65a504397273d98ea0414f22e5f31a8b6d33295c7539c1c1ba3a6160d7d68d50ac0d3a5beac2884faa"),
            ("test", MdType::Sha224,   "272aba31572f6cc55e30bf616b7a265312018dd325be031be0cc82aa17870ea3e9cc286a52cce201586722d36d1e917eb96a4ebdb47932f9576ac645b3a60806"),
            ("test", MdType::Sha256,   "8190012a1969f9957d56fccaad223186f423398d58ef5b3cefd5a4146a4476f07452a53f7075d417b4b013b278d1bb8bbd21863f5e7b1cee679cf2188e1ab19e"),
            ("test", MdType::Sha384,   "239e66ddbe8f8c230a3d071d601b6ffbdfb5901f94d444c6af56f732beb954be6bd737513d5e72fe85d1c750e0f73921fe299b945aad1c802f15c26a43d34961"),
            ("test", MdType::Sha512,   "89ec4bb1400eccff8e7d9aa515cd1de7803f2daff09693ee7fd1353e90a68307c9f0bdabcc0d880bb137a994cc7f3980ce91cc10faf529fc46565b15cea854e1"),
        ];

        let mdt = MdType::Sha512;
        let mdinfo: MdInfo = match mdt.into() {
            Some(m) => m,
            None => panic!()
        };

        let bad_seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
        let mut rng = HmacDrbg::from_buf(mdinfo, &bad_seed.to_be_bytes()).unwrap();

        for kat in rfc6979_results.iter() {
            let digest = hash_input(kat.0.as_bytes(), kat.1);
            let sig = privkey.sign_deterministic(kat.1, &digest, &mut rng).unwrap();
            assert_eq!(hex::encode(&sig), kat.2);
            assert!(pubkey.verify(&sig, &digest).unwrap());
        }
    }

    #[test]
    fn dsa_fips186_3_kats() {
        fn test_kat(inputs: &HashMap<String, String>) {
            let p = hex_to_bn(inputs.get("P").unwrap());
            let q = hex_to_bn(inputs.get("Q").unwrap());
            let g = hex_to_bn(inputs.get("G").unwrap());

            let x = hex_to_bn(inputs.get("X").unwrap());
            let y = hex_to_bn(inputs.get("Y").unwrap());

            let k = hex_to_bn(inputs.get("K").unwrap());
            let r = hex_to_bn(inputs.get("R").unwrap());
            let s = hex_to_bn(inputs.get("S").unwrap());
            let encoded_sig = encode_dsa_signature(q.bit_length().unwrap(), &r, &s).unwrap();

            let msg = hex::decode(inputs.get("Msg").unwrap()).unwrap();
            let hash = inputs.get("Hash").unwrap();
            let mdt = hash_to_mdt(hash);
            let hashed_message = hash_input(&msg, mdt);

            let mdinfo: MdInfo = match mdt.into() {
                Some(mdinfo) => mdinfo,
                None => panic!("no such digest"),
            };

            let bad_seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
            let mut rng = HmacDrbg::from_buf(mdinfo, &bad_seed.to_be_bytes()).unwrap();

            let params = DsaParams::from_components(p, q, g).unwrap();

            let privkey = DsaPrivateKey::from_components(params, x).unwrap();

            let pubkey = privkey.public_key().unwrap();
            assert_eq!(pubkey.y, y);

            assert!(pubkey.verify(&encoded_sig, &hashed_message).unwrap());

            assert_eq!(privkey.sign_with_explicit_nonce(&hashed_message, k, &mut rng).unwrap(), encoded_sig);

            // Additional tests done per KAT input:

            // Generate a new RFC 6979 signature and verify it
            let new_rfc6979_sig = privkey.sign_deterministic(mdt, &hashed_message, &mut rng).unwrap();
            assert!(pubkey.verify(&new_rfc6979_sig, &hashed_message).unwrap());

            // Generate a new random(-ish) signature and verify it
            let new_random_sig = privkey.sign(&hashed_message, &mut rng).unwrap();
            assert!(pubkey.verify(&new_random_sig, &hashed_message).unwrap());

            // Verify invalid signature is rejected
            let mut bad_sig = encoded_sig.clone();
            bad_sig[5] ^= 1;
            assert!(!pubkey.verify(&bad_sig, &hashed_message).unwrap());

            // Verify if we toggle an input bit, signature is rejected
            let mut bad_input = hashed_message.clone();
            bad_input[5] ^= 1;
            assert!(!pubkey.verify(&encoded_sig, &bad_input).unwrap());
        }

        let dsa_kats = include_str!("../../../tests/data/dsa.kat");

        let mut params : HashMap<String, String> = HashMap::new();

        for line in dsa_kats.lines() {
            if line == "" || line.chars().nth(0) == Some('#') {
                continue;
            }

            let k_v = line.split(" = ").collect::<Vec<_>>();

            assert_eq!(k_v.len(), 2);

            let key = k_v[0];
            let value = k_v[1];

            params.insert(key.to_string(), value.to_string());

            if key == "S" {
                test_kat(&params);
            }
        }
    }
}
