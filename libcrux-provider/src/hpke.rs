use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;
use rand_core::TryRngCore;
use std::error::Error as StdError;

use libcrux::hpke::aead::AEAD;
use libcrux::hpke::kdf::KDF;
use libcrux::hpke::kem::KEM;
use libcrux::hpke::HPKEConfig;

use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{
    HpkeAead as HpkeAeadId, HpkeKdf as HpkeKdfId, HpkeKem as HpkeKemId,
};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::{Error, OtherError};

/// All supported HPKE suites.
///
/// Note: hpke-rs w/ rust-crypto does not support P-384 and P-521 DH KEMs.
pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = &[
    DHKEM_P256_HKDF_SHA256_AES_128,
    DHKEM_P256_HKDF_SHA256_AES_256,
    DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305,
    DHKEM_X25519_HKDF_SHA256_AES_128,
    DHKEM_X25519_HKDF_SHA256_AES_256,
    DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305,
];

pub static DHKEM_P256_HKDF_SHA256_AES_128: &LibcruxHpke = &LibcruxHpke(HPKEConfig(
    libcrux::hpke::Mode::mode_base,
    KEM::DHKEM_P256_HKDF_SHA256,
    KDF::HKDF_SHA256,
    AEAD::AES_128_GCM,
));

pub static DHKEM_P256_HKDF_SHA256_AES_256: &LibcruxHpke = &LibcruxHpke(HPKEConfig(
    libcrux::hpke::Mode::mode_base,
    KEM::DHKEM_P256_HKDF_SHA256,
    KDF::HKDF_SHA256,
    AEAD::AES_256_GCM,
));

pub static DHKEM_P256_HKDF_SHA256_CHACHA20_POLY1305: &LibcruxHpke = &LibcruxHpke(HPKEConfig(
    libcrux::hpke::Mode::mode_base,
    KEM::DHKEM_P256_HKDF_SHA256,
    KDF::HKDF_SHA256,
    AEAD::ChaCha20Poly1305,
));

pub static DHKEM_X25519_HKDF_SHA256_AES_128: &LibcruxHpke = &LibcruxHpke(HPKEConfig(
    libcrux::hpke::Mode::mode_base,
    KEM::DHKEM_X25519_HKDF_SHA256,
    KDF::HKDF_SHA256,
    AEAD::AES_128_GCM,
));

pub static DHKEM_X25519_HKDF_SHA256_AES_256: &LibcruxHpke = &LibcruxHpke(HPKEConfig(
    libcrux::hpke::Mode::mode_base,
    KEM::DHKEM_X25519_HKDF_SHA256,
    KDF::HKDF_SHA256,
    AEAD::AES_256_GCM,
));

pub static DHKEM_X25519_HKDF_SHA256_CHACHA20_POLY1305: &LibcruxHpke = &LibcruxHpke(HPKEConfig(
    libcrux::hpke::Mode::mode_base,
    KEM::DHKEM_X25519_HKDF_SHA256,
    KDF::HKDF_SHA256,
    AEAD::ChaCha20Poly1305,
));

/// A HPKE suite backed by the [hpke-rs] crate and its rust-crypto cryptography provider.
///
/// [hpke-rs]: https://github.com/franziskuskiefer/hpke-rs
#[derive(Debug)]
pub struct HpkeRs(HpkeSuite);

impl HpkeRs {
    fn start(&self) -> Result<hpke_rs::Hpke<HpkeRustCrypto>, Error> {
        Ok(hpke_rs::Hpke::new(
            hpke_rs::Mode::Base,
            KemAlgorithm::try_from(u16::from(self.0.kem)).map_err(other_err)?,
            KdfAlgorithm::try_from(u16::from(self.0.sym.kdf_id)).map_err(other_err)?,
            AeadAlgorithm::try_from(u16::from(self.0.sym.aead_id)).map_err(other_err)?,
        ))
    }
}

impl Hpke for HpkeRs {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let pk_r = hpke_rs::HpkePublicKey::new(pub_key.0.clone());
        let (enc, ciphertext) = self
            .start()?
            .seal(&pk_r, info, aad, plaintext, None, None, None)
            .map_err(other_err)?;
        Ok((EncapsulatedSecret(enc.to_vec()), ciphertext))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let pk_r = hpke_rs::HpkePublicKey::new(pub_key.0.clone());
        let (enc, context) = self
            .start()?
            .setup_sender(&pk_r, info, None, None, None)
            .map_err(other_err)?;
        Ok((
            EncapsulatedSecret(enc.to_vec()),
            Box::new(HpkeRsSender { context }),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let sk_r = hpke_rs::HpkePrivateKey::new(secret_key.secret_bytes().to_vec());
        self.start()?
            .open(
                enc.0.as_slice(),
                &sk_r,
                info,
                aad,
                ciphertext,
                None,
                None,
                None,
            )
            .map_err(other_err)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let sk_r = hpke_rs::HpkePrivateKey::new(secret_key.secret_bytes().to_vec());
        Ok(Box::new(HpkeRsReceiver {
            context: self
                .start()?
                .setup_receiver(enc.0.as_slice(), &sk_r, info, None, None, None)
                .map_err(other_err)?,
        }))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let kem_algorithm = match self.0.kem {
            HpkeKemId::DHKEM_P256_HKDF_SHA256 => KemAlgorithm::DhKemP256,
            HpkeKemId::DHKEM_X25519_HKDF_SHA256 => KemAlgorithm::DhKem25519,
            _ => {
                // Safety: we don't expose HpkeRs static instances for unsupported algorithms.
                unimplemented!()
            }
        };

        let (public_key, secret_key) = HpkeRustCrypto::kem_key_gen(kem_algorithm, &mut HpkeRustCrypto::prng())
            .map_err(other_err)?;

        Ok((HpkePublicKey(public_key), HpkePrivateKey::from(secret_key)))
    }

    fn suite(&self) -> HpkeSuite {
        self.0
    }
}

#[derive(Debug)]
struct HpkeRsSender {
    context: hpke_rs::Context<HpkeRustCrypto>,
}

impl HpkeSealer for HpkeRsSender {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.context
            .seal(aad, plaintext)
            .map_err(other_err)
    }
}

#[derive(Debug)]
struct HpkeRsReceiver {
    context: hpke_rs::Context<HpkeRustCrypto>,
}

impl HpkeOpener for HpkeRsReceiver {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.context
            .open(aad, ciphertext)
            .map_err(other_err)
    }
}

#[derive(Debug)]
struct LibcruxHpkeSealer {
    context: (
        libcrux::hpke::aead::Key,
        libcrux::hpke::aead::Nonce,
        u32,
        Vec<u8>,
    ),
    config: libcrux::hpke::HPKEConfig,
}

impl HpkeSealer for LibcruxHpkeSealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut context = (
            libcrux::hpke::aead::Key::new(),
            libcrux::hpke::aead::Nonce::new(),
            0,
            Vec::new(),
        );
        core::mem::swap(&mut self.context, &mut context);

        let (ciphertext, mut context) =
            libcrux::hpke::ContextS_Seal(self.config.3, context, aad, plaintext)
                .map_err(|_| Error::General(String::from("hpke seal error")))?;
        core::mem::swap(&mut self.context, &mut context);

        Ok(ciphertext)
    }
}

#[derive(Debug)]
struct LibcruxHpkeOpener {
    context: (
        libcrux::hpke::aead::Key,
        libcrux::hpke::aead::Nonce,
        u32,
        Vec<u8>,
    ),
    config: libcrux::hpke::HPKEConfig,
}

impl HpkeOpener for LibcruxHpkeOpener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut context = (
            libcrux::hpke::aead::Key::new(),
            libcrux::hpke::aead::Nonce::new(),
            0,
            Vec::new(),
        );
        core::mem::swap(&mut self.context, &mut context);

        let (plaintext, mut context) =
            libcrux::hpke::ContextR_Open(self.config.3, context, aad, ciphertext)
                .map_err(|_| Error::General(String::from("hpke open error")))?;

        core::mem::swap(&mut self.context, &mut context);
        Ok(plaintext)
    }
}

#[derive(Debug)]
pub struct LibcruxHpke(libcrux::hpke::HPKEConfig);

impl Hpke for LibcruxHpke {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let mut randomness = alloc::vec![0u8; libcrux::hpke::kem::Nsecret(self.0 .1)];
        rand_core::OsRng.try_fill_bytes(&mut randomness).unwrap();

        libcrux::hpke::HpkeSeal(
            self.0, &pub_key.0, info, aad, plaintext, None, None, None, randomness,
        )
        .map_err(|_| Error::General(alloc::string::String::from("hpke seal error")))
        .map(|ctxt| (EncapsulatedSecret(ctxt.0), ctxt.1))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let mut randomness = alloc::vec![0u8; libcrux::hpke::kem::Nsecret(self.0 .1)];
        rand_core::OsRng.try_fill_bytes(&mut randomness).unwrap();

        let (kem_ctxt, ctx) = libcrux::hpke::SetupBaseS(self.0, &pub_key.0, info, randomness)
            .map_err(|_| Error::General(alloc::string::String::from("hpke setup sealer error")))?;

        Ok((
            EncapsulatedSecret(kem_ctxt),
            Box::new(LibcruxHpkeSealer {
                context: ctx,
                config: self.0,
            }),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        libcrux::hpke::HpkeOpen(
            self.0,
            &libcrux::hpke::HPKECiphertext(enc.0.clone(), Vec::from(ciphertext)),
            secret_key.secret_bytes(),
            info,
            aad,
            None,
            None,
            None,
        )
        .map_err(|_| Error::General(alloc::string::String::from("hpke open error")))
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let ctx = libcrux::hpke::SetupBaseR(self.0, &enc.0, secret_key.secret_bytes(), info)
            .map_err(|_| Error::General(alloc::string::String::from("hpke setup opener error")))?;

        Ok(Box::new(LibcruxHpkeOpener {
            context: ctx,
            config: self.0,
        }))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let mut randomness = alloc::vec![0u8; libcrux::hpke::kem::Nsecret(self.0 .1)];
        rand_core::OsRng.try_fill_bytes(&mut randomness).unwrap();

        libcrux::hpke::kem::GenerateKeyPair(self.0 .1, randomness)
            .map_err(|_| Error::General(String::from("hpke kem keygen error")))
            .map(|(sk, pk)| (HpkePublicKey(pk), HpkePrivateKey::from(sk)))
    }

    fn suite(&self) -> HpkeSuite {
        let kem = match self.0 .1 {
            KEM::DHKEM_P256_HKDF_SHA256 => HpkeKemId::DHKEM_P256_HKDF_SHA256,
            KEM::DHKEM_P384_HKDF_SHA384 => HpkeKemId::DHKEM_P384_HKDF_SHA384,
            KEM::DHKEM_P521_HKDF_SHA512 => HpkeKemId::DHKEM_P521_HKDF_SHA512,
            KEM::DHKEM_X25519_HKDF_SHA256 => HpkeKemId::DHKEM_X25519_HKDF_SHA256,
            KEM::DHKEM_X448_HKDF_SHA512 => HpkeKemId::DHKEM_X448_HKDF_SHA512,
            _ => unimplemented!(),
        };

        let kdf_id = match self.0 .2 {
            KDF::HKDF_SHA256 => HpkeKdfId::HKDF_SHA256,
            KDF::HKDF_SHA384 => HpkeKdfId::HKDF_SHA384,
            KDF::HKDF_SHA512 => HpkeKdfId::HKDF_SHA512,
        };

        let aead_id = match self.0 .3 {
            AEAD::AES_128_GCM => HpkeAeadId::AES_128_GCM,
            AEAD::AES_256_GCM => HpkeAeadId::AES_256_GCM,
            AEAD::ChaCha20Poly1305 => HpkeAeadId::CHACHA20_POLY_1305,
            AEAD::Export_only => HpkeAeadId::EXPORT_ONLY,
        };

        HpkeSuite {
            kem,
            sym: HpkeSymmetricCipherSuite { kdf_id, aead_id },
        }
    }
}

#[cfg(feature = "std")]
fn other_err(err: impl StdError + Send + Sync + 'static) -> Error {
    Error::Other(OtherError(Arc::new(err)))
}

#[cfg(not(feature = "std"))]
fn other_err(err: impl Send + Sync + 'static) -> Error {
    Error::General(alloc::format!("{}", err));
}

#[cfg(test)]
mod tests {
    use alloc::{format, vec};

    use super::*;

    #[test]
    fn smoke_test() {
        for suite in ALL_SUPPORTED_SUITES {
            _ = format!("{suite:?}"); // HpkeRs suites should be Debug.

            // We should be able to generate a random keypair.
            let (pk, sk) = suite.generate_key_pair().unwrap();

            // Info value corresponds to the first RFC 9180 base mode test vector.
            let info = &[
                0x4f, 0x64, 0x65, 0x20, 0x6f, 0x6e, 0x20, 0x61, 0x20, 0x47, 0x72, 0x65, 0x63, 0x69,
                0x61, 0x6e, 0x20, 0x55, 0x72, 0x6e,
            ][..];

            // We should be able to set up a sealer.
            let (enc, mut sealer) = suite.setup_sealer(info, &pk).unwrap();

            _ = format!("{sealer:?}"); // Sealer should be Debug.

            // Setting up a sealer with an invalid public key should fail.
            let bad_setup_res = suite.setup_sealer(info, &HpkePublicKey(vec![]));
            assert!(bad_setup_res.is_err());

            // We should be able to seal some plaintext.
            let aad = &[0xC0, 0xFF, 0xEE];
            let pt = &[0xF0, 0x0D];
            let ct = sealer.seal(aad, pt).unwrap();

            // We should be able to set up an opener.
            let mut opener = suite
                .setup_opener(&enc, info, &sk)
                .unwrap();
            _ = format!("{opener:?}"); // Opener should be Debug.

            // Setting up an opener with an invalid private key should fail.
            let bad_key_res = suite.setup_opener(&enc, info, &HpkePrivateKey::from(vec![]));
            assert!(bad_key_res.is_err());

            // Opening the plaintext should work with the correct opener and aad.
            let pt_prime = opener.open(aad, &ct).unwrap();
            assert_eq!(pt_prime, pt);

            // Opening the plaintext with the correct opener and wrong aad should fail.
            let open_res = opener.open(&[0x0], &ct);
            assert!(open_res.is_err());

            // Opening the plaintext with the wrong opener should fail.
            let mut sk_rm_prime = sk.secret_bytes().to_vec();
            sk_rm_prime[10] ^= 0xFF; // Corrupt a byte of the private key.
            let mut opener_two = suite
                .setup_opener(&enc, info, &HpkePrivateKey::from(sk_rm_prime))
                .unwrap();
            let open_res = opener_two.open(aad, &ct);
            assert!(open_res.is_err());
        }
    }

    #[test]
    fn test_fips() {
        // None of the rust-crypto backed hpke-rs suites should be considered FIPS approved.
        assert!(ALL_SUPPORTED_SUITES
            .iter()
            .all(|suite| !suite.fips()));
    }
}
