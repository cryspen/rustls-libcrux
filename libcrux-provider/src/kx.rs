use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use libcrux::ecdh;

use rustls::crypto::{self, SupportedKxGroup as _};
use rand_core::TryRngCore;

use crate::pq::X25519MlKem768;

pub struct KeyExchange {
    priv_key: Vec<u8>,
    pub_key: Vec<u8>,
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<KeyExchange>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let shared_secret = ecdh::derive(ecdh::Algorithm::X25519, peer, self.priv_key)
            .map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;

        Ok(crypto::SharedSecret::from(&shared_secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key[..]
    }

    fn group(&self) -> rustls::NamedGroup {
        X25519.name()
    }
}

pub const ALL_KX_GROUPS: &[&dyn crypto::SupportedKxGroup] = &[
    &X25519 as &dyn crypto::SupportedKxGroup,
    &X25519MlKem768 as &dyn crypto::SupportedKxGroup,
];

#[derive(Debug)]
pub struct X25519;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let (priv_key, pub_key) = ecdh::key_gen(ecdh::Algorithm::X25519, &mut rand_core::OsRng.unwrap_mut())
            .map_err(|_| rustls::Error::General(String::from("ecdh keygen error")))?;

        Ok(Box::new(KeyExchange { pub_key, priv_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}
