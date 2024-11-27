use alloc::boxed::Box;

use rustls::{
    crypto::cipher::{
        make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
        KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
        OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
        UnsupportedOperationError, NONCE_LEN,
    },
    ConnectionTrafficSecrets, ContentType, ProtocolVersion,
};

use libcrux::aead::{self, Chacha20Key, Key, Tag};

const TAG_LEN: usize = aead::Algorithm::Chacha20Poly1305.tag_size();

pub struct Chacha20Poly1305;

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let key = Key::Chacha20Poly1305(Chacha20Key(key.as_ref().try_into().unwrap()));
        Box::new(Tls13Cipher(key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        let key = Key::Chacha20Poly1305(Chacha20Key(key.as_ref().try_into().unwrap()));
        Box::new(Tls13Cipher(key, iv))
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        let key = Key::Chacha20Poly1305(Chacha20Key(key.as_ref().try_into().unwrap()));
        Box::new(Tls12Cipher(key, Iv::copy(iv)))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        let key = Key::Chacha20Poly1305(Chacha20Key(key.as_ref().try_into().unwrap()));
        Box::new(Tls12Cipher(key, Iv::copy(iv)))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

struct Tls13Cipher(Key, Iv);

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());
        let nonce = Nonce::new(&self.1, seq);
        let aad = make_tls13_aad(total_len);
        let iv = libcrux::aead::Iv(nonce.0);

        // self.0
        //     .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))

        let out = libcrux::aead::encrypt(&self.0, payload.as_mut(), iv, &aad)
            .map_err(|_| rustls::Error::EncryptError)
            .map(|tag| {
                payload.extend_from_slice(tag.as_ref());
                OutboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )
            });
        out
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_and_tag = &mut m.payload;
        let total_len = payload_and_tag.len();
        let payload_and_tag_len = payload_and_tag.len();
        if payload_and_tag_len < TAG_LEN {
            return Err(rustls::Error::DecryptError);
        }

        let (payload, tag) = payload_and_tag.split_at_mut(payload_and_tag_len - TAG_LEN);

        let nonce = Nonce::new(&self.1, seq);
        let aad = make_tls13_aad(total_len);
        let iv = libcrux::aead::Iv(nonce.0);
        let tag = Tag::from_slice(tag).unwrap();

        libcrux::aead::decrypt(&self.0, payload, iv, &aad, &tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        m.payload
            .truncate(m.payload.len() - TAG_LEN);

        m.into_tls13_unpadded_message()
    }
}

struct Tls12Cipher(Key, Iv);

impl MessageEncrypter for Tls12Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        let nonce = Nonce::new(&self.1, seq);
        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());
        let iv = libcrux::aead::Iv(nonce.0);

        libcrux::aead::encrypt(&self.0, payload.as_mut(), iv, &aad)
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_and_tag = &mut m.payload;
        let payload_and_tag_len = payload_and_tag.len();
        if payload_and_tag_len < TAG_LEN {
            return Err(rustls::Error::DecryptError);
        }

        let (payload, tag) = payload_and_tag.split_at_mut(payload_and_tag_len - TAG_LEN);
        let nonce = Nonce::new(&self.1, seq);
        let aad = make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );
        let iv = libcrux::aead::Iv(nonce.0);
        let tag = Tag::from_slice(tag).unwrap();

        let payload = &mut m.payload;
        libcrux::aead::decrypt(&self.0, payload.as_mut(), iv, &aad, &tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        m.payload
            .truncate(m.payload.len() - TAG_LEN);

        Ok(m.into_plain_message())
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;
