use der::Reader;
use libcrux::signature::{
    rsa_pss::{RsaPssPublicKey, RsaPssSignature},
    verify, DigestAlgorithm, EcDsaP256Signature, Ed25519Signature, Signature,
};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::{aws_lc_rs::RSA_PKCS1_2048_8192_SHA256 as AWS_LC_RSA_PKCS1_SHA256};

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        ED25519,
        ECDSA_P256_SHA256,
        AWS_LC_RSA_PKCS1_SHA256,
    ],
    mapping: &[
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[AWS_LC_RSA_PKCS1_SHA256],
        ),
    ],
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm =
    &RsaPssVerify(DigestAlgorithm::Sha256, 0x20);

static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm =
    &RsaPssVerify(DigestAlgorithm::Sha384, 0x20);

static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm =
    &RsaPssVerify(DigestAlgorithm::Sha512, 0x20);

static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Verify;

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaP256Verify(DigestAlgorithm::Sha256);

#[derive(Debug, Clone, Copy)]
struct EcdsaP256Verify(DigestAlgorithm);

impl SignatureVerificationAlgorithm for EcdsaP256Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut decoder = der::SliceReader::new(signature).map_err(|_| InvalidSignature)?;
        let sig: DerEcdsaSignature = decoder
            .decode()
            .map_err(|_| InvalidSignature)?;
        let r: [u8; 32] = sig
            .r
            .as_bytes()
            .try_into()
            .map_err(|_| InvalidSignature)?;
        let s: [u8; 32] = sig
            .s
            .as_bytes()
            .try_into()
            .map_err(|_| InvalidSignature)?;
        let signature = Signature::EcDsaP256(EcDsaP256Signature::from_raw(
            r,
            s,
            libcrux::signature::Algorithm::EcDsaP256(self.0),
        ));
        verify(message, &signature, public_key).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            DigestAlgorithm::Sha256 => alg_id::ECDSA_SHA256,
            DigestAlgorithm::Sha384 => alg_id::ECDSA_SHA384,
            DigestAlgorithm::Sha512 => alg_id::ECDSA_SHA512,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Ed25519Verify;

impl SignatureVerificationAlgorithm for Ed25519Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let signature = Signature::Ed25519(
            Ed25519Signature::from_slice(signature).map_err(|_| InvalidSignature)?,
        );
        verify(message, &signature, public_key).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

#[derive(Debug, Clone, Copy)]
struct RsaPssVerify(DigestAlgorithm, usize);

impl SignatureVerificationAlgorithm for RsaPssVerify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            libcrux::signature::DigestAlgorithm::Sha256 => alg_id::RSA_PSS_SHA256,
            libcrux::signature::DigestAlgorithm::Sha384 => alg_id::RSA_PSS_SHA384,
            libcrux::signature::DigestAlgorithm::Sha512 => alg_id::RSA_PSS_SHA512,
        }
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let Self(digest_algo, salt_len) = *self;
        let public_key = decode_spki_spk(public_key)?;
        let signature = RsaPssSignature::from(signature);

        public_key
            .verify(digest_algo, &signature, message, salt_len)
            .map_err(|_| InvalidSignature)
    }
}

fn decode_spki_spk(spki_spk: &[u8]) -> Result<RsaPssPublicKey, InvalidSignature> {
    // public_key: unfortunately this is not a whole SPKI, but just the key material.
    // decode the two integers manually.
    let mut reader = der::SliceReader::new(spki_spk).map_err(|_| InvalidSignature)?;
    let ne: [der::asn1::UintRef; 2] = reader
        .decode()
        .map_err(|_| InvalidSignature)?;

    let n = ne[0].as_bytes();
    let e = ne[1].as_bytes();

    if !matches!(e, [1, 0, 1]) {
        // it's actually a NotSupportedError, but it amounts to the same
        return Err(InvalidSignature);
    }

    let key_size = match n.len() {
        256 => libcrux::signature::rsa_pss::RsaPssKeySize::N2048,
        384 => libcrux::signature::rsa_pss::RsaPssKeySize::N3072,
        512 => libcrux::signature::rsa_pss::RsaPssKeySize::N4096,
        768 => libcrux::signature::rsa_pss::RsaPssKeySize::N6144,
        1024 => libcrux::signature::rsa_pss::RsaPssKeySize::N8192,
        _ => return Err(InvalidSignature),
    };

    libcrux::signature::rsa_pss::RsaPssPublicKey::new(key_size, n).map_err(|_| InvalidSignature)
}

struct DerEcdsaSignature {
    r: der::asn1::Int,
    s: der::asn1::Int,
}

impl<'a> der::Decode<'a> for DerEcdsaSignature {
    fn decode<R: Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            Ok(Self {
                r: decoder.decode()?,
                s: decoder.decode()?,
            })
        })
    }
}
