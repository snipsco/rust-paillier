
mod packing;
pub mod integral;

use super::*;
use self::packing::*;

pub trait WithCode<'k, 'c, K, C> {
     fn with_code(&'k self, code: &'c C) -> K;
}


pub struct EncodingEncryptionKey<'ek, 'e, EK: 'ek, E: 'e> {
    key: &'ek EK,
    encoder: &'e E,
}

pub struct DecodingDecryptionKey<'a, 'b, DK: 'a, D: 'b> {
    key: &'a DK,
    decoder: &'b D,
}

impl<'a, 'b, EK, E> WithCode<'a, 'b, EncodingEncryptionKey<'a, 'b, EK, E>, E> for EK
where
    EK: ::traits::EncryptionKey
{
    fn with_code(&'a self, code: &'b E) -> EncodingEncryptionKey<'a, 'b, EK, E> {
        EncodingEncryptionKey {
            key: self,
            encoder: code
        }
    }
}

impl<'a, 'b, DK, D> WithCode<'a, 'b, DecodingDecryptionKey<'a, 'b, DK, D>, D> for DK
where
    DK: ::traits::DecryptionKey
{
    fn with_code(&'a self, code: &'b D) -> DecodingDecryptionKey<'a, 'b, DK, D> {
        DecodingDecryptionKey {
            key: self,
            decoder: code
        }
    }
}


impl<'a, 'b, E: 'b, M, CT, S, EK: 'a> Encryption<EncodingEncryptionKey<'a, 'b, EK, E>, M, CT> for S
where
    M : EncodableType,
    E : Encoder<M>,
    S : Encryption<EK, E::Target, CT>,
{
    fn encrypt(ek: &EncodingEncryptionKey<EK, E>, m: &M) -> CT {
        S::encrypt(ek.key, &ek.encoder.encode(m))
    }
}


impl<'a, 'b, D: 'b, M, CT, S, DK: 'a> Decryption<DecodingDecryptionKey<'a, 'b, DK, D>, CT, M> for S
where
    M : EncodableType,
    D : Decoder<M>,
    S : Decryption<DK, CT, D::Source>,
{
    fn decrypt(dk: &DecodingDecryptionKey<DK, D>, c: &CT) -> M {
        dk.decoder.decode(&S::decrypt(dk.key, c))
    }
}


// impl<'a, 'b, E, CT, S, EK: 'a> Addition<EncodingEncryptionKey<'a, 'b, EK, E>, CT, CT, CT> for S
// where
//     E : Encoder<M>,
//     S : Addition<EK, CT, CT, CT>,
// {
//     fn add(ek: &EncodingEncryptionKey<EK, E>, c1: &CT, c2: &CT) -> CT {
//         S::add(ek.key, c1, c2)
//     }
// }

// TODO we could add something similar for addition, allowing public values to be implicitly convert (and encryption)


impl<'a, 'b, E, M: 'b, CT, S, EK: 'a> Multiplication<EncodingEncryptionKey<'a, 'b, EK, E>, CT, M, CT> for S
where
    M : EncodableType,
    E : Encoder<M>,
    S : Multiplication<EK, CT, E::Target, CT>,
{
    fn mul(ek: &EncodingEncryptionKey<EK, E>, c1: &CT, m2: &M) -> CT {
        S::mul(ek.key, c1, &ek.encoder.encode(m2))
    }
}
