
use super::*;


pub struct EncodingEncryptionKey<'ek, 'e, EK: 'ek, E: 'e> {
    key: &'ek EK,
    encoder: &'e E,
}

pub trait WithEncoder<'ek, 'e, EK, E> {
     fn with_encoder(&'ek self, encoder: &'e E) -> EK;
}

impl<'a, 'b, EK, E> WithEncoder<'a, 'b, EncodingEncryptionKey<'a, 'b, EK, E>, E> for EK
where
    EK: ::traits::EncryptionKey
{
    fn with_encoder(&'a self, encoder: &'b E) -> EncodingEncryptionKey<'a, 'b, EK, E> {
        EncodingEncryptionKey {
            key: self,
            encoder: encoder
        }
    }
}


pub struct DecodingDecryptionKey<'a, 'b, DK: 'a, D: 'b> {
    key: &'a DK,
    decoder: &'b D,
}

pub trait WithDecoder<'a, 'b, DK, D> {
     fn with_decoder(&'a self, decoder: &'b D) -> DK;
}

impl<'a, 'b, DK, D> WithDecoder<'a, 'b, DecodingDecryptionKey<'a, 'b, DK, D>, D> for DK
where
    DK: ::traits::DecryptionKey
{
    fn with_decoder(&'a self, decoder: &'b D) -> DecodingDecryptionKey<'a, 'b, DK, D> {
        DecodingDecryptionKey {
            key: self,
            decoder: decoder
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
