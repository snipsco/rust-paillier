
use super::*;


pub struct EncodingEncryptionKey<'a, 'b, EK: 'a, M: 'b, PT: 'b> {
    key: &'a EK,
    encoder: &'b Encoder<M, PT>,
}

pub trait WithEncoder<'a, 'b, EK, M, PT> {
     fn with_encoder(&'a self, encoder: &'b Encoder<M, PT>) -> EK;
}

impl<'a, 'b, EK, M, PT> WithEncoder<'a, 'b, EncodingEncryptionKey<'a, 'b, EK, M, PT>, M, PT> for EK
where
    EK: ::traits::EncryptionKey
{
    fn with_encoder(&'a self, encoder: &'b Encoder<M, PT>) -> EncodingEncryptionKey<'a, 'b, EK, M, PT> {
        EncodingEncryptionKey {
            key: self,
            encoder: encoder
        }
    }
}


pub struct DecodingDecryptionKey<'a, 'b, DK: 'a, PT: 'b, M: 'b> {
    key: &'a DK,
    decoder: &'b Decoder<PT, M>
}

pub trait WithDecoder<'a, 'b, DK, PT, M> {
     fn with_decoder(&'a self, decoder: &'b Decoder<PT, M>) -> DK;
}

impl<'a, 'b, DK, PT, M> WithDecoder<'a, 'b, DecodingDecryptionKey<'a, 'b, DK, PT, M>, PT, M> for DK
where
    DK: ::traits::DecryptionKey
{
    fn with_decoder(&'a self, decoder: &'b Decoder<PT, M>) -> DecodingDecryptionKey<'a, 'b, DK, PT, M> {
        DecodingDecryptionKey {
            key: self,
            decoder: decoder
        }
    }
}


impl<'a, 'b, M: 'b, PT: 'b, CT, S, EK: 'a> Encryption<EncodingEncryptionKey<'a, 'b, EK, M, PT>, M, CT> for S
where
    M : EncodableType,
    S : Encryption<EK, PT, CT>,
{
    fn encrypt(ek: &EncodingEncryptionKey<EK, M, PT>, m: &M) -> CT {
        S::encrypt(ek.key, &ek.encoder.encode(m))
    }
}

impl<'a, 'b, PT: 'b, M: 'b, CT, S, DK: 'a> Decryption<DecodingDecryptionKey<'a, 'b, DK, PT, M>, CT, M> for S
where
    M : EncodableType,
    S : Decryption<DK, CT, PT>,
{
    fn decrypt(dk: &DecodingDecryptionKey<DK, PT, M>, c: &CT) -> M {
        dk.decoder.decode(&S::decrypt(dk.key, c))
    }
}

// TODO we could add something similar for addition, allowing public values to be implicitly convert (and encryption)

impl<'a, 'b, M: 'b, PT: 'b, CT, S, EK: 'a> Multiplication<EncodingEncryptionKey<'a, 'b, EK, M, PT>, CT, M, CT> for S
where
    M : EncodableType,
    S : Multiplication<EK, CT, PT, CT>,
{
    fn mul(ek: &EncodingEncryptionKey<EK, M, PT>, c1: &CT, m2: &M) -> CT {
        S::mul(ek.key, c1, &ek.encoder.encode(m2))
    }
}
