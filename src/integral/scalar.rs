
use super::*;

use std::marker::PhantomData;


/// Representation of unencrypted message.
#[derive(Debug,Clone,PartialEq)]
pub struct ScalarPlaintext<I, T> {
    pub data: basic::Plaintext<I>,
    _phantom: PhantomData<T>
}


/// Representation of encrypted message.
#[derive(Debug,Clone)]
pub struct ScalarCiphertext<I, T> {
    pub data: basic::Ciphertext<I>,
    _phantom: PhantomData<T>
}


impl<I, T, S, EK> Encryption<EK, ScalarPlaintext<I, T>, ScalarCiphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Encryption<EK, basic::Plaintext<I>, basic::Ciphertext<I>>,
{
    fn encrypt(ek: &EK, m: &ScalarPlaintext<I, T>) -> ScalarCiphertext<I, T> {
        ScalarCiphertext {
            data: S::encrypt(&ek, &m.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, DK> Decryption<DK, ScalarCiphertext<I, T>, ScalarPlaintext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Decryption<DK, basic::Ciphertext<I>, basic::Plaintext<I>>,
{
    fn decrypt(dk: &DK, c: &ScalarCiphertext<I, T>) -> ScalarPlaintext<I, T> {
        ScalarPlaintext {
            data: S::decrypt(dk, &c.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Rerandomisation<EK, ScalarCiphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Rerandomisation<EK, basic::Ciphertext<I>>,
{
    fn rerandomise(ek: &EK, c: &ScalarCiphertext<I, T>) -> ScalarCiphertext<I, T> {
        ScalarCiphertext {
            data: S::rerandomise(&ek, &c.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Addition<EK, ScalarCiphertext<I, T>, ScalarCiphertext<I, T>, ScalarCiphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Addition<EK, basic::Ciphertext<I>, basic::Ciphertext<I>, basic::Ciphertext<I>>,
{
    fn add(ek: &EK, c1: &ScalarCiphertext<I, T>, c2: &ScalarCiphertext<I, T>) -> ScalarCiphertext<I, T> {
        ScalarCiphertext {
            data: S::add(&ek, &c1.data, &c2.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Multiplication<EK, ScalarCiphertext<I, T>, ScalarPlaintext<I, T>, ScalarCiphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Multiplication<EK, basic::Ciphertext<I>, basic::Plaintext<I>, basic::Ciphertext<I>>,
{
    fn mul(ek: &EK, c1: &ScalarCiphertext<I, T>, m2: &ScalarPlaintext<I, T>) -> ScalarCiphertext<I, T> {
        ScalarCiphertext {
            data: S::mul(&ek, &c1.data, &m2.data),
            _phantom: PhantomData
        }
    }
}


impl<I, T> From<T> for ScalarPlaintext<I, T>
where
    T: Copy,  // marker to avoid infinite loop by excluding Plaintext
    I: From<T>,
{
    fn from(x: T) -> ScalarPlaintext<I, T> {
        ScalarPlaintext{
            data: basic::Plaintext(I::from(x)),
            _phantom: PhantomData
        }
    }
}


pub struct Coding<I, T>(PhantomData<(I, T)>);

impl<I, T> Coding<I, T> {
    pub fn new() -> Coding<I, T> {
        Coding(PhantomData)
    }
}

impl<I, T> Encoder<T, ScalarPlaintext<I, T>> for Coding<I, T>
where
    T: Clone,
    I: From<T>,
{
    fn encode(&self, x: &T) -> ScalarPlaintext<I, T> {
        ScalarPlaintext {
            data: basic::Plaintext(I::from(x.clone())),
            _phantom: PhantomData
        }
    }
}

impl<I, T> Encoding<T, ScalarPlaintext<I, T>> for Coding<I, T>
where
    I: From<T>,
    T: Copy,
{
    fn encode(x: &T) -> ScalarPlaintext<I, T> {
        ScalarPlaintext {
            data: basic::Plaintext(I::from(*x)),
            _phantom: PhantomData
        }
    }
}

use arithimpl::traits::ConvertFrom;
impl<I, T> Decoding<ScalarPlaintext<I, T>, T> for Coding<I, T>
where
    T: ConvertFrom<I>,
{
    fn decode(x: &ScalarPlaintext<I, T>) -> T {
        T::_from(&x.data.0)
    }
}


bigint!(I,
#[cfg(test)]
mod tests {

    use super::I;
    use ::Scheme;
    use ::integral::scalar::*;

    fn test_keypair() -> (EncryptionKey<I>, DecryptionKey<I>) {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        let n = &p * &q;
        let ek = EncryptionKey::from(&n);
        let dk = DecryptionKey::from((&p, &q));
        (ek, dk)
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();
        let code = Coding::new();

        let m = code.encode(&10);
        let c = Scheme::encrypt(&ek, &m);

        let recovered_m = Scheme::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();
        let code = Coding::new();

        let m1 = code.encode(&10);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = code.encode(&20);
        let c2 = Scheme::encrypt(&ek, &m2);

        let c = Scheme::add(&ek, &c1, &c2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(code.decode(&m), 30);
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = test_keypair();
        let code = Coding::new();

        let m1 = code.encode(&10);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = code.encode(&20);

        let c = Scheme::mul(&ek, &c1, &m2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(code.decode(&m), 200);
    }

});
