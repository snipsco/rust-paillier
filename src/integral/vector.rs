
//! Packed variant of Paillier allowing several (small) values to be encrypted together.
//! Homomorphic properties are preserved, as long as the absolute values stay within specified bounds.

use super::*;
use super::scalar::*;

use std::marker::PhantomData;
use std::ops::{Add, Shl, Shr, Rem};
use num_traits::One;


/// Representation of unencrypted message (vector).
#[derive(Debug,Clone,PartialEq)]
pub struct VectorPlaintext<I, T> {
    pub data: basic::Plaintext<I>,
    component_count: usize,
    component_size: usize,  // in bits
    _phantom: PhantomData<T>
}


/// Representation of encrypted message (vector).
#[derive(Debug,Clone)]
pub struct VectorCiphertext<I, T> {
    pub data: basic::Ciphertext<I>,
    component_count: usize,
    component_size: usize,  // in bits
    _phantom: PhantomData<T>
}


impl<I, T, S, EK> Encryption<EK, VectorPlaintext<I, T>, VectorCiphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Encryption<EK, basic::Plaintext<I>, basic::Ciphertext<I>>,
{
    fn encrypt(ek: &EK, m: &VectorPlaintext<I, T>) -> VectorCiphertext<I, T> {
        VectorCiphertext {
            data: S::encrypt(&ek, &m.data),
            component_count: m.component_count,
            component_size: m.component_size,
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, DK> Decryption<DK, VectorCiphertext<I, T>, VectorPlaintext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Decryption<DK, basic::Ciphertext<I>, basic::Plaintext<I>>,
{
    fn decrypt(dk: &DK, c: &VectorCiphertext<I, T>) -> VectorPlaintext<I, T> {
        VectorPlaintext {
            data: S::decrypt(dk, &c.data),
            component_count: c.component_count,
            component_size: c.component_size,
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Rerandomisation<EK, VectorCiphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Rerandomisation<EK, basic::Ciphertext<I>>,
{
    fn rerandomise(ek: &EK, c: &VectorCiphertext<I, T>) -> VectorCiphertext<I, T> {
        VectorCiphertext {
            data: S::rerandomise(&ek, &c.data),
            component_count: c.component_count,
            component_size: c.component_size,
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Addition<EK, VectorCiphertext<I, T>, VectorCiphertext<I, T>, VectorCiphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Addition<EK, basic::Ciphertext<I>, basic::Ciphertext<I>, basic::Ciphertext<I>>,
{
    fn add(ek: &EK, c1: &VectorCiphertext<I, T>, c2: &VectorCiphertext<I, T>) -> VectorCiphertext<I, T> {
        let c = S::add(&ek, &c1.data, &c2.data);
        VectorCiphertext {
            data: c,
            component_count: c1.component_count,
            component_size: c1.component_size, // TODO equality
            _phantom: PhantomData
        }
    }
}


impl<I, T, S, EK> Multiplication<EK, VectorCiphertext<I, T>, ScalarPlaintext<I, T>, VectorCiphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Multiplication<EK, basic::Ciphertext<I>, basic::Plaintext<I>, basic::Ciphertext<I>>,
{
    fn mul(ek: &EK, c1: &VectorCiphertext<I, T>, m2: &ScalarPlaintext<I, T>) -> VectorCiphertext<I, T> {
        VectorCiphertext {
            data: S::mul(&ek, &c1.data, &m2.data),
            component_count: c1.component_count, // TODO equality
            component_size: c1.component_size,
            _phantom: PhantomData
        }
    }
}


pub struct Coding<I, T> {
    component_count: usize,
    component_size: usize,  // in bits
    _phantom: PhantomData<(I, T)>
}

impl<I, T> Coding<I, T> {
    pub fn default() -> Coding<I, T> {
        Self::new(10, 64)
    }

    pub fn new(component_count: usize, component_size: usize) -> Coding<I, T> {
        use std::mem::size_of;
        assert!(size_of::<T>() <= component_size);
        Coding {
            component_count: component_count,
            component_size: component_size,
            _phantom: PhantomData,
        }
    }
}

use arithimpl::traits::ConvertFrom;
impl<I, T> ::traits::Encoder<Vec<T>, VectorPlaintext<I, T>> for Coding<I, T>
where
    T: One,
    T: Clone,
    I: From<T>,
    T: Shl<usize, Output=T>,
    T: ConvertFrom<I>,
    I: One,
    I: Clone,
    I: From<T>,
    I: Shl<usize, Output=I>,
    I: Add<I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    fn encode(&self, x: &Vec<T>) -> VectorPlaintext<I, T> {
        VectorPlaintext {
            data: basic::Plaintext(pack(x, self.component_count, self.component_size)),
            component_count: self.component_count,
            component_size: self.component_size,
            _phantom: PhantomData,
        }
    }
}

impl<I, T> ::traits::Decoder<VectorPlaintext<I, T>, Vec<T>> for Coding<I, T>
where
    T: One,
    T: Clone,
    I: From<T>,
    T: Shl<usize, Output=T>,
    T: ConvertFrom<I>,
    I: One,
    I: Clone,
    I: From<T>,
    I: Shl<usize, Output=I>,
    I: Add<I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    fn decode(&self, x: &VectorPlaintext<I, T>) -> Vec<T> {
        unpack(x.data.0.clone(), self.component_count, self.component_size)
    }
}


bigint!(I,
#[cfg(test)]
mod tests {

    use super::I;
    use ::Scheme;
    use ::integral::vector::*;

    fn test_keypair() -> (EncryptionKey<I>, DecryptionKey<I>) {
        //1024 bits prime
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

        let code = Coding::new(3, 64);
        let m = vec![1, 2, 3];

        let p = code.encode(&m);
        let c = Scheme::encrypt(&ek, &p);
        let recovered_p = Scheme::decrypt(&dk, &c);
        let recovered_m = code.decode(&recovered_p);

        assert_eq!(recovered_p, p);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let code = Coding::new(3, 16);

        let m1 = code.encode(&vec![1, 2, 3]);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = code.encode(&vec![1, 2, 3]);
        let c2 = Scheme::encrypt(&ek, &m2);

        let c = Scheme::add(&ek, &c1, &c2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(code.decode(&m), vec![2, 4, 6]);
    }

    #[test]
    fn test_correct_multiplication() {
        let (ek, dk) = test_keypair();

        let code = Coding::new(3, 16);

        let m1 = code.encode(&vec![1, 2, 3]);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = ScalarPlaintext::from(4);

        let c = Scheme::mul(&ek, &c1, &m2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(code.decode(&m), vec![4, 8, 12]);
    }

});
