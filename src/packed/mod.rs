
//! Packed variant of Paillier allowing several (small) values to be encrypted together.
//! Homomorphic properties are preserved, as long as the absolute values stay within specified bounds.

use traits::*;
use plain;

use std::marker::PhantomData;
use std::ops::{Add, Shl, Shr, Rem};
use num_traits::One;


/// Representation of unencrypted message (vector).
#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<I, T> {
    pub data: plain::Plaintext<I>,
    component_count: usize,
    component_size: usize,  // in bits
    _phantom: PhantomData<T>
}

impl <I, T> From<T> for Plaintext<I, T>
where
    I: From<T>,
    T: Clone
{
    fn from(x: T) -> Self {
        Plaintext {
            data: vec![x.clone()],
            component_count: 3,
            component_size: 32,  // TODO
            _phantom: PhantomData
        }
    }
}

impl <I, T> From<Vec<T>> for Plaintext<I, T>
where
    I : From<T>,
    T : Clone,
{
    fn from(x: Vec<T>) -> Self {
        Plaintext {
            data: x.clone(),
            component_count: 3,
            component_size: 32,  // TODO
            _phantom: PhantomData
        }
    }
}

pub struct Packer {
    component_count: usize,
    component_size: usize,  // in bits
}

impl Packer {

    pub fn default() -> Packer {
        Self::new(10, 32)
    }

    pub fn new(component_count: usize, component_size: usize) -> Packer {
        Packer {
            component_count: component_count,
            component_size: component_size
        }
    }

}

impl Packer
{
    fn encode<I, T>(&self, x: &Vec<T>) -> Plaintext<I, T>
    where
        T: Clone,
        I: From<T>,
        I: Shl<usize, Output=I>,
        I: Add<I, Output=I>,
    {
        Plaintext {
            data: x.clone(),
            component_count: self.component_count,
            component_size: self.component_size,
            _phantom: PhantomData,
        }
    }

    // fn decode<I, T>(&self, x: &Vec<T>) -> Plaintext<I, T>
}

fn pack<I, T>(components: &Vec<T>, component_count: usize, component_size: usize) -> I
where
    T: Clone,
    I: From<T>,
    I: Shl<usize, Output=I>,
    I: Add<I, Output=I>,
{
    assert!(components.len() == component_count);
    let mut packed: I = I::from(components[0].clone());
    for component in &components[1..] {
        packed = packed << component_size;
        packed = packed + I::from(component.clone());
    }
    packed
}

fn unpack<I, T>(mut packed_components: I, component_count: usize, component_size: usize) -> Vec<T>
where
    T: One,
    T: Clone,
    T: Shl<usize, Output=T>,
    T: ConvertFrom<I>,
    I: One,
    I: From<T>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    let raw_mask: T = T::one() << component_size;
    let mask: I = I::from(raw_mask.clone());
    let mut components: Vec<T> = vec![];
    for _ in 0..component_count {
        let raw_component = &packed_components % &mask;  // TODO replace with bitwise AND
        let component = T::_from(&raw_component);
        components.push(component);
        packed_components = &packed_components >> component_size;
    }
    components.reverse();
    components
}

// impl <I, T> Encoding<T, Plaintext<I, T>> for Packer
// {
//     fn encode(&self, x: T) -> Plaintext<I, T> {
//         x
//
//     }
// }

// pub trait Encoding<T, P>
// {
//     fn encode(x: T) -> P;
// }
//
// /// Decoding of e.g. primitive values as plaintexts.
// pub trait Decoding<P, T>
// {
//     fn decode(y: P) -> T;
// }


// impl <I, T, S> Encoding<Vec<T>, Plaintext<I, T>> for S
// where
//     S: AbstractScheme<BigInteger=I>,
//     Plaintext<I, T> : From<T>,
// {
//     fn encode(x: Vec<T>) -> Plaintext<I, T> {
//         Plaintext::from(x)
//     }
// }


// impl <T : Clone> From<[T]> for Plaintext<T> {
//     fn from(x: [T]) -> Self {
//         Plaintext(x.to_vec())
//     }
// }

/// Representation of encrypted message (vector).
#[derive(Debug,Clone)]
pub struct Ciphertext<I, T> {
    pub data: plain::Ciphertext<I>,
    component_count: usize,
    component_size: usize,  // in bits
    _phantom: PhantomData<T>
}


impl <I, T, S, EK> Rerandomisation<EK, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Rerandomisation<EK, plain::Ciphertext<I>>,
{
    fn rerandomise(ek: &EK, c: &Ciphertext<I, T>) -> Ciphertext<I, T> {
        let d = S::rerandomise(&ek, &c.data);
        Ciphertext {
            data: d,
            component_count: c.component_count,
            component_size:  c.component_size,
            _phantom: PhantomData
        }
    }
}


impl <I, T, S, EK> Encryption<EK, Plaintext<I, T>, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Encryption<EK, plain::Plaintext<I>, plain::Ciphertext<I>>,
    T: Clone,
    I: From<T>,
    I: Shl<usize, Output=I>,
    I: Add<I, Output=I>,
{
    fn encrypt(ek: &EK, m: &Plaintext<I, T>) -> Ciphertext<I, T> {
        let packed = pack(&m.data, m.component_count, m.component_size);
        let c = S::encrypt(&ek, &plain::Plaintext(packed));
        Ciphertext {
            data: c,
            component_count: m.component_count,
            component_size: m.component_size,
            _phantom: PhantomData
        }
    }
}


use arithimpl::traits::ConvertFrom;
impl <I, T, S, DK> Decryption<DK, Ciphertext<I, T>, Plaintext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Decryption<DK, plain::Ciphertext<I>, plain::Plaintext<I>>,
    T: One,
    T: Clone,
    T: Shl<usize, Output=T>,
    T: ConvertFrom<I>,
    I: One,
    I: From<T>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    fn decrypt(dk: &DK, c: &Ciphertext<I, T>) -> Plaintext<I, T> {
        let raw_plaintext = S::decrypt(dk, &c.data).0;
        let result = unpack(raw_plaintext, c.component_count, c.component_size);
        Plaintext {
            data: result,
            component_count: c.component_count,
            component_size: c.component_size,
            _phantom: PhantomData
        }
    }
}


impl <I, T, S, EK> Addition<EK, Ciphertext<I, T>, Ciphertext<I, T>, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Addition<EK, plain::Ciphertext<I>, plain::Ciphertext<I>, plain::Ciphertext<I>>,
{
    fn add(ek: &EK, c1: &Ciphertext<I, T>, c2: &Ciphertext<I, T>) -> Ciphertext<I, T> {
        let c = S::add(&ek, &c1.data, &c2.data);
        Ciphertext {
            data: c,
            component_count: c1.component_count,
            component_size: c1.component_size, // TODO equality
            _phantom: PhantomData
        }
    }
}


impl <I, T, S, EK> Multiplication<EK, Ciphertext<I, T>, T, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Multiplication<EK, plain::Ciphertext<I>, plain::Plaintext<I>, plain::Ciphertext<I>>,
    T: Clone,
    I: From<T>,
{
    fn mul(ek: &EK, c1: &Ciphertext<I, T>, m2: &T) -> Ciphertext<I, T> {
        let scalar = plain::Plaintext(I::from(m2.clone()));
        let c = S::mul(&ek, &c1.data, &scalar);
        Ciphertext {
            data: c,
            component_count: c1.component_count, // TODO equality
            component_size: c1.component_size,
            _phantom: PhantomData
        }
    }
}




bigint!(I,
#[cfg(test)]
mod tests {

    use super::I;
    use ::packed::*;
    use ::Scheme;

    fn test_keypair() -> (plain::EncryptionKey<I>, ::plain::CrtDecryptionKey<I>) {
        //1024 bits prime
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();

        let n = &p * &q;
        let plain_ek = ::plain::EncryptionKey::from(&n);
        let plain_dk = ::plain::CrtDecryptionKey::from((&p, &q));

        // let ek = EncryptionKey::from(plain_ek, 10, 64);
        // let dk = DecryptionKey::from(plain_dk, 3, 10);
        (plain_ek, plain_dk)
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let m: Plaintext<I, u64> = Plaintext::from(vec![1, 2, 3]);
        let c = Scheme::encrypt(&ek, &m);

        let recovered_m = Scheme::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let m1 = Plaintext::from(vec![1, 2, 3]);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = Plaintext::from(vec![1, 2, 3]);
        let c2 = Scheme::encrypt(&ek, &m2);

        let c = Scheme::add(&ek, &c1, &c2);
        let m: Plaintext<I, u64> = Scheme::decrypt(&dk, &c);
        assert_eq!(m.data, vec![2, 4, 6]);
    }

    #[test]
    fn test_correct_multiplication() {
        let (ek, dk) = test_keypair();

        let m1: Plaintext<I, u64> = Plaintext::from(vec![1, 2, 3]);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = 4;

        let c = Scheme::mul(&ek, &c1, &m2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(m.data, vec![4, 8, 12]);
    }

});
