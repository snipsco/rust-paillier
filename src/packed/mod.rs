
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


pub struct Encoder<I, T> {
    component_count: usize,
    component_size: usize,  // in bits
    _phantom: PhantomData<(I, T)>
}

impl<I, T> Encoder<I, T> {
    pub fn default() -> Encoder<I, T> {
        Self::new(10, 64)
    }

    pub fn new(component_count: usize, component_size: usize) -> Encoder<I, T> {
        use std::mem::size_of;
        assert!(size_of::<T>() <= component_size);
        Encoder {
            component_count: component_count,
            component_size: component_size,
            _phantom: PhantomData,
        }
    }
}

impl<I, T> Encoder<I, T>
where
    T: One,
    T: Clone,
    I: From<T>,
    T: Shl<usize, Output=T>,
    T: ConvertFrom<I>,
    T: Debug,
    I: One,
    I: Clone,
    I: From<T>,
    I: Shl<usize, Output=I>,
    I: Add<I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    pub fn encode(&self, x: &Vec<T>) -> Plaintext<I, T> {
        Plaintext {
            data: plain::Plaintext(pack(x, self.component_count, self.component_size)),
            component_count: self.component_count,
            component_size: self.component_size,
            _phantom: PhantomData,
        }
    }

    pub fn decode(&self, x: &Plaintext<I, T>) -> Vec<T> {
        unpack(x.data.0.clone(), self.component_count, self.component_size)
    }
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

use std::fmt::Debug;
use arithimpl::traits::ConvertFrom;
fn unpack<I, T>(mut packed_components: I, component_count: usize, component_size: usize) -> Vec<T>
where
    T: ConvertFrom<I>,
    I: One,
    I: From<T>,
    I: Shl<usize, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    let mask = I::one() << component_size;
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
        Ciphertext {
            data: S::rerandomise(&ek, &c.data),
            component_count: c.component_count,
            component_size: c.component_size,
            _phantom: PhantomData
        }
    }
}


impl <I, T, S, EK> Encryption<EK, Plaintext<I, T>, Ciphertext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Encryption<EK, plain::Plaintext<I>, plain::Ciphertext<I>>,
{
    fn encrypt(ek: &EK, m: &Plaintext<I, T>) -> Ciphertext<I, T> {
        Ciphertext {
            data: S::encrypt(&ek, &m.data),
            component_count: m.component_count,
            component_size: m.component_size,
            _phantom: PhantomData
        }
    }
}


impl <I, T, S, DK> Decryption<DK, Ciphertext<I, T>, Plaintext<I, T>> for S
where
    S: AbstractScheme<BigInteger=I>,
    S: Decryption<DK, plain::Ciphertext<I>, plain::Plaintext<I>>,
{
    fn decrypt(dk: &DK, c: &Ciphertext<I, T>) -> Plaintext<I, T> {
        Plaintext {
            data: S::decrypt(dk, &c.data),
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
    use ::traits::*;

    fn test_keypair() -> (plain::EncryptionKey<I>, plain::CrtDecryptionKey<I>) {
        //1024 bits prime
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();

        let n = &p * &q;
        let ek = plain::EncryptionKey::from(&n);
        let dk = plain::CrtDecryptionKey::from((&p, &q));
        (ek, dk)
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let encoder = Encoder::new(3, 64);
        let m = vec![1, 2, 3];

        let p = encoder.encode(&m);
        let c = Scheme::encrypt(&ek, &p);
        let recovered_p = Scheme::decrypt(&dk, &c);
        let recovered_m = encoder.decode(&recovered_p);

        assert_eq!(recovered_p, p);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let encoder = Encoder::new(3, 16);

        let m1 = encoder.encode(&vec![1, 2, 3]);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = encoder.encode(&vec![1, 2, 3]);
        let c2 = Scheme::encrypt(&ek, &m2);

        let c = Scheme::add(&ek, &c1, &c2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(m, encoder.encode(&vec![2, 4, 6]));
    }

    #[test]
    fn test_correct_multiplication() {
        let (ek, dk) = test_keypair();

        let encoder = Encoder::new(3, 16);

        let m1 = encoder.encode(&vec![1, 2, 3]);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = 4;

        let c = Scheme::mul(&ek, &c1, &m2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(m, encoder.encode(&vec![4, 8, 12]));
    }

});
