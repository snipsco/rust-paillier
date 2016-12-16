
use plain;


#[derive(Debug,Clone)]
pub struct EncryptionKey<I> {
    underlying_ek: plain::EncryptionKey<I>,
    component_count: usize,
    component_size: usize,  // in bits
}

impl <I> EncryptionKey<I> {
    pub fn from(underlying_ek: plain::EncryptionKey<I>,
                component_count: usize,
                component_size: usize)
                -> EncryptionKey<I> {
        // assert!(component_size * component_count <= plain_ek.n.bits());
        // assert!(component_size * component_count <= underlying_ek.n.bit_length() as usize); // TODO
        assert!(component_size <= 64);
        EncryptionKey {
            underlying_ek: underlying_ek,
            component_size: component_size,
            component_count: component_count,
        }
    }
}


#[derive(Debug,Clone)]
pub struct DecryptionKey<I> {
    underlying_dk: plain::DecryptionKey<I>,
    component_count: usize,
    component_size: usize,  // in bits
}

impl <I> DecryptionKey<I> {
    pub fn from(underlying_dk: plain::DecryptionKey<I>,
                component_count: usize,
                component_size: usize)
                -> DecryptionKey<I> {
        assert!(component_size <= 64);
        DecryptionKey {
            underlying_dk: underlying_dk,
            component_size: component_size,
            component_count: component_count,
        }
    }
}


#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<ComponentType>(Vec<ComponentType>);

impl <ComponentType : Clone> From<ComponentType> for Plaintext<ComponentType> {
    fn from(x: ComponentType) -> Self {
        Plaintext(vec![x.clone()])
    }
}

impl <ComponentType : Clone> From<Vec<ComponentType>> for Plaintext<ComponentType> {
    fn from(x: Vec<ComponentType>) -> Self {
        Plaintext(x.clone())
    }
}


#[derive(Debug,Clone)]
pub struct Ciphertext<I>(plain::Ciphertext<I>);


use std::ops::{Sub, Mul, Div};
use std::ops::{Add, Shl, ShlAssign, Shr, Rem};
use num_traits::{One};
use arithimpl::traits::*;

pub struct AbstractPackedPaillier<ComponentType, I> {
    junk: ::std::marker::PhantomData<(ComponentType, I)>
}

impl <ComponentType, I> AbstractPackedPaillier<ComponentType, I>
where
    // regarding ComponentType
    ComponentType: Clone,
    ComponentType: One,
    ComponentType: Shl<usize, Output=ComponentType>,
    for<'b> ComponentType: ConvertFrom<I>,
    // regarding BasePHE
    // plain::Plaintext<I>: From<I>,
    I: From<ComponentType>,
    I: Shl<usize, Output=I>,
    I: ShlAssign<usize>,
    I: Shr<usize, Output=I>,
    for<'a> &'a I: Shr<usize, Output=I>,
    I: Add<Output=I>,
    I: Rem<Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    I: One,
    I: Samplable,
    I: ModularArithmetic,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
    for<'a>    &'a I: Sub<I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'b>        I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>
{

    pub fn encrypt(ek: &EncryptionKey<I>, ms: &Plaintext<ComponentType>) -> Ciphertext<I> {
        let plaintexts: &Vec<ComponentType> = &ms.0;
        assert!(plaintexts.len() == ek.component_count);
        let mut packed_plaintexts: I = I::from(plaintexts[0].clone());
        for plaintext in &plaintexts[1..] {
            packed_plaintexts = packed_plaintexts << ek.component_size;
            packed_plaintexts = packed_plaintexts + I::from(plaintext.clone());
        }
        let c: plain::Ciphertext<I> = plain::AbstractPlainPaillier::encrypt(
            &ek.underlying_ek,
            &plain::Plaintext(packed_plaintexts));
        Ciphertext(c)
    }

    pub fn decrypt(dk: &DecryptionKey<I>, c: &Ciphertext<I>) -> Plaintext<ComponentType> {
        let mut packed_plaintext: I = plain::AbstractPlainPaillier::decrypt(&dk.underlying_dk, &c.0).0;
        let raw_mask: ComponentType = ComponentType::one() << dk.component_size;
        let mask: I = I::from(raw_mask.clone());
        let mut result: Vec<ComponentType> = vec![];
        for _ in 0..dk.component_count {
            let slot_value = &packed_plaintext % &mask;
            let foo = ComponentType::_from(&slot_value);
            result.push(foo);
            packed_plaintext = &packed_plaintext >> dk.component_size;
        }
        result.reverse();
        Plaintext(result)
    }

    pub fn add(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, c2: &Ciphertext<I>) -> Ciphertext<I> {
        let c: plain::Ciphertext<I> = plain::AbstractPlainPaillier::add(&ek.underlying_ek, &c1.0, &c2.0);
        Ciphertext(c)
    }

    pub fn mult(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, m2: &ComponentType) -> Ciphertext<I> {
        let scalar = plain::Plaintext(I::from(m2.clone()));
        let c: plain::Ciphertext<I> = plain::AbstractPlainPaillier::mult(&ek.underlying_ek, &c1.0, &scalar);
        Ciphertext(c)
    }

    pub fn rerandomise(ek: &EncryptionKey<I>, c: &Ciphertext<I>) -> Ciphertext<I> {
        let d: plain::Ciphertext<I> = plain::AbstractPlainPaillier::rerandomise(&ek.underlying_ek, &c.0);
        Ciphertext(d)
    }

}

#[cfg(test)]
mod tests {

    use ::{BigInteger, PackedPaillier};
    use ::plain;
    use super::*;

    fn test_keypair() -> (EncryptionKey<BigInteger>, DecryptionKey<BigInteger>) {
        //1024 bits prime
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();

        let n = &p * &q;
        let plain_ek = plain::EncryptionKey::from(&n);
        let plain_dk = plain::DecryptionKey::from(&p, &q);

        let ek = EncryptionKey::from(plain_ek, 3, 10);
        let dk = DecryptionKey::from(plain_dk, 3, 10);
        (ek, dk)
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let m: Plaintext<u64> = Plaintext::from(vec![1, 2, 3]);
        let c: Ciphertext<BigInteger> = PackedPaillier::encrypt(&ek, &m);

        let recovered_m: Plaintext<u64> = AbstractPackedPaillier::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let m1 = Plaintext::from(vec![1, 2, 3]);
        let c1 = PackedPaillier::encrypt(&ek, &m1);
        let m2 = Plaintext::from(vec![1, 2, 3]);
        let c2 = PackedPaillier::encrypt(&ek, &m2);

        let c = PackedPaillier::add(&ek, &c1, &c2);
        let m = PackedPaillier::decrypt(&dk, &c);
        assert_eq!(m.0, vec![2, 4, 6]);
    }

    #[test]
    fn test_correct_multiplication() {
        let (ek, dk) = test_keypair();

        let m1 = Plaintext::from(vec![1, 2, 3]);
        let c1 = PackedPaillier::encrypt(&ek, &m1);
        let m2 = 4;

        let c = PackedPaillier::mult(&ek, &c1, &m2);
        let m = PackedPaillier::decrypt(&dk, &c);
        assert_eq!(m.0, vec![4, 8, 12]);
    }

}
