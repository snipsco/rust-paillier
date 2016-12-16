
use std::ops::{Add, Sub, Mul, Div, Rem};
use num_traits::{One};
use arithimpl::traits::*;


#[derive(Debug,Clone)]
pub struct EncryptionKey<I> {
    pub n: I,  // the modulus
    nn: I,     // the modulus squared
    g: I,      // the generator, fixed at g = n + 1
}

impl <I> EncryptionKey<I>
where
    I: Clone,
    I: One,
    for<'a, 'b> &'a I: Mul<&'b I, Output=I>,
    for<'a, 'b> &'a I: Add<&'b I, Output=I>
{
    pub fn from(modulus: &I) -> EncryptionKey<I> {
        EncryptionKey {
            n: modulus.clone(),
            nn: modulus * modulus,
            g: modulus + &I::one()
        }
    }
}


#[derive(Debug,Clone)]
pub struct DecryptionKey<I> {
    pub p: I,  // first prime
    pub q: I,  // second prime
    pub n: I,  // the modulus (also in public key)
    nn: I,     // the modulus squared
    lambda: I, // fixed at lambda = (p-1)*(q-1)
    mu: I,     // fixed at lambda^{-1}
}

impl <I> DecryptionKey<I>
where
    I: Clone,
    I: One,
    I: ModularArithmetic,
                   I: Mul<Output=I>,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>
{
    pub fn from(p: &I, q: &I) -> DecryptionKey<I> {
        let ref one = I::one();
        let modulus = p * q;
        let nn = &modulus * &modulus;
        let lambda = (p - one) * (q - one);
        let mu = I::modinv(&lambda, &modulus);
        DecryptionKey {
            p: p.clone(),
            q: q.clone(),
            n: modulus,
            nn: nn,
            lambda: lambda,
            mu: mu,
        }
    }
}


#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<I>(pub I);

// impl <I> From<usize> for Plaintext<I>
// where
//     I: From<usize>
// {
//     fn from(x: usize) -> Plaintext<I> {
//         Plaintext(I::from(x))
//     }
// }

// impl <I> Add for PlainPlaintext<I>
// where
//     I: Add<Output=I>
// {
//     type Output=PlainPlaintext<I>;
//     fn add(self: Self, y: Self) -> PlainPlaintext<I> {
//         PlainPlaintext(self.0 + y.0)
//     }
// }


#[derive(Debug,Clone)]
pub struct Ciphertext<I>(pub I);


pub struct Scheme<I> {
    junk: ::std::marker::PhantomData<I>
}


pub trait AbstractScheme
{
    type BigInteger;
    fn encrypt(ek: &EncryptionKey<Self::BigInteger>, m: &Plaintext<Self::BigInteger>) -> Ciphertext<Self::BigInteger>;
    fn decrypt(dk: &DecryptionKey<Self::BigInteger>, c: &Ciphertext<Self::BigInteger>) -> Plaintext<Self::BigInteger>;
    fn add(ek: &EncryptionKey<Self::BigInteger>, c1: &Ciphertext<Self::BigInteger>, c2: &Ciphertext<Self::BigInteger>) -> Ciphertext<Self::BigInteger>;
    fn mult(ek: &EncryptionKey<Self::BigInteger>, c1: &Ciphertext<Self::BigInteger>, m2: &Plaintext<Self::BigInteger>) -> Ciphertext<Self::BigInteger>;
    fn rerandomise(ek: &EncryptionKey<Self::BigInteger>, c: &Ciphertext<Self::BigInteger>) -> Ciphertext<Self::BigInteger>;
}

impl <I> AbstractScheme for Scheme<I>
where
    // I: From<usize>,
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

    type BigInteger = I;

    fn encrypt(ek: &EncryptionKey<I>, m: &Plaintext<I>) -> Ciphertext<I> {
        let gx = I::modpow(&ek.g, &m.0, &ek.nn);
        Self::rerandomise(ek, &Ciphertext(gx))
    }

    fn decrypt(dk: &DecryptionKey<I>, c: &Ciphertext<I>) -> Plaintext<I> {
        let u = I::modpow(&c.0, &dk.lambda, &dk.nn);
        let m = ((&u - I::one()) / &dk.n * &dk.mu) % &dk.n;
        Plaintext(m)
    }

    fn add(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, c2: &Ciphertext<I>) -> Ciphertext<I> {
        let c = (&c1.0 * &c2.0) % &ek.nn;
        Ciphertext(c)
    }

    fn mult(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, m2: &Plaintext<I>) -> Ciphertext<I> {
        let c = I::modpow(&c1.0, &m2.0, &ek.nn);
        Ciphertext(c)
    }

    fn rerandomise(ek: &EncryptionKey<I>, c: &Ciphertext<I>) -> Ciphertext<I> {
        let r = I::sample_below(&ek.n);
        let d = (&c.0 * I::modpow(&r, &ek.n, &ek.nn)) % &ek.nn;
        Ciphertext(d)
    }

}


pub trait Encode<T>
{
    type BigInteger;
    fn encode(x: T) -> Plaintext<Self::BigInteger>;
}

impl <I, T> Encode<T> for Scheme<I>
where
    I : From<T>
{
    type BigInteger = I;
    fn encode(x: T) -> Plaintext<I> {
        Plaintext(I::from(x))
    }
}


pub trait KeyGeneration<I>
{
    fn keypair(big_length: usize) -> (EncryptionKey<I>, DecryptionKey<I>);
}

#[cfg(feature="keygen")]
use arithimpl::primes::*;

#[cfg(feature="keygen")]
impl <I> KeyGeneration<I> for Scheme<I>
where
    I: From<u64>,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug,
    I: Clone,
    I: Samplable,
    I: ModularArithmetic,
    I: One,
    I: PrimeSampable,
                   I: Mul<Output=I>,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'b>        I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
    for<'a>    &'a I: Sub<I, Output=I>,
    for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
    for<'a,'b> &'a I: Div<&'b I, Output=I>,
    for<'a>        I: Rem<&'a I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>
{
    fn keypair(bit_length: usize) -> (EncryptionKey<I>, DecryptionKey<I>) {
        let p = I::sample_prime(bit_length/2);
        let q = I::sample_prime(bit_length/2);
        let n = &p * &q;
        let ek = EncryptionKey::from(&n);
        let dk = DecryptionKey::from(&p, &q);
        (ek, dk)
    }
}


#[cfg(test)]
mod tests {

    use ::BigInteger;
    use super::*;

    fn test_keypair() -> (EncryptionKey<BigInteger>, DecryptionKey<BigInteger>) {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        let n = &p * &q;
        let ek = EncryptionKey::from(&n);
        let dk = DecryptionKey::from(&p, &q);
        (ek, dk)
    }

    #[cfg(feature="keygen")]
    fn test_keypair_sized(bitsize: usize) -> (EncryptionKey<BigInteger>, DecryptionKey<BigInteger>) {
        Scheme::keypair(bitsize)
    }

    #[cfg(feature="keygen")]
    #[test]
    fn test_correct_keygen() {
        let (ek, dk) = test_keypair_sized(2048);

        let m = Scheme::encode(10);
        let c = Scheme::encrypt(&ek, &m);

        let recovered_m = Scheme::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let m = Scheme::encode(10);
        let c = Scheme::encrypt(&ek, &m);

        let recovered_m = Scheme::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let m1 = Scheme::encode(10);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = Scheme::encode(20);
        let c2 = Scheme::encrypt(&ek, &m2);

        let c = Scheme::add(&ek, &c1, &c2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(m, Scheme::encode(30));
    }

    #[test]
    fn test_correct_multiplication() {
        let (ek, dk) = test_keypair();

        let m1 = Scheme::encode(10);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = Scheme::encode(20);

        let c = Scheme::mult(&ek, &c1, &m2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(m, Scheme::encode(200));
    }

}
