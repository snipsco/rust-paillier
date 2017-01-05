
//! Standard Paillier supporting ciphertext addition and plaintext multiplication.

use std::ops::{Add, Sub, Mul, Div, Rem};
use num_traits::{One};
use arithimpl::traits::*;


/// Secure generation of fresh key pairs for encryption and decryption.
pub trait KeyGeneration<EK, DK>
{
    // /// Generate fresh key pair with currently recommended security level (2048 bit modulus).
    // fn keypair() -> (EncryptionKey<I>, DecryptionKey<I>) {
    //     keypair(2048)
    // }

    /// Generate fresh key pair with security level specified as the `bit_length` of the modulus.
    ///
    /// Currently recommended security level is a minimum of 2048 bits.
    fn keypair(big_length: usize) -> (EK, DK);
}

/// Encryption of plaintext
pub trait Encryption<EK, PT, CT> {
    /// Encrypt plaintext `m` under key `ek` into a ciphertext.
    fn encrypt(ek: &EK, m: &PT) -> CT;
}

/// Decryption of ciphertext
pub trait Decryption<DK, CT, PT> {
    /// Decrypt ciphertext `c` using key `dk` into a plaintext.
    fn decrypt(ek: &DK, c: &CT) -> PT;
}

/// Addition of two ciphertexts
pub trait Addition<EK, CT> {
    /// Homomorphically combine ciphertexts `c1` and `c2` to obtain a ciphertext containing
    /// the sum of the two underlying plaintexts, reduced modulus `n` from `ek`.
    fn add(ek: &EK, c1: &CT, c2: &CT) -> CT;
}

/// Multiplication of ciphertext with plaintext
pub trait Multiplication<EK, CT, PT> {
    /// Homomorphically combine ciphertext `c1` and plaintext `m2` to obtain a ciphertext
    /// containing the multiplication of the (underlying) plaintexts, reduced modulus `n` from `ek`.
    fn mul(ek: &EK, c1: &CT, m2: &PT) -> CT;
}

/// Rerandomisation of ciphertext
pub trait Rerandomisation<EK, CT> {
    /// Rerandomise ciphertext `c` to hide any history of which homomorphic operations were
    /// used to compute it, making it look exactly like a fresh encryption of the same plaintext.
    fn rerandomise(ek: &EK, c: &CT) -> CT;
}


/// Operations exposed by the basic Paillier scheme.
pub trait AbstractScheme
{
    /// Underlying arbitrary precision arithmetic type.
    type BigInteger;
}

/// Implementation of the Paillier operations, such as encryption, decryption, and addition.
pub struct Scheme<I> {
    junk: ::std::marker::PhantomData<I>
}

impl <I> AbstractScheme for Scheme<I>
{
    type BigInteger = I;
}



/// Representation of unencrypted message.
#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<I>(pub I);

/// Representation of encrypted message.
#[derive(Debug,Clone)]
pub struct Ciphertext<I>(pub I);

/// Encryption key that may be shared publicly.
#[derive(Debug,Clone)]
pub struct EncryptionKey<I> {
    n: I,  // the modulus
    nn: I, // the modulus squared
}

impl <I, T> From<T> for Plaintext<I>
where
    T: Copy,  // marker to avoid infinite loop by excluding Plaintext
    I: From<T>,
{
    fn from(x: T) -> Plaintext<I> {
        Plaintext(I::from(x))
    }
}

impl <'i, I> From<&'i I> for EncryptionKey<I>
where
    I: Clone,
    for<'a, 'b> &'a I: Mul<&'b I, Output=I>,
{
    fn from(modulus: &I) -> EncryptionKey<I> {
        EncryptionKey {
            n: modulus.clone(),
            nn: modulus * modulus
        }
    }
}


impl <I> Rerandomisation<EncryptionKey<I>, Ciphertext<I>> for Scheme<I>
where
    I: Samplable,
    I: ModularArithmetic,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'b>        I: Rem<&'b I, Output=I>,
{
    fn rerandomise(ek: &EncryptionKey<I>, c: &Ciphertext<I>) -> Ciphertext<I> {
        let r = I::sample_below(&ek.n);
        let d = (&c.0 * I::modpow(&r, &ek.n, &ek.nn)) % &ek.nn;
        Ciphertext(d)
    }
}


impl <I> Encryption<EncryptionKey<I>, Plaintext<I>, Ciphertext<I>> for Scheme<I>
where
    I: One,
    I: Samplable,
    I: ModularArithmetic,
    for<'a,'b> &'a I: Add<&'b I, Output=I>,
    for<'a>    &'a I: Mul<I, Output=I>,
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Rem<&'b I, Output=I>,
{
    fn encrypt(ek: &EncryptionKey<I>, m: &Plaintext<I>) -> Ciphertext<I> {
        // here we assume that g = n+1
        let nm = &m.0 * &ek.n;
        let gx = (&nm + &I::one()) % &ek.nn;
        Self::rerandomise(ek, &Ciphertext(gx))
    }
}


impl <I> Addition<EncryptionKey<I>, Ciphertext<I>> for Scheme<I>
where
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Rem<&'b I, Output=I>,
{
    fn add(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, c2: &Ciphertext<I>) -> Ciphertext<I> {
        let c = (&c1.0 * &c2.0) % &ek.nn;
        Ciphertext(c)
    }
}


impl <I> Multiplication<EncryptionKey<I>, Ciphertext<I>, Plaintext<I>> for Scheme<I>
where
    I: ModularArithmetic,
{
    fn mul(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, m2: &Plaintext<I>) -> Ciphertext<I> {
        let c = I::modpow(&c1.0, &m2.0, &ek.nn);
        Ciphertext(c)
    }
}



fn l<I>(u: &I, n: &I) -> I
where
    I: One,
    for<'a>    &'a I: Sub<I, Output=I>,
    for<'b>        I: Div<&'b I, Output=I>,
{
    (u - I::one()) / n
}



mod basic_decryption {

    use super::*;

    /// Decryption key that should be kept private.
    #[derive(Debug,Clone)]
    pub struct BasicDecryptionKey<I> {
        p: I,  // first prime
        q: I,  // second prime
        n: I,  // the modulus (also in public key)
        nn: I,     // the modulus squared
        lambda: I, // fixed at lambda = (p-1)*(q-1)
        mu: I,     // fixed at lambda^{-1}
    }

    impl <'p, 'q, I> From<(&'p I, &'q I)> for BasicDecryptionKey<I>
    where
        I: One,
        I: Clone,
        I: ModularArithmetic,
        for<'a,'b> &'a I: Mul<&'b I, Output=I>,
        for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    {
        fn from((p, q): (&I, &I)) -> BasicDecryptionKey<I> {
            let ref one = I::one();
            let modulus = p * q;
            let nn = &modulus * &modulus;
            let lambda = (p - one) * (q - one);
            let mu = I::modinv(&lambda, &modulus);
            BasicDecryptionKey {
                p: p.clone(),
                q: q.clone(),
                n: modulus,
                nn: nn,
                lambda: lambda,
                mu: mu,
            }
        }
    }

    impl <I> Decryption<BasicDecryptionKey<I>, Ciphertext<I>, Plaintext<I>> for Scheme<I>
    where
        I: One,
        I: ModularArithmetic,
        for<'a>    &'a I: Sub<I, Output=I>,
        for<'b>        I: Mul<&'b I, Output=I>,
        for<'b>        I: Div<&'b I, Output=I>,
        for<'a>        I: Rem<&'a I, Output=I>,
    {
        fn decrypt(dk: &BasicDecryptionKey<I>, c: &Ciphertext<I>) -> Plaintext<I> {
            let u = I::modpow(&c.0, &dk.lambda, &dk.nn);
            let m = (l(&u, &dk.n) * &dk.mu) % &dk.n;
            Plaintext(m)
        }
    }

}
pub use self::basic_decryption::*;



mod crt_decryption {

    use super::*;

    pub struct CrtDecryptionKey<I> {
        p: I,  // first prime
        pp: I,
        pminusone: I,
        q: I,  // second prime
        qq: I,
        qminusone: I,
        pinvq: I,
        hp: I,
        hq: I,
        n: I,  // the modulus (also in public key)
    }

    impl <'p, 'q, I> From<(&'p I, &'q I)> for CrtDecryptionKey<I>
    where
        I: Clone,
        I: One,
        I: ModularArithmetic,
        for<'a>     &'a I: Sub<I, Output=I>,
        for<'a,'b>  &'a I: Mul<&'b I, Output=I>,
        for<'b>         I: Sub<&'b I, Output=I>,
        for<'b>         I: Rem<&'b I, Output=I>,
        for<'b>         I: Div<&'b I, Output=I>,
    {
        fn from((p, q): (&I, &I)) -> CrtDecryptionKey<I> {
            let ref pp = p * p;
            let ref qq = q * q;
            let ref n = p * q;
            CrtDecryptionKey {
                p: p.clone(),
                pp: pp.clone(),
                pminusone: p - I::one(),

                q: q.clone(),
                qq: qq.clone(),
                qminusone: q - I::one(),

                pinvq: I::modinv(p, q),
                hp: h(p, pp, n),
                hq: h(q, qq, n),

                n: n.clone()
            }
        }
    }

    impl <I> Decryption<CrtDecryptionKey<I>, Ciphertext<I>, Plaintext<I>> for Scheme<I>
    where
        I: One,
        I: ModularArithmetic,
        for<'a>    &'a I: Add<I, Output=I>,
        for<'a>    &'a I: Sub<I, Output=I>,
        for<'a,'b> &'a I: Sub<&'b I, Output=I>,
        for<'b>        I: Mul<&'b I, Output=I>,
        for<'a,'b> &'a I: Mul<&'b I, Output=I>,
        for<'b>        I: Div<&'b I, Output=I>,
        for<'a>        I: Rem<&'a I, Output=I>,
    {
        fn decrypt(dk: &CrtDecryptionKey<I>, c: &Ciphertext<I>) -> Plaintext<I> {
            // process using p
            let cp = I::modpow(&c.0, &dk.pminusone, &dk.pp);
            let lp = l(&cp, &dk.p);
            let mp = (&lp * &dk.hp) % &dk.p;
            // process using q
            let cq = I::modpow(&c.0, &dk.qminusone, &dk.qq);
            let lq = l(&cq, &dk.q);
            let mq = (&lq * &dk.hq) % &dk.q;
            // perform CRT
            Plaintext(crt(&mp, &mq, &dk))
        }
    }

    fn h<I>(p: &I, pp: &I, n: &I) -> I
    where
        I: One,
        I: ModularArithmetic,
        for<'a> &'a I: Sub<I, Output=I>,
        for<'b>     I: Sub<&'b I, Output=I>,
        for<'b>     I: Rem<&'b I, Output=I>,
        for<'b>     I: Div<&'b I, Output=I>,
    {
        // here we assume:
        //  - p \in {P, Q}
        //  - n = P * Q
        //  - g = 1 + n

        // compute g^{p-1} mod p^2
        let gp = (I::one() - n) % pp;
        // compute L_p(.)
        let lp = l(&gp, p);
        // compute L_p(.)^{-1}
        let hp = I::modinv(&lp, p);
        hp
    }

    fn crt<I>(mp: &I, mq: &I, dk: &CrtDecryptionKey<I>) -> I
    where
        for<'a>    &'a I: Add<I, Output=I>,
        for<'a,'b> &'a I: Sub<&'b I, Output=I>,
        for<'a,'b> &'a I: Mul<&'b I, Output=I>,
        for<'b>        I: Mul<&'b I, Output=I>,
        for<'b>        I: Rem<&'b I, Output=I>,
    {
        let u = ((mq - mp) * &dk.pinvq) % &dk.q;
        let m = mp + (&u * &dk.p);
        m % &dk.n
    }

}
pub use self::crt_decryption::*;


#[cfg(feature="keygen")]
mod keygen {

    use super::*;
    use arithimpl::primes::*;

    impl <I> KeyGeneration<EncryptionKey<I>, BasicDecryptionKey<I>> for Scheme<I>
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
        fn keypair(bit_length: usize) -> (EncryptionKey<I>, BasicDecryptionKey<I>) {
            let p = I::sample_prime(bit_length/2);
            let q = I::sample_prime(bit_length/2);
            let n = &p * &q;
            let ek = EncryptionKey::from(&n);
            let dk = BasicDecryptionKey::from((&p, &q));
            (ek, dk)
        }
    }
}
#[cfg(feature="keygen")]
pub use self::keygen::*;






/// Encoding of e.g. primitive values as plaintexts.
pub trait Encode<T>
{
    type I;
    fn encode(x: T) -> Plaintext<Self::I>;
}

impl <I, T> Encode<T> for Scheme<I>
where
    Plaintext<I> : From<T>
{
    type I = I;
    fn encode(x: T) -> Plaintext<I> {
        Plaintext::from(x)
    }
}

/// Decoding of plaintexts into e.g. primitive values.
pub trait Decode<T>
{
    type I;
    fn decode(x: Plaintext<Self::I>) -> T;
}

impl <I, T> Decode<T> for Scheme<I>
where
    Plaintext<I> : Into<T>
{
    type I = I;
    fn decode(x: Plaintext<I>) -> T {
        Plaintext::into(x)
    }
}



bigint!(I,
#[cfg(test)]
mod tests {

    use super::I;
    use ::plain::*;

    fn test_keypair() -> (EncryptionKey<I>, CrtDecryptionKey<I>) {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        let n = &p * &q;
        let ek = EncryptionKey::from(&n);
        let dk = CrtDecryptionKey::from((&p, &q));
        (ek, dk)
    }

    #[test]
    fn test_correct_encryption_decryption() {
        let (ek, dk) = test_keypair();

        let m = Plaintext::from(10);
        let c = Scheme::encrypt(&ek, &m);

        let recovered_m = Scheme::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

    #[test]
    fn test_correct_addition() {
        let (ek, dk) = test_keypair();

        let m1 = Plaintext::from(10);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = Plaintext::from(20);
        let c2 = Scheme::encrypt(&ek, &m2);

        let c = Scheme::add(&ek, &c1, &c2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(m, Plaintext::from(30));
    }

    #[test]
    fn correct_multiplication() {
        let (ek, dk) = test_keypair();

        let m1 = Plaintext::from(10);
        let c1 = Scheme::encrypt(&ek, &m1);
        let m2 = Plaintext::from(20);

        let c = Scheme::mul(&ek, &c1, &m2);
        let m = Scheme::decrypt(&dk, &c);
        assert_eq!(m, Plaintext::from(200));
    }

    #[cfg(feature="keygen")]
    fn test_keypair_sized(bitsize: usize) -> (EncryptionKey<I>, BasicDecryptionKey<I>) {
        Scheme::keypair(bitsize)
    }

    #[cfg(feature="keygen")]
    #[test]
    fn test_correct_keygen() {
        let (ek, dk) = test_keypair_sized(2048);

        let m = Plaintext::from(10);
        let c = Scheme::encrypt(&ek, &m);

        let recovered_m = Scheme::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

});
