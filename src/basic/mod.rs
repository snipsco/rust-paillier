
//! Standard Paillier supporting ciphertext addition and plaintext multiplication.

use ::Scheme;
use traits::*;

use std::ops::{Add, Sub, Mul, Div, Rem};
use num_traits::{One};
use arithimpl::traits::*;

impl <I> AbstractScheme for Scheme<I>
{
    type BigInteger = I;
}


/// Encryption key that may be shared publicly.
#[derive(Debug,Clone)]
pub struct EncryptionKey<I> {
    n: I,  // the modulus
    nn: I, // the modulus squared
}

impl<'i, I> From<&'i I> for EncryptionKey<I>
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


mod with_encoding {

    use super::*;

    pub struct EncodingEncryptionKey<'a, 'b, EK: 'a, M: 'b, PT: 'b> {
        key: &'a EK,
        encoder: &'b Encoder<M, PT>
    }

    impl<I> EncryptionKey<I>
    {
        pub fn with_encoder<'a, 'b, M, PT>(&'a self, encoder: &'b Encoder<M, PT>) -> EncodingEncryptionKey<'a, 'b, EncryptionKey<I>, M, PT> {
            EncodingEncryptionKey {
                key: self,
                encoder: encoder
            }
        }
    }

    impl<'a, 'b, M: 'b, PT: 'b, CT, S, EK: 'a> Encryption<EncodingEncryptionKey<'a, 'b, EK, M, PT>, M, CT> for S
    where
        S : Encryption<EK, PT, CT>
    {
        fn encrypt(ek: &EncodingEncryptionKey<EK, M, PT>, m: &M) -> CT {
            S::encrypt(ek.key, &ek.encoder.encode(m))
        }
    }

    // pub struct DecodingDecryptionKey<'a, 'b, DK: 'a, PT: 'b, M: 'b> {
    //     key: &'a DK,
    //     decoder: &'b Decoder<PT, M>
    // }
    //
    // impl<I> crt::DecryptionKey<I>
    // {
    //     pub fn with_decoder<'a, 'b, PT, M>(&'a self, decoder: &'b Decoder<PT, M>) -> DecodingDecryptionKey<'a, 'b, crt::DecryptionKey<I>, PT, M> {
    //         DecodingDecryptionKey {
    //             key: self,
    //             decoder: decoder
    //         }
    //     }
    // }
    //
    // impl<'a, 'b, PT: 'b, M: 'b, CT, S, DK: 'a> Decryption<DecodingDecryptionKey<'a, 'b, DK, PT, M>, CT, M> for S
    // where
    //     S : Decryption<DK, CT, PT>
    // {
    //     fn decrypt(dk: &DecodingDecryptionKey<DK, PT, M>, c: &CT) -> M {
    //         dk.encoder.encode(S::decrypt(dk.key, c))
    //     }
    // }

}
pub use self::with_encoding::*;




/// Representation of unencrypted message.
#[derive(Debug,Clone,PartialEq)]
pub struct Plaintext<I>(pub I);

/// Representation of encrypted message.
#[derive(Debug,Clone)]
pub struct Ciphertext<I>(pub I);


impl<I, T> From<T> for Plaintext<I>
where
    T: Copy,  // marker to avoid infinite loop by excluding Plaintext
    I: From<T>,
{
    fn from(x: T) -> Plaintext<I> {
        Plaintext(I::from(x))
    }
}


impl<I, T> Encoding<T, Plaintext<I>> for Scheme<I>
where
    T: Copy,
    Plaintext<I> : From<T>,
{
    fn encode(x: &T) -> Plaintext<I> {
        Plaintext::from(*x)
    }
}

impl<I, T> Decoding<Plaintext<I>, T> for Scheme<I>
where
    Plaintext<I>: Copy,
    T: From<Plaintext<I>>,
{
    fn decode(x: &Plaintext<I>) -> T {
        T::from(*x)
    }
}


impl<I> Rerandomisation<EncryptionKey<I>, Ciphertext<I>> for Scheme<I>
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


impl<I> Encryption<EncryptionKey<I>, Plaintext<I>, Ciphertext<I>> for Scheme<I>
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


impl<I> Addition<EncryptionKey<I>, Ciphertext<I>, Ciphertext<I>, Ciphertext<I>> for Scheme<I>
where
    for<'a,'b> &'a I: Mul<&'b I, Output=I>,
    for<'b>        I: Rem<&'b I, Output=I>,
{
    fn add(ek: &EncryptionKey<I>, c1: &Ciphertext<I>, c2: &Ciphertext<I>) -> Ciphertext<I> {
        let c = (&c1.0 * &c2.0) % &ek.nn;
        Ciphertext(c)
    }
}


impl<I> Multiplication<EncryptionKey<I>, Ciphertext<I>, Plaintext<I>, Ciphertext<I>> for Scheme<I>
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


pub mod standard {

    use super::*;

    /// Decryption key that should be kept private.
    #[derive(Debug,Clone)]
    pub struct DecryptionKey<I> {
        p: I,  // first prime
        q: I,  // second prime
        n: I,  // the modulus (also in public key)
        nn: I,     // the modulus squared
        lambda: I, // fixed at lambda = (p-1)*(q-1)
        mu: I,     // fixed at lambda^{-1}
    }

    impl<'p, 'q, I> From<(&'p I, &'q I)> for DecryptionKey<I>
    where
        I: One,
        I: Clone,
        I: ModularArithmetic,
        for<'a,'b> &'a I: Mul<&'b I, Output=I>,
        for<'a,'b> &'a I: Sub<&'b I, Output=I>,
    {
        fn from((p, q): (&I, &I)) -> DecryptionKey<I> {
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

    impl<I> Decryption<DecryptionKey<I>, Ciphertext<I>, Plaintext<I>> for Scheme<I>
    where
        I: One,
        I: ModularArithmetic,
        for<'a>    &'a I: Sub<I, Output=I>,
        for<'b>        I: Mul<&'b I, Output=I>,
        for<'b>        I: Div<&'b I, Output=I>,
        for<'a>        I: Rem<&'a I, Output=I>,
    {
        fn decrypt(dk: &DecryptionKey<I>, c: &Ciphertext<I>) -> Plaintext<I> {
            let u = I::modpow(&c.0, &dk.lambda, &dk.nn);
            let m = (l(&u, &dk.n) * &dk.mu) % &dk.n;
            Plaintext(m)
        }
    }

}


pub mod crt {

    use super::*;

    /// Decryption key that should be kept private.
    #[derive(Debug,Clone)]
    pub struct DecryptionKey<I> {
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

    impl<'p, 'q, I> From<(&'p I, &'q I)> for DecryptionKey<I>
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
        fn from((p, q): (&I, &I)) -> DecryptionKey<I> {
            let ref pp = p * p;
            let ref qq = q * q;
            let ref n = p * q;
            DecryptionKey {
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

    impl<I> Decryption<DecryptionKey<I>, Ciphertext<I>, Plaintext<I>> for Scheme<I>
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
        fn decrypt(dk: &DecryptionKey<I>, c: &Ciphertext<I>) -> Plaintext<I> {
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

    fn crt<I>(mp: &I, mq: &I, dk: &DecryptionKey<I>) -> I
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


#[cfg(feature="keygen")]
mod keygen {

    use super::*;
    use arithimpl::primes::*;

    impl<I> KeyGeneration<EncryptionKey<I>, crt::DecryptionKey<I>> for Scheme<I>
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
        for<'b>        I: Sub<&'b I, Output=I>,
        for<'a,'b> &'a I: Sub<&'b I, Output=I>,
        for<'b>        I: Div<&'b I, Output=I>,
        for<'a,'b> &'a I: Div<&'b I, Output=I>,
        for<'a>        I: Rem<&'a I, Output=I>,
        for<'a,'b> &'a I: Rem<&'b I, Output=I>
    {
        fn keypair_of_size(bit_length: usize) -> (EncryptionKey<I>, crt::DecryptionKey<I>) {
            let p = I::sample_prime(bit_length/2);
            let q = I::sample_prime(bit_length/2);
            let n = &p * &q;
            let ek = EncryptionKey::from(&n);
            let dk = crt::DecryptionKey::from((&p, &q));
            (ek, dk)
        }
    }
}
#[cfg(feature="keygen")]
pub use self::keygen::*;




bigint!(I,
#[cfg(test)]
mod tests {

    use super::I;
    use ::basic::*;

    fn test_keypair() -> (EncryptionKey<I>, crt::DecryptionKey<I>) {
        let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
        let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
        let n = &p * &q;
        let ek = EncryptionKey::from(&n);
        let dk = crt::DecryptionKey::from((&p, &q));
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
    #[test]
    fn test_correct_keygen() {
        let (ek, dk): (EncryptionKey<I>, _) = Scheme::keypair_of_size(2048);

        let m = Plaintext::from(10);
        let c = Scheme::encrypt(&ek, &m);

        let recovered_m = Scheme::decrypt(&dk, &c);
        assert_eq!(recovered_m, m);
    }

});
