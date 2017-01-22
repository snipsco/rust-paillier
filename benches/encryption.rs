#[macro_use]
extern crate bencher;
extern crate paillier;
extern crate num_traits;

use bencher::Bencher;
use paillier::*;
use paillier::core::*;
// use paillier::core::standard::*;

mod helpers;
use helpers::*;

pub fn bench_encryption<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, _) = S::test_keypair().keys();
    let m = Plaintext::from(10);
    b.iter(|| {
        let _ = S::encrypt(&ek, &m);
    });
}

pub fn bench_decryption<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Decryption<
            DecryptionKey<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, dk) = S::test_keypair().keys();
    let m = Plaintext::from(10);
    let c = S::encrypt(&ek, &m);
    b.iter(|| {
        let _ = S::decrypt(&dk, &c);
    });
}

pub fn bench_rerandomisation<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Rerandomisation<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, _) = S::test_keypair().keys();
    let m = Plaintext::from(10);
    let c = S::encrypt(&ek, &m);
    b.iter(|| {
        let _ = S::rerandomise(&ek, &c);
    });
}

pub fn bench_addition<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Addition<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let (ek, _) = S::test_keypair().keys();

    let m1 = Plaintext::from(10);
    let c1 = S::encrypt(&ek, &m1);

    let m2 = Plaintext::from(20);
    let c2 = S::encrypt(&ek, &m2);

    b.iter(|| {
        let _ = S::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication<S>(b: &mut Bencher)
where
    S : AbstractScheme,
    S : Encryption<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : Multiplication<
            EncryptionKey<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>,
            Plaintext<<S as AbstractScheme>::BigInteger>,
            Ciphertext<<S as AbstractScheme>::BigInteger>>,
    S : TestKeyGeneration<<S as AbstractScheme>::BigInteger>,
    <S as AbstractScheme>::BigInteger : From<u32>,
{
    let ref keypair = S::test_keypair();
    let ek = standard::EncryptionKey::from(keypair);

    let m1 = Plaintext::from(10);
    let c1 = S::encrypt(&ek, &m1);

    let m2 = Plaintext::from(20);

    b.iter(|| {
        let _ = S::mul(&ek, &c1, &m2);
    });
}

#[cfg(feature="inclramp")]
benchmark_group!(ramp,
    self::bench_encryption<RampPaillier>,
    self::bench_decryption<RampPaillier>,
    self::bench_rerandomisation<RampPaillier>,
    self::bench_addition<RampPaillier>,
    self::bench_multiplication<RampPaillier>
);

#[cfg(feature="inclnum")]
benchmark_group!(num,
    self::bench_encryption<NumPaillier>,
    self::bench_decryption<NumPaillier>,
    self::bench_rerandomisation<NumPaillier>,
    self::bench_addition<NumPaillier>,
    self::bench_multiplication<NumPaillier>
);

#[cfg(feature="inclgmp")]
benchmark_group!(gmp,
    self::bench_encryption<GmpPaillier>,
    self::bench_decryption<GmpPaillier>,
    self::bench_rerandomisation<GmpPaillier>,
    self::bench_addition<GmpPaillier>,
    self::bench_multiplication<GmpPaillier>
);

pub fn dummy(_: &mut Bencher) {}

#[cfg(not(feature="inclramp"))]
benchmark_group!(ramp, dummy);

#[cfg(not(feature="inclnum"))]
benchmark_group!(num, dummy);

#[cfg(not(feature="inclgmp"))]
benchmark_group!(gmp, dummy);

benchmark_main!(ramp, num, gmp);
