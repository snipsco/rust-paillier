#[macro_use]
extern crate bencher;
extern crate paillier;

#[cfg(feature="keygen")]
mod bench {

    use bencher::Bencher;
    use paillier::RampPaillier;
    use paillier::*;
    use paillier::core::*;

    pub fn bench_key_generation_512<Scheme>(b: &mut Bencher)
    where
        Scheme : AbstractScheme,
        Scheme : Encoding<
            usize,
            Plaintext<<Scheme as AbstractScheme>::BigInteger>>,
        Scheme : KeyGeneration<
            EncryptionKey<<Scheme as AbstractScheme>::BigInteger>,
            DecryptionKey<<Scheme as AbstractScheme>::BigInteger>>
    {
        b.iter(|| {
            Scheme::keypair_of_size(512);
        });
    }

    pub fn bench_key_generation_1024<Scheme>(b: &mut Bencher)
    where
        Scheme : AbstractScheme,
        Scheme : Encoding<
            usize,
            Plaintext<<Scheme as AbstractScheme>::BigInteger>>,
        Scheme : KeyGeneration<
            EncryptionKey<<Scheme as AbstractScheme>::BigInteger>,
            DecryptionKey<<Scheme as AbstractScheme>::BigInteger>>
    {
        b.iter(|| {
            Scheme::keypair_of_size(1024);
        });
    }

    pub fn bench_key_generation_2048<Scheme>(b: &mut Bencher)
    where
        Scheme : AbstractScheme,
        Scheme : Encoding<
            usize,
            Plaintext<<Scheme as AbstractScheme>::BigInteger>>,
        Scheme : KeyGeneration<
            EncryptionKey<<Scheme as AbstractScheme>::BigInteger>,
            DecryptionKey<<Scheme as AbstractScheme>::BigInteger>>
    {
        b.iter(|| {
            Scheme::keypair_of_size(2048);
        });
    }

    pub fn bench_key_generation_3072<Scheme>(b: &mut Bencher)
    where
        Scheme : AbstractScheme,
        Scheme : Encoding<
            usize,
            Plaintext<<Scheme as AbstractScheme>::BigInteger>>,
        Scheme : KeyGeneration<
            EncryptionKey<<Scheme as AbstractScheme>::BigInteger>,
            DecryptionKey<<Scheme as AbstractScheme>::BigInteger>>
    {
        b.iter(|| {
            Scheme::keypair_of_size(3072);
        });
    }

    benchmark_group!(ramp,
        self::bench_key_generation_512<RampPaillier>,
        self::bench_key_generation_1024<RampPaillier>,
        self::bench_key_generation_2048<RampPaillier>,
        self::bench_key_generation_3072<RampPaillier>
    );

}

#[cfg(feature="keygen")]
benchmark_main!(bench::ramp);

#[cfg(not(feature="keygen"))]
fn main() {}
