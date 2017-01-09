
/// Operations exposed by the Paillier scheme.
pub trait AbstractScheme
{
    /// Underlying arbitrary precision arithmetic type.
    type BigInteger;
}

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
pub trait Addition<EK, CT1, CT2, CT> {
    /// Homomorphically combine ciphertexts `c1` and `c2` to obtain a ciphertext containing
    /// the sum of the two underlying plaintexts, reduced modulus `n` from `ek`.
    fn add(ek: &EK, c1: &CT1, c2: &CT2) -> CT;
}

/// Multiplication of ciphertext with plaintext
pub trait Multiplication<EK, CT1, PT2, CT> {
    /// Homomorphically combine ciphertext `c1` and plaintext `m2` to obtain a ciphertext
    /// containing the multiplication of the (underlying) plaintexts, reduced modulus `n` from `ek`.
    fn mul(ek: &EK, c1: &CT1, m2: &PT2) -> CT;
}

/// Rerandomisation of ciphertext
pub trait Rerandomisation<EK, CT> {
    /// Rerandomise ciphertext `c` to hide any history of which homomorphic operations were
    /// used to compute it, making it look exactly like a fresh encryption of the same plaintext.
    fn rerandomise(ek: &EK, c: &CT) -> CT;
}

/// Encoding of e.g. primitive values as plaintexts.
pub trait Encoding<T, P>
{
    fn encode(x: T) -> P;
}

/// Decoding of e.g. primitive values as plaintexts.
pub trait Decoding<P, T>
{
    fn decode(y: P) -> T;
}