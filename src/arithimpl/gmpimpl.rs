#![cfg(feature="inclgmp")]

extern crate gmp;

use super::traits::*;
use self::gmp::mpz::Mpz;
use self::gmp::rand::RandState;
use rand::{OsRng, Rng};

impl Samplable for Mpz {

    fn sample_below(upper: &Self) -> Self {
        let mut state = RandState::new();
        let mut rng = OsRng::new().unwrap();

        let seed = rng.gen();
        state.seed_ui(seed);
        state.urandom(upper)
    }
    
    fn sample(bitsize: usize) -> Self {
        let mut state = RandState::new();
        let mut rng = OsRng::new().unwrap();

        let seed = rng.gen();
        state.seed_ui(seed);

        state.urandom_2exp(bitsize as u64)
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        lower + Self::sample_below(&(upper - lower))
    }
}

impl NumberTests for Mpz {
    fn is_zero(me: &Self) -> bool { me.is_zero() }
    fn is_even(me: &Self) -> bool { me.is_multiple_of(&Mpz::from(2)) }
    fn is_negative(me: &Self) -> bool { me < &Mpz::from(0) }
}

pub use num_traits::{Zero, One};
use std::ops::{Div, Rem};
impl ModularArithmetic for Mpz {

    fn modinv(a: &Self, prime: &Self) -> Self {
        a.invert(prime).unwrap()
    }

    fn modpow(x: &Self, e: &Self, prime: &Self) -> Self {
        x.powm(e, prime)
    }

    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        a.gcdext(b)
    }

    fn divmod(dividend: &Self, module: &Self) -> (Self, Self) {
        (dividend.div(module), dividend.rem(module))
    }

}

impl ConvertFrom<Mpz> for u64 {
    fn _from(x: &Mpz) -> u64 {
        let foo: Option<u64> = x.into();
        foo.unwrap()
    }
}

impl BitManipulation for Mpz {
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        if bit_val {
            self.setbit(bit);
        } else {
            self.clrbit(bit);
        }
    }
}


pub type BigInteger = Mpz;
