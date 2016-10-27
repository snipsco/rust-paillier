#![cfg(feature="inclgmp")]

extern crate gmp;

use rand;

use super::traits::*;

use self::gmp::mpz::Mpz;

// #[derive(Clone)]
// pub struct GmpInteger(Mpz);

impl Samplable for Mpz {
    fn sample(upper: &Self) -> Self {
        // TODO
        Mpz::zero()
    }
}

impl NumberTests for Mpz {
    fn is_zero(me: &Self) -> bool { me.is_zero() }
    fn is_even(me: &Self) -> bool { me.is_multiple_of(&Mpz::from(2)) }
    fn is_negative(me: &Self) -> bool { me < &Mpz::from(0) }
}

pub use num_traits::{Zero, One};

// impl ModularArithmetic for Mpz {
//
//     // fn modinv(a: &Self, prime: &Self) -> Self {
//     //     a.clone()
//     // }
//     //
//     // fn modpow(x: &Self, e: &Self, prime: &Self) -> Self {
//     //     x.clone()
//     // }
//     //
//     // fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
//     //     (a.clone(), a.clone(), a.clone())
//     // }
//
// }

impl ConvertFrom<Mpz> for u64 {
    fn _from(x: &Mpz) -> u64 {
        // TODO
        0_u64
        // Mpz::into(x.clone())
        // u64::from(x)
    }
}

pub type BigInteger = Mpz;
