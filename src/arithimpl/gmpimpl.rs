#![cfg(feature="inclgmp")]

extern crate gmp;

use rand;

use super::traits::*;

use self::gmp::mpz::Mpz;

#[derive(Clone)]
pub struct GmpInteger(Mpz);

// impl Samplable for ramp::Int {
//     fn sample(upper: &Self) -> Self {
//         use self::ramp::RandomInt;
//         let mut rng = rand::OsRng::new().unwrap();
//         rng.gen_uint_below(upper)
//     }
// }

impl NumberTests for GmpInteger {
    fn is_zero(me: &Self) -> bool { me.is_zero() }
    fn is_even(me: &Self) -> bool { me.is_multiple_of(&Mpz::from(2)) }
    fn is_negative(me: &Self) -> bool { me < &Mpz::from(0) }
}

use num_traits::{Zero, One};

impl Zero for GmpInteger {
    fn zero() -> Self {
        GmpInteger::zero()
    }
    fn is_zero(self: &Self) -> bool {
        self.is_zero()
    }
}

impl One for GmpInteger {
    fn one() -> Self {
        GmpInteger::one()
    }
}

use std::ops::{Add, Sub, Mul, Rem, Div, Neg, Shr};
impl         Add for GmpInteger { type Output=GmpInteger; }
impl<'a, 'b> Add<&'a GmpInteger> for &'b GmpInteger {}
impl         Sub for GmpInteger {}
impl<'a>     Sub<&'a GmpInteger> for GmpInteger {}
impl<'a, 'b> Sub<&'a GmpInteger> for &'b GmpInteger {}
impl         Mul for GmpInteger {}
impl<'b>     Mul<GmpInteger> for &'b GmpInteger {}
impl<'a, 'b> Mul<&'a GmpInteger> for &'b GmpInteger {}
impl<'a, 'b> Div<&'a GmpInteger> for &'b GmpInteger {}
impl         Rem<GmpInteger> for GmpInteger {}
impl<'a>     Rem<&'a GmpInteger> for GmpInteger { type Output=GmpInteger; }
impl<'b>     Rem<GmpInteger> for &'b GmpInteger {}
impl<'a, 'b> Rem<&'a GmpInteger> for &'b GmpInteger { type Output=GmpInteger; }
impl Neg for GmpInteger {}
impl Shr<usize> for GmpInteger {}

impl ModularArithmetic for GmpInteger {

    // fn modpow(x: &Self, e: &Self, prime: &Self) -> Self {
    // }

}

// use std::convert::Into;
//
// impl ConvertFrom<Mpz> for u64 {
//     fn _from(x: &Mpz) -> u64 {
//         Mpz::into(x.clone())
//         // u64::from(x)
//     }
// }

pub type BigInteger = Mpz;
