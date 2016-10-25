#![feature(test)]
#![feature(step_trait)]

extern crate test;
extern crate rand;
extern crate num_traits;

mod arithimpl;
mod phe;
mod plain;
mod packed;

pub use phe::{KeyGeneration, PartiallyHomomorphicScheme};


/*************************
  Ramp instance (default)
 *************************/

#[cfg(feature="inclramp")]
mod rampinstance
{
    pub use arithimpl::rampimpl::BigInteger as RampBigInteger;
    pub type RampPlainPaillier = ::plain::AbstractPlainPaillier<RampBigInteger>;
    pub type RampPackedPaillier = ::packed::AbstractPackedPaillier<u64, RampPlainPaillier>;

    // pub type BigInteger = RampBigInteger;
    // pub type PlainPaillier = RampPlainPaillier;
    // pub type PackedPaillier = RampPackedPaillier;
}
#[cfg(feature="inclramp")]
pub use self::rampinstance::*;


/**************
  Num instance
 **************/

#[cfg(feature="inclnum")]
mod numinstance
{
    pub use arithimpl::numimpl::BigInteger as NumBigInteger;
    pub type NumPlainPaillier = ::plain::AbstractPlainPaillier<NumBigInteger>;
    pub type NumPackedPaillier = ::packed::AbstractPackedPaillier<u64, NumPlainPaillier>;

    // #[cfg(not(feature="inclramp"))]
    // pub type BigInteger = NumBigInteger;
    // #[cfg(not(feature="inclramp"))]
    // pub type PlainPaillier = NumPlainPaillier;
    // #[cfg(not(feature="inclramp"))]
    // pub type PackedPaillier = NumPackedPaillier;
}
#[cfg(feature="inclnum")]
pub use self::numinstance::*;


/**************
  GMP instance
 **************/

#[cfg(feature="inclgmp")]
mod gmpinstance
{
    pub use arithimpl::gmpimpl::BigInteger as GmpBigInteger;
    pub type GmpPlainPaillier = ::plain::AbstractPlainPaillier<GmpBigInteger>;
    pub type GmpPackedPaillier = ::packed::AbstractPackedPaillier<u64, GmpPlainPaillier>;

    pub type BigInteger = GmpBigInteger;
    pub type PlainPaillier = GmpPlainPaillier;
    pub type PackedPaillier = GmpPackedPaillier;
}
#[cfg(feature="inclgmp")]
pub use self::gmpinstance::*;
