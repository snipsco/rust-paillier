#![feature(test)]
#![feature(step_trait)]
#![feature(specialization)]

extern crate test;
extern crate rand;
extern crate num_traits;

macro_rules! bigint {
    ( $t:ident, $body:item ) => {

        #[cfg(feature="inclramp")]
        mod ramp {
            #[allow(dead_code)]
            type $t = ::RampBigInteger;
            $body
        }

        #[cfg(feature="inclgmp")]
        mod gmp {
            #[allow(dead_code)]
            type $t = ::GmpBigInteger;
            $body
        }

        #[cfg(feature="inclnum")]
        mod num {
            #[allow(dead_code)]
            type $t = ::NumBigInteger;
            $body
        }

    };
}

pub mod arithimpl;
pub mod traits;
pub mod basic;
pub mod coding;

pub use traits::*;
pub use coding::*;
pub use basic::standard::EncryptionKey;
pub use basic::crt::DecryptionKey;


/// Implementation of the Paillier operations, such as encryption, decryption, and addition.
pub struct Scheme<I> {
    junk: ::std::marker::PhantomData<I>
}


/*************************
  Ramp instance (default)
 *************************/

#[cfg(feature="inclramp")]
mod rampinstance
{
    pub use arithimpl::rampimpl::BigInteger as RampBigInteger;
    pub type RampPaillier = ::Scheme<RampBigInteger>;

    #[cfg(feature="defaultramp")]
    pub type BigInteger = RampBigInteger;
    #[cfg(feature="defaultramp")]
    pub type Paillier = RampPaillier;
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
    pub type NumPaillier = ::Scheme<NumBigInteger>;

    #[cfg(feature="defaultnum")]
    pub type BigInteger = NumBigInteger;
    #[cfg(feature="defaultnum")]
    pub type Paillier = NumPaillier;
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
    pub type GmpPaillier = ::Scheme<GmpBigInteger>;

    #[cfg(feature="defaultgmp")]
    pub type BigInteger = GmpBigInteger;
    #[cfg(feature="defaultgmp")]
    pub type Paillier = GmpPaillier;
}
#[cfg(feature="inclgmp")]
pub use self::gmpinstance::*;
