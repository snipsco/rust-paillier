
use super::*;

pub mod scalar;
pub mod vector;

use std::ops::{Add, Shl, Shr, Rem};
use num_traits::One;
use arithimpl::traits::ConvertFrom;
use std::marker::PhantomData;


pub struct Coding<I> {
    pub component_count: usize,
    pub component_size: usize,  // in bits
    pub _phantom: PhantomData<I>
}


impl<I> Coding<I> {
    pub fn default() -> Coding<I> {
        Self::new(10, 64)
    }

    pub fn new(component_count: usize, component_size: usize) -> Coding<I> {
        Coding {
            component_count: component_count,
            component_size: component_size,
            _phantom: PhantomData,
        }
    }
}


impl<I> Encoder<usize> for Coding<I>
where
    I: From<usize>,
{
    type Target=scalar::Plaintext<I, usize>;
    fn encode(&self, x: &usize) -> Self::Target {
        scalar::Plaintext {
            data: basic::Plaintext(I::from(*x)),
            _phantom: PhantomData,
        }
    }
}


impl<I> Encoder<u8> for Coding<I>
where
    I: From<u8>,
{
    type Target=scalar::Plaintext<I, u8>;
    fn encode(&self, x: &u8) -> Self::Target {
        scalar::Plaintext {
            data: basic::Plaintext(I::from(*x)),
            _phantom: PhantomData,
        }
    }
}


impl<I> Encoder<u16> for Coding<I>
where
    I: From<u16>,
{
    type Target=scalar::Plaintext<I, u16>;
    fn encode(&self, x: &u16) -> Self::Target {
        scalar::Plaintext {
            data: basic::Plaintext(I::from(*x)),
            _phantom: PhantomData,
        }
    }
}


impl<I> Encoder<u32> for Coding<I>
where
    I: From<u32>,
{
    type Target=scalar::Plaintext<I, u32>;
    fn encode(&self, x: &u32) -> Self::Target {
        scalar::Plaintext {
            data: basic::Plaintext(I::from(*x)),
            _phantom: PhantomData,
        }
    }
}


impl<I> Encoder<u64> for Coding<I>
where
    I: From<u64>,
{
    type Target=scalar::Plaintext<I, u64>;
    fn encode(&self, x: &u64) -> Self::Target {
        scalar::Plaintext {
            data: basic::Plaintext(I::from(*x)),
            _phantom: PhantomData,
        }
    }
}


impl<I> Encoder<Vec<u64>> for Coding<I>
where
    I: One,
    I: Clone,
    I: From<u64>,
    I: Shl<usize, Output=I>,
    I: Add<I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    type Target=vector::Plaintext<I, u64>;
    fn encode(&self, x: &Vec<u64>) -> Self::Target {
        vector::Plaintext {
            data: basic::Plaintext(pack(x, self.component_count, self.component_size)),
            component_count: self.component_count,
            component_size: self.component_size,
            _phantom: PhantomData,
        }
    }
}


impl<I> Decoder<usize> for Coding<I>
where
    usize: ConvertFrom<I>,
{
    type Source=scalar::Plaintext<I, usize>;
    fn decode(&self, x: &scalar::Plaintext<I, usize>) -> usize {
        usize::_from(&x.data.0)
    }
}

impl<I> Decoder<u8> for Coding<I>
where
    u8: ConvertFrom<I>,
{
    type Source=scalar::Plaintext<I, u8>;
    fn decode(&self, x: &scalar::Plaintext<I, u8>) -> u8 {
        u8::_from(&x.data.0)
    }
}

impl<I> Decoder<u16> for Coding<I>
where
    u16: ConvertFrom<I>,
{
    type Source=scalar::Plaintext<I, u16>;
    fn decode(&self, x: &scalar::Plaintext<I, u16>) -> u16 {
        u16::_from(&x.data.0)
    }
}

impl<I> Decoder<u32> for Coding<I>
where
    u32: ConvertFrom<I>,
{
    type Source=scalar::Plaintext<I, u32>;
    fn decode(&self, x: &scalar::Plaintext<I, u32>) -> u32 {
        u32::_from(&x.data.0)
    }
}

impl<I> Decoder<u64> for Coding<I>
where
    u64: ConvertFrom<I>,
{
    type Source=scalar::Plaintext<I, u64>;
    fn decode(&self, x: &scalar::Plaintext<I, u64>) -> u64 {
        u64::_from(&x.data.0)
    }
}


impl<I> Decoder<Vec<u64>> for Coding<I>
where
    u64: ConvertFrom<I>,
    I: One,
    I: Clone,
    I: From<u64>,
    I: Shl<usize, Output=I>,
    I: Add<I, Output=I>,
    for<'a,'b> &'a I: Rem<&'b I, Output=I>,
    for<'a> &'a    I: Shr<usize, Output=I>,
{
    type Source=vector::Plaintext<I, u64>;

    fn decode(&self, x: &vector::Plaintext<I, u64>) -> Vec<u64> {
        unpack(x.data.0.clone(), self.component_count, self.component_size)
    }
}
