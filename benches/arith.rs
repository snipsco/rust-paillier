
#[macro_use]
extern crate bencher;
extern crate paillier;

use bencher::Bencher;
use paillier::*;

use std::ops::{Mul, Rem};

static P: &'static str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
static Q: &'static str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";
static N: &'static str = "446397596678771930935753654586920306936946621208913265356418844327220812727766442444894747633541329301877801861589929170469310562024276317335720389819531817915083642419664574530820516411614402061341540773621609718596217130180876113842466833544592377419546315874157443700724565446359813992789873047692473646165446397596678771930935753654586920306936946621208913265356418844327220812727766442444894747633541329301877801861589929170469310562045923774195463";

pub fn bench_mul<I>(b: &mut Bencher)
where
    for<'a, 'b> &'a I : Mul<&'b I, Output=I>,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug
{
    let ref p: I = str::parse(P).unwrap();
    let ref q: I = str::parse(Q).unwrap();

    b.iter(|| {
        let _ = p * q;
    });
}

pub fn bench_mulrem<I>(b: &mut Bencher)
where
    for<'a, 'b> &'a I : Mul<&'b I, Output=I>,
    for<'b> I : Rem<&'b I, Output=I>,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug
{
    let ref p: I = str::parse(P).unwrap();
    let ref q: I = str::parse(Q).unwrap();
    let ref n: I = str::parse(N).unwrap();

    b.iter(|| {
        let _ = (p * q) % n;
    });
}

#[cfg(feature="inclramp")]
benchmark_group!(ramp,
    self::bench_mul<RampBigInteger>,
    self::bench_mulrem<RampBigInteger>
);

#[cfg(feature="inclnum")]
benchmark_group!(num,
    self::bench_mul<NumBigInteger>,
    self::bench_mulrem<NumBigInteger>
);

#[cfg(feature="inclgmp")]
benchmark_group!(gmp,
    self::bench_mul<GmpBigInteger>,
    self::bench_mulrem<GmpBigInteger>
);

pub fn dummy(_: &mut Bencher) {}

#[cfg(not(feature="inclramp"))]
benchmark_group!(ramp, dummy);

#[cfg(not(feature="inclnum"))]
benchmark_group!(num, dummy);

#[cfg(not(feature="inclgmp"))]
benchmark_group!(gmp, dummy);

benchmark_main!(ramp, num, gmp);
