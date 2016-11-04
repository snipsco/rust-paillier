
#[macro_use]
extern crate bencher;
extern crate paillier;

use bencher::Bencher;
use paillier::*;

use std::ops::{Mul, Rem};

// 1024 bit primes
static P: &'static str = "148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517";
static Q: &'static str = "158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463";
static N: &'static str = "446397596678771930935753654586920306936946621208913265356418844327220812727766442444894747633541329301877801861589929170469310562024276317335720389819531817915083642419664574530820516411614402061341540773621609718596217130180876113842466833544592377419546315874157443700724565446359813992789873047692473646165446397596678771930935753654586920306936946621208913265356418844327220812727766442444894747633541329301877801861589929170469310562045923774195463";

// 2048 bit primes
// static P: &'static str = "54012895487015803837782421918841304863093162502146915827099238255626761389465957752056702693431430972436786355954646022466841435632094385265559627938436498972714352765471698566168945062965812056432412175521672036039582393637684261505269548649599691053041645072024278713283987472744964393377089048380212183701013564638897218456903964669359622810875460724326972855594957135344351009076932272355015777958742805494234839710255927334289902051693131165245513596331706022111667560809760947628509288759753593140967096047486612859680010875340619186313770693509235798857494768621913543203586903819461926872265770592622637080247";
// static Q: &'static str = "60110804761482905184172241999095064083721568391310132372880785562823040626081548259976195239057024762128798436684644401019565227508680839629752481384744855648596664223620474562582585419094571730852126918991494749938349375651158144545334949768160783962056913632707282062013023732986998195594940491859337992015569093391582644730733764652146222141495874869085082992832080902317418308778550853362446428222413647016439326663338175383509775221151568910938769471308411320393345489705012051577672571014388700476797545130036524629098427518061068575727892423981365405385986469525296662636940291427883820330312960173766723887143";
// static N: &'static str = "3246758615222388102257247104619985257592790129095589210285276009429248256483846762934600391064503048539903536673803710898604266821127692553307361753316149607744596533947638369976896670599527959946456949729058671997201321029364087175491520869992605813032138070666142912786334578770232410719158199903915219886365963038477353646170462629197320969461918509765448690461526595960295577353920421639783555592907467785122476992591305198715822048909651296920289129580964452643808772386398216489780200158235271114140320078333479463828730923289630749950844692411371115829797899202089704002350025399751552212048387273162551252449279900043300405231911911403088435999645178423690062241837444313757921133439123090595809089406205378183174668004730796885645012612585689200392985339436110097924364054047371753194447028031925597558713228181086781152399656291395019275676908809117433906584203865571607578128934025711654282559310109420295931262272083976366943491672319050567929651567558548285963107610847891996140722185310234362659096832657024506723511060949620779357547927351440604423321590228598130693198375381347497839507868423146129670757985484273179950113558103417825488895000061485634292528378356202449380174380166345045052714420243023833347862564321";

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

pub fn bench_modarith<I>(b: &mut Bencher)
where
    I: paillier::arithimpl::traits::ModularArithmetic,
    I: ::std::str::FromStr, <I as ::std::str::FromStr>::Err: ::std::fmt::Debug
{
    let ref p: I = str::parse(P).unwrap();
    let ref q: I = str::parse(Q).unwrap();
    let ref n: I = str::parse(N).unwrap();

    b.iter(|| {
        let _ = I::modpow(p, q, n);
    });
}

#[cfg(feature="inclramp")]
benchmark_group!(ramp,
    self::bench_mul<RampBigInteger>,
    self::bench_mulrem<RampBigInteger>,
    self::bench_modarith<RampBigInteger>
);

#[cfg(feature="inclnum")]
benchmark_group!(num,
    self::bench_mul<NumBigInteger>,
    self::bench_mulrem<NumBigInteger>,
    self::bench_modarith<NumBigInteger>
);

#[cfg(feature="inclgmp")]
benchmark_group!(gmp,
    self::bench_mul<GmpBigInteger>,
    self::bench_mulrem<GmpBigInteger>,
    self::bench_modarith<GmpBigInteger>
);

pub fn dummy(_: &mut Bencher) {}

#[cfg(not(feature="inclramp"))]
benchmark_group!(ramp, dummy);

#[cfg(not(feature="inclnum"))]
benchmark_group!(num, dummy);

#[cfg(not(feature="inclgmp"))]
benchmark_group!(gmp, dummy);

benchmark_main!(ramp, num, gmp);
