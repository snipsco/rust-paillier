
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::{Scheme, BigInteger, integral};  // could be a specific type such as RampBigInteger as well
    use paillier::coding::*;
    use paillier::traits::*;
    type MyScheme = Scheme<BigInteger>;

    let (ek, dk) = MyScheme::keypair();
    let code = integral::Coding::default();

    let eek = ek.with_encoder(&code);

    let c1 = MyScheme::encrypt(&eek, &10_u64);
    let c2 = MyScheme::encrypt(&eek, &20_u64);
    let c3 = MyScheme::encrypt(&eek, &30_u64);
    let c4 = MyScheme::encrypt(&eek, &40_u64);

    // add up all four encryptions
    let c = MyScheme::add(&ek,
        &MyScheme::add(&ek, &c1, &c2),
        &MyScheme::add(&ek, &c3, &c4)
    );

    // divide by 4 (only correct when result is integer)
    //  - note that this could just as well be done after decrypting!
    // let d = plain::div(&ek, &c, &BigUint::from(4u32));

    let m: u64 = code.decode(&MyScheme::decrypt(&dk, &c));
    // let n = plain::decrypt(&dk, &d);
    println!("decrypted total sum is {}", m);
    // println!("... and after dividing {}", n);
}
