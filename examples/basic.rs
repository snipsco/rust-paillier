
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::*;

    let (ek, dk) = Paillier::keypair();

    let m1 = 10;
    let c1 = Paillier::encrypt(&ek, &m1);

    let m2 = Paillier::encode(20);;
    let c2 = Paillier::encrypt(&ek, &m2);

    let m3 = Paillier::encode(30);
    let c3 = Paillier::encrypt(&ek, &m3);

    let m4 = Paillier::encode(40);
    let c4 = Paillier::encrypt(&ek, &m4);

    // add up all four encryptions
    let c = Paillier::add(&ek,
        &Paillier::add(&ek, &c1, &c2),
        &Paillier::add(&ek, &c3, &c4)
    );

    // divide by 4 (only correct when result is integer)
    //  - note that this could just as well be done after decrypting!
    // let d = plain::div(&ek, &c, &BigUint::from(4u32));

    let m = Paillier::decrypt(&dk, &c).0;
    // let n = plain::decrypt(&dk, &d);
    println!("decrypted total sum is {}", m);
    // println!("... and after dividing {}", n);
}
