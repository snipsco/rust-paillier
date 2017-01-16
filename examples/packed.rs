
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::*;

    let (ek, dk) = Paillier::keypair();

    let encoding = integral::vector::Encoding::new(3, 16);
    let eek = ek.with_encoder(&encoding);

    let m1 = vec![1, 5, 10];
    let c1 = Paillier::encrypt(&eek, &m1);

    let m2 = vec![2, 10, 20];
    let c2 = Paillier::encrypt(&eek, &m2);

    let m3 = vec![3, 15, 30];
    let c3 = Paillier::encrypt(&eek, &m3);

    let m4 = vec![4, 20, 40];
    let c4 = Paillier::encrypt(&eek, &m4);

    // add up all four encryptions
    let c = Paillier::add(&ek,
        &Paillier::add(&ek, &c1, &c2),
        &Paillier::add(&ek, &c3, &c4)
    );

    let d = Paillier::mul(&ek, &c, &integral::scalar::ScalarPlaintext::from(2));

    // divide by 4 (only correct when result is integer)
    //  - note that this could just as well be done after decrypting!
    // let d = plain::div(&ek, &c, &BigUint::from(4u32));

    let m = encoding.decode(&Paillier::decrypt(&dk, &c));
    let n = encoding.decode(&Paillier::decrypt(&dk, &d));
    println!("decrypted total sum is {:?}", m);
    println!("... and after multiplying {:?}", n);
    assert_eq!(m, vec![10, 50, 100]);
}
