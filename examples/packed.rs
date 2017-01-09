
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::PackedPaillier;
    use paillier::*;

    let (ek, dk) = PackedPaillier::keypair(100);
    let encoder = packed::Encoder::new(3, 16);

    let m1 = encoder.encode(&vec![1, 2, 3]);
    let c1 = PackedPaillier::encrypt(&ek, &m1);
    let m2 = encoder.encode(&vec![1, 2, 3]);
    let c2 = PackedPaillier::encrypt(&ek, &m2);

    let c = PackedPaillier::add(&ek, &c1, &c2);
    let m = PackedPaillier::decrypt(&dk, &c);
    assert_eq!(encoder.decode(&m), vec![2, 4, 6]);

    let m1 = encoder.encode(&vec![1, 5, 10]);
    let c1 = PackedPaillier::encrypt(&ek, &m1);

    let m2 = encoder.encode(&vec![2, 10, 20]);;
    let c2 = PackedPaillier::encrypt(&ek, &m2);

    let m3 = encoder.encode(&vec![3, 15, 30]);
    let c3 = PackedPaillier::encrypt(&ek, &m3);

    let m4 = encoder.encode(&vec![4, 20, 40]);
    let c4 = PackedPaillier::encrypt(&ek, &m4);

    // add up all four encryptions
    let c = PackedPaillier::add(&ek,
        &PackedPaillier::add(&ek, &c1, &c2),
        &PackedPaillier::add(&ek, &c3, &c4)
    );

    let d = PackedPaillier::mul(&ek, &c, &2);

    // divide by 4 (only correct when result is integer)
    //  - note that this could just as well be done after decrypting!
    // let d = plain::div(&ek, &c, &BigUint::from(4u32));

    let m = encoder.decode(&PackedPaillier::decrypt(&dk, &c));
    let n = encoder.decode(&PackedPaillier::decrypt(&dk, &d));
    println!("decrypted total sum is {:?}", m);
    println!("... and after multiplying {:?}", n);
}
