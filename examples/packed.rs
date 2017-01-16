
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::*;

    let (ek, dk) = Paillier::keypair();
    let vectorcode = integral::vector::Coding::new(3, 16);
    let scalarcode = integral::scalar::Coding::new();

    //
    // Encryption
    //

    let vek = ek.with_encoder(&vectorcode);
    let sek = ek.with_encoder(&scalarcode);

    let m1 = vec![1, 5, 10];
    let c1 = Paillier::encrypt(&vek, &m1);

    let m2 = vec![2, 10, 20];
    let c2 = Paillier::encrypt(&vek, &m2);

    let m3 = vec![3, 15, 30];
    let c3 = Paillier::encrypt(&vek, &m3);

    let m4 = vec![4, 20, 40];
    let c4 = Paillier::encrypt(&vek, &m4);

    // add up all four encryptions
    let c = Paillier::add(&ek,
        &Paillier::add(&ek, &c1, &c2),
        &Paillier::add(&ek, &c3, &c4)
    );

    let d = Paillier::mul(&sek, &c, &2);

    //
    // Decryption
    //

    let vdk = dk.with_decoder(&vectorcode);

    let m = Paillier::decrypt(&vdk, &c);
    let n = Paillier::decrypt(&vdk, &d);
    println!("decrypted total sum is {:?}", m);
    println!("... and after multiplying {:?}", n);
    assert_eq!(m, vec![10, 50, 100]);
}
