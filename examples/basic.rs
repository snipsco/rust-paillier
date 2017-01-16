
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::*;

    let (ek, dk) = Paillier::keypair();
    let code = integral::Coding::default();

    let eek = ek.with_encoder(&code);

    let m1 = 10;
    let c1 = Paillier::encrypt(&eek, &m1);

    let m2 = 20;
    let c2 = Paillier::encrypt(&eek, &m2);

    let m3 = 30;
    let c3 = Paillier::encrypt(&eek, &m3);

    let m4 = 40;
    let c4 = Paillier::encrypt(&eek, &m4);

    // add up all four encryptions
    let c = Paillier::add(&ek,
        &Paillier::add(&ek, &c1, &c2),
        &Paillier::add(&ek, &c3, &c4)
    );

    let ddk = dk.with_decoder(&code);

    let m: u64 = Paillier::decrypt(&ddk, &c);
    println!("decrypted total sum is {}", m);
}
