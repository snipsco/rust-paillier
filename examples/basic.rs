
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

    let c1 = Paillier::encrypt(&eek, &10_u32);
    let c2 = Paillier::encrypt(&eek, &20_u32);
    let c3 = Paillier::encrypt(&eek, &30_u32);
    let c4 = Paillier::encrypt(&eek, &40_u32);

    // add up all four encryptions
    let c = Paillier::add(&ek,
        &Paillier::add(&ek, &c1, &c2),
        &Paillier::add(&ek, &c3, &c4)
    );

    let ddk = dk.with_decoder(&code);

    let m: u32 = Paillier::decrypt(&ddk, &c);
    println!("decrypted total sum is {}", m);
}
