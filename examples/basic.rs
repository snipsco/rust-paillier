
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::*;

    // generate a fresh keypair
    let (ek, dk) = Paillier::keypair();

    // select integral coding
    let code = integral::Coding::default();

    // pair keys with coding
    let eek = ek.with_code(&code);
    let ddk = dk.with_code(&code);

    // encrypt four values
    let c1 = Paillier::encrypt(&eek, &10);
    let c2 = Paillier::encrypt(&eek, &20);
    let c3 = Paillier::encrypt(&eek, &30);
    let c4 = Paillier::encrypt(&eek, &40);

    // add all of them together
    let c = Paillier::add(&ek, &Paillier::add(&ek, &c1, &c2), &Paillier::add(&ek, &c3, &c4));

    // multiply the sum by 2
    let d = Paillier::mul(&eek, &c, &2);

    // decrypt final result
    let m: u64 = Paillier::decrypt(&ddk, &d);
    println!("decrypted total sum is {}", m);

}
