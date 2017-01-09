
extern crate paillier;

#[cfg(not(feature="keygen"))]
fn main() {
    println!("*** please run with 'keygen' feature ***")
}

#[cfg(feature="keygen")]
fn main() {

    use paillier::*;

    let (ek, dk) = PlainPaillier::keypair(100);
    // let ek = keypair.encryption_key();
    // let dk = keypair.decryption_key();

    // let e = IntegralEncoder::new(10, 60);
    // let m: IntegralPlaintext<Vec<T>> = e.encode(vec![]);
    // let c: IntegralCiphertext<Vec<T>> = Paillier::encrypt(m);
    //
    // mul(IntegralCiphertext<Vec<T>>, IntegralPlaintext<T>) -> IntegralCiphertext<Vec<T>>
    // mul(IntegralCiphertext<T>, IntegralPlaintext<T>) -> IntegralCiphertext<T>
    //
    // mul(IntegralPackedCiphertext<T>, IntegralPlaintext<T>) -> IntegralCiphertext<Vec<T>>
    // mul(IntegralCiphertext<T>, IntegralPlaintext<T>) -> IntegralCiphertext<T>
    //
    // let n = ..
    // let _ : Vec<T> = e.decode(n)

    let m1 = PlainPaillier::encode(10);
    let c1 = PlainPaillier::encrypt(&ek, &m1);

    let m2 = PlainPaillier::encode(20);;
    let c2 = PlainPaillier::encrypt(&ek, &m2);

    let m3 = PlainPaillier::encode(30);
    let c3 = PlainPaillier::encrypt(&ek, &m3);

    let m4 = PlainPaillier::encode(40);
    let c4 = PlainPaillier::encrypt(&ek, &m4);

    // add up all four encryptions
    let c = PlainPaillier::add(&ek,
        &PlainPaillier::add(&ek, &c1, &c2),
        &PlainPaillier::add(&ek, &c3, &c4)
    );

    // divide by 4 (only correct when result is integer)
    //  - note that this could just as well be done after decrypting!
    // let d = plain::div(&ek, &c, &BigUint::from(4u32));

    let m = PlainPaillier::decrypt(&dk, &c).0;
    // let n = plain::decrypt(&dk, &d);
    println!("decrypted total sum is {}", m);
    // println!("... and after dividing {}", n);
}
