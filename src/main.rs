use ecdsa::hazmat::sign_prehashed;
use elliptic_curve::ops::MulByGenerator;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::PrimeField;
use hex as other_hex;
use hex_literal::hex;
use k256::{NonZeroScalar, ProjectivePoint, Scalar, Secp256k1};
use rfc6979::{consts::U32, generate_k};
use sha2::Sha256;

fn main() {
    let test_vectors = vec![
        (
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ),
        (
            hex!("c0c77d7b7c24cf4ee08d8c368a3b0bcc3ac17c949b6a8455287cbe065cfc088c"),
            hex!("9811ebd6296e6078940504347735f04ae42da831f793cd83cb031980543c5ad1"),
        ),
    ];

    let modulus = hex!("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

    for (private_key, message) in test_vectors {
        println!("\nTest vector:");
        println!("Private key: {:x?}", private_key);
        println!("Message: {:x?}", message);

        let k =
            generate_k::<Sha256, U32>(&private_key.into(), &modulus.into(), &message.into(), b"");
        println!("k: {}", other_hex::encode(&k));

        let k = Scalar::from_repr(k.into()).unwrap();
        let k_inv = k.invert();
        println!("k_inv: {}", other_hex::encode(k_inv.unwrap().to_repr()));

        let big_r = ProjectivePoint::mul_by_generator(&k).to_affine();
        println!("Rx: {}", other_hex::encode(&big_r.x()));

        let d = NonZeroScalar::from_repr(private_key.into()).unwrap();
        let (signature, _) = sign_prehashed::<Secp256k1, Scalar>(&d, k, &message.into()).unwrap();
        let (r, s) = signature.split_scalars();
        println!("r: {}", other_hex::encode(r.to_repr()));
        println!("s: {}", other_hex::encode(s.to_repr()));
    }
}
