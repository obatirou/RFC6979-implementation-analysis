import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToNumberBE, concatBytes } from '@noble/curves/abstract/utils';
import { createHmacDrbg } from '@noble/curves/abstract/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { invert } from '@noble/curves/abstract/modular';

const { ProjectivePoint: Point, CURVE } = secp256k1;

// Rest of the implementation remains the same
const drbg = createHmacDrbg(
  32,
  32,
  (key: Uint8Array, ...messages: Uint8Array[]) => hmac(sha256, key, concatBytes(...messages))
);

const test_vectors = [
  {
      privateKey: new Uint8Array(Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex")),
      message: new Uint8Array(Buffer.from("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "hex"))
  },
  {
      privateKey: new Uint8Array(Buffer.from("c0c77d7b7c24cf4ee08d8c368a3b0bcc3ac17c949b6a8455287cbe065cfc088c", "hex")),
      message: new Uint8Array(Buffer.from("9811ebd6296e6078940504347735f04ae42da831f793cd83cb031980543c5ad1", "hex"))
  }
];

for (const test of test_vectors) {
  console.log("\nTest vector:", test);
  
  const k = drbg(concatBytes(test.privateKey, test.message), (bytes) => {
      const num = bytesToNumberBE(bytes);
      if (num <= 0n || num >= CURVE.n) return;
      return num;
  }) as bigint;
  console.log('k:', k.toString(16));
  
  const kInv = invert(k, CURVE.n);
  console.log('k_inv:', kInv.toString(16));
 
  const R = Point.BASE.multiply(k);
  console.log('Rx:', R.toAffine().x.toString(16));
  
  
  const signature = secp256k1.sign(test.message, test.privateKey);
  console.log('r:', signature.r.toString(16));
  console.log('s:', signature.s.toString(16));
}