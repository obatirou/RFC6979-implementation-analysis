# RFC6979 implementation investigation

The noble-curves library performs modular reduction of the message hash before generating the deterministic nonce k. This leads to generating different signatures when the message hash is equal or superior to the curve order compared to the other implementations that perform modular reduction after generating the nonce.
The cause is a difference of inputs to the HMAC operations.

This was found following this https://github.com/verklegarden/crysol/issues/23#issuecomment-2451687926:  
The signature generated by nobles curves for certain test vectors was different from the signature generated by foundry.
It lead to investigate the noble-curves library and how foundry generates the signature. It uses the RustCrypto library under the hood. Noble curves and RustCrypto libraries were compared to the reference implementations [eth-keys](https://github.com/ethereum/eth-keys/tree/d8d1ecc6e159dd1dd7b12d7a203f8a276fa2a8ba).

* noble-curves on commit [e0ad0530f64d7cc01514b65d819b7f76db5f0da4](https://github.com/paulmillr/noble-curves/tree/e0ad0530f64d7cc01514b65d819b7f76db5f0da4)
* [RustCrypto on tag ecdsa/0.16.9](https://github.com/RustCrypto/signatures/tree/ecdsa/v0.16.9/ecdsa) used by [foundry on master](https://github.com/foundry-rs/foundry/blob/4817280d96e0e33a2e96cf169770da60514d1764/Cargo.lock#L2888)
* eth-keys on commit [d8d1ecc6e159dd1dd7b12d7a203f8a276fa2a8ba](https://github.com/ethereum/eth-keys/tree/d8d1ecc6e159dd1dd7b12d7a203f8a276fa2a8ba)

In [`weierstrass.ts from noble curves`](https://github.com/paulmillr/noble-curves/blob/e0ad0530f64d7cc01514b65d819b7f76db5f0da4/src/abstract/weierstrass.ts#L1052):
```ts
 const h1int = bits2int_modN(msgHash); // <- here is the reduction
 const d = normPrivateKeyToScalar(privateKey);
 const seedArgs = [int2octets(d), int2octets(h1int)]; // <-  passed to the seed for HMAC
```

See https://www.rfc-editor.org/rfc/rfc6979#section-3.2  
The seed for the deterministic nonce k is generated by concatenating the private key and the message hash
```
3.2.  Generation of k
Given the input message m, the following process is applied:

   a.  Process m through the hash function H, yielding:

          h1 = H(m)
...
    d.  Set:
        K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
```

For RustCrypto the message hash is used directly in the seed generation and not reduced:
https://github.com/RustCrypto/signatures/blob/89232d6a962a199fd8211a117db74408353e4383/ecdsa/src/hazmat.rs#L103
```rust
fn try_sign_prehashed_rfc6979<D>(
        &self,
        z: &FieldBytes<C>,
        ad: &[u8],
    ) -> Result<(Signature<C>, Option<RecoveryId>)>
    where
        Self: From<ScalarPrimitive<C>> + Invert<Output = CtOption<Self>>,
        D: Digest + BlockSizeUser + FixedOutput<OutputSize = FieldBytesSize<C>> + FixedOutputReset,
    {
        let k = Scalar::<C>::from_repr(rfc6979::generate_k::<D, _>(
            &self.to_repr(),
            &C::ORDER.encode_field_bytes(),
            z,                             // <- here the msgHash is used directly
            ad,
        ))
        .unwrap();

        self.try_sign_prehashed::<Self>(k, z)
    }
```
The reduction is only performed after the k is generated:
https://github.com/RustCrypto/signatures/blob/89232d6a962a199fd8211a117db74408353e4383/ecdsa/src/hazmat.rs#L239
```rust
pub fn sign_prehashed<C, K>(
    d: &Scalar<C>,
    k: K,
    z: &FieldBytes<C>,
) -> Result<(Signature<C>, RecoveryId)>
where
    C: PrimeCurve + CurveArithmetic,
    K: AsRef<Scalar<C>> + Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArrayLength<u8>,
{
    // TODO(tarcieri): use `NonZeroScalar<C>` for `k`.
    if k.as_ref().is_zero().into() {
        return Err(Error::new());
    }

    let z = <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(z); // <- msghash is reduced here only after the k gerneration

    // Compute scalar inversion of 𝑘
    let k_inv = Option::<Scalar<C>>::from(k.invert()).ok_or_else(Error::new)?;

    // Compute 𝑹 = 𝑘×𝑮
    let R = ProjectivePoint::<C>::mul_by_generator(k.as_ref()).to_affine();

...

    Ok((signature, recovery_id))
}
```

After careful review of the test vectors that were leading different signature depending on the library used, it was found they shared one similarity: the message hash was greater or equal to the `secp256k1` curve order `0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`

Here are the 3 vectors:

```rust
(
    hex!("0000000000000000000000000000000000000000000000000000000000000001"), // privateKey
    hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), // msgHash
),
(
    hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"),
    hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
),
(
    hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"),
    hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
)
```

When signing the messages with the corresponding private keys, RustCrypto and eth-keys generated the same signature, while noble-curves generated a different one.

According to the [RFC6979 rational](https://www.rfc-editor.org/rfc/rfc6979#section-3.5),
```
... the truncated H(m) could be externally reduced modulo q,
since that is the first thing that (EC)DSA performs on the hashed
message.  With the definition of bits2octets, deterministic (EC)DSA
can be applied with the same input.
```

This is what noble curves is implementing but this leads to a different signature for the same message hash and private key when the message hash is greater or equal to the curve order breaking the deterministic nature of the signature.

It means either the RFC is not strict enough or there is a misinterpretation of the RFC.
One thing is certain, libraries need to be aware of this issue and implement a fix.

*Note:  
it seems RustCrypto is now doing the reduction before the k generation.
https://github.com/RustCrypto/signatures/blob/8f93676ea0fcefe3787b805a9b35afa722b7a5c6/ecdsa/src/hazmat.rs#L192  
This was introduced by this PR https://github.com/RustCrypto/signatures/pull/793  
This is not release yet at commit 8f93676ea0fcefe3787b805a9b35afa722b7a5c6*

# POC
Scripts were written to compare the generation of K and values that are needed for the signature but also the signatures themselves.
Those scripts showing the difference of signatures between nobles curves and RustCrypto/Eth-key can be replicated by running the following commands:  

Install packages:
* `npm install`
* `cargo install`
* [Install uv](https://docs.astral.sh/uv/getting-started/installation/)

Run tests:
* `cargo run --quiet` for RustCrypto
* `npx ts-node-esm noble-curves.ts` for noble-curves
* `uv run python eth-key-rfc6979.py` for eth-key

Requirements
* `rustc 1.82.0 (f6e511eec 2024-10-15)`
* `Python 3.10.11`
* `node v18.16.1`
* `uv 0.4.7 (a178051e8 2024-09-07)`

Debug:
* in vscode, the `launch.json` file can be used to debug the `noble-curves.ts` showing the reduction of the message hash before the k generation.

To fix the difference you can change the following line [`weierstrass.ts from noble curves`](https://github.com/paulmillr/noble-curves/blob/e0ad0530f64d7cc01514b65d819b7f76db5f0da4/src/abstract/weierstrass.ts#L1052)
```ts
 const seedArgs = [int2octets(d), msgHash]; // <-  msgHash is passed directly now
```