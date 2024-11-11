"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var hmac_1 = require("@noble/hashes/hmac");
var sha256_1 = require("@noble/hashes/sha256");
var utils_1 = require("@noble/curves/abstract/utils");
var utils_2 = require("@noble/curves/abstract/utils");
var secp256k1_1 = require("@noble/curves/secp256k1");
var modular_1 = require("@noble/curves/abstract/modular");
var Point = secp256k1_1.secp256k1.ProjectivePoint, CURVE = secp256k1_1.secp256k1.CURVE;
// Rest of the implementation remains the same
var drbg = (0, utils_2.createHmacDrbg)(32, 32, function (key) {
    var messages = [];
    for (var _i = 1; _i < arguments.length; _i++) {
        messages[_i - 1] = arguments[_i];
    }
    return (0, hmac_1.hmac)(sha256_1.sha256, key, utils_1.concatBytes.apply(void 0, messages));
});
var test_vectors = [
    {
        privateKey: new Uint8Array(Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex")),
        message: new Uint8Array(Buffer.from("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "hex")),
    },
    {
        privateKey: new Uint8Array(Buffer.from("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "hex")),
        message: new Uint8Array(Buffer.from("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "hex")),
    },
    {
        privateKey: new Uint8Array(Buffer.from("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "hex")),
        message: new Uint8Array(Buffer.from("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "hex")),
    },
];
for (var _i = 0, test_vectors_1 = test_vectors; _i < test_vectors_1.length; _i++) {
    var test = test_vectors_1[_i];
    console.log("\nTest vector:", test);
    var k = drbg((0, utils_1.concatBytes)(test.privateKey, test.message), function (bytes) {
        var num = (0, utils_1.bytesToNumberBE)(bytes);
        if (num <= 0n || num >= CURVE.n)
            return;
        return num;
    });
    console.log('k:', k.toString(16));
    var kInv = (0, modular_1.invert)(k, CURVE.n);
    console.log('k_inv:', kInv.toString(16));
    var R = Point.BASE.multiply(k);
    console.log('Rx:', R.toAffine().x.toString(16));
    var signature = secp256k1_1.secp256k1.sign(test.message, test.privateKey);
    console.log('r:', signature.r.toString(16));
    console.log('s:', signature.s.toString(16));
}
