// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x2ace7a97c8815e0d02885ab91bdd4ff0a2c6c3d51ae7581042a225bcb6d2a992), uint256(0x10427a58a62fcf35dc1a11edcb42fc8d87a72c7f05bfdfb6a829efb5c0a61ade));
        vk.beta = Pairing.G2Point([uint256(0x2195742b49e2fdc33cf49b37ad9b73bc1aa5254a8e78e4445a634319901bfb0c), uint256(0x0cec1476215b83e8313fc7f0d77ac42b4558767dca93b735cc54cf8b0d12f080)], [uint256(0x229e738fb8d7dc0842403f0afa94e430a52775958dd4e0cff3dddf3b8bf23168), uint256(0x10462fd2686b645afc70dd00baec97e18f48d81eba3db12d48ea37d696007d7c)]);
        vk.gamma = Pairing.G2Point([uint256(0x2888caa25e85a8ac0c56be2b65c7450f55e0483a55ba29df1dd1ef5a65632068), uint256(0x184f092eb3ea7b7dabc2e0f9e09fbe4b245019eca9aa6a244ebd90efa129bcfa)], [uint256(0x1095b81e7f521db2c684ccbe5283fbddc27ec37c906bf51d9577bba56e881bfd), uint256(0x18806ac2a6483398a4d6d0b9add01ef13e715d4185aa9b5fe382de360e4f6b50)]);
        vk.delta = Pairing.G2Point([uint256(0x01a6c37b929ba80bef9f721154b6bd88c5a01416090a631e783eee0963a0e843), uint256(0x1fa9a8129e5c80d25ec5c3853f59c08e06693b10dd29f53b56faf2a0b4d6ec19)], [uint256(0x0134857ef3186e85282d1fce80518bc80eba2ebdbeefb4e37d90867160fb8f22), uint256(0x16ca08ddf6bcb5e075d702189ead026ffe25d4c54917328c92bb9b6fc1bbdbb9)]);
        vk.gamma_abc = new Pairing.G1Point[](7);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x01cf4ba9bf55d5ec8f63555d0b1dc21f822e659d60699462a7a2a4c5a3ea1b75), uint256(0x0f18b1efc64f6252664048b171142af94a85cc6422039ea3eb254c89462a2e37));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0e54e633ea4fd26769b0dcd79b2e82bdf6646305536c94eff40579542caa2978), uint256(0x069ba39e832185413a36fe1d3a3ef447cc478f087e46756a7e51adf569ff0f56));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2fb214500cb6a7fb7038f28a10d36803f6ca6f98a2483c2a6fc61f8f6a9bb2e7), uint256(0x272ffbfb4a10dcd9898d10ab8cf49f4ffd1ee5631ebda8f86989aca1c0e1bc1d));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x211d7ff1671703ed796cb7b8c2b5b72fb7d8c0834b2cd978299ced0bcad71371), uint256(0x23d9b67ad2a8042b227f05d71d99791a7787c42a108ef67929d1f07951ee3cad));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x04098f1ea36f1d491a0698a6f8077d78befc8e8fbcf012375cf8f6e1c00ea9cd), uint256(0x03eb7df2da5971d5bfe3f4d4ac814856d33651bf160150c264e37a35424ce702));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x27886c37882976f2ef4db35882870fcfc73d0881641355fc74401e92880ca9f8), uint256(0x1284d574c59d27a16f9140bc8514f86621e5164923bba7d0fd6474a71e4d9861));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x216d0495e352b4be4c32f70a194fd7d6eb1af6de0ef1fa0eaf08992e15e15585), uint256(0x13d7246d711c1e75bc5898d0ee03828854781a90f830aad1db65c8c5c753acd5));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[6] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](6);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
