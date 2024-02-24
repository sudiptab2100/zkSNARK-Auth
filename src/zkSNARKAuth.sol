// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./verifier.sol";

contract zkSNARKAuth is Verifier {
    uint256 public number;

    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }

    function increment() public {
        number++;
    }

    function genProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c
    ) public pure returns (Proof memory) {
        Pairing.G1Point memory A = Pairing.G1Point(a[0], a[1]);
        Pairing.G2Point memory B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        Pairing.G1Point memory C = Pairing.G1Point(c[0], c[1]);
        return Proof(A, B, C);
    }
}
