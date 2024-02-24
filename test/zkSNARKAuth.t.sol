// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {zkSNARKAuth} from "../src/zkSNARKAuth.sol";

contract zkSNARKAuthTest is Test {
    zkSNARKAuth public counter;

    function setUp() public {
        counter = new zkSNARKAuth();
        counter.setNumber(0);
    }

    function test_Increment() public {
        counter.increment();
        assertEq(counter.number(), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        counter.setNumber(x);
        assertEq(counter.number(), x);
    }

    function test_verifyTx() public {
        uint[5] memory input = [
            uint256(0x0000000000000000000000000000000000000000000000000000000000000000), 
            uint256(0x00000000000000000000000000000000f5a5fd42d16a20302798ef6ed309979b), 
            uint256(0x0000000000000000000000000000000043003d2320d9f0e8ea9831a92759fb4b), 
            uint256(0x00000000000000000000000000000000f5a5fd42d16a20302798ef6ed309979b), 
            uint256(0x0000000000000000000000000000000043003d2320d9f0e8ea9831a92759fb4b)
        ];
        bool result = counter.verifyTx(
            counter.genProof(
                [0x05e682a2e43ca4f7ae0005e8e651af1eb78f490f299a9e93441721716d38ae54, 0x013ab1100d4a4fdd8a51c8804bfa92dfffbf2be5917b90460492b465c14495b6],
                [
                    [0x302448842f773bf34227aec050f24bf0af68275bedaa080e39796119846ebb14, 0x274d4460c3cae210a22a87d46c0d41378e45eecfc4627829129129a2c0f2b608],
                    [0x087afca1ae107658c474f611963f0cfafa234552dc002289ce2e0c4b0ce62400, 0x2d7c5d4ffa57a3c2866db0ef76bb68824d8b2d63dce69c981f32f833c2e5a4fa]
                ], 
                [0x1fc3b18dbbcdd0c9a8102021b25294c9eb5e54b9c6e33ff17b8814a8696d8b1f, 0x23812e4cc5ce5f9bedd20eb53a56d22d3e53e09e02fb68ae85f67eec79cd77aa]
            ), 
            input
        );
        assertEq(result, true);

        uint[5] memory input1 = [
            uint256(0x0000000000000000000000000000000000000000000000000000000000000001), // k = 0
            // sha256([a, b, c, 0]) =>
            uint256(0x00000000000000000000000000000000f5a5fd42d16a20302798ef6ed309979b), 
            uint256(0x0000000000000000000000000000000043003d2320d9f0e8ea9831a92759fb4b), 
            // sha256([a, b, c, k]) =>
            uint256(0x0000000000000000000000000000000090f4b39548df55ad6187a1d20d731ece), 
            uint256(0x00000000000000000000000000000000e78c545b94afd16f42ef7592d99cd365)
        ];
        bool result1 = counter.verifyTx(
            counter.genProof(
                [0x2ecdbe472de444e24d2aef4afb9c8099004f28738e996415f87312fd99c215cf, 0x26b2d320b05748fefd2bcf72218221ff4e4233e15c0d6208a4152facd1f396ea],
                [
                    [0x24cf678aea96843c165f8f348c0bab2a943f74aaf94ccd9ee13d37756d57466f, 0x106f0eeb7b2bbba436c98655f12f4a4f8fd922aa883c599de1fcb55214597450],
                    [0x09de12facb5609ccc6614d996f4b222fce3f5993a45f9bf13d27a58f8c19855b, 0x0b847aea5f951944ef395964aaf0987642745750ea96a3f01e1ce3bbeb4dcda5]
                ],
                [0x2b01c70e55f19746c17046b187c4689c3c581bfb51e423e55aabde65f1bcd0d8, 0x205f815f185a768421b085620bf1575175520ae3e97f05e52c083dda49fcb6ce]
            ), 
            input1
        );
        assertEq(result1, true);
    }
}
