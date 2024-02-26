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
        uint[6] memory input = [
            uint256(0x0000000000000000000000000000000000000000000000000000000000000001), 
            uint256(0x00000000000000000000000000000000533e529f40aa846310b199046570b3e2), 
            uint256(0x000000000000000000000000000000000f8c57f97ab03d5679cb585948199438), 
            uint256(0x00000000000000000000000000000000e70564494d60fd31c2b2a9267daf5259), 
            uint256(0x000000000000000000000000000000004bc5cdfbdca3ca0e7fe836b6ff50eff7),
            uint256(0x0000000000000000000000000000000000000000000000000000000000000001)
        ];
        bool result = counter.verifyTx(
            counter.genProof(
                [0x22cd8ba9bcf38b389be1eb82cabd894003bd2a90450360cdf5a04d69e7cc8862, 0x02b481945ffba8823021f4813535e43afff6b14dcc8d8aa002ecc09295fe1941],
                [
                    [0x269ed941e3138583283d12d06614c620003d3d3c8ee06239463acc50d4b50d7f, 0x1c29f62e866a59925c3c37b13b407915d5d476f60b5fb587546ccbcade859852],
                    [0x1505f52abdffcf9e62cc5437a0f310ae7f2c11f8b0c6d5b431ffbfc1e913e0ff, 0x0f632ce769790f183a95fcfdcd58ceb6aa488bcf5b53a8a402dac3f10c5f8933]
                ], 
                [0x23efcd33badd89d5dfa0fcb6586e75f5dbc44b1c72d55ea60b7bc7a5cdfbaa4f, 0x0c9f700a3e4ac7ad41d0c3bf14133a35c68a5742e3b41cc9618fdccbdc601217]
            ), 
            input
        );
        assertEq(result, true);
    }
}
