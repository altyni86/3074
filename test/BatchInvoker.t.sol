// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {BatchInvoker} from "../src/BatchInvoker.sol";
import {Auth} from "../src/Auth.sol";

contract Callee {
    error UnexpectedSender(address expected, address actual);

    function expectSender(address expected) public payable {
        if (msg.sender != expected) revert UnexpectedSender(expected, msg.sender);
    }
}

contract BatchInvokerTest is Test {
    Callee public callee;
    BatchInvoker public invoker;
    BatchInvoker.Batch public batch;
    address public authority;
    uint256 public authorityKey = 1234;

    function setUp() public {
        invoker = new BatchInvoker();
        callee = new Callee();
        authority = vm.addr(authorityKey);
        vm.label(address(invoker), "invoker");
        vm.label(address(callee), "callee");
        vm.label(authority, "authority");
    }

    // TODO: update test so that expectedSender is authority, NOT address(invoker), once Auth contract is fully implemented
    // for now, the Invoker is calling the Callee with CALL (so msg.sender = Invoker)
    // later, the Invoker SHOULD calls the Callee with AUTHCALL (so msg.sender = authority)
    function constructAndSignBatch(uint256 nonce, uint256 value) internal returns (uint8 v, bytes32 r, bytes32 s) {
        batch.nonce = nonce;
        batch.calls.push(
            BatchInvoker.Call({
                to: address(callee),
                data: abi.encodeWithSelector(Callee.expectSender.selector, address(invoker)),
                value: value,
                gasLimit: 10_000
            })
        );
        // construct batch digest & sign
        bytes32 digest = invoker.getDigest(batch);
        (v, r, s) = vm.sign(authorityKey, digest);
    }

    function test_authCall() public {
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatch(0, 0);
        // this will call Callee.expectSender(authority)
        invoker.execute(batch, v, r, s);
    }

    // invalid nonce fails
    function test_invalidNonce() public {
        // 1 is invalid starting nonce
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatch(1, 0);
        vm.expectRevert(abi.encodeWithSelector(BatchInvoker.InvalidNonce.selector, authority, 0, 1));
        invoker.execute(batch, v, r, s);
    }

    function test_authCallWithValue() public {
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatch(0, 1 ether);
        // this will call Callee.expectSender(authority)
        invoker.execute{value: 1 ether}(batch, v, r, s);
    }

    // fails if too little value to pass to sub-call
    function test_tooLittleValue() public {
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatch(0, 1 ether);
        vm.expectRevert();
        invoker.execute{value: 0.5 ether}(batch, v, r, s);
    }

    // fails if too much value to pass to sub-call
    function test_tooMuchValue() public {
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatch(0, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(BatchInvoker.ExtraValue.selector));
        invoker.execute{value: 2 ether}(batch, v, r, s);
    }

    // test that invalid signature is rejected (zero address recovery)
    function test_invalidSignature() public {
        batch.nonce = 0;
        batch.calls.push(
            BatchInvoker.Call({
                to: address(callee),
                data: abi.encodeWithSelector(Callee.expectSender.selector, address(invoker)),
                value: 0,
                gasLimit: 10_000
            })
        );
        // use invalid signature values that will cause ecrecover to return address(0)
        uint8 v = 27;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);
        vm.expectRevert(Auth.InvalidSignature.selector);
        invoker.execute(batch, v, r, s);
    }

    // test that malleable signatures (high-s) are rejected
    function test_malleableSignature() public {
        batch.nonce = 0;
        batch.calls.push(
            BatchInvoker.Call({
                to: address(callee),
                data: abi.encodeWithSelector(Callee.expectSender.selector, address(invoker)),
                value: 0,
                gasLimit: 10_000
            })
        );
        bytes32 digest = invoker.getDigest(batch);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorityKey, digest);

        // secp256k1 curve order
        uint256 SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        // flip s to create a malleable signature (s' = n - s)
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));
        // flip v to maintain valid signature
        uint8 flippedV = v == 27 ? 28 : 27;

        vm.expectRevert(Auth.InvalidSignature.selector);
        invoker.execute(batch, flippedV, r, highS);
    }

    // TODO: test that auth returns authority address
}
