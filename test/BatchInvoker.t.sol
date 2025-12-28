// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {BatchInvoker} from "../src/BatchInvoker.sol";
import {Auth} from "../src/Auth.sol";

contract Callee {
    error UnexpectedSender(address expected, address actual);

    uint256 public counter;

    function expectSender(address expected) public payable {
        if (msg.sender != expected) revert UnexpectedSender(expected, msg.sender);
    }

    function increment() external {
        counter++;
    }

    function incrementAndRevert() external {
        counter++;
        revert("intentional revert");
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
        return constructAndSignBatchWithDeadline(nonce, value, 0);
    }

    function constructAndSignBatchWithDeadline(uint256 nonce, uint256 value, uint256 deadline) internal returns (uint8 v, bytes32 r, bytes32 s) {
        batch.nonce = nonce;
        batch.deadline = deadline;
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

    // test that auth correctly recovers and returns authority address
    function test_authReturnsAuthority() public {
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatch(0, 0);
        // execute should succeed, meaning auth recovered the correct authority
        invoker.execute(batch, v, r, s);
        // nonce should have incremented for the authority
        assertEq(invoker.nextNonce(authority), 1);
    }

    // test that invalid signature (zero address) reverts
    function test_invalidSignature() public {
        batch.nonce = 0;
        batch.deadline = 0;
        batch.calls.push(
            BatchInvoker.Call({
                to: address(callee),
                data: abi.encodeWithSelector(Callee.expectSender.selector, address(invoker)),
                value: 0,
                gasLimit: 10_000
            })
        );
        // use invalid signature values that result in zero address
        vm.expectRevert(Auth.InvalidSignature.selector);
        invoker.execute(batch, 27, bytes32(0), bytes32(0));
    }

    // test batch with deadline that hasn't passed
    function test_batchWithValidDeadline() public {
        uint256 futureDeadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatchWithDeadline(0, 0, futureDeadline);
        invoker.execute(batch, v, r, s);
    }

    // test batch with expired deadline fails
    function test_expiredBatch() public {
        // set a meaningful timestamp first (default is 1, and 1-1=0 means no expiration)
        uint256 currentTime = 1000000;
        vm.warp(currentTime);
        uint256 pastDeadline = currentTime - 1;
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatchWithDeadline(0, 0, pastDeadline);
        vm.expectRevert(abi.encodeWithSelector(BatchInvoker.BatchExpired.selector, pastDeadline, currentTime));
        invoker.execute(batch, v, r, s);
    }

    // test that deadline of 0 means no expiration
    function test_noExpirationWithZeroDeadline() public {
        // warp far into the future
        vm.warp(block.timestamp + 365 days);
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatchWithDeadline(0, 0, 0);
        // should still execute because deadline=0 means no expiration
        invoker.execute(batch, v, r, s);
    }

    // test multiple calls in a single batch
    function test_multipleCallsInBatch() public {
        batch.nonce = 0;
        batch.deadline = 0;
        // add 3 increment calls
        for (uint256 i = 0; i < 3; i++) {
            batch.calls.push(
                BatchInvoker.Call({
                    to: address(callee),
                    data: abi.encodeWithSelector(Callee.increment.selector),
                    value: 0,
                    gasLimit: 50_000
                })
            );
        }
        bytes32 digest = invoker.getDigest(batch);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorityKey, digest);

        assertEq(callee.counter(), 0);
        invoker.execute(batch, v, r, s);
        assertEq(callee.counter(), 3);
    }

    // test atomicity - if one call fails, entire batch reverts
    function test_atomicity() public {
        batch.nonce = 0;
        batch.deadline = 0;
        // first call increments counter
        batch.calls.push(
            BatchInvoker.Call({
                to: address(callee),
                data: abi.encodeWithSelector(Callee.increment.selector),
                value: 0,
                gasLimit: 50_000
            })
        );
        // second call will revert
        batch.calls.push(
            BatchInvoker.Call({
                to: address(callee),
                data: abi.encodeWithSelector(Callee.incrementAndRevert.selector),
                value: 0,
                gasLimit: 50_000
            })
        );
        bytes32 digest = invoker.getDigest(batch);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorityKey, digest);

        assertEq(callee.counter(), 0);
        vm.expectRevert("intentional revert");
        invoker.execute(batch, v, r, s);
        // counter should still be 0 because entire batch reverted
        assertEq(callee.counter(), 0);
    }

    // test BatchExecuted event is emitted
    function test_batchExecutedEvent() public {
        (uint8 v, bytes32 r, bytes32 s) = constructAndSignBatch(0, 0);

        vm.expectEmit(true, true, false, true);
        emit BatchInvoker.BatchExecuted(authority, 0, 1);

        invoker.execute(batch, v, r, s);
    }

    // test sequential batch execution
    function test_sequentialBatches() public {
        // execute first batch
        (uint8 v1, bytes32 r1, bytes32 s1) = constructAndSignBatch(0, 0);
        invoker.execute(batch, v1, r1, s1);
        assertEq(invoker.nextNonce(authority), 1);

        // reset batch for second execution
        delete batch;

        // execute second batch
        (uint8 v2, bytes32 r2, bytes32 s2) = constructAndSignBatch(1, 0);
        invoker.execute(batch, v2, r2, s2);
        assertEq(invoker.nextNonce(authority), 2);
    }
}
