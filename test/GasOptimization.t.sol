// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {BatchInvoker} from "../src/BatchInvoker.sol";
import {ECDSA} from "openzeppelin-contracts/utils/cryptography/ECDSA.sol";

contract GasOptimizationTest is Test {
    BatchInvoker public batchInvoker;

    // Test accounts
    address internal alice;
    uint256 internal alicePrivKey;

    function setUp() public {
        batchInvoker = new BatchInvoker();

        // Setup a test account
        (alice, alicePrivKey) = makeAddrAndKey("alice");
    }

    // Gas test for getDigest function
    function testGasGetDigest() public {
        // Prepare a sample batch
        BatchInvoker.Call[] memory calls = new BatchInvoker.Call[](1);
        calls[0] = BatchInvoker.Call({
            to: address(0x1234),
            data: abi.encodeWithSignature("transfer(address,uint256)", address(0x5678), 100),
            value: 0,
            gasLimit: 100000
        });

        BatchInvoker.Batch memory batch = BatchInvoker.Batch({
            nonce: 0,
            calls: calls
        });

        // Measure gas for getDigest
        uint256 gasStart = gasleft();
        batchInvoker.getDigest(batch);
        uint256 gasEnd = gasleft();

        console2.log("Gas used for getDigest:", gasStart - gasEnd);
    }

    // Gas test for getCommit function
    function testGasGetCommit() public {
        // Prepare a sample batch
        BatchInvoker.Call[] memory calls = new BatchInvoker.Call[](1);
        calls[0] = BatchInvoker.Call({
            to: address(0x1234),
            data: abi.encodeWithSignature("transfer(address,uint256)", address(0x5678), 100),
            value: 0,
            gasLimit: 100000
        });

        BatchInvoker.Batch memory batch = BatchInvoker.Batch({
            nonce: 0,
            calls: calls
        });

        // Measure gas for getCommit
        uint256 gasStart = gasleft();
        batchInvoker.getCommit(batch);
        uint256 gasEnd = gasleft();

        console2.log("Gas used for getCommit:", gasStart - gasEnd);
    }

    // Gas test for execute function
    function testGasExecute() public {
        // Prepare a sample batch
        BatchInvoker.Call[] memory calls = new BatchInvoker.Call[](2);

        // First call: transfer to an address
        calls[0] = BatchInvoker.Call({
            to: address(0x1234),
            data: abi.encodeWithSignature("transfer(address,uint256)", address(0x5678), 100),
            value: 0,
            gasLimit: 100000
        });

        // Second call: another transfer
        calls[1] = BatchInvoker.Call({
            to: address(0x5678),
            data: abi.encodeWithSignature("transfer(address,uint256)", address(0x9abc), 50),
            value: 0,
            gasLimit: 100000
        });

        BatchInvoker.Batch memory batch = BatchInvoker.Batch({
            nonce: 0,
            calls: calls
        });

        // Prepare signature
        bytes32 digest = batchInvoker.getDigest(batch);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivKey, digest);

        // Measure gas for execute
        uint256 gasStart = gasleft();
        batchInvoker.execute(batch, v, r, s);
        uint256 gasEnd = gasleft();

        console2.log("Gas used for execute (2 calls):", gasStart - gasEnd);
    }

    // Gas test for execute with multiple calls
    function testGasExecuteMultipleCalls() public {
        // Prepare a batch with multiple calls
        BatchInvoker.Call[] memory calls = new BatchInvoker.Call[](5);

        for (uint256 i = 0; i < 5; i++) {
            calls[i] = BatchInvoker.Call({
                to: address(uint160(0x1234 + i)),
                data: abi.encodeWithSignature("transfer(address,uint256)", address(uint160(0x5678 + i)), 100),
                value: 0,
                gasLimit: 100000
            });
        }

        BatchInvoker.Batch memory batch = BatchInvoker.Batch({
            nonce: 0,
            calls: calls
        });

        // Prepare signature
        bytes32 digest = batchInvoker.getDigest(batch);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivKey, digest);

        // Measure gas for execute with multiple calls
        uint256 gasStart = gasleft();
        batchInvoker.execute(batch, v, r, s);
        uint256 gasEnd = gasleft();

        console2.log("Gas used for execute (5 calls):", gasStart - gasEnd);
    }
}