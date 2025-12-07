pragma solidity ^0.8.13;

import {Auth} from "./Auth.sol";

contract BatchInvoker is Auth {
    struct Batch {
        uint256 nonce;
        Call[] calls;
    }

    struct Call {
        address to;
        bytes data;
        uint256 value;
        uint256 gasLimit;
    }

    mapping(address => uint256) public nextNonce;

    error InvalidNonce(address authority, uint256 expected, uint256 attempted);
    error ExtraValue();
    error InvalidSignature();

    function getDigest(Batch calldata batch) external view returns (bytes32 digest) {
        digest = getDigest(getCommit(batch));
    }

    function getCommit(Batch calldata batch) public pure returns (bytes32 commit) {
        commit = keccak256(abi.encode(batch));
    }

    function execute(Batch calldata batch, uint8 v, bytes32 r, bytes32 s) public payable {
        uint256 startingBalance = address(this).balance - msg.value;
        address authority = auth(getCommit(batch), v, r, s);
        if (authority == address(0)) revert InvalidSignature();
        uint256 expectedNonce = nextNonce[authority]++;
        if (expectedNonce != batch.nonce) revert InvalidNonce(authority, expectedNonce, batch.nonce);
        for (uint256 i; i < batch.calls.length; i++) {
            exec(batch.calls[i]);
        }
        if (address(this).balance != startingBalance) revert ExtraValue();
    }

    function exec(Call memory call) internal {
        authCall(call.to, call.data, call.value, call.gasLimit);
    }
}
