// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

abstract contract Auth is ReentrancyGuard {
    /// @notice magic byte to disambiguate EIP-3074 signature payloads
    uint8 constant MAGIC = 0x04;

    /// Events for critical operations
    event AuthDigestGenerated(bytes32 indexed digest, bytes32 indexed commit);
    event AuthenticationPerformed(address indexed authority, bytes32 indexed commit);
    event AuthCallExecuted(address indexed to, uint256 value, bool success);

    /// @notice produce a digest for the authorizer to sign
    /// @param commit - any 32-byte value used to commit to transaction validity conditions
    /// @return digest - sign the `digest` to authorize the invoker to execute the `calls`
    function getDigest(bytes32 commit) public view returns (bytes32 digest) {
        // Validate input commit
        require(commit != bytes32(0), "Invalid commit");

        // address(this) is the contract that will execute the AUTH. cast it to left-padded 32 bytes.
        bytes32 paddedInvokerAddress = bytes32(uint256(uint160(address(this))));
        digest = keccak256(abi.encodePacked(MAGIC, bytes32(block.chainid), paddedInvokerAddress, commit));

        emit AuthDigestGenerated(digest, commit);
    }

    /// @notice call AUTH opcode with a given a commitment + signature
    /// @param commit - any 32-byte value used to commit to transaction validity conditions
    /// @dev (v, r, s) are interpreted as an ECDSA signature on the secp256k1 curve over getDigest(commit)
    /// @return authority - the signer of the digest recovered from the signature
    function auth(bytes32 commit, uint8 v, bytes32 r, bytes32 s) internal view returns (address authority) {
        bytes32 digest = getDigest(commit);

        // Derive authority from the signature + digest
        authority = ecrecover(digest, v, r, s);

        // Validate recovered address is not zero
        require(authority != address(0), "Invalid signature");

        emit AuthenticationPerformed(authority, commit);
    }

    /// @notice call AUTHCALL opcode with given call instructions
    /// @dev MUST call AUTH before attempting to AUTHCALL
    /// @dev Uses ReentrancyGuard to prevent reentrancy
    function authCall(
        address to,
        bytes memory data,
        uint256 value,
        uint256 gasLimit
    ) internal nonReentrant {
        // Input validation
        require(to != address(0), "Invalid recipient address");
        require(data.length > 0, "Empty call data");
        require(gasLimit > 0, "Invalid gas limit");

        (bool success, bytes memory returnData) = to.call{value: value, gas: gasLimit}(data);

        emit AuthCallExecuted(to, value, success);

        // Revert with original error if call fails
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returnDataSize := mload(returnData)
                    revert(add(returnData, 0x20), returnDataSize)
                }
            } else {
                revert("AuthCall failed");
            }
        }
    }
}