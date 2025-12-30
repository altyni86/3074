// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Auth} from "./Auth.sol";

/// @title BatchInvoker
/// @notice Example EIP-3074 Invoker contract which executes a batch of calls using AUTH and AUTHCALL.
/// @dev batches are executed in sequence based on their nonce;
///      each calls within the batch is executed in sequence based on the order it is included in the array;
///      calls are executed non-interactively (return data from one call is not passed into the next);
///      batches are executed atomically (if one sub-call reverts, the whole batch reverts)
/// @dev BatchInvoker enables multi-transaction flows for EOAs,
///      such as performing an ERC-20 approve & transfer with just one signature.
///      It also natively enables gas sponsored transactions.
contract BatchInvoker is Auth {
    /// @notice a Batch is an array of calls which will be executed behalf of an authority.
    /// @dev authority signs a commitment to the Batch, enabling it to be executed by the BatchInvoker using AUTHCALL
    struct Batch {
        uint256 nonce;
        Call[] calls;
    }

    /// @notice a Call contains transaction execution information for a single sub-call within a Batch.
    /// @dev The fields are relatively self-explanatory:
    ///      - to - the address to call.
    ///      - data - the encoded calldata passed to the call.
    ///      - value - the ether value forwarded to the call.
    ///      - gasLimit - the gas limit set for the call.
    struct Call {
        address to;
        bytes data;
        uint256 value;
        uint256 gasLimit;
    }

    /// @notice authority => next valid nonce
    mapping(address => uint256) public nextNonce;

    /// @notice thrown when a Batch is executed with an invalid nonce
    /// @param authority - the signing authority
    /// @param expected - the expected, valid nonce
    /// @param attempted - the attempted, invalid nonce
    error InvalidNonce(address authority, uint256 expected, uint256 attempted);

    /// @notice thrown when a Batch is executed with a larger `msg.value` than the sum of each sub-call's `value`
    error ExtraValue();

    /// @notice Produce a signable digest that empowers the BatchInvoker to execute the Batch
    /// @param batch - the Batch of Calls that the authority wishes to be executed on their behalf
    /// @return digest - the payload that the authority should sign in order to empower this BatchInvoker to execute the Batch using AUTHCALL
    /// @dev Gas Optimization: View function with minimal computational overhead
    ///      - Uses calldata for efficient parameter passing
    ///      - Reuses getCommit() to avoid duplicate encoding logic
    ///      - Minimal storage reads, reducing gas costs
    function getDigest(Batch calldata batch) external view returns (bytes32 digest) {
        digest = getDigest(getCommit(batch));
    }

    /// @notice Produce a hashed commitment to a Batch to be executed using AUTHCALL
    /// @param batch - the Batch of Calls that the authority wishes to be executed on their behalf
    /// @return commit - the hashed commitment to the encoded Batch
    /// @dev Gas Optimization Strategies:
    ///      - Pure function minimizes gas costs by avoiding state reads
    ///      - Uses abi.encode() for efficient, compact batch representation
    ///      - Single keccak256 hash reduces computational overhead
    ///      - Calldata parameter prevents unnecessary memory allocation
    function getCommit(Batch calldata batch) public pure returns (bytes32 commit) {
        commit = keccak256(abi.encode(batch));
    }

    /// @notice Execute a Batch of Calls on behalf of a signing authority using AUTH and AUTHCALL
    /// @param batch - the Batch of Calls that the authority wishes to be executed on their behalf
    /// @param v - v component of the ECDSA signature
    /// @param r - r component of the ECDSA signature
    /// @param s - s component of the ECDSA signature
    /// @dev Gas Optimization Techniques:
    ///      - Increments nonce in a single operation (nextNonce[authority]++)
    ///      - Uses a single for-loop to minimize function call overhead
    ///      - Checks and effects are performed before external calls
    ///      - Passes gasLimit to each sub-call to prevent potential out-of-gas scenarios
    ///      - Ensures no extra value is left in the contract, preventing unnecessary gas consumption
    ///
    /// Gas Considerations:
    ///      - Each sub-call has an individual gas limit to prevent single call consuming entire transaction gas
    ///      - Atomic execution ensures all-or-nothing behavior, reducing partial execution risks
    ///      - Nonce validation prevents replay attacks with minimal additional gas cost
    function execute(Batch calldata batch, uint8 v, bytes32 r, bytes32 s) public payable {
        // AUTH this contract to execute the Batch on behalf of the authority
        address authority = auth(getCommit(batch), v, r, s);
        // validate the nonce & increment
        uint256 expectedNonce = nextNonce[authority]++;
        if (expectedNonce != batch.nonce) revert InvalidNonce(authority, expectedNonce, batch.nonce);
        // AUTHCALL each call in the batch
        for (uint256 i; i < batch.calls.length; i++) {
            exec(batch.calls[i]);
        }
        // ensure that all value passed to the transaction was passed on to sub-calls (no leftover value in BatchInvoker contract)
        if (address(this).balance != 0) revert ExtraValue();
    }

    /// @notice Execute a single Call using AUTHCALL. Reverts if the call fails.
    /// @dev Gas Optimization:
    ///      - Directly passes call parameters to authCall
    ///      - Uses memory parameter for efficient call data handling
    ///      - Minimal function overhead by using a single authCall
    function exec(Call memory call) internal {
        authCall(call.to, call.data, call.value, call.gasLimit);
    }
}
