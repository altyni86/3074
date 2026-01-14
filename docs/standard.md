# Batch Invoker Standard (EIP-3074 Reference)

## Purpose
EIP-3074 introduces two new EVM opcodes, `AUTH` and `AUTHCALL`, that let an Externally Owned Account (EOA) delegate execution rights to a contract for a single, signed intent. This repository demonstrates a minimal standard for authoring and executing those intents via the `Auth` base contract and a concrete `BatchInvoker`. The goal of this document is to describe the data model, execution semantics, and security assumptions required for anyone who wants to interoperate with this standard.

## Components
### `Auth`
`Auth` encapsulates the low-level digest calculation shared by every invoker. It:
- prefixes signatures with a unique `MAGIC` byte to prevent collisions with other signing schemes,
- binds signatures to a specific chain ID and invoker address, and
- (eventually) wraps the `AUTH` and `AUTHCALL` opcodes once Solidity exposes them.

Today `AUTH`/`AUTHCALL` are shimmed with `ecrecover` + `call`. As soon as the upstream compiler supports the new opcodes, the `auth` and `authCall` helpers can be swapped in without changing the higher-level flow.

### `BatchInvoker`
`BatchInvoker` inherits from `Auth` and defines a concrete intent format. Each intent is a `Batch`:

```solidity
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
```

- `nonce` guarantees replay protection on a per-authority basis via the on-chain `nextNonce` mapping.
- `calls` is an ordered list of sub-transactions that must all succeed; if any revert, the entire batch reverts.
- Each `Call` specifies the target, calldata, ETH value, and gas limit for that sub-transaction.

## Commitment and Signature Format
1. Encode the full batch with `abi.encode(batch)`.
2. Hash it to produce the `commit` (`keccak256(abi.encode(batch))`).
3. Ask the invoker for the digest to sign via `invoker.getDigest(batch)`; internally it calls `Auth.getDigest(commit)` which computes `keccak256(MAGIC || chainId || paddedInvokerAddress || commit)`.
4. Sign that digest with the authority's EOA key using standard secp256k1 ECDSA and produce `(v, r, s)`.

This process ensures:
- Signatures are domain-separated by opcode (`MAGIC`), chain, and invoker address.
- Off-chain tools can build the exact digest either by replicating the formula or by calling `getDigest` on-chain/off-chain.

## Execution Semantics
Calling `BatchInvoker.execute(batch, v, r, s)` performs the following steps:
1. Recompute `commit` from the provided batch and recover the `authority` with the signature.
2. Check that `batch.nonce` matches `nextNonce[authority]` and increment the stored nonce.
3. Iterate through each `Call` in order and execute it via `authCall` (currently `call`).
4. Enforce that the invoker does not retain stray ETH (`ExtraValue` error) by ensuring every wei sent to `execute` is forwarded to sub-calls.

### Ordering and Atomicity
- Batches execute strictly in the order their nonces are consumed; there is no parallelism or skipping.
- Within a batch, calls execute in array order. They do **not** pipe return data to subsequent calls; each call starts fresh.
- The whole batch is atomic: any revert bubbles up and reverts every prior sub-call.

### Gas and Sponsorship
- `msg.sender` during each sub-call will be the authority once native `AUTHCALL` is available. Until then it is the invoker contract.
- Anyone can submit the transaction and pay gas on behalf of the authority, enabling native sponsorship. ETH needed for individual calls should be supplied as `msg.value` to `execute`.

## Integrating the Standard
1. **Compose the batch** – Decide the ordered list of actions, set the expected nonce, and include enough `value` for each call.
2. **Commit and sign** – Either call `getDigest(batch)` or reimplement the digest formula. Sign the digest off-chain with the authority’s private key.
3. **Submit for execution** – Relay the batch, signature, and any ETH top-up to `BatchInvoker.execute` on-chain.
4. **Handle receipts** – Because batches are atomic, a successful transaction implies every call succeeded. Inspect event logs from individual contracts for granular status.

Client libraries should treat `Batch` as a typed data structure and surface helper utilities for:
- computing the expected nonce (`nextNonce(authority)`),
- packing calldata for each `Call`,
- simulating execution via `eth_call` against a fork that supports EIP-3074, and
- surfacing revert data for failed batches.

## Security Considerations
- **Invoker logic is the trust anchor.** Once an authority signs a digest, the invoker can perform any action allowed by the encoded batch. Review invoker code as carefully as you would a wallet contract.
- **Never reuse commits.** Because commits hash the entire batch, any mutation requires a fresh signature. Reusing the same `commit` with an altered batch invalidates the signature anyway, but tooling should treat commits as single-use.
- **Nonce discipline.** If a batch is dropped from the mempool, the nonce is still considered pending. Tooling should allow resubmission of the exact same batch or provide a cancellation flow that issues a benign replacement batch.
- **Value forwarding.** The `ExtraValue` check enforces that the invoker cannot retain ETH, but sub-calls can still transfer ETH to arbitrary destinations. Include guard rails in the `commit` (e.g., hash of the expected recipients) if that matters for your use case.
- **AUTH/AUTHCALL availability.** Until the opcodes are live in the EVM and surfaced in Solidity, the shimmed implementation will call downstream contracts as the invoker, not the authority. Design downstream contracts accordingly during this transition phase.

## Testing and Tooling
- Run `forge test` to execute the Foundry test suite, which validates nonce handling, value accounting, and basic execution flows.
- Extend `test/BatchInvoker.t.sol` with additional scenarios (e.g., multi-call batches, failure cases) to document expected behavior.
- When a 3074-enabled client is available, craft integration tests that fork that chain to ensure `AUTH`/`AUTHCALL` semantics match expectations.

## Future Extensions
- Add richer commit schemas (e.g., deadlines, chain of trust metadata, session keys).
- Support dynamic gas budgeting per call to better emulate EOA transactions.
- Consider emitting detailed events per sub-call for easier indexing.
- Build relayer APIs that accept signed batches and enforce policies (KYB, rate limits, fee collection) before forwarding them on-chain.
