// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FlopsStructs
 * @notice Data structures for the FLOps protocol
 * @dev These structures enforce deterministic transaction ordering and execution
 */

/**
 * @notice Indicates why a block was marked as broken
 * @param BrokenPrecondition Validation failed in _validatePaymasterUserOp (pre-execution)
 * @param FailedExecution Execution failed in _postOp (post-execution)
 */
enum BlockBrokenReason {
    BrokenPrecondition,
    FailedExecution
}

/**
 * @notice Tracks the state of a block in the FLOps protocol
 * @param broken Whether this block's execution has been violated
 * @param rollingHash The cumulative hash of all user operations in this block
 * @dev Once a block is marked broken, all subsequent operations in that block fail.
 *      The rollingHash is computed as: keccak256(abi.encode(previousHash, userOpHash))
 */
struct BlockState {
    bool broken;
    bytes32 rollingHash;
}

/**
 * @notice Data that bundlers commit to when including a transaction
 * @param blockNumber The block number this operation must execute in (uint64 sufficient until year ~584 billion)
 * @param preTxState The expected rolling hash before this transaction executes
 * @param userOpHash The hash of the user operation being committed to
 * @dev This data is signed by approved bundlers to prove they committed to a specific
 *      transaction order before execution.
 */
struct FlopsData {
    uint64 blockNumber;
    bytes32 preTxState;
    bytes32 userOpHash;
}

/**
 * @notice A bundler's signed commitment to include a transaction
 * @param data The FlopsData being committed to
 * @param signature The bundler's ECDSA signature over the FlopsData
 * @dev The signature is verified using ECDSA.recover and must match an approved bundler.
 *      This commitment proves the bundler knew the transaction order before execution.
 */
struct FlopsCommitment {
    FlopsData data;
    bytes signature;
}
