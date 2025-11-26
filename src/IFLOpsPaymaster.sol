// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {FlopsData} from "./FlopsStructs.sol";

/**
 * @title IFlopsPaymaster
 * @notice Interface for the FLOps paymaster contract
 * @dev Defines the public API for interacting with FLOps protocol enforcement
 */
interface IFlopsPaymaster {
    // ============ View Functions ============

    /**
     * @notice Checks if the current block is broken
     * @return True if current block's execution is broken
     */
    function blockBroken() external view returns (bool);

    /**
     * @notice Checks if a specific block is broken
     * @param blockNumber The block number to check
     * @return True if the specified block's execution is broken
     */
    function blockBroken(uint64 blockNumber) external view returns (bool);

    /**
     * @notice Returns the factory address
     * @return The FlopsAccountFactory address
     */
    function factory() external view returns (address);

    /**
     * @notice Computes what the rolling hash would be after including a user operation
     * @param userOp The user operation to simulate including
     * @return The next rolling hash value
     */
    function nextRollingHash(PackedUserOperation calldata userOp) external view returns (bytes32);

    /**
     * @notice Verifies that a user operation has a valid bundler signature
     * @param userOp The user operation to verify
     * @return True if signature is valid and from an approved bundler
     */
    function verifyBundlerSignature(PackedUserOperation calldata userOp) external view returns (bool);

    /**
     * @notice Computes the hash that bundlers must sign to commit to a transaction
     * @param data The FlopsData containing block number, pre-tx state, and userOpHash
     * @return The EIP-191 signed message hash
     */
    function computeBundlerCommitHash(FlopsData memory data) external pure returns (bytes32);

    // ============ Owner Functions ============

    /**
     * @notice Sets the FlopsAccountFactory reference
     * @param factory_ The factory contract address
     */
    function setFactory(address factory_) external;

    /**
     * @notice Approves a new bundler
     * @param bundler The bundler address to approve
     */
    function approveBundler(address bundler) external;

    /**
     * @notice Revokes a bundler's approval
     * @param bundler The bundler address to revoke
     */
    function revokeBundler(address bundler) external;
}
