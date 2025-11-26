// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IBundlerManager
 * @notice Interface for managing approved bundlers in the FLOps protocol
 * @dev Defines the public API for bundler approval and validation
 */
interface IBundlerManager {
    // ============ Custom Errors ============

    /// @notice Thrown when a zero address is provided where not allowed
    error ZeroAddress();

    /// @notice Thrown when bundler array is empty during construction
    error EmptyBundlerArray();

    // ============ Events ============

    /// @notice Emitted when a bundler is approved
    /// @param bundler The address of the approved bundler
    event BundlerApproved(address indexed bundler);

    /// @notice Emitted when a bundler is revoked
    /// @param bundler The address of the revoked bundler
    event BundlerRevoked(address indexed bundler);

    // ============ View Functions ============

    /**
     * @notice Checks if an address is an approved bundler
     * @param bundler The address to check
     * @return True if the address is an approved bundler
     */
    function isApprovedBundler(address bundler) external view returns (bool);

    // ============ Owner Functions ============

    /**
     * @notice Approves a new bundler
     * @param bundler The bundler address to approve
     * @dev Only callable by the owner
     */
    function approveBundler(address bundler) external;

    /**
     * @notice Revokes a bundler's approval
     * @param bundler The bundler address to revoke
     * @dev Only callable by the owner
     */
    function revokeBundler(address bundler) external;
}

