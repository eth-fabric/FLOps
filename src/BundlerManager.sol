// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import {IBundlerManager} from "./IBundlerManager.sol";

/**
 * @title BundlerManager
 * @notice Manages approved bundlers for the FLOps protocol
 * @dev Maintains a registry of approved bundlers that can sign FLOps commitments
 */
contract BundlerManager is Ownable, IBundlerManager {
    // ============ State Variables ============

    /// @notice Mapping of approved bundler addresses
    mapping(address => bool) private _approvedBundlers;

    // ============ Constructor ============

    /**
     * @notice Constructs the BundlerManager
     * @param _owner The owner address for this contract
     * @param bundlers Array of approved bundler addresses
     * @dev Validates and approves initial bundlers
     */
    constructor(address _owner, address[] memory bundlers) Ownable(_owner) {
        if (_owner == address(0)) revert ZeroAddress();
        if (bundlers.length == 0) revert EmptyBundlerArray();

        for (uint256 i = 0; i < bundlers.length; i++) {
            if (bundlers[i] == address(0)) revert ZeroAddress();
            _approvedBundlers[bundlers[i]] = true;
            emit BundlerApproved(bundlers[i]);
        }
    }

    // ============ View Functions ============

    /**
     * @notice Checks if an address is an approved bundler
     * @param bundler The address to check
     * @return True if the address is an approved bundler
     */
    function isApprovedBundler(address bundler) external view override returns (bool) {
        return _approvedBundlers[bundler];
    }

    // ============ Owner Functions ============

    /**
     * @notice Approves a new bundler
     * @param bundler The bundler address to approve
     * @dev Only approved bundlers can sign FLOps commitments
     */
    function approveBundler(address bundler) external override onlyOwner {
        if (bundler == address(0)) revert ZeroAddress();
        _approvedBundlers[bundler] = true;
        emit BundlerApproved(bundler);
    }

    /**
     * @notice Revokes a bundler's approval
     * @param bundler The bundler address to revoke
     * @dev Revoked bundlers can no longer sign valid FLOps commitments
     */
    function revokeBundler(address bundler) external override onlyOwner {
        _approvedBundlers[bundler] = false;
        emit BundlerRevoked(bundler);
    }
}

